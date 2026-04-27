/*
 * honeypot_listener.c — Honeypot trap listener for PacketSonde Agent
 *
 * Opens passive TCP listener sockets on configured trap ports, accepts
 * inbound connections, captures the first HP_MAX_PAYLOAD bytes of payload,
 * and publishes a probe event to Redis for alerting and analysis.
 *
 * Config section: [honeypot]
 * Numeric keys are port numbers whose values are banner strings (sent on
 * accept). Banners support \r\n escape sequences.
 *
 * Publishes to channel: honeypot.probe (configurable)
 *
 * JSON output:
 *   {"timestamp":N,"src_ip":"...","src_port":N,"dst_host":"","dst_port":N,
 *    "connection_type":"established","connection_duration_ms":N,
 *    "total_bytes_received":N,"packet_count":N,"banner_sent":"...",
 *    "packets":[{"seq":N,"time_offset_ms":N.N,"tcp_flags":"S",
 *                "tcp_window":N,"ttl":N,"ip_flags_df":N,"ecn":N,
 *                "payload_len":N,"payload":"<base64>",
 *                "tcp_options":""},...]}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "packetsonde/module_api.h"
#include "packetsonde/honeypot_listener.h"
#include "json.h"
#include "log.h"

/* ------------------------------------------------------------------ */
/* Internal structures                                                  */
/* ------------------------------------------------------------------ */

struct hp_packet {
    int         seq;
    double      time_offset_ms;
    uint8_t     tcp_flags;
    uint16_t    tcp_window;
    uint8_t     ttl;
    uint8_t     ip_flags_df;
    uint8_t     ecn;
    uint16_t    payload_len;
    uint8_t     payload[HP_MAX_PAYLOAD];
    char        tcp_options[256];
};

/*
 * hp_halfopen_burst — accumulates pcap-visible SYN/XMAS/NULL packets from
 * one src_ip:dst_port pair within HP_DEDUP_WINDOW_MS.  After the window
 * expires the burst is emitted as a single "half_open" probe event.
 */
#define HP_MAX_BURSTS 32

struct hp_halfopen_burst {
    uint32_t    src_ip;          /* network byte order */
    uint16_t    dst_port;        /* host byte order */
    uint64_t    first_usec;
    uint64_t    last_usec;
    struct hp_packet packets[HP_MAX_PACKETS];
    int         packet_count;
    int         active;
};

struct hp_session {
    int          fd;
    uint16_t     trap_port;
    struct sockaddr_in peer;
    uint64_t     start_usec;
    uint64_t     last_activity_usec;
    int          banner_sent;
    struct hp_packet packets[HP_MAX_PACKETS];
    int          packet_count;
    int          total_bytes;
    int          payload_budget;
    const struct hp_trap_config *trap;
};

struct honeypot_state {
    struct hp_config cfg;
    /* Trap listen socket file descriptors — -1 when not open. */
    int trap_fds[HP_MAX_TRAPS];
    int listen_fds[HP_MAX_TRAPS];
    int listen_count;
    /* Active sessions */
    struct hp_session sessions[HP_MAX_SESSIONS];
    int session_count;
    /* pcap handle — -1 if not open (no CAP_NET_RAW / half-open disabled) */
    int pcap_handle;
    /* Half-open burst accumulators (filled by honeypot_on_packet) */
    struct hp_halfopen_burst bursts[HP_MAX_BURSTS];
    int burst_count;
};

/* ------------------------------------------------------------------ */
/* Config parser helpers                                                 */
/* ------------------------------------------------------------------ */

/*
 * Return 1 if the string is a valid decimal port number in 1..65535.
 */
static int is_port_str(const char *s)
{
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char)*p)) return 0;
    }
    long v = strtol(s, NULL, 10);
    return (v >= 1 && v <= 65535);
}

/*
 * Unescape \r and \n sequences in-place within dst (max dst_cap bytes).
 * src and dst may alias. Returns the length of the resulting string
 * (which may contain embedded NUL bytes from other escapes in the future).
 */
static int unescape_banner(char *dst, size_t dst_cap,
                            const char *src, size_t src_len)
{
    size_t ri = 0, wi = 0;
    while (ri < src_len && wi + 1 < dst_cap) {
        if (src[ri] == '\\' && ri + 1 < src_len) {
            char next = src[ri + 1];
            if (next == 'r') {
                dst[wi++] = '\r';
                ri += 2;
                continue;
            } else if (next == 'n') {
                dst[wi++] = '\n';
                ri += 2;
                continue;
            }
        }
        dst[wi++] = src[ri++];
    }
    dst[wi] = '\0';
    return (int)wi;
}

/*
 * Minimal line-oriented INI parser for the [honeypot] section.
 * Operates directly on the config string — does not use ps_config so
 * this file can be tested in isolation without pulling in config.c.
 */
int hp_parse_config_string(struct hp_config *cfg, const char *text)
{
    if (!cfg || !text) return -1;

    /* Apply defaults */
    memset(cfg, 0, sizeof(*cfg));
    cfg->enabled     = 0;
    cfg->timeout_sec = 10;
    cfg->max_payload = HP_MAX_PAYLOAD;
    cfg->max_events  = 10000;
    snprintf(cfg->redis_key,     sizeof(cfg->redis_key),
             "packetsonde:honeypot:probes");
    snprintf(cfg->redis_channel, sizeof(cfg->redis_channel),
             "honeypot.probe");

    int in_honeypot = 0;
    const char *p = text;

    while (*p) {
        /* Find end of line */
        const char *nl = strchr(p, '\n');
        size_t line_len = nl ? (size_t)(nl - p) : strlen(p);

        /* Copy line to mutable buffer */
        char line[1024];
        if (line_len >= sizeof(line)) line_len = sizeof(line) - 1;
        memcpy(line, p, line_len);
        line[line_len] = '\0';

        /* Advance p past line (and newline) */
        p += line_len;
        if (*p == '\n') p++;

        /* Trim leading whitespace */
        char *s = line;
        while (*s && isspace((unsigned char)*s)) s++;

        /* Skip blank lines and comments */
        if (*s == '\0' || *s == '#' || *s == ';') continue;

        /* Section header */
        if (*s == '[') {
            char *end = strchr(s, ']');
            if (!end) return -1;
            *end = '\0';
            char *sec = s + 1;
            while (*sec && isspace((unsigned char)*sec)) sec++;
            in_honeypot = (strcmp(sec, "honeypot") == 0);
            continue;
        }

        if (!in_honeypot) continue;

        /* Key = value */
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';

        /* Trim key */
        char *key = s;
        char *ke  = eq - 1;
        while (ke > key && isspace((unsigned char)*ke)) *ke-- = '\0';
        while (*key && isspace((unsigned char)*key)) key++;

        /* Trim value */
        char *val = eq + 1;
        while (*val && isspace((unsigned char)*val)) val++;
        char *ve = val + strlen(val) - 1;
        while (ve > val && isspace((unsigned char)*ve)) *ve-- = '\0';

        /* Dispatch on key */
        if (strcmp(key, "enabled") == 0) {
            cfg->enabled = (strcmp(val, "true") == 0 ||
                            strcmp(val, "yes")  == 0 ||
                            strcmp(val, "1")    == 0) ? 1 : 0;
        } else if (strcmp(key, "timeout") == 0) {
            cfg->timeout_sec = (int)strtol(val, NULL, 10);
        } else if (strcmp(key, "max_payload") == 0) {
            cfg->max_payload = (int)strtol(val, NULL, 10);
            if (cfg->max_payload > HP_MAX_PAYLOAD)
                cfg->max_payload = HP_MAX_PAYLOAD;
        } else if (strcmp(key, "redis_key") == 0) {
            snprintf(cfg->redis_key, sizeof(cfg->redis_key), "%s", val);
        } else if (strcmp(key, "max_events") == 0) {
            cfg->max_events = (int)strtol(val, NULL, 10);
        } else if (strcmp(key, "redis_channel") == 0) {
            snprintf(cfg->redis_channel, sizeof(cfg->redis_channel), "%s", val);
        } else if (is_port_str(key)) {
            /* Numeric key — trap port definition */
            if (cfg->trap_count >= HP_MAX_TRAPS) continue;
            struct hp_trap_config *t = &cfg->traps[cfg->trap_count++];
            t->port       = (uint16_t)strtol(key, NULL, 10);
            t->banner_len = unescape_banner(t->banner, sizeof(t->banner),
                                            val, strlen(val));
        }
        /* Unknown scalar keys are silently ignored */
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Task 4: TCP flags → string                                           */
/* ------------------------------------------------------------------ */

/*
 * hp_flags_to_string — Convert TCP flags byte to abbreviated flag string.
 *
 * Flag chars (high to low bit):
 *   C=CWR(0x80), E=ECE(0x40), U=URG(0x20), A=ACK(0x10),
 *   P=PSH(0x08), R=RST(0x04), S=SYN(0x02), F=FIN(0x01)
 *
 * Special cases:
 *   0x00 = "NULL"
 *   All flags set = printed as individual letters
 *
 * The result is a compact string like "S", "SA", "AP", "FPU", "NULL".
 */
static void hp_flags_to_string(uint8_t flags, char *buf, int buflen)
{
    if (buflen <= 0) return;

    if (flags == 0) {
        snprintf(buf, (size_t)buflen, "NULL");
        return;
    }

    char tmp[16];
    int wi = 0;

    if (flags & 0x80) tmp[wi++] = 'C';
    if (flags & 0x40) tmp[wi++] = 'E';
    if (flags & 0x20) tmp[wi++] = 'U';
    if (flags & 0x10) tmp[wi++] = 'A';
    if (flags & 0x08) tmp[wi++] = 'P';
    if (flags & 0x04) tmp[wi++] = 'R';
    if (flags & 0x02) tmp[wi++] = 'S';
    if (flags & 0x01) tmp[wi++] = 'F';
    tmp[wi] = '\0';

    snprintf(buf, (size_t)buflen, "%s", tmp);
}

/* ------------------------------------------------------------------ */
/* Task 4: Base64 encoder                                               */
/* ------------------------------------------------------------------ */

static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * hp_base64_encode — Standard base64 encode src[0..srclen-1] into dst.
 *
 * dst must have capacity >= ceil(srclen/3)*4 + 1.
 * Returns number of characters written (not including NUL), or -1 if
 * dst capacity (dstcap) is insufficient.
 */
static int hp_base64_encode(const uint8_t *src, size_t srclen,
                             char *dst, size_t dstcap)
{
    size_t needed = ((srclen + 2) / 3) * 4 + 1;
    if (dstcap < needed) return -1;

    size_t si = 0, di = 0;
    while (si + 3 <= srclen) {
        uint32_t v = ((uint32_t)src[si] << 16) |
                     ((uint32_t)src[si+1] << 8) |
                      (uint32_t)src[si+2];
        dst[di++] = B64_TABLE[(v >> 18) & 0x3F];
        dst[di++] = B64_TABLE[(v >> 12) & 0x3F];
        dst[di++] = B64_TABLE[(v >>  6) & 0x3F];
        dst[di++] = B64_TABLE[(v      ) & 0x3F];
        si += 3;
    }
    if (srclen - si == 2) {
        uint32_t v = ((uint32_t)src[si] << 16) | ((uint32_t)src[si+1] << 8);
        dst[di++] = B64_TABLE[(v >> 18) & 0x3F];
        dst[di++] = B64_TABLE[(v >> 12) & 0x3F];
        dst[di++] = B64_TABLE[(v >>  6) & 0x3F];
        dst[di++] = '=';
    } else if (srclen - si == 1) {
        uint32_t v = (uint32_t)src[si] << 16;
        dst[di++] = B64_TABLE[(v >> 18) & 0x3F];
        dst[di++] = B64_TABLE[(v >> 12) & 0x3F];
        dst[di++] = '=';
        dst[di++] = '=';
    }
    dst[di] = '\0';
    return (int)di;
}

/* ------------------------------------------------------------------ */
/* Task 4: Probe event JSON building + publishing                       */
/* ------------------------------------------------------------------ */

/*
 * hp_emit_probe_event_ex — Build and publish a full probe event JSON.
 *
 * Allocates a 32 KiB heap buffer for the JSON (payload base64 can be large).
 * Publishes to cfg->redis_channel.
 */
static void hp_emit_probe_event_ex(ps_module_ctx_t *ctx,
                                   const struct hp_config *cfg,
                                   const struct hp_session *session,
                                   uint64_t close_usec,
                                   const char *connection_type)
{
    char *buf = malloc(32768);
    if (!buf) return;

    /* Peer IP string */
    char src_ip[INET_ADDRSTRLEN] = "0.0.0.0";
    inet_ntop(AF_INET, &session->peer.sin_addr, src_ip, sizeof(src_ip));
    uint16_t src_port = ntohs(session->peer.sin_port);

    /* Duration */
    double duration_ms = 0.0;
    if (close_usec > session->start_usec) {
        duration_ms = (double)(close_usec - session->start_usec) / 1000.0;
    }

    /* Timestamp in milliseconds (Unix epoch) */
    int64_t timestamp_ms = (int64_t)(session->start_usec / 1000);

    /* Banner text (NUL-safe string for JSON — just the printable prefix) */
    char banner_str[HP_MAX_BANNER + 1];
    if (session->trap && session->banner_sent && session->trap->banner_len > 0) {
        /* Copy banner, truncate at NUL for JSON purposes */
        int blen = session->trap->banner_len;
        if (blen >= (int)sizeof(banner_str)) blen = (int)sizeof(banner_str) - 1;
        memcpy(banner_str, session->trap->banner, (size_t)blen);
        banner_str[blen] = '\0';
    } else {
        banner_str[0] = '\0';
    }

    struct ps_json j;
    ps_json_init(&j, buf, 32768);
    ps_json_object_begin(&j);

    ps_json_key_int   (&j, "timestamp",              timestamp_ms);
    ps_json_key_string(&j, "src_ip",                 src_ip);
    ps_json_key_int   (&j, "src_port",               (int64_t)src_port);
    ps_json_key_string(&j, "dst_host",               "");
    ps_json_key_int   (&j, "dst_port",               (int64_t)session->trap_port);
    ps_json_key_string(&j, "connection_type",        connection_type);
    ps_json_key_double(&j, "connection_duration_ms", duration_ms);
    ps_json_key_int   (&j, "total_bytes_received",   (int64_t)session->total_bytes);
    ps_json_key_int   (&j, "packet_count",           (int64_t)session->packet_count);
    ps_json_key_bool  (&j, "banner_sent",            session->banner_sent);
    ps_json_key_string(&j, "banner_text",            banner_str);

    /* Packets array */
    ps_json_array_begin(&j, "packets");

    for (int i = 0; i < session->packet_count; i++) {
        const struct hp_packet *pkt = &session->packets[i];

        /* Base64-encode payload */
        size_t b64cap = ((pkt->payload_len + 2) / 3) * 4 + 2;
        char  *b64buf = malloc(b64cap);
        if (!b64buf) continue;
        hp_base64_encode(pkt->payload, pkt->payload_len, b64buf, b64cap);

        /* Flags string */
        char flags_str[16];
        hp_flags_to_string(pkt->tcp_flags, flags_str, sizeof(flags_str));

        ps_json_object_begin(&j);
        ps_json_key_int   (&j, "seq",            (int64_t)pkt->seq);
        ps_json_key_double(&j, "time_offset_ms", pkt->time_offset_ms);
        ps_json_key_string(&j, "tcp_flags",      flags_str);
        ps_json_key_int   (&j, "tcp_window",     (int64_t)pkt->tcp_window);
        ps_json_key_int   (&j, "ttl",            (int64_t)pkt->ttl);
        ps_json_key_int   (&j, "ip_flags_df",    (int64_t)pkt->ip_flags_df);
        ps_json_key_int   (&j, "ecn",            (int64_t)pkt->ecn);
        ps_json_key_int   (&j, "payload_len",    (int64_t)pkt->payload_len);
        ps_json_key_string(&j, "payload",        b64buf);
        ps_json_key_string(&j, "tcp_options",    pkt->tcp_options);
        ps_json_object_end(&j);

        free(b64buf);
    }

    ps_json_array_end(&j);
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, cfg->redis_channel, buf, (uint32_t)j.len);
    }

    free(buf);
}

/*
 * hp_emit_probe_event — Convenience wrapper for established connections.
 */
static void hp_emit_probe_event(ps_module_ctx_t *ctx,
                                const struct hp_config *cfg,
                                const struct hp_session *session,
                                uint64_t close_usec)
{
    hp_emit_probe_event_ex(ctx, cfg, session, close_usec, "established");
}

/* ------------------------------------------------------------------ */
/* Task 3: Socket management helpers                                    */
/* ------------------------------------------------------------------ */

/* Forward declaration — defined after hp_read_sessions */
static void hp_close_session(struct honeypot_state *st, int idx,
                              ps_module_ctx_t *ctx, uint64_t now_usec);

/*
 * hp_set_nonblocking — Set O_NONBLOCK on fd via fcntl.
 * Returns 0 on success, -1 on error.
 */
static int hp_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/*
 * hp_bind_trap — Create a non-blocking TCP listen socket on the given port.
 * Returns the fd on success, -1 on any error.
 */
static int hp_bind_trap(ps_module_ctx_t *ctx, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        ps_warn("honeypot: socket() failed for port %u: %s",
                (unsigned)port, strerror(errno));
        return -1;
    }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ps_warn("honeypot: bind() on port %u failed: %s",
                (unsigned)port, strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 16) < 0) {
        ps_warn("honeypot: listen() on port %u failed: %s",
                (unsigned)port, strerror(errno));
        close(fd);
        return -1;
    }

    if (hp_set_nonblocking(fd) < 0) {
        ps_warn("honeypot: fcntl O_NONBLOCK on port %u failed: %s",
                (unsigned)port, strerror(errno));
        close(fd);
        return -1;
    }

    ps_info("honeypot: listening on port %u (fd=%d)", (unsigned)port, fd);
    return fd;
}

/*
 * hp_accept_connections — Accept pending connections on all listen sockets.
 * Populates new hp_session entries. Drops new connections when at capacity.
 */
static void hp_accept_connections(struct honeypot_state *st,
                                  ps_module_ctx_t *ctx,
                                  uint64_t now_usec)
{
    for (int li = 0; li < st->listen_count; li++) {
        int lfd = st->listen_fds[li];
        if (lfd < 0) continue;

        /* Find which trap config this listen fd belongs to */
        const struct hp_trap_config *trap = NULL;
        for (int ti = 0; ti < st->cfg.trap_count; ti++) {
            if (st->trap_fds[ti] == lfd) {
                trap = &st->cfg.traps[ti];
                break;
            }
        }

        for (;;) {
            struct sockaddr_in peer;
            socklen_t peer_len = sizeof(peer);
            int cfd = accept(lfd, (struct sockaddr *)&peer, &peer_len);
            if (cfd < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                ps_warn("honeypot: accept() error: %s", strerror(errno));
                break;
            }

            if (st->session_count >= HP_MAX_SESSIONS) {
                ps_warn("honeypot: session table full — dropping connection");
                close(cfd);
                continue;
            }

            /* Set SO_NOSIGPIPE on accepted socket (macOS) */
            int one = 1;
#ifdef SO_NOSIGPIPE
            setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#else
            (void)one;
#endif
            hp_set_nonblocking(cfd);

            struct hp_session *sess = &st->sessions[st->session_count++];
            memset(sess, 0, sizeof(*sess));
            sess->fd                 = cfd;
            sess->trap_port          = trap ? trap->port : 0;
            sess->peer               = peer;
            sess->start_usec         = now_usec;
            sess->last_activity_usec = now_usec;
            sess->banner_sent        = 0;
            sess->packet_count       = 0;
            sess->total_bytes        = 0;
            sess->payload_budget     = st->cfg.max_payload;
            sess->trap               = trap;

            char src_ip[INET_ADDRSTRLEN] = "?";
            inet_ntop(AF_INET, &peer.sin_addr, src_ip, sizeof(src_ip));
            ps_info("honeypot: connection from %s:%u on port %u",
                    src_ip, (unsigned)ntohs(peer.sin_port),
                    (unsigned)(trap ? trap->port : 0));
        }
    }
    (void)ctx;
}

/*
 * hp_send_banners — Send banner to any sessions that haven't received one yet.
 * Non-blocking best-effort — partial sends are treated as success for now.
 */
static void hp_send_banners(struct honeypot_state *st, ps_module_ctx_t *ctx)
{
    for (int i = 0; i < st->session_count; i++) {
        struct hp_session *sess = &st->sessions[i];
        if (sess->banner_sent) continue;
        if (!sess->trap || sess->trap->banner_len <= 0) {
            sess->banner_sent = 1; /* no banner configured — mark done */
            continue;
        }

        /* write() avoids SIGPIPE on all platforms */
        ssize_t n = write(sess->fd,
                          sess->trap->banner,
                          (size_t)sess->trap->banner_len);
        if (n > 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
            sess->banner_sent = 1;
        }
        /* On hard error, session will be cleaned up by hp_read_sessions */
    }
    (void)ctx;
}

/*
 * hp_read_sessions — Non-blocking read from each active session.
 * Records received data as hp_packet entries (one packet per recv() call).
 * Closes sessions where the peer has disconnected or an error occurred.
 */
static void hp_read_sessions(struct honeypot_state *st,
                              ps_module_ctx_t *ctx,
                              uint64_t now_usec)
{
    for (int i = 0; i < st->session_count; ) {
        struct hp_session *sess = &st->sessions[i];

        uint8_t rbuf[HP_MAX_PAYLOAD];
        int cap = (sess->payload_budget > HP_MAX_PAYLOAD)
                    ? HP_MAX_PAYLOAD : sess->payload_budget;
        if (cap <= 0) { i++; continue; }

        ssize_t n = recv(sess->fd, rbuf, (size_t)cap, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                i++;
                continue;
            }
            /* Real error — close */
            hp_close_session(st, i, ctx, now_usec);
            /* don't increment i — array compacted */
            continue;
        }
        if (n == 0) {
            /* Peer disconnected cleanly */
            hp_close_session(st, i, ctx, now_usec);
            continue;
        }

        /* Record the received chunk as a packet entry */
        sess->last_activity_usec = now_usec;
        sess->total_bytes += (int)n;
        sess->payload_budget -= (int)n;

        if (sess->packet_count < HP_MAX_PACKETS) {
            struct hp_packet *pkt = &sess->packets[sess->packet_count++];
            memset(pkt, 0, sizeof(*pkt));
            pkt->seq = sess->packet_count; /* 1-based */
            pkt->time_offset_ms = (sess->start_usec < now_usec)
                ? (double)(now_usec - sess->start_usec) / 1000.0
                : 0.0;
            /* tcp_flags/window/ttl/etc. not available at this layer —
             * set to 0 (pcap-based enrichment is Task 5) */
            uint16_t copy_len = (uint16_t)((size_t)n < HP_MAX_PAYLOAD
                                            ? (size_t)n : HP_MAX_PAYLOAD);
            pkt->payload_len = copy_len;
            memcpy(pkt->payload, rbuf, copy_len);
        }
        i++;
    }
}

/*
 * hp_check_timeouts — Close sessions that have exceeded the idle timeout.
 */
static void hp_check_timeouts(struct honeypot_state *st,
                               ps_module_ctx_t *ctx,
                               uint64_t now_usec)
{
    uint64_t timeout_usec = (uint64_t)st->cfg.timeout_sec * 1000000ULL;

    for (int i = 0; i < st->session_count; ) {
        struct hp_session *sess = &st->sessions[i];
        uint64_t idle = now_usec - sess->last_activity_usec;
        uint64_t age  = now_usec - sess->start_usec;

        if (idle > timeout_usec || age > timeout_usec * 2) {
            hp_close_session(st, i, ctx, now_usec);
            /* don't increment i */
        } else {
            i++;
        }
    }
}

/*
 * hp_close_session — Emit probe event (if data received), close fd,
 * and compact the sessions array by moving the last entry into slot idx.
 */
static void hp_close_session(struct honeypot_state *st,
                              int idx,
                              ps_module_ctx_t *ctx,
                              uint64_t now_usec)
{
    if (idx < 0 || idx >= st->session_count) return;

    struct hp_session *sess = &st->sessions[idx];

    /* Emit event if any data was exchanged */
    if (sess->packet_count > 0 || sess->total_bytes > 0) {
        hp_emit_probe_event(ctx, &st->cfg, sess, now_usec);
    }

    close(sess->fd);

    /* Compact: move last session into this slot */
    int last = st->session_count - 1;
    if (idx != last) {
        st->sessions[idx] = st->sessions[last];
    }
    st->session_count--;
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int honeypot_init(ps_module_ctx_t *ctx)
{
    struct honeypot_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("honeypot_listener: out of memory");
        return -1;
    }

    for (int i = 0; i < HP_MAX_TRAPS; i++) {
        st->trap_fds[i]   = -1;
        st->listen_fds[i] = -1;
    }
    st->listen_count  = 0;
    st->session_count = 0;
    st->pcap_handle   = -1;

    ctx->userdata = st;

    /* Load config from file if no traps have been configured yet.
     * Try the local path first, then the system-wide location. */
    if (st->cfg.trap_count == 0) {
        static const char *cfg_paths[] = {
            "honeypot.conf",
            "/etc/packetsonde/honeypot.conf",
        };
        for (int ci = 0; ci < (int)(sizeof(cfg_paths)/sizeof(cfg_paths[0])); ci++) {
            FILE *f = fopen(cfg_paths[ci], "r");
            if (!f) continue;

            /* Read entire file into a heap buffer */
            fseek(f, 0, SEEK_END);
            long fsz = ftell(f);
            rewind(f);

            if (fsz > 0 && fsz < 65536) {
                char *fbuf = (char *)malloc((size_t)(fsz + 1));
                if (fbuf) {
                    size_t nread = fread(fbuf, 1, (size_t)fsz, f);
                    fbuf[nread] = '\0';
                    if (hp_parse_config_string(&st->cfg, fbuf) == 0) {
                        ps_info("honeypot_listener: loaded config from %s "
                                "(%d traps)", cfg_paths[ci], st->cfg.trap_count);
                    } else {
                        ps_warn("honeypot_listener: parse error in %s",
                                cfg_paths[ci]);
                    }
                    free(fbuf);
                }
            }
            fclose(f);
            break;   /* use first file found */
        }
    }

    /* Bind trap sockets for each configured port */
    for (int i = 0; i < st->cfg.trap_count; i++) {
        uint16_t port = st->cfg.traps[i].port;
        int fd = hp_bind_trap(ctx, port);
        st->trap_fds[i] = fd;
        if (fd >= 0 && st->listen_count < HP_MAX_TRAPS) {
            st->listen_fds[st->listen_count++] = fd;
        }
    }

    /* Open a pcap handle for half-open SYN detection scoped to trap ports.
     * This requires CAP_NET_RAW; failure is non-fatal — half-open detection
     * is disabled gracefully if the handle cannot be opened. */
    if (ctx->open_pcap && st->cfg.trap_count > 0) {
        /* Build BPF filter: "tcp and (dst port P or dst port Q ...)" */
        char bpf[512];
        int  bpf_pos = 0;
        bpf_pos += snprintf(bpf + bpf_pos, sizeof(bpf) - (size_t)bpf_pos,
                            "tcp and (");
        for (int i = 0; i < st->cfg.trap_count && bpf_pos < (int)sizeof(bpf) - 32; i++) {
            if (i > 0)
                bpf_pos += snprintf(bpf + bpf_pos, sizeof(bpf) - (size_t)bpf_pos,
                                    " or ");
            bpf_pos += snprintf(bpf + bpf_pos, sizeof(bpf) - (size_t)bpf_pos,
                                "dst port %u", (unsigned)st->cfg.traps[i].port);
        }
        snprintf(bpf + bpf_pos, sizeof(bpf) - (size_t)bpf_pos, ")");

        int h = ctx->open_pcap(ctx, NULL, bpf, 128);
        if (h >= 0) {
            st->pcap_handle = h;
            ps_info("honeypot_listener: pcap handle %d opened (half-open detection active, filter: %s)",
                    h, bpf);
        } else {
            ps_warn("honeypot_listener: pcap open failed — half-open detection disabled (no CAP_NET_RAW?)");
        }
    }

    ps_info("honeypot_listener: initialized (%d traps configured, %d bound)",
            st->cfg.trap_count, st->listen_count);
    return 0;
}

static void honeypot_shutdown(ps_module_ctx_t *ctx)
{
    struct honeypot_state *st = (struct honeypot_state *)ctx->userdata;
    if (!st) return;

    /* Close all active sessions (emit events for those with data) */
    while (st->session_count > 0) {
        hp_close_session(st, 0, ctx, 0);
    }

    /* Close listen sockets */
    for (int i = 0; i < st->listen_count; i++) {
        if (st->listen_fds[i] >= 0) {
            close(st->listen_fds[i]);
            st->listen_fds[i] = -1;
        }
    }
    st->listen_count = 0;

    free(st);
    ctx->userdata = NULL;
    ps_info("honeypot_listener: shutdown");
}

/* Forward declaration — defined in the on_packet section below */
static void hp_burst_to_session(const struct hp_halfopen_burst *b,
                                 struct hp_session *out);

/*
 * hp_flush_expired_bursts — emit half-open probe events for bursts whose
 * dedup window has expired and compact the burst array.
 */
static void hp_flush_expired_bursts(struct honeypot_state *st,
                                     ps_module_ctx_t *ctx,
                                     uint64_t now_usec)
{
    uint64_t window_usec = (uint64_t)HP_DEDUP_WINDOW_MS * 1000ULL;
    int wi = 0;

    for (int ri = 0; ri < st->burst_count; ri++) {
        struct hp_halfopen_burst *b = &st->bursts[ri];

        if (b->active && b->packet_count > 0 &&
            now_usec - b->last_usec >= window_usec)
        {
            /* Window expired — emit event and mark inactive */
            struct hp_session *synth = calloc(1, sizeof(*synth));
            if (!synth) { b->active = 0; continue; }
            hp_burst_to_session(b, synth);
            hp_emit_probe_event_ex(ctx, &st->cfg, synth,
                                   b->last_usec, "half_open");
            free(synth);
            b->active = 0;
        }

        /* Compact: keep active bursts only */
        if (b->active) {
            if (wi != ri)
                st->bursts[wi] = *b;
            wi++;
        }
    }
    st->burst_count = wi;
}

/*
 * honeypot_tick — periodic maintenance: accept, banner, read, timeout,
 * and half-open burst flush.
 */
static void honeypot_tick(ps_module_ctx_t *ctx, uint64_t now_usec)
{
    struct honeypot_state *st = (struct honeypot_state *)ctx->userdata;
    if (!st) return;

    hp_accept_connections(st, ctx, now_usec);
    hp_send_banners(st, ctx);
    hp_read_sessions(st, ctx, now_usec);
    hp_check_timeouts(st, ctx, now_usec);
    hp_flush_expired_bursts(st, ctx, now_usec);
}

/* ------------------------------------------------------------------ */
/* Task 5: Half-open SYN watcher helpers                                */
/* ------------------------------------------------------------------ */

/*
 * hp_parse_tcp_options — parse TCP options region and build a comma-
 * separated summary string like "mss:1460,ws:7,sack,ts" in buf[buflen].
 */
static void hp_parse_tcp_options(const uint8_t *opts, int opts_len,
                                  char *buf, int buflen)
{
    int pos = 0;
    int wi  = 0;

    buf[0] = '\0';

    while (pos < opts_len) {
        uint8_t kind = opts[pos];

        if (kind == 0) break;          /* EOL */
        if (kind == 1) { pos++; continue; } /* NOP */

        if (pos + 1 >= opts_len) break;
        uint8_t olen = opts[pos + 1];
        if (olen < 2 || pos + olen > opts_len) break;

        char tmp[64];
        tmp[0] = '\0';

        switch (kind) {
        case 2: /* MSS */
            if (olen == 4) {
                uint16_t mss = (uint16_t)((opts[pos+2] << 8) | opts[pos+3]);
                snprintf(tmp, sizeof(tmp), "mss:%u", (unsigned)mss);
            }
            break;
        case 3: /* Window scale */
            if (olen == 3) {
                snprintf(tmp, sizeof(tmp), "ws:%u", (unsigned)opts[pos+2]);
            }
            break;
        case 4: /* SACK permitted */
            snprintf(tmp, sizeof(tmp), "sack");
            break;
        case 8: /* Timestamps */
            snprintf(tmp, sizeof(tmp), "ts");
            break;
        default:
            break;
        }

        if (tmp[0] != '\0') {
            int tlen = (int)strlen(tmp);
            if (wi + tlen + 2 < buflen) {
                if (wi > 0) buf[wi++] = ',';
                memcpy(buf + wi, tmp, (size_t)tlen);
                wi += tlen;
                buf[wi] = '\0';
            }
        }

        pos += olen;
    }
}

/*
 * hp_find_or_create_burst — return a burst slot for src_ip:dst_port,
 * creating one if none exists and there is room.  Returns NULL if full.
 */
static struct hp_halfopen_burst *
hp_find_or_create_burst(struct honeypot_state *st,
                         uint32_t src_ip, uint16_t dst_port,
                         uint64_t now_usec)
{
    for (int i = 0; i < st->burst_count; i++) {
        struct hp_halfopen_burst *b = &st->bursts[i];
        if (b->active && b->src_ip == src_ip && b->dst_port == dst_port)
            return b;
    }

    /* Create new */
    if (st->burst_count >= HP_MAX_BURSTS) return NULL;

    struct hp_halfopen_burst *b = &st->bursts[st->burst_count++];
    memset(b, 0, sizeof(*b));
    b->src_ip    = src_ip;
    b->dst_port  = dst_port;
    b->first_usec = now_usec;
    b->last_usec  = now_usec;
    b->active     = 1;
    return b;
}

/*
 * hp_burst_to_session — build a synthetic hp_session from a burst so that
 * hp_emit_probe_event_ex can be reused without modification.
 */
static void hp_burst_to_session(const struct hp_halfopen_burst *b,
                                 struct hp_session *s)
{
    memset(s, 0, sizeof(*s));
    s->fd          = -1;
    s->trap_port   = b->dst_port;
    s->start_usec  = b->first_usec;
    s->last_activity_usec = b->last_usec;
    s->banner_sent = 0;
    s->packet_count = b->packet_count;
    s->trap        = NULL;

    /* Reconstruct peer sockaddr from the burst src_ip */
    s->peer.sin_family      = AF_INET;
    s->peer.sin_addr.s_addr = b->src_ip;   /* already network byte order */
    s->peer.sin_port        = 0;

    /* Copy packets */
    int n = b->packet_count;
    if (n > HP_MAX_PACKETS) n = HP_MAX_PACKETS;
    for (int i = 0; i < n; i++) {
        s->packets[i] = b->packets[i];
        s->total_bytes += b->packets[i].payload_len;
    }
}

/*
 * honeypot_on_packet — pcap callback.
 *
 * Receives raw Ethernet frames for the trap ports.  Parses the Ethernet +
 * IPv4 + TCP headers, skips packets that belong to already-established
 * sessions (SYN-ACK / data from us), and accumulates half-open probe bursts.
 *
 * Header layout assumed: Ethernet(14) + IPv4(20) + TCP(20+opts).
 * Only IPv4 (ethertype 0x0800) / TCP (protocol 6) frames are processed.
 */
static void honeypot_on_packet(ps_module_ctx_t *ctx,
                                const uint8_t *pkt, uint32_t len,
                                uint64_t ts_usec, int handle_id)
{
    struct honeypot_state *st = (struct honeypot_state *)ctx->userdata;
    if (!st) return;
    (void)handle_id;

    /* Minimum frame: Ethernet(14) + IPv4(20) + TCP(20) = 54 bytes */
    if (len < 54) return;

    /* ---- Ethernet ---- */
    uint16_t ethertype = (uint16_t)((pkt[12] << 8) | pkt[13]);
    if (ethertype != 0x0800) return;   /* IPv4 only */

    /* ---- IPv4 ---- */
    const uint8_t *ip = pkt + 14;
    uint8_t  ihl      = (ip[0] & 0x0F) * 4;
    if (ihl < 20 || 14u + ihl + 20u > len) return;

    uint8_t  protocol  = ip[9];
    if (protocol != 6) return;         /* TCP only */

    uint8_t  ttl       = ip[8];
    uint8_t  df        = (ip[6] & 0x40) ? 1 : 0;  /* bit 6 of byte [6] */
    uint8_t  ecn       = ip[1] & 0x03;             /* DSCP/ECN LSBs */

    /* Source IP (network byte order — kept as-is for sockaddr) */
    uint32_t src_ip;
    memcpy(&src_ip, ip + 12, 4);

    /* ---- TCP ---- */
    const uint8_t *tcp = ip + ihl;
    if (14u + ihl + 20u > len) return;

    uint16_t src_port  = (uint16_t)((tcp[0] << 8) | tcp[1]);
    uint16_t dst_port  = (uint16_t)((tcp[2] << 8) | tcp[3]);
    uint8_t  data_off  = (tcp[12] >> 4) * 4;   /* TCP header length in bytes */
    uint8_t  tcp_flags = tcp[13];
    uint16_t tcp_win   = (uint16_t)((tcp[14] << 8) | tcp[15]);

    /* Skip ACK-only — these are our own SYN-ACK replies or keepalives */
    if (tcp_flags == 0x10) return;

    /* Skip packets belonging to an established session (match src_ip:src_port) */
    for (int i = 0; i < st->session_count; i++) {
        const struct hp_session *s = &st->sessions[i];
        if (s->peer.sin_addr.s_addr == src_ip &&
            ntohs(s->peer.sin_port) == src_port)
            return;
    }

    /* ---- TCP options ---- */
    char tcp_opts_str[256];
    tcp_opts_str[0] = '\0';
    if (data_off > 20 && 14u + ihl + data_off <= len) {
        hp_parse_tcp_options(tcp + 20, (int)(data_off - 20),
                             tcp_opts_str, (int)sizeof(tcp_opts_str));
    }

    /* ---- Find or create burst accumulator ---- */
    struct hp_halfopen_burst *burst =
        hp_find_or_create_burst(st, src_ip, dst_port, ts_usec);
    if (!burst) return;   /* burst table full */

    burst->last_usec = ts_usec;

    if (burst->packet_count < HP_MAX_PACKETS) {
        struct hp_packet *p = &burst->packets[burst->packet_count++];
        memset(p, 0, sizeof(*p));
        p->seq            = burst->packet_count;   /* 1-based */
        p->time_offset_ms = (ts_usec > burst->first_usec)
                            ? (double)(ts_usec - burst->first_usec) / 1000.0
                            : 0.0;
        p->tcp_flags      = tcp_flags;
        p->tcp_window     = tcp_win;
        p->ttl            = ttl;
        p->ip_flags_df    = df;
        p->ecn            = ecn;
        p->payload_len    = 0;    /* SYN carries no application payload */
        snprintf(p->tcp_options, sizeof(p->tcp_options), "%s", tcp_opts_str);
    }

    (void)src_port;   /* captured in session skip check; not stored in burst */
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

#ifndef PS_HONEYPOT_LISTENER_TESTING

const ps_module_t ps_honeypot_listener_module = {
    .name        = "honeypot_listener",
    .description = "TCP honeypot trap — captures probe payloads and publishes events",
    .version     = "1.0",
    .flags       = PS_MOD_PASSIVE | PS_MOD_NEEDS_PCAP,

    .init        = honeypot_init,
    .shutdown    = honeypot_shutdown,
    .on_packet   = honeypot_on_packet,
    .on_job      = NULL,
    .on_response = NULL,
    .tick        = honeypot_tick,
};

#endif /* PS_HONEYPOT_LISTENER_TESTING */
