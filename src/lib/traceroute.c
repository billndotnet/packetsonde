#include "traceroute.h"
#include "traceroute_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

const char *ps_tr_proto_str(enum ps_tr_proto p) {
    return p == PS_TR_PROTO_UDP ? "udp" : p == PS_TR_PROTO_TCP ? "tcp" : "icmp";
}
const char *ps_tr_mode_str(enum ps_tr_mode m) {
    return m == PS_TR_MODE_CLASSIC ? "classic" : m == PS_TR_MODE_PARIS ? "paris" : "dublin";
}

static long usec_diff(struct timeval *a, struct timeval *b) {
    return (b->tv_sec - a->tv_sec) * 1000000L + (b->tv_usec - a->tv_usec);
}

void ps_tr_sink_init(struct ps_tr_sink *s, ps_tr_hop_cb cb, void *user,
                     int max_gap) {
    s->cb = cb; s->user = user; s->max_gap = max_gap;
    s->seen_live = 0; s->consec_dead = 0; s->stopped = 0;
}

int ps_tr_sink_emit(struct ps_tr_sink *s, const struct ps_tr_hop *hop) {
    if (s->stopped) return 1;
    if (s->cb(hop, s->user)) { s->stopped = 1; return 1; }   /* consumer stop */

    if (hop->addr[0]) { s->seen_live = 1; s->consec_dead = 0; }
    else              { s->consec_dead++; }

    if (hop->reached_dst) { s->stopped = 1; return 1; }      /* dest reached */
    if (s->max_gap > 0 && s->seen_live && s->consec_dead >= s->max_gap) {
        s->stopped = 1; return 1;                            /* gap after live */
    }
    return 0;
}

static int resolve_v4(const char *host, struct sockaddr_in *out) {
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *r = NULL;
    if (getaddrinfo(host, NULL, &hints, &r) != 0) return -1;
    *out = *(struct sockaddr_in *)r->ai_addr;
    freeaddrinfo(r);
    return 0;
}

static int recv_icmp_for(int icmp_fd, int timeout_ms,
                         struct sockaddr_in *src_out, int *kind_out) {
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(icmp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[2048];
    struct sockaddr_in from; socklen_t flen = sizeof(from);
    ssize_t n = recvfrom(icmp_fd, buf, sizeof(buf), 0,
                        (struct sockaddr *)&from, &flen);
    if (n <= 0) return -1;

    if (n < (int)(sizeof(struct ip) + sizeof(struct icmp))) return -1;
    struct ip *ip = (struct ip *)buf;
    int ip_hl = ip->ip_hl * 4;
    if (n < ip_hl + (int)sizeof(struct icmp)) return -1;
    struct icmp *ic = (struct icmp *)(buf + ip_hl);

    if (ic->icmp_type == ICMP_TIMXCEED || ic->icmp_type == ICMP_UNREACH) {
        *src_out = from;
        if (kind_out) *kind_out = ic->icmp_type;
        return 0;
    }
    return -1;
}

/* Walk a single UDP flow at increasing TTLs, streaming hops through sink.
 *
 * mode controls how each probe identifies itself on the wire:
 *
 *   CLASSIC — dst_port increments per TTL. Flow tuple changes every hop,
 *             so ECMP-balanced paths may differ between hops.
 *   PARIS   — dst_port held constant; src_port held constant (the socket
 *             is bound to src_port). ECMP hash is stable; every hop
 *             traverses the same path.
 *
 * Returns 0 on success. Stops early when the sink signals stop. */
static int udp_flow_walk(int udp_fd, int icmp_fd,
                         struct sockaddr_in dst, enum ps_tr_mode mode,
                         const struct ps_traceroute_opts *opts,
                         struct ps_tr_sink *sink) {
    int max = opts->max_hops > 0 ? opts->max_hops : 30;
    if (max > PS_TRACEROUTE_MAX_HOPS) max = PS_TRACEROUTE_MAX_HOPS;

    for (int ttl = 1; ttl <= max; ttl++) {
        setsockopt(udp_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        struct sockaddr_in d = dst;
        d.sin_port = htons(mode == PS_TR_MODE_CLASSIC
                           ? opts->dst_port + ttl - 1 : opts->dst_port);

        struct timeval t0; gettimeofday(&t0, NULL);
        char payload[16] = "PSTR";
        sendto(udp_fd, payload, sizeof(payload), 0,
               (struct sockaddr *)&d, sizeof(d));

        struct ps_tr_hop h; memset(&h, 0, sizeof(h));
        h.ttl = ttl;
        struct sockaddr_in src; int kind = 0;
        if (recv_icmp_for(icmp_fd, opts->timeout_ms, &src, &kind) == 0) {
            struct timeval t1; gettimeofday(&t1, NULL);
            inet_ntop(AF_INET, &src.sin_addr, h.addr, sizeof(h.addr));
            h.rtt_us = usec_diff(&t0, &t1);
            h.reached_dst = (kind == ICMP_UNREACH) ||
                            (src.sin_addr.s_addr == dst.sin_addr.s_addr);
        }
        if (ps_tr_sink_emit(sink, &h)) return 0;
    }
    return 0;
}

/* Bind a fresh UDP socket to a specific source port (for Paris/Dublin).
 * Returns the fd, or -1 on failure. */
static int udp_socket_bound(uint16_t src_port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(src_port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int icmp_listener(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (fd >= 0) return fd;
    return socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
}

static int tr_udp_classic(const char *target,
                          const struct ps_traceroute_opts *opts,
                          struct ps_tr_sink *sink) {
    struct sockaddr_in dst;
    if (resolve_v4(target, &dst) != 0) return -1;
    int icmp_fd = icmp_listener();
    if (icmp_fd < 0) return -1;
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) { close(icmp_fd); return -1; }
    int rc = udp_flow_walk(udp_fd, icmp_fd, dst, PS_TR_MODE_CLASSIC, opts, sink);
    close(udp_fd); close(icmp_fd);
    return rc;
}

static int tr_udp_paris(const char *target,
                        const struct ps_traceroute_opts *opts,
                        struct ps_tr_sink *sink) {
    struct sockaddr_in dst;
    if (resolve_v4(target, &dst) != 0) return -1;
    int icmp_fd = icmp_listener();
    if (icmp_fd < 0) return -1;
    /* Bind src_port so the (src_ip, dst_ip, src_port, dst_port, proto) tuple
     * is stable across every probe in the run. */
    int udp_fd = udp_socket_bound(33500);
    if (udp_fd < 0) { close(icmp_fd); return -1; }
    int rc = udp_flow_walk(udp_fd, icmp_fd, dst, PS_TR_MODE_PARIS, opts, sink);
    close(udp_fd); close(icmp_fd);
    return rc;
}

/* ---- TCP traceroute ----
 *
 * Send a TCP SYN per TTL via non-blocking connect(). The kernel emits a real
 * SYN; intermediate routers drop it and emit ICMP TTL exceeded; the
 * destination either accepts (SYN+ACK -> connect succeeds) or refuses (RST ->
 * ECONNREFUSED). Both destination outcomes mean we reached it.
 *
 * Each hop opens a fresh socket so connect() state is clean. We select() on
 * both the TCP fd (for connect completion) and the ICMP fd (for intermediate
 * TTL exceeded) so whichever arrives first wins.
 *
 * CLASSIC TCP: dst_port held constant (the audit target port — typically 80
 *              or 443). src_port is ephemeral and varies per hop. This is
 *              already a "stable" flow for most ECMP hashes because src+dst
 *              tuple changes only in src_port.
 * PARIS TCP:   dst_port held constant AND src_port bound to a fixed value
 *              so every probe traverses the same ECMP-balanced path.
 *
 * Note: SYN cookies / DDoS protections may eat SYNs silently. That's a real
 * limit of unprivileged TCP traceroute — no different from tcptraceroute(1).
 */
static int tcp_flow_walk(int icmp_fd, struct sockaddr_in dst,
                         enum ps_tr_mode mode, uint16_t src_port,
                         const struct ps_traceroute_opts *opts,
                         struct ps_tr_sink *sink) {
    int max = opts->max_hops > 0 ? opts->max_hops : 30;
    if (max > PS_TRACEROUTE_MAX_HOPS) max = PS_TRACEROUTE_MAX_HOPS;

    for (int ttl = 1; ttl <= max; ttl++) {
        int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (tcp_fd < 0) return -1;
        int one = 1;
        setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (mode == PS_TR_MODE_PARIS && src_port != 0) {
            struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_port = htons(src_port);
            sa.sin_addr.s_addr = htonl(INADDR_ANY);
            int br = bind(tcp_fd, (struct sockaddr *)&sa, sizeof(sa));
            (void)br;
        }
        setsockopt(tcp_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        int flags = fcntl(tcp_fd, F_GETFL, 0);
        fcntl(tcp_fd, F_SETFL, flags | O_NONBLOCK);

        struct timeval t0; gettimeofday(&t0, NULL);
        int cr = connect(tcp_fd, (struct sockaddr *)&dst, sizeof(dst));
        if (cr != 0 && errno != EINPROGRESS) {
            close(tcp_fd);
            struct ps_tr_hop h; memset(&h, 0, sizeof(h)); h.ttl = ttl;
            if (ps_tr_sink_emit(sink, &h)) return 0;
            continue;
        }

        /* select() on icmp_fd (read) + tcp_fd (write). Whichever fires first
         * tells us what happened to this probe. */
        fd_set rfds, wfds;
        FD_ZERO(&rfds); FD_ZERO(&wfds);
        FD_SET(icmp_fd, &rfds);
        FD_SET(tcp_fd, &wfds);
        int nfds = (tcp_fd > icmp_fd ? tcp_fd : icmp_fd) + 1;
        struct timeval tv = { opts->timeout_ms / 1000,
                              (opts->timeout_ms % 1000) * 1000 };
        int sr = select(nfds, &rfds, &wfds, NULL, &tv);

        struct ps_tr_hop h; memset(&h, 0, sizeof(h)); h.ttl = ttl;

        if (sr <= 0) { close(tcp_fd); if (ps_tr_sink_emit(sink, &h)) return 0; continue; }
        if (FD_ISSET(icmp_fd, &rfds)) {
            struct sockaddr_in src; int kind = 0;
            if (recv_icmp_for(icmp_fd, 0, &src, &kind) == 0) {
                struct timeval t1; gettimeofday(&t1, NULL);
                inet_ntop(AF_INET, &src.sin_addr, h.addr, sizeof(h.addr));
                h.rtt_us = usec_diff(&t0, &t1);
                h.reached_dst = (src.sin_addr.s_addr == dst.sin_addr.s_addr);
            }
        }
        if (h.reached_dst == 0 && FD_ISSET(tcp_fd, &wfds)) {
            /* connect() completed. Inspect SO_ERROR:
             *   0              -- SYN+ACK -> reached dst, port open
             *   ECONNREFUSED   -- RST     -> reached dst, port closed
             *   EHOSTUNREACH / ENETUNREACH / ETIMEDOUT -- intermediate router
             *     sent ICMP (kernel ate it on this socket's behalf), so we
             *     know a hop responded but lost its address.
             *
             * Unprivileged TCP traceroute can't recover the intermediate
             * router address on every platform — that needs IP_RECVERR
             * (Linux) or raw sockets. Mark the hop as anonymous response. */
            int err = 0; socklen_t el = sizeof(err);
            getsockopt(tcp_fd, SOL_SOCKET, SO_ERROR, &err, &el);
            struct timeval t1; gettimeofday(&t1, NULL);
            h.rtt_us = usec_diff(&t0, &t1);
            if (err == 0 || err == ECONNREFUSED) {
                inet_ntop(AF_INET, &dst.sin_addr, h.addr, sizeof(h.addr));
                h.reached_dst = 1;
            }
            /* else: intermediate hop ate the SYN; addr stays blank. */
        }
        close(tcp_fd);
        if (ps_tr_sink_emit(sink, &h)) return 0;
    }
    return 0;
}

static int tr_tcp_classic(const char *target,
                          const struct ps_traceroute_opts *opts,
                          struct ps_tr_sink *sink) {
    struct sockaddr_in dst;
    if (resolve_v4(target, &dst) != 0) return -1;
    dst.sin_port = htons(opts->dst_port);
    int icmp_fd = icmp_listener();
    if (icmp_fd < 0) return -1;
    int rc = tcp_flow_walk(icmp_fd, dst, PS_TR_MODE_CLASSIC, 0, opts, sink);
    close(icmp_fd);
    return rc;
}

static int tr_tcp_paris(const char *target,
                        const struct ps_traceroute_opts *opts,
                        struct ps_tr_sink *sink) {
    struct sockaddr_in dst;
    if (resolve_v4(target, &dst) != 0) return -1;
    dst.sin_port = htons(opts->dst_port);
    int icmp_fd = icmp_listener();
    if (icmp_fd < 0) return -1;
    int rc = tcp_flow_walk(icmp_fd, dst, PS_TR_MODE_PARIS, 33500, opts, sink);
    close(icmp_fd);
    return rc;
}

/* Dublin: enumerate ECMP paths by walking multiple Paris-style flows whose
 * src_port differs between flows. Each flow internally holds its tuple
 * constant (Paris-style), so each flow produces a coherent path; varying
 * src_port between flows makes the ECMP hash key differ, exposing alternative
 * paths.
 *
 * Hops are deduplicated by (ttl, addr) before forwarding to the caller's sink.
 */
struct dublin_dedup {
    struct ps_tr_sink *sink;
    struct { int ttl; char addr[64]; } seen[PS_TRACEROUTE_MAX_HOPS];
    int n;
    int stop;
};
static int dublin_cb(const struct ps_tr_hop *h, void *u) {
    struct dublin_dedup *d = u;
    for (int j = 0; j < d->n; j++)
        if (d->seen[j].ttl == h->ttl && strcmp(d->seen[j].addr, h->addr) == 0)
            return 0;   /* duplicate: swallow, keep this flow going */
    if (d->n >= PS_TRACEROUTE_MAX_HOPS) { d->stop = 1; return 1; }  /* table full */
    d->seen[d->n].ttl = h->ttl;
    snprintf(d->seen[d->n].addr, sizeof(d->seen[d->n].addr), "%s", h->addr);
    d->n++;
    /* Forward to the user callback directly, NOT through ps_tr_sink_emit:
     * Dublin enumerates every flow to the destination, so the outer sink's
     * dest-reached / gap early-stop must not halt enumeration. Only an
     * explicit consumer stop (cb returns non-zero) ends the run. */
    if (d->sink->cb(h, d->sink->user)) { d->stop = 1; return 1; }
    return 0;
}

static int tr_udp_dublin(const char *target,
                         const struct ps_traceroute_opts *opts,
                         struct ps_tr_sink *sink) {
    struct sockaddr_in dst;
    if (resolve_v4(target, &dst) != 0) return -1;
    int icmp_fd = icmp_listener();
    if (icmp_fd < 0) return -1;
    int flows = opts->flow_count > 0 ? opts->flow_count : 8;
    if (flows > 32) flows = 32;

    struct dublin_dedup dd; memset(&dd, 0, sizeof(dd)); dd.sink = sink;
    for (int f = 0; f < flows && !dd.stop; f++) {
        int udp_fd = udp_socket_bound((uint16_t)(33500 + f));
        if (udp_fd < 0) continue;
        struct ps_tr_sink inner; ps_tr_sink_init(&inner, dublin_cb, &dd, 0);
        udp_flow_walk(udp_fd, icmp_fd, dst, PS_TR_MODE_PARIS, opts, &inner);
        close(udp_fd);
    }
    close(icmp_fd);
    return 0;
}

static int tr_tcp_dublin(const char *target,
                         const struct ps_traceroute_opts *opts,
                         struct ps_tr_sink *sink) {
    struct sockaddr_in dst;
    if (resolve_v4(target, &dst) != 0) return -1;
    dst.sin_port = htons(opts->dst_port);
    int icmp_fd = icmp_listener();
    if (icmp_fd < 0) return -1;
    int flows = opts->flow_count > 0 ? opts->flow_count : 8;
    if (flows > 32) flows = 32;
    struct dublin_dedup dd; memset(&dd, 0, sizeof(dd)); dd.sink = sink;
    for (int f = 0; f < flows && !dd.stop; f++) {
        struct ps_tr_sink inner; ps_tr_sink_init(&inner, dublin_cb, &dd, 0);
        tcp_flow_walk(icmp_fd, dst, PS_TR_MODE_PARIS, (uint16_t)(33500 + f), opts, &inner);
    }
    close(icmp_fd);
    return 0;
}

/* ---- ICMP traceroute ----
 *
 * Send ICMP Echo Requests with increasing TTL via SOCK_DGRAM/IPPROTO_ICMP
 * (unprivileged on Linux when ping_group_range covers the user; supported
 * unprivileged on macOS for ICMP echo). Intermediate routers emit ICMP TTL
 * exceeded; destination emits ICMP Echo Reply.
 *
 * One socket serves both send and receive — the same SOCK_DGRAM ICMP fd is
 * the listener for replies.
 */
static uint16_t icmp_checksum(const void *data, size_t len) {
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static int icmp_flow_walk(int icmp_fd, struct sockaddr_in dst,
                          const struct ps_traceroute_opts *opts,
                          struct ps_tr_sink *sink) {
    int max = opts->max_hops > 0 ? opts->max_hops : 30;
    if (max > PS_TRACEROUTE_MAX_HOPS) max = PS_TRACEROUTE_MAX_HOPS;

    /*
     * Per-trace unique ICMP id. When many `probe traceroute` processes run
     * concurrently, an ICMP socket may be handed replies belonging to other
     * traces (raw sockets copy every host reply; even SOCK_DGRAM ping sockets
     * can deliver foreign/stale datagrams). We MUST match each reply strictly
     * by (id == ident) AND (inner seq == ttl), or processes cross-talk: every
     * trace then attributes siblings' replies to its current hop, never times
     * out, never reaches the destination, and reports impossible sub-ms RTTs.
     *
     * PID alone can collide across concurrent processes, so mix in a random
     * word; the strict id+seq match is the real guarantee.
     */
    srand((unsigned)(getpid() ^ (unsigned)time(NULL)));
    uint16_t ident = (uint16_t)((getpid() & 0xffff) ^ (rand() & 0xffff));
    if (ident == 0) ident = 1;
    for (int ttl = 1; ttl <= max; ttl++) {
        setsockopt(icmp_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        struct {
            uint8_t  type, code;
            uint16_t checksum;
            uint16_t id, seq;
            char     payload[16];
        } pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.type = 8; /* echo request */
        pkt.code = 0;
        pkt.id = htons(ident);
        pkt.seq = htons((uint16_t)ttl);
        memcpy(pkt.payload, "PSTR-ICMP", 9);
        pkt.checksum = 0;
        pkt.checksum = icmp_checksum(&pkt, sizeof(pkt));

        struct timeval t0; gettimeofday(&t0, NULL);
        sendto(icmp_fd, &pkt, sizeof(pkt), 0,
               (struct sockaddr *)&dst, sizeof(dst));

        /*
         * Receive loop: keep draining replies until we get one that is OURS
         * (matching id + seq) or the timeout budget for this hop is exhausted.
         * Foreign replies (other traces, stale hops) are skipped, not counted.
         */
        long budget_us = (long)opts->timeout_ms * 1000;
        struct ps_tr_hop h; memset(&h, 0, sizeof(h)); h.ttl = ttl;
        int got = 0;

        for (;;) {
            struct timeval now; gettimeofday(&now, NULL);
            long elapsed = usec_diff(&t0, &now);
            long remain = budget_us - elapsed;
            if (remain <= 0) break;

            struct timeval tv = { remain / 1000000, remain % 1000000 };
            setsockopt(icmp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            char rbuf[2048];
            struct sockaddr_in from; socklen_t flen = sizeof(from);
            ssize_t n = recvfrom(icmp_fd, rbuf, sizeof(rbuf), 0,
                                 (struct sockaddr *)&from, &flen);
            if (n <= 0) break;  /* timeout or error */

            /* On macOS SOCK_DGRAM ICMP, the kernel strips the IP header on
             * receive; on Linux it varies. Walk past optional IP header. */
            uint8_t *icmp_hdr = (uint8_t *)rbuf;
            ssize_t icmp_len = n;
            if (n >= (ssize_t)sizeof(struct ip) && (rbuf[0] & 0xf0) == 0x40) {
                int hl = (rbuf[0] & 0x0f) * 4;
                if (n >= hl + 8) { icmp_hdr = (uint8_t *)rbuf + hl; icmp_len = n - hl; }
            }
            if (icmp_len < 8) continue;
            uint8_t type = icmp_hdr[0];

            /* Extract the (id, seq) that identifies which probe this reply is
             * for. Echo reply (type 0): id/seq are in this ICMP header. Time
             * Exceeded (type 11): id/seq are in the embedded original echo
             * request (inner IP + inner ICMP). */
            uint16_t r_id = 0, r_seq = 0;
            int matched = 0;
            if (type == 0) {
                memcpy(&r_id,  icmp_hdr + 4, 2);
                memcpy(&r_seq, icmp_hdr + 6, 2);
                matched = 1;
            } else if (type == 11) {
                /* TE header (8) + inner IP + inner ICMP echo (>=8) */
                if (icmp_len >= 8 + (ssize_t)sizeof(struct ip) + 8) {
                    uint8_t *inner_ip = icmp_hdr + 8;
                    int ihl = (inner_ip[0] & 0x0f) * 4;
                    if (icmp_len >= 8 + ihl + 8) {
                        uint8_t *inner_icmp = inner_ip + ihl;
                        if (inner_icmp[0] == 8) {  /* inner echo request */
                            memcpy(&r_id,  inner_icmp + 4, 2);
                            memcpy(&r_seq, inner_icmp + 6, 2);
                            matched = 1;
                        }
                    }
                }
            }
            if (!matched) continue;
            r_id  = ntohs(r_id);
            r_seq = ntohs(r_seq);

            /* STRICT match: only our id, and only the hop we're probing. */
            if (r_id != ident || r_seq != (uint16_t)ttl) continue;

            struct timeval t1; gettimeofday(&t1, NULL);
            inet_ntop(AF_INET, &from.sin_addr, h.addr, sizeof(h.addr));
            h.rtt_us = usec_diff(&t0, &t1);
            if (type == 0)       h.reached_dst = (from.sin_addr.s_addr == dst.sin_addr.s_addr);
            else if (type == 11) h.reached_dst = 0;
            got = 1;
            break;
        }

        (void)got;  /* h is a timeout entry (zeroed) when got == 0 */
        if (ps_tr_sink_emit(sink, &h)) return 0;
    }
    return 0;
}

static int tr_icmp_classic(const char *target,
                           const struct ps_traceroute_opts *opts,
                           struct ps_tr_sink *sink) {
    struct sockaddr_in dst;
    if (resolve_v4(target, &dst) != 0) return -1;
    int icmp_fd = icmp_listener();
    if (icmp_fd < 0) return -1;
    int rc = icmp_flow_walk(icmp_fd, dst, opts, sink);
    close(icmp_fd);
    return rc;
}

int ps_traceroute_run_cb(const char *target,
                         const struct ps_traceroute_opts *opts,
                         ps_tr_hop_cb cb, void *user) {
    struct ps_tr_sink sink;
    ps_tr_sink_init(&sink, cb, user, opts->max_gap);

    if (opts->proto == PS_TR_PROTO_UDP) {
        if (opts->mode == PS_TR_MODE_CLASSIC) return tr_udp_classic(target, opts, &sink);
        if (opts->mode == PS_TR_MODE_PARIS)   return tr_udp_paris  (target, opts, &sink);
        if (opts->mode == PS_TR_MODE_DUBLIN)  return tr_udp_dublin (target, opts, &sink);
    }
    if (opts->proto == PS_TR_PROTO_TCP) {
        if (opts->mode == PS_TR_MODE_CLASSIC) return tr_tcp_classic(target, opts, &sink);
        if (opts->mode == PS_TR_MODE_PARIS)   return tr_tcp_paris  (target, opts, &sink);
        if (opts->mode == PS_TR_MODE_DUBLIN)  return tr_tcp_dublin (target, opts, &sink);
    }
    if (opts->proto == PS_TR_PROTO_ICMP) {
        return tr_icmp_classic(target, opts, &sink);
    }
    return -1;
}

/* Back-compat: collect every hop into a result array. */
static int collect_cb(const struct ps_tr_hop *h, void *u) {
    struct ps_traceroute_result *out = u;
    if (out->hop_count >= PS_TRACEROUTE_MAX_HOPS) return 1;   /* stop, full */
    out->hops[out->hop_count++] = *h;
    if (h->reached_dst) out->reached = 1;
    return 0;
}

int ps_traceroute_run(const char *target,
                      const struct ps_traceroute_opts *opts,
                      struct ps_traceroute_result *out) {
    memset(out, 0, sizeof(*out));
    return ps_traceroute_run_cb(target, opts, collect_cb, out);
}
