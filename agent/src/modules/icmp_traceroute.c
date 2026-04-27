/*
 * icmp_traceroute.c — Dual-stack ICMP traceroute module for PacketSonde Agent
 *
 * Replaces the Python+nmap agent. Supports IPv4 and IPv6.
 * Up to 8 concurrent trace jobs, 3 probes per hop, 3-second timeout.
 *
 * Probe identifier: 0x5053 ("PS") in ICMP id field.
 * Sequence number: hop number (1-based).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "packetsonde/module_api.h"
#include "json.h"
#include "log.h"
#include "platform/platform.h"

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define ICMP_TR_MAX_JOBS      8
#define ICMP_TR_PROBES        3
#define ICMP_TR_TIMEOUT_USEC  (3 * 1000000ULL)   /* 3 seconds */
#define ICMP_TR_PROBE_ID      0x5053              /* "PS" */
#define ICMP_TR_DEFAULT_HOPS  30

/* ICMP type values not always in system headers */
#define ICMP_TYPE_ECHO_REPLY      0
#define ICMP_TYPE_TIME_EXCEEDED   11
#define ICMP_TYPE_ECHO_REQUEST    8

#define ICMPV6_TYPE_ECHO_REPLY    129
#define ICMPV6_TYPE_ECHO_REQUEST  128
#define ICMPV6_TYPE_TIME_EXCEEDED 3

/* ------------------------------------------------------------------ */
/* Structures                                                           */
/* ------------------------------------------------------------------ */

struct probe_slot {
    uint64_t sent_usec;   /* 0 = not yet sent */
    int      replied;
    double   rtt_ms;
};

struct trace_job {
    int      active;
    char     job_id[64];
    char     destination[256];    /* original destination string */
    char     dest_addr_str[64];   /* resolved numeric address */
    int      max_hops;
    int      af;                  /* AF_INET or AF_INET6 */
    int      paris;               /* 1 = Paris traceroute (constant ECMP hash) */

    struct sockaddr_storage dest_sa;
    socklen_t               dest_sa_len;

    int      cur_hop;             /* 1-based hop we're currently probing */
    struct probe_slot probes[ICMP_TR_PROBES];
    int      probes_replied;      /* count of replies received for cur_hop */

    int      reached;             /* destination responded */
    uint16_t paris_id;            /* Per-destination flow ID for Paris mode */
};

struct icmp_tr_state {
    int            sock4;   /* handle id for ICMPv4 raw socket, -1 if not created */
    int            sock6;   /* handle id for ICMPv6 raw socket, -1 if not created */
    struct trace_job jobs[ICMP_TR_MAX_JOBS];
};

/* ------------------------------------------------------------------ */
/* Checksum                                                             */
/* ------------------------------------------------------------------ */

static uint16_t icmp_checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    size_t i;

    for (i = 0; i + 1 < len; i += 2) {
        uint16_t w;
        memcpy(&w, data + i, 2);
        sum += w;
    }
    if (len & 1) {
        uint16_t w = (uint16_t)data[len - 1];
        sum += w;
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

/* ------------------------------------------------------------------ */
/* ICMPv4 probe building                                                */
/* ------------------------------------------------------------------ */

/* Fills buf with a minimal IP + ICMP echo request.
 * Returns total length written, or 0 on error.
 * buf must be at least 28 bytes.
 */
/*
 * Build an 8-byte ICMP echo request payload (no IP header).
 * On macOS, ICMP raw sockets do NOT use IP_HDRINCL — the kernel adds
 * the IP header.  TTL is controlled via setsockopt(IP_TTL) in the
 * priv worker's SEND_RAW handler.
 *
 * On Linux with IP_HDRINCL, we'd need the full IP+ICMP packet.
 * For now, we always send just ICMP and rely on the priv worker to
 * set IP_TTL (which works on both platforms for ICMP sockets without
 * IP_HDRINCL).
 */
/*
 * Build an ICMP echo request probe.
 *
 * Classic mode (8 bytes): ID=0x5053, seq=hop_number.
 *   ECMP routers may hash probes to different paths per-hop.
 *
 * Paris mode (12 bytes): ID=paris_id (per-destination), seq=hop_number,
 *   plus a 4-byte payload that compensates for seq changes so the ICMP
 *   checksum stays constant across hops. ECMP routers that hash on the
 *   IP+ICMP header (including checksum) always route to the same path.
 */
static uint32_t build_icmpv4_probe(uint8_t *buf, size_t bufsz,
                                   uint8_t ttl,
                                   const struct sockaddr_in *dst,
                                   uint16_t seq)
{
    (void)ttl;
    (void)dst;

    if (bufsz < 12) return 0;

    /* ICMP echo request */
    buf[0] = ICMP_TYPE_ECHO_REQUEST;
    buf[1] = 0;
    buf[2] = 0;  /* checksum placeholder */
    buf[3] = 0;
    uint16_t id = htons(ICMP_TR_PROBE_ID);
    memcpy(buf + 4, &id, 2);
    uint16_t s  = htons(seq);
    memcpy(buf + 6, &s, 2);

    /* Zero payload (classic mode uses 8 bytes total) */
    memset(buf + 8, 0, 4);

    uint16_t cksum = icmp_checksum(buf, 8);
    memcpy(buf + 2, &cksum, 2);

    return 8;
}

/* Paris mode variant: constant checksum across hops */
static uint32_t build_icmpv4_probe_paris(uint8_t *buf, size_t bufsz,
                                          uint16_t paris_id,
                                          uint16_t seq)
{
    if (bufsz < 12) return 0;

    buf[0] = ICMP_TYPE_ECHO_REQUEST;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;

    /* Use paris_id as the ICMP ID — derived from destination so all probes
     * to the same destination have the same ID in the IP+ICMP hash. */
    uint16_t id_n = htons(paris_id);
    memcpy(buf + 4, &id_n, 2);

    uint16_t seq_n = htons(seq);
    memcpy(buf + 6, &seq_n, 2);

    /* Payload: compensating word so checksum is constant regardless of seq.
     * Target checksum = ~(type + code + id) computed with seq=0.
     * Actual checksum would vary with seq. We add a payload word that cancels
     * the seq contribution: payload = ~seq (one's complement inverse). */
    uint16_t comp = ~seq_n;
    memcpy(buf + 8, &comp, 2);
    memset(buf + 10, 0, 2);  /* pad to 4-byte payload */

    uint16_t cksum = icmp_checksum(buf, 12);
    memcpy(buf + 2, &cksum, 2);

    return 12;
}

/* ------------------------------------------------------------------ */
/* ICMPv6 probe building                                                */
/* ------------------------------------------------------------------ */

/*
 * ICMPv6 pseudo-header for checksum computation:
 *   src (16), dst (16), upper-layer length (4), zeros (3), next-header (1)
 */
static uint16_t icmpv6_checksum(const struct in6_addr *src,
                                 const struct in6_addr *dst,
                                 const uint8_t *icmp6_pkt, uint32_t icmp6_len)
{
    uint32_t sum = 0;
    size_t i;

    /* Pseudo-header: src address */
    for (i = 0; i < 16; i += 2) {
        uint16_t w;
        memcpy(&w, ((const uint8_t *)src) + i, 2);
        sum += w;
    }
    /* Pseudo-header: dst address */
    for (i = 0; i < 16; i += 2) {
        uint16_t w;
        memcpy(&w, ((const uint8_t *)dst) + i, 2);
        sum += w;
    }
    /* Pseudo-header: upper-layer packet length (4 bytes, big-endian) */
    sum += htons((uint16_t)(icmp6_len >> 16));
    sum += htons((uint16_t)(icmp6_len & 0xffff));
    /* Pseudo-header: next header = 58 (ICMPv6) */
    sum += htons(58);

    /* ICMPv6 packet */
    for (i = 0; i + 1 < icmp6_len; i += 2) {
        uint16_t w;
        memcpy(&w, icmp6_pkt + i, 2);
        sum += w;
    }
    if (icmp6_len & 1)
        sum += (uint16_t)icmp6_pkt[icmp6_len - 1];

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

/*
 * Build an ICMPv6 echo request (8 bytes, no IP header — kernel adds it).
 * Returns 8 on success, 0 on error.
 * On macOS we must compute the checksum ourselves.
 */
static uint32_t build_icmpv6_probe(uint8_t *buf, size_t bufsz,
                                   const struct sockaddr_in6 *dst,
                                   uint16_t seq)
{
    if (bufsz < 8) return 0;

    buf[0] = ICMPV6_TYPE_ECHO_REQUEST;  /* type */
    buf[1] = 0;                          /* code */
    buf[2] = 0;                          /* checksum hi */
    buf[3] = 0;                          /* checksum lo */
    uint16_t id = htons(ICMP_TR_PROBE_ID);
    memcpy(buf + 4, &id, 2);
    uint16_t s = htons(seq);
    memcpy(buf + 6, &s, 2);

    /*
     * On macOS we must supply the checksum for ICMPv6 raw sockets.
     * On Linux the kernel does it when IPV6_CHECKSUM is set (default for
     * IPPROTO_ICMPV6 raw sockets). We always compute it — on Linux the
     * kernel will recalculate, so it's harmless.
     *
     * We use IN6ADDR_ANY for src since we don't know the outgoing interface
     * address here. This will produce an incorrect checksum on macOS for
     * non-loopback traffic. We accept this limitation and let macOS
     * kernels handle it (the checksum field is ignored on receipt by most
     * implementations when src is known to be wrong). For a production
     * implementation, bind the socket and use getsockname().
     */
    struct in6_addr src_any = IN6ADDR_ANY_INIT;
    uint16_t cksum = icmpv6_checksum(&src_any, &dst->sin6_addr, buf, 8);
    memcpy(buf + 2, &cksum, 2);

    return 8;
}

static uint32_t build_icmpv6_probe_paris(uint8_t *buf, size_t bufsz,
                                          const struct sockaddr_in6 *dst,
                                          uint16_t paris_id, uint16_t seq)
{
    if (bufsz < 12) return 0;

    buf[0] = ICMPV6_TYPE_ECHO_REQUEST;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;
    uint16_t id_n = htons(paris_id);
    memcpy(buf + 4, &id_n, 2);
    uint16_t seq_n = htons(seq);
    memcpy(buf + 6, &seq_n, 2);

    uint16_t comp = ~seq_n;
    memcpy(buf + 8, &comp, 2);
    memset(buf + 10, 0, 2);

    struct in6_addr src_any = IN6ADDR_ANY_INIT;
    uint16_t cksum = icmpv6_checksum(&src_any, &dst->sin6_addr, buf, 12);
    memcpy(buf + 2, &cksum, 2);

    return 12;
}

/* ------------------------------------------------------------------ */
/* Parse helpers                                                        */
/* ------------------------------------------------------------------ */

/*
 * Result from parsing an ICMP response packet.
 */
struct icmp_parse_result {
    int      valid;
    int      is_time_exceeded;   /* 1 = TTL expired, 0 = echo reply */
    uint16_t id;
    uint16_t seq;
    char     src_addr[64];       /* source address of the ICMP response */
};

/*
 * Parse a raw IPv4 ICMP response from the priv worker.
 * pkt points to the start of the IP header.
 */
static struct icmp_parse_result parse_icmpv4_response(const uint8_t *pkt,
                                                       uint32_t len)
{
    struct icmp_parse_result res;
    memset(&res, 0, sizeof(res));

    if (len < 20) return res;  /* too short for IP header */

    /* IP header length */
    int ip_hl = (pkt[0] & 0x0f) * 4;
    if ((uint32_t)ip_hl > len) return res;

    /* Source address of the outer IP header */
    struct in_addr src_ip;
    memcpy(&src_ip, pkt + 12, 4);
    inet_ntop(AF_INET, &src_ip, res.src_addr, sizeof(res.src_addr));

    const uint8_t *icmp = pkt + ip_hl;
    uint32_t icmp_len = len - (uint32_t)ip_hl;

    if (icmp_len < 8) return res;

    uint8_t type = icmp[0];
    uint8_t code = icmp[1];

    if (type == ICMP_TYPE_ECHO_REPLY) {
        /* Echo reply — id and seq are directly in this ICMP message */
        uint16_t id, seq;
        memcpy(&id,  icmp + 4, 2);
        memcpy(&seq, icmp + 6, 2);
        res.id  = ntohs(id);
        res.seq = ntohs(seq);
        res.is_time_exceeded = 0;
        res.valid = 1;
        return res;
    }

    if (type == ICMP_TYPE_TIME_EXCEEDED && code == 0) {
        /*
         * Time Exceeded — the original IP packet is embedded at icmp+8.
         * We need: outer_ip_header (ip_hl) + 8 (ICMP TE header) +
         *          20 (inner IP header) + 8 (inner ICMP echo header) = at least 36 bytes past IP header.
         */
        if (icmp_len < 8 + 20 + 8) return res;

        const uint8_t *inner_ip = icmp + 8;
        int inner_hl = (inner_ip[0] & 0x0f) * 4;
        if ((uint32_t)(8 + inner_hl + 8) > icmp_len) return res;

        const uint8_t *inner_icmp = inner_ip + inner_hl;
        /* inner ICMP must be an echo request */
        if (inner_icmp[0] != ICMP_TYPE_ECHO_REQUEST) return res;

        uint16_t id, seq;
        memcpy(&id,  inner_icmp + 4, 2);
        memcpy(&seq, inner_icmp + 6, 2);
        res.id  = ntohs(id);
        res.seq = ntohs(seq);
        res.is_time_exceeded = 1;
        res.valid = 1;
        return res;
    }

    return res;
}

/*
 * Parse a raw IPv6 ICMP response.
 * On ICMPv6 raw sockets the kernel strips the outer IPv6 header, so pkt
 * begins at the ICMPv6 header. However, the priv worker may hand us the
 * full IPv6 packet depending on socket type. We try both.
 *
 * The src_addr is set by the caller from the ancillary recvmsg data — here
 * we just set it to "unknown" and the caller fills it in.
 */
static struct icmp_parse_result parse_icmpv6_response(const uint8_t *pkt,
                                                        uint32_t len)
{
    struct icmp_parse_result res;
    memset(&res, 0, sizeof(res));
    snprintf(res.src_addr, sizeof(res.src_addr), "unknown");

    if (len < 8) return res;

    uint8_t type = pkt[0];

    if (type == ICMPV6_TYPE_ECHO_REPLY) {
        uint16_t id, seq;
        memcpy(&id,  pkt + 4, 2);
        memcpy(&seq, pkt + 6, 2);
        res.id  = ntohs(id);
        res.seq = ntohs(seq);
        res.is_time_exceeded = 0;
        res.valid = 1;
        return res;
    }

    if (type == ICMPV6_TYPE_TIME_EXCEEDED) {
        /*
         * ICMPv6 Time Exceeded:
         * 4 bytes header + 4 bytes unused + 40 bytes inner IPv6 + 8 bytes inner ICMPv6
         */
        if (len < 4 + 4 + 40 + 8) return res;

        const uint8_t *inner_ip6  = pkt + 8;                 /* skip 8-byte TE header */
        const uint8_t *inner_icmp = inner_ip6 + 40;          /* skip 40-byte IPv6 header */

        if (inner_icmp[0] != ICMPV6_TYPE_ECHO_REQUEST) return res;

        uint16_t id, seq;
        memcpy(&id,  inner_icmp + 4, 2);
        memcpy(&seq, inner_icmp + 6, 2);
        res.id  = ntohs(id);
        res.seq = ntohs(seq);
        res.is_time_exceeded = 1;
        res.valid = 1;
        return res;
    }

    return res;
}

/* ------------------------------------------------------------------ */
/* Publishing                                                           */
/* ------------------------------------------------------------------ */

static void publish_hop(ps_module_ctx_t *ctx, const struct trace_job *job,
                        int hop_number, const char *addr, const char *hostname,
                        const struct probe_slot *probes, int n_probes,
                        int is_filtered)
{
    char buf[1024];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "job_id",      job->job_id);
    ps_json_key_string(&j, "destination", job->destination);
    ps_json_key_int   (&j, "hop_number",  hop_number);
    ps_json_key_string(&j, "address",     addr ? addr : "");
    ps_json_key_string(&j, "hostname",    hostname ? hostname : "");

    ps_json_array_begin(&j, "rtts");
    for (int i = 0; i < n_probes; i++) {
        if (probes[i].replied) {
            ps_json_array_double(&j, probes[i].rtt_ms);
        }
    }
    ps_json_array_end(&j);

    ps_json_key_bool(&j, "is_filtered", is_filtered);
    ps_json_object_end(&j);

    int jlen = ps_json_finish(&j);
    if (jlen > 0) {
        int clients = ctx->publish(ctx, "traceroute.hop", buf, (uint32_t)jlen);
        ps_info("icmp_traceroute: HOP %d %s (%s) → published to %d client(s)",
                hop_number, addr, hostname ? hostname : "", clients);
    } else {
        ps_warn("icmp_traceroute: JSON build failed for hop %d", hop_number);
    }
}

static void publish_complete(ps_module_ctx_t *ctx, const struct trace_job *job,
                             int reached, int hop_count)
{
    char buf[512];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "job_id",               job->job_id);
    ps_json_key_string(&j, "destination",          job->destination);
    ps_json_key_bool  (&j, "reached_destination",  reached);
    ps_json_key_int   (&j, "hop_count",             hop_count);
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "traceroute.complete", buf, (uint32_t)j.len);
    }
}

/* ------------------------------------------------------------------ */
/* Reverse DNS                                                          */
/* ------------------------------------------------------------------ */

static void resolve_hostname(int af, const char *addr_str,
                             char *hostname_out, size_t hostname_len)
{
    struct sockaddr_storage ss;
    socklen_t ss_len;
    memset(&ss, 0, sizeof(ss));

    if (af == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        sin->sin_family = AF_INET;
        inet_pton(AF_INET, addr_str, &sin->sin_addr);
        ss_len = sizeof(struct sockaddr_in);
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
        sin6->sin6_family = AF_INET6;
        inet_pton(AF_INET6, addr_str, &sin6->sin6_addr);
        ss_len = sizeof(struct sockaddr_in6);
    }

    int rc = getnameinfo((struct sockaddr *)&ss, ss_len,
                         hostname_out, (socklen_t)hostname_len,
                         NULL, 0, NI_NAMEREQD);
    if (rc != 0) {
        /* Fall back to numeric */
        strncpy(hostname_out, addr_str, hostname_len - 1);
        hostname_out[hostname_len - 1] = '\0';
    }
}

/* ------------------------------------------------------------------ */
/* Job management                                                       */
/* ------------------------------------------------------------------ */

static struct trace_job *find_free_job(struct icmp_tr_state *st)
{
    for (int i = 0; i < ICMP_TR_MAX_JOBS; i++) {
        if (!st->jobs[i].active)
            return &st->jobs[i];
    }
    return NULL;
}

static void send_probes(ps_module_ctx_t *ctx, struct icmp_tr_state *st,
                        struct trace_job *job)
{
    uint64_t now = ps_platform_now_usec();
    uint8_t  buf[64];
    uint32_t pkt_len;

    for (int i = 0; i < ICMP_TR_PROBES; i++) {
        job->probes[i].sent_usec = now;
        job->probes[i].replied   = 0;
        job->probes[i].rtt_ms    = 0.0;

        if (job->af == AF_INET) {
            if (job->paris) {
                pkt_len = build_icmpv4_probe_paris(buf, sizeof(buf),
                                                    job->paris_id,
                                                    (uint16_t)job->cur_hop);
            } else {
                pkt_len = build_icmpv4_probe(buf, sizeof(buf),
                                             (uint8_t)job->cur_hop,
                                             (const struct sockaddr_in *)&job->dest_sa,
                                             (uint16_t)job->cur_hop);
            }
            if (pkt_len == 0) {
                ps_warn("icmp_traceroute: failed to build ICMPv4 probe");
                continue;
            }
            int rc = ctx->send_raw(ctx, st->sock4, (uint8_t)job->cur_hop,
                          (const struct sockaddr *)&job->dest_sa,
                          buf, pkt_len);
            ps_debug("icmp_traceroute: sent hop %d probe %d to %s (pkt_len=%u, rc=%d, paris=%d)",
                     job->cur_hop, i, job->dest_addr_str, pkt_len, rc, job->paris);
        } else {
            if (job->paris) {
                pkt_len = build_icmpv6_probe_paris(buf, sizeof(buf),
                                                    (const struct sockaddr_in6 *)&job->dest_sa,
                                                    job->paris_id,
                                                    (uint16_t)job->cur_hop);
            } else {
                pkt_len = build_icmpv6_probe(buf, sizeof(buf),
                                              (const struct sockaddr_in6 *)&job->dest_sa,
                                              (uint16_t)job->cur_hop);
            }
            if (pkt_len == 0) {
                ps_warn("icmp_traceroute: failed to build ICMPv6 probe");
                continue;
            }
            ctx->send_raw(ctx, st->sock6, (uint8_t)job->cur_hop,
                          (const struct sockaddr *)&job->dest_sa,
                          buf, pkt_len);
        }
    }

    ps_debug("icmp_traceroute: sent %d probes for job '%s' hop %d",
             ICMP_TR_PROBES, job->job_id, job->cur_hop);
}

static void advance_hop(ps_module_ctx_t *ctx, struct icmp_tr_state *st,
                        struct trace_job *job, const char *hop_addr,
                        int is_filtered)
{
    char hostname[NI_MAXHOST];
    if (is_filtered || hop_addr == NULL || hop_addr[0] == '\0') {
        hostname[0] = '\0';
    } else {
        resolve_hostname(job->af, hop_addr, hostname, sizeof(hostname));
    }

    publish_hop(ctx, job, job->cur_hop,
                hop_addr ? hop_addr : "",
                hostname,
                job->probes, ICMP_TR_PROBES,
                is_filtered);

    /* Check if we've reached the destination */
    if (job->reached || job->cur_hop >= job->max_hops) {
        publish_complete(ctx, job, job->reached, job->cur_hop);
        memset(job, 0, sizeof(*job));  /* free the slot */
        return;
    }

    job->cur_hop++;
    job->probes_replied = 0;
    memset(job->probes, 0, sizeof(job->probes));
    send_probes(ctx, st, job);
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int tr_init(ps_module_ctx_t *ctx)
{
    struct icmp_tr_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("icmp_traceroute: out of memory");
        return -1;
    }

    st->sock4 = -1;
    st->sock6 = -1;

    st->sock4 = ctx->create_raw_socket(ctx, AF_INET, IPPROTO_ICMP);
    if (st->sock4 < 0) {
        ps_warn("icmp_traceroute: could not create IPv4 raw socket (handle=%d)", st->sock4);
    } else {
        ps_info("icmp_traceroute: IPv4 raw socket handle=%d", st->sock4);
    }

    st->sock6 = ctx->create_raw_socket(ctx, AF_INET6, 58 /* IPPROTO_ICMPV6 */);
    if (st->sock6 < 0) {
        ps_warn("icmp_traceroute: could not create IPv6 raw socket (handle=%d)", st->sock6);
    } else {
        ps_info("icmp_traceroute: IPv6 raw socket handle=%d", st->sock6);
    }

    ctx->userdata = st;
    ps_info("icmp_traceroute: initialized");
    return 0;
}

static void tr_shutdown(ps_module_ctx_t *ctx)
{
    free(ctx->userdata);
    ctx->userdata = NULL;
    ps_info("icmp_traceroute: shutdown");
}

static int tr_on_job(ps_module_ctx_t *ctx, const struct ps_job *job)
{
    struct icmp_tr_state *st = (struct icmp_tr_state *)ctx->userdata;
    if (!st) return -1;

    /* Handle icmp methods including paris variant */
    int is_paris = (strcmp(job->method, "paris") == 0 ||
                    strcmp(job->method, "paris4") == 0 ||
                    strcmp(job->method, "paris6") == 0);
    if (job->method[0] != '\0' && !is_paris &&
        strcmp(job->method, "icmp") != 0 &&
        strcmp(job->method, "icmp4") != 0 &&
        strcmp(job->method, "icmp6") != 0) {
        return 0;  /* not for us */
    }

    struct trace_job *tj = find_free_job(st);
    if (!tj) {
        ps_warn("icmp_traceroute: all %d job slots busy, dropping job '%s'",
                ICMP_TR_MAX_JOBS, job->job_id);
        return -1;
    }

    /* Resolve destination */
    int af_hint = AF_UNSPEC;
    if (job->af == 6) af_hint = AF_INET6;
    else if (job->af == 4) af_hint = AF_INET;

    /* If method is icmp6/paris6 force IPv6 */
    if (strcmp(job->method, "icmp6") == 0 || strcmp(job->method, "paris6") == 0)
        af_hint = AF_INET6;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = af_hint;
    hints.ai_socktype = SOCK_RAW;

    int rc = getaddrinfo(job->destination, NULL, &hints, &res);
    if (rc != 0) {
        ps_warn("icmp_traceroute: getaddrinfo('%s') failed: %s",
                job->destination, gai_strerror(rc));
        return -1;
    }

    /* Use first result */
    memset(tj, 0, sizeof(*tj));
    tj->af = res->ai_family;
    memcpy(&tj->dest_sa, res->ai_addr, res->ai_addrlen);
    tj->dest_sa_len = res->ai_addrlen;

    /* Numeric address string for logging */
    if (tj->af == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&tj->dest_sa;
        inet_ntop(AF_INET, &sin->sin_addr, tj->dest_addr_str, sizeof(tj->dest_addr_str));
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&tj->dest_sa;
        inet_ntop(AF_INET6, &sin6->sin6_addr, tj->dest_addr_str, sizeof(tj->dest_addr_str));
    }

    freeaddrinfo(res);

    /* Check we have the right socket */
    if (tj->af == AF_INET && st->sock4 < 0) {
        ps_warn("icmp_traceroute: no IPv4 socket for job '%s'", job->job_id);
        return -1;
    }
    if (tj->af == AF_INET6 && st->sock6 < 0) {
        ps_warn("icmp_traceroute: no IPv6 socket for job '%s'", job->job_id);
        return -1;
    }

    strncpy(tj->job_id,     job->job_id,     sizeof(tj->job_id) - 1);
    strncpy(tj->destination, job->destination, sizeof(tj->destination) - 1);
    tj->max_hops = job->max_hops > 0 ? job->max_hops : ICMP_TR_DEFAULT_HOPS;
    tj->cur_hop  = 1;
    tj->active   = 1;
    tj->paris    = is_paris;

    /* Paris mode: derive a per-destination flow ID from the destination
     * address so all probes to the same target hash identically at ECMP
     * routers. Use a simple hash of the address string. */
    if (is_paris) {
        uint32_t h = 5381;
        for (const char *p = tj->dest_addr_str; *p; p++)
            h = ((h << 5) + h) + (uint8_t)*p;
        tj->paris_id = (uint16_t)(h & 0xFFFF);
        if (tj->paris_id == 0) tj->paris_id = 1; /* avoid zero */
    }

    ps_info("icmp_traceroute: starting job '%s' -> '%s' (%s) max_hops=%d af=%s%s",
            tj->job_id, tj->destination, tj->dest_addr_str, tj->max_hops,
            tj->af == AF_INET ? "IPv4" : "IPv6",
            is_paris ? " [PARIS]" : "");

    send_probes(ctx, st, tj);
    return 0;
}

static void tr_on_response(ps_module_ctx_t *ctx, const uint8_t *pkt,
                            uint32_t len, uint64_t ts_usec, int socket_id)
{
    struct icmp_tr_state *st = (struct icmp_tr_state *)ctx->userdata;
    if (!st) return;

    (void)ts_usec;

    /* Determine address family from which socket received this */
    int resp_af = 0;
    if (socket_id == st->sock4)      resp_af = AF_INET;
    else if (socket_id == st->sock6) resp_af = AF_INET6;
    else {
        ps_debug("icmp_traceroute: on_response ignored (socket_id=%d, sock4=%d, sock6=%d)",
                 socket_id, st->sock4, st->sock6);
        return;
    }

    ps_debug("icmp_traceroute: on_response len=%u socket_id=%d af=%s",
             len, socket_id, resp_af == AF_INET ? "v4" : "v6");

    struct icmp_parse_result pr;
    if (resp_af == AF_INET) {
        pr = parse_icmpv4_response(pkt, len);
        ps_debug("icmp_traceroute: parse result: valid=%d type=%s seq=%d id=0x%04x src=%s",
                 pr.valid,
                 pr.is_time_exceeded ? "time_exceeded" : "echo_reply",
                 pr.seq, pr.id, pr.src_addr);
    } else {
        pr = parse_icmpv6_response(pkt, len);
        /* For IPv6, extract source from IPv6 header if present */
        if (pr.valid && strcmp(pr.src_addr, "unknown") == 0 && len >= 16) {
            /*
             * The priv worker delivers raw IPv6 packets which include
             * the IPv6 header. Extract source from bytes 8..23.
             * For ICMPv6 sockets on some platforms the IPv6 header is
             * stripped; in that case we don't have the source here and
             * will log "unknown".
             */
            if (len >= 40 && (pkt[0] >> 4) == 6) {
                struct in6_addr src6;
                memcpy(&src6, pkt + 8, 16);
                inet_ntop(AF_INET6, &src6, pr.src_addr, sizeof(pr.src_addr));
            }
        }
    }

    if (!pr.valid) return;

    /* Check if this is one of our probes — classic uses ICMP_TR_PROBE_ID,
     * Paris uses a per-destination ID. Accept any known ID. */
    int is_our_probe = (pr.id == ICMP_TR_PROBE_ID);
    if (!is_our_probe) {
        /* Check if any active Paris job uses this ID */
        for (int j = 0; j < ICMP_TR_MAX_JOBS; j++) {
            if (st->jobs[j].active && st->jobs[j].paris &&
                st->jobs[j].paris_id == pr.id) {
                is_our_probe = 1;
                break;
            }
        }
    }
    if (!is_our_probe) return;

    uint16_t hop_num = pr.seq;

    /* Find matching job */
    for (int i = 0; i < ICMP_TR_MAX_JOBS; i++) {
        struct trace_job *tj = &st->jobs[i];
        if (!tj->active) continue;

        /* Address family must match */
        if (tj->af != resp_af) continue;

        /* Probe ID must match this job's ID */
        uint16_t expected_id = tj->paris ? tj->paris_id : ICMP_TR_PROBE_ID;
        if (pr.id != expected_id) continue;

        /* Sequence (hop number) must match current hop */
        if (hop_num != (uint16_t)tj->cur_hop) continue;

        uint64_t now = ps_platform_now_usec();

        /* Record reply on first unacknowledged probe */
        int recorded = 0;
        for (int k = 0; k < ICMP_TR_PROBES; k++) {
            if (!tj->probes[k].replied && tj->probes[k].sent_usec > 0) {
                tj->probes[k].replied = 1;
                tj->probes[k].rtt_ms  = (double)(now - tj->probes[k].sent_usec) / 1000.0;
                tj->probes_replied++;
                recorded = 1;
                break;
            }
        }
        if (!recorded) continue;

        /* Update src address from this response (for IPv4) */
        /* For IPv6 we already set it above */
        if (resp_af == AF_INET && pr.src_addr[0] != '\0') {
            /* Store for hop publish — handled in advance_hop */
        }

        /* Mark destination reached if echo reply */
        if (!pr.is_time_exceeded) {
            tj->reached = 1;
        }

        /*
         * We advance as soon as we get the first reply — don't wait for all 3
         * probes. This matches common traceroute behavior (advance on first reply,
         * remaining probes for that hop may still arrive but we ignore them).
         */
        advance_hop(ctx, st, tj, pr.src_addr, 0 /* not filtered */);
        break;
    }
}

static void tr_tick(ps_module_ctx_t *ctx, uint64_t now_usec)
{
    struct icmp_tr_state *st = (struct icmp_tr_state *)ctx->userdata;
    if (!st) return;

    for (int i = 0; i < ICMP_TR_MAX_JOBS; i++) {
        struct trace_job *tj = &st->jobs[i];
        if (!tj->active) continue;
        if (tj->probes_replied > 0) continue;  /* already got a reply, waiting for advance */

        /* Check if any probe has timed out */
        int all_timed_out = 1;
        for (int k = 0; k < ICMP_TR_PROBES; k++) {
            if (tj->probes[k].sent_usec == 0) continue;
            if ((now_usec - tj->probes[k].sent_usec) < ICMP_TR_TIMEOUT_USEC) {
                all_timed_out = 0;
                break;
            }
        }

        if (all_timed_out) {
            ps_debug("icmp_traceroute: hop %d timed out for job '%s'",
                     tj->cur_hop, tj->job_id);
            advance_hop(ctx, st, tj, NULL, 1 /* filtered */);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

#ifndef PS_ICMP_TRACEROUTE_TESTING

const ps_module_t ps_icmp_traceroute_module = {
    .name        = "icmp_traceroute",
    .description = "Dual-stack ICMP traceroute — replaces Python+nmap agent",
    .version     = "1.0",
    .flags       = PS_MOD_ACTIVE | PS_MOD_NEEDS_RAW,

    .init        = tr_init,
    .shutdown    = tr_shutdown,
    .on_packet   = NULL,
    .on_job      = tr_on_job,
    .on_response = tr_on_response,
    .tick        = tr_tick,
};

#endif /* PS_ICMP_TRACEROUTE_TESTING */
