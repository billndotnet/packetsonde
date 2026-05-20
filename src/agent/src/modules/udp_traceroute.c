/*
 * udp_traceroute.c — Dual-stack UDP traceroute module for PacketSonde Agent
 *
 * Traditional Unix traceroute method. Sends UDP packets to high ports
 * (33434 + hop) with incrementing TTL. Intermediate routers return
 * ICMP Time Exceeded. The destination returns ICMP Port Unreachable.
 *
 * Probe identifier: source port 0x5053 ("PS").
 * Hop identification: destination port = 33434 + hop (1-based).
 * Payload: 2-byte job_index + 2-byte probe_index (4 bytes total).
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

#define UDP_TR_MAX_JOBS      8
#define UDP_TR_PROBES        3
#define UDP_TR_TIMEOUT_USEC  (3 * 1000000ULL)   /* 3 seconds */
#define UDP_TR_SRC_PORT      0x5053              /* "PS" */
#define UDP_TR_BASE_DST_PORT 33434
#define UDP_TR_DEFAULT_HOPS  30

/* ICMP type/code values */
#define ICMP_TYPE_TIME_EXCEEDED      11
#define ICMP_TYPE_DEST_UNREACHABLE   3
#define ICMP_CODE_PORT_UNREACHABLE   3

#define ICMPV6_TYPE_TIME_EXCEEDED    3
#define ICMPV6_TYPE_DEST_UNREACHABLE 1
#define ICMPV6_CODE_PORT_UNREACHABLE 4

/* ------------------------------------------------------------------ */
/* Structures                                                           */
/* ------------------------------------------------------------------ */

struct udp_probe_slot {
    uint64_t sent_usec;   /* 0 = not yet sent */
    int      replied;
    double   rtt_ms;
};

struct udp_trace_job {
    int      active;
    int      job_index;             /* slot index — embedded in probe payload */
    char     job_id[64];
    char     destination[256];      /* original destination string */
    char     dest_addr_str[64];     /* resolved numeric address */
    int      max_hops;
    int      af;                    /* AF_INET or AF_INET6 */

    struct sockaddr_storage dest_sa;
    socklen_t               dest_sa_len;

    int      cur_hop;               /* 1-based hop we're currently probing */
    struct udp_probe_slot probes[UDP_TR_PROBES];
    int      probes_replied;        /* count of replies received for cur_hop */

    int      reached;               /* destination responded (port unreachable) */
};

struct udp_tr_state {
    int            send_sock4;   /* IPv4 UDP raw send socket (IP_HDRINCL) */
    int            recv_sock4;   /* IPv4 ICMP raw recv socket */
    int            send_sock6;   /* IPv6 UDP raw send socket */
    int            recv_sock6;   /* IPv6 ICMPv6 raw recv socket */
    struct udp_trace_job jobs[UDP_TR_MAX_JOBS];
};

/* ------------------------------------------------------------------ */
/* Checksum                                                             */
/* ------------------------------------------------------------------ */

static uint16_t udp_checksum_generic(const uint8_t *data, size_t len)
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

/*
 * Compute UDP checksum over IPv4 pseudo-header + UDP header + payload.
 * Pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + proto=17(1) + udp_len(2)
 */
static uint16_t udp_checksum_v4(const struct in_addr *src,
                                  const struct in_addr *dst,
                                  const uint8_t *udp_hdr, uint16_t udp_len)
{
    uint32_t sum = 0;
    size_t i;

    /* Pseudo-header: src address */
    const uint8_t *src_b = (const uint8_t *)src;
    for (i = 0; i < 4; i += 2) {
        uint16_t w;
        memcpy(&w, src_b + i, 2);
        sum += w;
    }
    /* Pseudo-header: dst address */
    const uint8_t *dst_b = (const uint8_t *)dst;
    for (i = 0; i < 4; i += 2) {
        uint16_t w;
        memcpy(&w, dst_b + i, 2);
        sum += w;
    }
    /* Pseudo-header: zero + proto(17) + udp_len */
    sum += htons(17);
    sum += htons(udp_len);

    /* UDP header + data */
    for (i = 0; i + 1 < (size_t)udp_len; i += 2) {
        uint16_t w;
        memcpy(&w, udp_hdr + i, 2);
        sum += w;
    }
    if (udp_len & 1)
        sum += (uint16_t)udp_hdr[udp_len - 1];

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

/* ------------------------------------------------------------------ */
/* Probe building                                                        */
/* ------------------------------------------------------------------ */

/*
 * Build an IPv4 UDP probe with IP_HDRINCL:
 *   [20-byte IP header][8-byte UDP header][4-byte payload]
 *
 * Returns total length (32), or 0 on error.
 * buf must be at least 32 bytes.
 */
static uint32_t build_udpv4_probe(uint8_t *buf, size_t bufsz,
                                   uint8_t ttl,
                                   const struct sockaddr_in *dst,
                                   int hop,
                                   uint16_t job_index,
                                   uint16_t probe_index)
{
    if (bufsz < 32) return 0;

    const uint16_t udp_total = 12;     /* 8 header + 4 payload */
    const uint16_t ip_total  = 20 + udp_total;
    const uint16_t dst_port  = (uint16_t)(UDP_TR_BASE_DST_PORT + hop);
    const uint16_t src_port  = UDP_TR_SRC_PORT;

    /* IP header (20 bytes) */
    struct ip *iph = (struct ip *)buf;
    memset(iph, 0, 20);
    iph->ip_v   = 4;
    iph->ip_hl  = 5;
#ifdef __APPLE__
    iph->ip_len = ip_total;
#else
    iph->ip_len = htons(ip_total);
#endif
    iph->ip_ttl = ttl;
    iph->ip_p   = IPPROTO_UDP;
    iph->ip_dst = dst->sin_addr;
    /* ip_src left 0 — kernel fills */
    /* ip_sum left 0 — kernel fills when IP_HDRINCL set */

    /* UDP header (8 bytes) at offset 20 */
    uint8_t *udp = buf + 20;
    uint16_t sp = htons(src_port);
    uint16_t dp = htons(dst_port);
    uint16_t ul = htons(udp_total);
    memcpy(udp + 0, &sp, 2);
    memcpy(udp + 2, &dp, 2);
    memcpy(udp + 4, &ul, 2);
    udp[6] = 0;  /* checksum placeholder hi */
    udp[7] = 0;  /* checksum placeholder lo */

    /* 4-byte payload at offset 28 */
    uint8_t *payload = buf + 28;
    uint16_t ji = htons(job_index);
    uint16_t pi = htons(probe_index);
    memcpy(payload + 0, &ji, 2);
    memcpy(payload + 2, &pi, 2);

    /*
     * UDP checksum over pseudo-header + UDP header + payload.
     * We use src=0 since we don't know the outgoing address here.
     * On macOS with IP_HDRINCL the kernel does not recompute UDP checksum,
     * so a zero-source checksum will be sent. For ICMP response matching
     * we rely on the dst_port (33434+hop) and src_port (0x5053), not the
     * checksum.  Setting checksum to 0 disables UDP checksum validation,
     * which is permitted by RFC 768.
     */
    /* Leave checksum at 0 (disabled) */

    return 32;
}

/*
 * Build an IPv6 UDP probe.
 * For IPv6 raw sockets (IPPROTO_UDP) without IP_HDRINCL, we send only the
 * UDP header + payload (12 bytes). The kernel adds the IPv6 header and
 * handles TTL via IPV6_UNICAST_HOPS (set in send_raw via the ttl parameter).
 *
 * Returns 12 on success, 0 on error.
 */
static uint32_t build_udpv6_probe(uint8_t *buf, size_t bufsz,
                                   int hop,
                                   uint16_t job_index,
                                   uint16_t probe_index)
{
    if (bufsz < 12) return 0;

    const uint16_t udp_total = 12;
    const uint16_t dst_port  = (uint16_t)(UDP_TR_BASE_DST_PORT + hop);
    const uint16_t src_port  = UDP_TR_SRC_PORT;

    uint16_t sp = htons(src_port);
    uint16_t dp = htons(dst_port);
    uint16_t ul = htons(udp_total);
    memcpy(buf + 0, &sp, 2);
    memcpy(buf + 2, &dp, 2);
    memcpy(buf + 4, &ul, 2);
    buf[6] = 0;   /* checksum hi */
    buf[7] = 0;   /* checksum lo — set to 0 (disabled for IPv6 UDP, RFC 2460 allows it for UDP) */

    /* 4-byte payload */
    uint16_t ji = htons(job_index);
    uint16_t pi = htons(probe_index);
    memcpy(buf + 8,  &ji, 2);
    memcpy(buf + 10, &pi, 2);

    return 12;
}

/* ------------------------------------------------------------------ */
/* Parse helpers                                                        */
/* ------------------------------------------------------------------ */

struct udp_parse_result {
    int      valid;
    int      is_time_exceeded;    /* 1 = TTL expired, 0 = port unreachable (dest reached) */
    uint16_t src_port;            /* from embedded inner UDP header */
    uint16_t dst_port;            /* from embedded inner UDP header */
    char     src_addr[64];        /* source address of the ICMP response */
};

/*
 * Parse a raw IPv4 ICMP Time Exceeded or Destination Unreachable (Port Unreach)
 * response. pkt points to the outer IP header.
 *
 * Structure:
 *   [outer IP hdr][ICMP hdr (8)][inner IP hdr][inner UDP hdr (8)][inner payload]
 */
static struct udp_parse_result parse_udpv4_icmp_response(const uint8_t *pkt,
                                                          uint32_t len)
{
    struct udp_parse_result res;
    memset(&res, 0, sizeof(res));

    if (len < 20) return res;

    /* Outer IP header */
    int ip_hl = (pkt[0] & 0x0f) * 4;
    if ((uint32_t)ip_hl > len) return res;

    /* Source address of the outer IP header (the router/dest responding) */
    struct in_addr src_ip;
    memcpy(&src_ip, pkt + 12, 4);
    inet_ntop(AF_INET, &src_ip, res.src_addr, sizeof(res.src_addr));

    const uint8_t *icmp = pkt + ip_hl;
    uint32_t icmp_len = len - (uint32_t)ip_hl;

    if (icmp_len < 8) return res;

    uint8_t type = icmp[0];
    uint8_t code = icmp[1];

    int is_time_exceeded   = (type == ICMP_TYPE_TIME_EXCEEDED && code == 0);
    int is_port_unreachable = (type == ICMP_TYPE_DEST_UNREACHABLE &&
                               code == ICMP_CODE_PORT_UNREACHABLE);

    if (!is_time_exceeded && !is_port_unreachable) return res;

    /*
     * Embedded original packet starts at icmp+8.
     * Need: inner IP header (>= 20) + inner UDP header (8)
     */
    if (icmp_len < 8 + 20 + 8) return res;

    const uint8_t *inner_ip = icmp + 8;
    int inner_hl = (inner_ip[0] & 0x0f) * 4;
    if ((uint32_t)(8 + inner_hl + 8) > icmp_len) return res;

    /* Inner protocol must be UDP */
    if (inner_ip[9] != IPPROTO_UDP) return res;

    const uint8_t *inner_udp = inner_ip + inner_hl;

    uint16_t sp, dp;
    memcpy(&sp, inner_udp + 0, 2);
    memcpy(&dp, inner_udp + 2, 2);
    res.src_port = ntohs(sp);
    res.dst_port = ntohs(dp);

    res.is_time_exceeded = is_time_exceeded ? 1 : 0;
    res.valid = 1;
    return res;
}

/*
 * Parse a raw ICMPv6 Time Exceeded or Destination Unreachable (Port Unreach)
 * response. On ICMPv6 raw sockets the kernel strips the outer IPv6 header on
 * Linux; on macOS the full IPv6 packet may be present.
 *
 * We attempt both: if the first byte looks like an IPv6 header (version == 6),
 * we skip the 40-byte header first.
 *
 * src_addr is set to "unknown" — the caller fills it from socket ancillary data.
 */
static struct udp_parse_result parse_udpv6_icmp_response(const uint8_t *pkt,
                                                          uint32_t len)
{
    struct udp_parse_result res;
    memset(&res, 0, sizeof(res));
    snprintf(res.src_addr, sizeof(res.src_addr), "unknown");

    const uint8_t *icmp6 = pkt;
    uint32_t icmp6_len   = len;

    /* If the packet starts with an IPv6 header (version=6), skip it */
    if (len >= 40 && (pkt[0] >> 4) == 6) {
        /* Extract source address from IPv6 header bytes 8..23 */
        struct in6_addr src6;
        memcpy(&src6, pkt + 8, 16);
        inet_ntop(AF_INET6, &src6, res.src_addr, sizeof(res.src_addr));
        icmp6     = pkt + 40;
        icmp6_len = len - 40;
    }

    if (icmp6_len < 8) return res;

    uint8_t type = icmp6[0];
    uint8_t code = icmp6[1];

    int is_time_exceeded    = (type == ICMPV6_TYPE_TIME_EXCEEDED && code == 0);
    int is_port_unreachable = (type == ICMPV6_TYPE_DEST_UNREACHABLE &&
                               code == ICMPV6_CODE_PORT_UNREACHABLE);

    if (!is_time_exceeded && !is_port_unreachable) return res;

    /*
     * Embedded original packet: 4-byte ICMPv6 header + 4 unused +
     * 40-byte inner IPv6 header + 8-byte inner UDP header
     */
    if (icmp6_len < 8 + 40 + 8) return res;

    const uint8_t *inner_ip6 = icmp6 + 8;

    /* Inner next-header must be UDP (17) — at IPv6 header offset 6 */
    if (inner_ip6[6] != IPPROTO_UDP) return res;

    const uint8_t *inner_udp = inner_ip6 + 40;

    uint16_t sp, dp;
    memcpy(&sp, inner_udp + 0, 2);
    memcpy(&dp, inner_udp + 2, 2);
    res.src_port = ntohs(sp);
    res.dst_port = ntohs(dp);

    res.is_time_exceeded = is_time_exceeded ? 1 : 0;
    res.valid = 1;
    return res;
}

/* ------------------------------------------------------------------ */
/* Publishing                                                           */
/* ------------------------------------------------------------------ */

static void udp_publish_hop(ps_module_ctx_t *ctx,
                             const struct udp_trace_job *job,
                             int hop_number, const char *addr,
                             const char *hostname,
                             const struct udp_probe_slot *probes,
                             int n_probes, int is_filtered)
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

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "traceroute.hop", buf, (uint32_t)j.len);
    }
}

static void udp_publish_complete(ps_module_ctx_t *ctx,
                                  const struct udp_trace_job *job,
                                  int reached, int hop_count)
{
    char buf[512];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "job_id",              job->job_id);
    ps_json_key_string(&j, "destination",         job->destination);
    ps_json_key_bool  (&j, "reached_destination", reached);
    ps_json_key_int   (&j, "hop_count",            hop_count);
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "traceroute.complete", buf, (uint32_t)j.len);
    }
}

/* ------------------------------------------------------------------ */
/* Reverse DNS                                                          */
/* ------------------------------------------------------------------ */

static void udp_resolve_hostname(int af, const char *addr_str,
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
        strncpy(hostname_out, addr_str, hostname_len - 1);
        hostname_out[hostname_len - 1] = '\0';
    }
}

/* ------------------------------------------------------------------ */
/* Job management                                                       */
/* ------------------------------------------------------------------ */

static struct udp_trace_job *find_free_udp_job(struct udp_tr_state *st)
{
    for (int i = 0; i < UDP_TR_MAX_JOBS; i++) {
        if (!st->jobs[i].active)
            return &st->jobs[i];
    }
    return NULL;
}

static void udp_send_probes(ps_module_ctx_t *ctx, struct udp_tr_state *st,
                             struct udp_trace_job *job)
{
    uint64_t now = ps_platform_now_usec();
    uint8_t  buf[64];
    uint32_t pkt_len;

    for (int i = 0; i < UDP_TR_PROBES; i++) {
        job->probes[i].sent_usec = now;
        job->probes[i].replied   = 0;
        job->probes[i].rtt_ms    = 0.0;

        if (job->af == AF_INET) {
            pkt_len = build_udpv4_probe(buf, sizeof(buf),
                                        (uint8_t)job->cur_hop,
                                        (const struct sockaddr_in *)&job->dest_sa,
                                        job->cur_hop,
                                        (uint16_t)job->job_index,
                                        (uint16_t)i);
            if (pkt_len == 0) {
                ps_warn("udp_traceroute: failed to build UDPv4 probe");
                continue;
            }
            ctx->send_raw(ctx, st->send_sock4, (uint8_t)job->cur_hop,
                          (const struct sockaddr *)&job->dest_sa,
                          buf, pkt_len);
        } else {
            pkt_len = build_udpv6_probe(buf, sizeof(buf),
                                        job->cur_hop,
                                        (uint16_t)job->job_index,
                                        (uint16_t)i);
            if (pkt_len == 0) {
                ps_warn("udp_traceroute: failed to build UDPv6 probe");
                continue;
            }
            ctx->send_raw(ctx, st->send_sock6, (uint8_t)job->cur_hop,
                          (const struct sockaddr *)&job->dest_sa,
                          buf, pkt_len);
        }
    }

    ps_debug("udp_traceroute: sent %d probes for job '%s' hop %d (dst_port=%d)",
             UDP_TR_PROBES, job->job_id, job->cur_hop,
             UDP_TR_BASE_DST_PORT + job->cur_hop);
}

static void udp_advance_hop(ps_module_ctx_t *ctx, struct udp_tr_state *st,
                             struct udp_trace_job *job,
                             const char *hop_addr, int is_filtered)
{
    char hostname[NI_MAXHOST];
    if (is_filtered || hop_addr == NULL || hop_addr[0] == '\0') {
        hostname[0] = '\0';
    } else {
        udp_resolve_hostname(job->af, hop_addr, hostname, sizeof(hostname));
    }

    udp_publish_hop(ctx, job, job->cur_hop,
                    hop_addr ? hop_addr : "",
                    hostname,
                    job->probes, UDP_TR_PROBES,
                    is_filtered);

    if (job->reached || job->cur_hop >= job->max_hops) {
        udp_publish_complete(ctx, job, job->reached, job->cur_hop);
        memset(job, 0, sizeof(*job));
        return;
    }

    job->cur_hop++;
    job->probes_replied = 0;
    memset(job->probes, 0, sizeof(job->probes));
    udp_send_probes(ctx, st, job);
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int udp_tr_init(ps_module_ctx_t *ctx)
{
    struct udp_tr_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("udp_traceroute: out of memory");
        return -1;
    }

    st->send_sock4 = -1;
    st->recv_sock4 = -1;
    st->send_sock6 = -1;
    st->recv_sock6 = -1;

    /* IPv4: raw UDP send socket (IP_HDRINCL) + raw ICMP recv socket */
    st->send_sock4 = ctx->create_raw_socket(ctx, AF_INET, IPPROTO_UDP);
    if (st->send_sock4 < 0) {
        ps_warn("udp_traceroute: could not create IPv4 UDP send socket (handle=%d)",
                st->send_sock4);
    } else {
        ps_info("udp_traceroute: IPv4 UDP send socket handle=%d", st->send_sock4);
    }

    st->recv_sock4 = ctx->create_raw_socket(ctx, AF_INET, IPPROTO_ICMP);
    if (st->recv_sock4 < 0) {
        ps_warn("udp_traceroute: could not create IPv4 ICMP recv socket (handle=%d)",
                st->recv_sock4);
    } else {
        ps_info("udp_traceroute: IPv4 ICMP recv socket handle=%d", st->recv_sock4);
    }

    /* IPv6: raw UDP send socket + raw ICMPv6 recv socket */
    st->send_sock6 = ctx->create_raw_socket(ctx, AF_INET6, IPPROTO_UDP);
    if (st->send_sock6 < 0) {
        ps_warn("udp_traceroute: could not create IPv6 UDP send socket (handle=%d)",
                st->send_sock6);
    } else {
        ps_info("udp_traceroute: IPv6 UDP send socket handle=%d", st->send_sock6);
    }

    st->recv_sock6 = ctx->create_raw_socket(ctx, AF_INET6, 58 /* IPPROTO_ICMPV6 */);
    if (st->recv_sock6 < 0) {
        ps_warn("udp_traceroute: could not create IPv6 ICMPv6 recv socket (handle=%d)",
                st->recv_sock6);
    } else {
        ps_info("udp_traceroute: IPv6 ICMPv6 recv socket handle=%d", st->recv_sock6);
    }

    ctx->userdata = st;
    ps_info("udp_traceroute: initialized");
    return 0;
}

static void udp_tr_shutdown(ps_module_ctx_t *ctx)
{
    free(ctx->userdata);
    ctx->userdata = NULL;
    ps_info("udp_traceroute: shutdown");
}

static int udp_tr_on_job(ps_module_ctx_t *ctx, const struct ps_job *job)
{
    struct udp_tr_state *st = (struct udp_tr_state *)ctx->userdata;
    if (!st) return -1;

    /* Only handle udp method */
    if (strcmp(job->method, "udp") != 0)
        return 0;  /* not for us */

    struct udp_trace_job *tj = find_free_udp_job(st);
    if (!tj) {
        ps_warn("udp_traceroute: all %d job slots busy, dropping job '%s'",
                UDP_TR_MAX_JOBS, job->job_id);
        return -1;
    }

    /* Resolve destination */
    int af_hint = AF_UNSPEC;
    if (job->af == 6)      af_hint = AF_INET6;
    else if (job->af == 4) af_hint = AF_INET;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = af_hint;
    hints.ai_socktype = SOCK_DGRAM;

    int rc = getaddrinfo(job->destination, NULL, &hints, &res);
    if (rc != 0) {
        ps_warn("udp_traceroute: getaddrinfo('%s') failed: %s",
                job->destination, gai_strerror(rc));
        return -1;
    }

    memset(tj, 0, sizeof(*tj));
    tj->af = res->ai_family;
    memcpy(&tj->dest_sa, res->ai_addr, res->ai_addrlen);
    tj->dest_sa_len = res->ai_addrlen;

    if (tj->af == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&tj->dest_sa;
        inet_ntop(AF_INET, &sin->sin_addr, tj->dest_addr_str, sizeof(tj->dest_addr_str));
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&tj->dest_sa;
        inet_ntop(AF_INET6, &sin6->sin6_addr, tj->dest_addr_str, sizeof(tj->dest_addr_str));
    }

    freeaddrinfo(res);

    /* Check we have the required sockets */
    if (tj->af == AF_INET && (st->send_sock4 < 0 || st->recv_sock4 < 0)) {
        ps_warn("udp_traceroute: missing IPv4 sockets for job '%s'", job->job_id);
        return -1;
    }
    if (tj->af == AF_INET6 && (st->send_sock6 < 0 || st->recv_sock6 < 0)) {
        ps_warn("udp_traceroute: missing IPv6 sockets for job '%s'", job->job_id);
        return -1;
    }

    /* Compute job_index — slot index in jobs array */
    int slot = (int)(tj - st->jobs);
    tj->job_index = slot;

    strncpy(tj->job_id,      job->job_id,      sizeof(tj->job_id) - 1);
    strncpy(tj->destination, job->destination, sizeof(tj->destination) - 1);
    tj->max_hops = job->max_hops > 0 ? job->max_hops : UDP_TR_DEFAULT_HOPS;
    tj->cur_hop  = 1;
    tj->active   = 1;

    ps_info("udp_traceroute: starting job '%s' -> '%s' (%s) max_hops=%d af=%s",
            tj->job_id, tj->destination, tj->dest_addr_str, tj->max_hops,
            tj->af == AF_INET ? "IPv4" : "IPv6");

    udp_send_probes(ctx, st, tj);
    return 0;
}

static void udp_tr_on_response(ps_module_ctx_t *ctx, const uint8_t *pkt,
                                uint32_t len, uint64_t ts_usec, int socket_id)
{
    struct udp_tr_state *st = (struct udp_tr_state *)ctx->userdata;
    if (!st) return;

    (void)ts_usec;

    /* Only handle packets from our ICMP recv sockets */
    int resp_af = 0;
    if (socket_id == st->recv_sock4)      resp_af = AF_INET;
    else if (socket_id == st->recv_sock6) resp_af = AF_INET6;
    else return;

    struct udp_parse_result pr;
    if (resp_af == AF_INET) {
        pr = parse_udpv4_icmp_response(pkt, len);
    } else {
        pr = parse_udpv6_icmp_response(pkt, len);
        /* For IPv6 without header, fill source from packet if present */
        if (pr.valid && strcmp(pr.src_addr, "unknown") == 0 && len >= 16) {
            if (len >= 40 && (pkt[0] >> 4) == 6) {
                struct in6_addr src6;
                memcpy(&src6, pkt + 8, 16);
                inet_ntop(AF_INET6, &src6, pr.src_addr, sizeof(pr.src_addr));
            }
        }
    }

    if (!pr.valid) return;

    /* Check our probe signature: source port must be 0x5053 */
    if (pr.src_port != UDP_TR_SRC_PORT) return;

    /* Decode hop number from destination port */
    if (pr.dst_port < UDP_TR_BASE_DST_PORT) return;
    uint16_t hop_num = pr.dst_port - UDP_TR_BASE_DST_PORT;
    if (hop_num == 0 || hop_num > UDP_TR_DEFAULT_HOPS) return;

    /* Find matching active job */
    for (int i = 0; i < UDP_TR_MAX_JOBS; i++) {
        struct udp_trace_job *tj = &st->jobs[i];
        if (!tj->active) continue;
        if (tj->af != resp_af) continue;
        if (hop_num != (uint16_t)tj->cur_hop) continue;

        uint64_t now = ps_platform_now_usec();

        /* Record reply on first unacknowledged probe */
        int recorded = 0;
        for (int k = 0; k < UDP_TR_PROBES; k++) {
            if (!tj->probes[k].replied && tj->probes[k].sent_usec > 0) {
                tj->probes[k].replied = 1;
                tj->probes[k].rtt_ms  = (double)(now - tj->probes[k].sent_usec) / 1000.0;
                tj->probes_replied++;
                recorded = 1;
                break;
            }
        }
        if (!recorded) continue;

        /* Port Unreachable means we've reached the destination */
        if (!pr.is_time_exceeded) {
            tj->reached = 1;
        }

        udp_advance_hop(ctx, st, tj, pr.src_addr, 0 /* not filtered */);
        break;
    }
}

static void udp_tr_tick(ps_module_ctx_t *ctx, uint64_t now_usec)
{
    struct udp_tr_state *st = (struct udp_tr_state *)ctx->userdata;
    if (!st) return;

    for (int i = 0; i < UDP_TR_MAX_JOBS; i++) {
        struct udp_trace_job *tj = &st->jobs[i];
        if (!tj->active) continue;
        if (tj->probes_replied > 0) continue;

        int all_timed_out = 1;
        for (int k = 0; k < UDP_TR_PROBES; k++) {
            if (tj->probes[k].sent_usec == 0) continue;
            if ((now_usec - tj->probes[k].sent_usec) < UDP_TR_TIMEOUT_USEC) {
                all_timed_out = 0;
                break;
            }
        }

        if (all_timed_out) {
            ps_debug("udp_traceroute: hop %d timed out for job '%s'",
                     tj->cur_hop, tj->job_id);
            udp_advance_hop(ctx, st, tj, NULL, 1 /* filtered */);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

#ifndef PS_UDP_TRACEROUTE_TESTING

const ps_module_t ps_udp_traceroute_module = {
    .name        = "udp_traceroute",
    .description = "Dual-stack UDP traceroute (traditional Unix method)",
    .version     = "1.0",
    .flags       = PS_MOD_ACTIVE | PS_MOD_NEEDS_RAW,

    .init        = udp_tr_init,
    .shutdown    = udp_tr_shutdown,
    .on_packet   = NULL,
    .on_job      = udp_tr_on_job,
    .on_response = udp_tr_on_response,
    .tick        = udp_tr_tick,
};

#endif /* PS_UDP_TRACEROUTE_TESTING */
