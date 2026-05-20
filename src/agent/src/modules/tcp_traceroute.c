/*
 * tcp_traceroute.c — Dual-stack TCP SYN traceroute module for PacketSonde Agent
 *
 * Sends TCP SYN packets with incrementing TTL. Intermediate routers return
 * ICMP Time Exceeded. The destination returns TCP SYN-ACK (or RST) → reached.
 *
 * Probe identification:
 *   Source port = 0x5053 + job_index  ("PS" + index)
 *   TCP sequence number = hop number (1-based)
 *
 * Sockets (per address family):
 *   One IPPROTO_TCP raw socket  — sending SYN probes (IP_HDRINCL)
 *   One IPPROTO_ICMP raw socket — receiving ICMP Time Exceeded replies
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
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "packetsonde/module_api.h"
#include "json.h"
#include "log.h"
#include "platform/platform.h"

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define TCP_TR_MAX_JOBS       8
#define TCP_TR_PROBES         3
#define TCP_TR_TIMEOUT_USEC   (3 * 1000000ULL)   /* 3 seconds */
#define TCP_TR_BASE_SRC_PORT  0x5053              /* "PS" — job_index added */
#define TCP_TR_DEFAULT_PORT   443
#define TCP_TR_DEFAULT_HOPS   30

/* ICMP type constants */
#define ICMP_TYPE_TIME_EXCEEDED   11

/* TCP flag bits */
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_ACK  0x10

/* ------------------------------------------------------------------ */
/* Structures                                                           */
/* ------------------------------------------------------------------ */

struct tcp_probe_slot {
    uint64_t sent_usec;   /* 0 = not yet sent */
    int      replied;
    double   rtt_ms;
};

struct tcp_trace_job {
    int      active;
    int      job_index;              /* 0..TCP_TR_MAX_JOBS-1, used for src port */
    char     job_id[64];
    char     destination[256];       /* original destination string */
    char     dest_addr_str[64];      /* resolved numeric address */
    int      max_hops;
    int      tcp_port;               /* destination port for SYN probes */
    int      af;                     /* AF_INET or AF_INET6 */

    struct sockaddr_storage dest_sa;
    socklen_t               dest_sa_len;

    int      cur_hop;                /* 1-based hop we're currently probing */
    struct tcp_probe_slot probes[TCP_TR_PROBES];
    int      probes_replied;         /* count of replies received for cur_hop */

    int      reached;                /* destination responded */
};

struct tcp_tr_state {
    int            tcp_sock4;   /* TCP raw socket for IPv4 sending, -1 if unavailable */
    int            tcp_sock6;   /* TCP raw socket for IPv6 sending, -1 if unavailable */
    int            icmp_sock4;  /* ICMP raw socket for IPv4 receiving */
    int            icmp_sock6;  /* ICMPv6 raw socket for IPv6 receiving */
    struct tcp_trace_job jobs[TCP_TR_MAX_JOBS];
};

/* ------------------------------------------------------------------ */
/* TCP Pseudo-header checksum                                           */
/* ------------------------------------------------------------------ */

/*
 * Standard one's-complement 16-bit checksum.
 */
static uint16_t tcp_tr_checksum(const uint8_t *data, size_t len)
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
 * Compute TCP checksum over a pseudo-header + TCP segment.
 *
 * IPv4 pseudo-header layout (12 bytes):
 *   [0..3]   src IP
 *   [4..7]   dst IP
 *   [8]      zero
 *   [9]      protocol (6)
 *   [10..11] TCP segment length (big-endian)
 *
 * Returns the checksum value (network byte order already set by caller).
 */
static uint16_t tcp_checksum_v4(const struct in_addr *src,
                                 const struct in_addr *dst,
                                 const uint8_t *tcp_seg, uint16_t tcp_len)
{
    /* Build pseudo-header + TCP segment in a contiguous buffer */
    uint8_t pseudo[12 + 20];  /* pseudo (12) + max TCP header (20) */
    if (tcp_len > 20) {
        /* Shouldn't happen — we only send 20-byte TCP headers */
        tcp_len = 20;
    }

    memcpy(pseudo,      &src->s_addr, 4);
    memcpy(pseudo + 4,  &dst->s_addr, 4);
    pseudo[8] = 0;
    pseudo[9] = IPPROTO_TCP;
    uint16_t tlen_be = htons(tcp_len);
    memcpy(pseudo + 10, &tlen_be, 2);
    memcpy(pseudo + 12, tcp_seg, tcp_len);

    return tcp_tr_checksum(pseudo, 12 + tcp_len);
}

/* ------------------------------------------------------------------ */
/* IPv4 probe building (IP_HDRINCL)                                     */
/* ------------------------------------------------------------------ */

/*
 * Build a complete IP + TCP SYN packet for an IPv4 hop probe.
 *
 * Layout:
 *   [0..19]   IPv4 header (ttl=hop, proto=TCP, dst=target, src=0)
 *   [20..39]  TCP header  (src_port=0x5053+idx, dst_port=job.tcp_port,
 *                          seq=hop, SYN, checksum over pseudo-header)
 *
 * buf must be at least 40 bytes.
 * Returns 40 on success, 0 on error.
 */
static uint32_t build_tcpv4_probe(uint8_t *buf, size_t bufsz,
                                   uint8_t ttl,
                                   const struct sockaddr_in *dst,
                                   uint16_t src_port,
                                   uint16_t dst_port,
                                   uint32_t seq_num)
{
    if (bufsz < 40) return 0;

    memset(buf, 0, 40);

    /* ---- IPv4 header (20 bytes) ---- */
    struct ip *iph = (struct ip *)buf;
    iph->ip_v   = 4;
    iph->ip_hl  = 5;
#ifdef __APPLE__
    iph->ip_len = 40;
#else
    iph->ip_len = htons(40);
#endif
    iph->ip_ttl = ttl;
    iph->ip_p   = IPPROTO_TCP;
    iph->ip_dst = dst->sin_addr;
    /* ip_src left 0 — kernel fills it */
    /* ip_sum left 0 — kernel fills it when IP_HDRINCL is set */

    /* ---- TCP header (20 bytes) ---- */
    uint8_t *tcp = buf + 20;

    uint16_t sp = htons(src_port);
    uint16_t dp = htons(dst_port);
    uint32_t sq = htonl(seq_num);

    memcpy(tcp + 0, &sp, 2);   /* source port */
    memcpy(tcp + 2, &dp, 2);   /* destination port */
    memcpy(tcp + 4, &sq, 4);   /* sequence number */
    /* ack number = 0 */
    tcp[12] = 0x50;             /* data offset = 5 (20 bytes), reserved = 0 */
    tcp[13] = TCP_FLAG_SYN;     /* flags: SYN */
    uint16_t win = htons(1024);
    memcpy(tcp + 14, &win, 2);  /* window size */
    /* checksum and urgent pointer left 0 for now */

    /* Compute TCP checksum */
    struct in_addr src_zero;
    src_zero.s_addr = 0;  /* kernel will fill src; use 0 for checksum (Linux recalculates) */
    uint16_t cksum = tcp_checksum_v4(&src_zero, &dst->sin_addr, tcp, 20);
    memcpy(tcp + 16, &cksum, 2);

    return 40;
}

/* ------------------------------------------------------------------ */
/* Parse helpers                                                        */
/* ------------------------------------------------------------------ */

/*
 * Result from parsing a TCP traceroute response packet.
 */
struct tcp_parse_result {
    int      valid;
    int      is_time_exceeded;   /* 1 = ICMP TTL expired, 0 = TCP reply */
    int      is_rst;             /* 1 = RST (also counts as reached) */
    uint16_t job_src_port;       /* TCP src port identifying job index */
    uint32_t hop_seq;            /* TCP seq number identifying hop */
    char     src_addr[64];       /* responder's address */
};

/*
 * Parse an ICMP Time Exceeded packet that contains an embedded TCP segment.
 * Delivered as a full raw IPv4 packet (includes outer IP header).
 *
 * Structure:
 *   [outer IP header (ip_hl*4 bytes)]
 *   [ICMP Time Exceeded: type=11, code=0, cksum(2), unused(4)]   8 bytes
 *   [inner IP header (20 bytes min)]
 *   [inner TCP header (8+ bytes, we only need first 8)]
 *
 * We extract:
 *   src_addr       = outer IP src (the router that replied)
 *   job_src_port   = inner TCP src port (identifies job)
 *   hop_seq        = inner TCP seq number (identifies hop)
 */
static struct tcp_parse_result parse_icmp_time_exceeded_v4(const uint8_t *pkt,
                                                             uint32_t len)
{
    struct tcp_parse_result res;
    memset(&res, 0, sizeof(res));

    if (len < 20) return res;

    /* Outer IP header length */
    int ip_hl = (pkt[0] & 0x0f) * 4;
    if ((uint32_t)ip_hl > len) return res;

    /* Source address of the outer IP header (the router) */
    struct in_addr src_ip;
    memcpy(&src_ip, pkt + 12, 4);
    inet_ntop(AF_INET, &src_ip, res.src_addr, sizeof(res.src_addr));

    const uint8_t *icmp = pkt + ip_hl;
    uint32_t icmp_len = len - (uint32_t)ip_hl;

    if (icmp_len < 8) return res;

    uint8_t type = icmp[0];
    uint8_t code = icmp[1];

    if (type != ICMP_TYPE_TIME_EXCEEDED || code != 0) return res;

    /*
     * ICMP Time Exceeded body:
     *   8 bytes ICMP header (type+code+cksum+unused)
     *   inner IP header (min 20 bytes)
     *   first 8 bytes of inner TCP header (src_port, dst_port, seq[4])
     */
    if (icmp_len < 8 + 20 + 8) return res;

    const uint8_t *inner_ip = icmp + 8;
    int inner_hl = (inner_ip[0] & 0x0f) * 4;

    /* Verify we have enough data for inner IP + 8 bytes TCP */
    if ((uint32_t)(8 + inner_hl + 8) > icmp_len) return res;

    /* Inner IP protocol must be TCP */
    if (inner_ip[9] != IPPROTO_TCP) return res;

    const uint8_t *inner_tcp = inner_ip + inner_hl;

    /* TCP src_port (2 bytes) + dst_port (2 bytes) + seq (4 bytes) */
    uint16_t src_port;
    uint32_t seq;
    memcpy(&src_port, inner_tcp + 0, 2);
    memcpy(&seq,      inner_tcp + 4, 4);

    res.job_src_port   = ntohs(src_port);
    res.hop_seq        = ntohl(seq);
    res.is_time_exceeded = 1;
    res.valid          = 1;
    return res;
}

/*
 * Parse a TCP SYN-ACK or RST reply received on the raw TCP socket.
 * Delivered as a full raw IPv4 packet (includes IP header).
 *
 * We extract:
 *   src_addr       = IP src (the destination host)
 *   job_src_port   = TCP dst port (must match 0x5053 + job_index)
 *   hop_seq        = not meaningful for SYN-ACK; set to 0
 *   is_rst         = 1 if RST flag set
 */
static struct tcp_parse_result parse_tcp_reply_v4(const uint8_t *pkt,
                                                    uint32_t len)
{
    struct tcp_parse_result res;
    memset(&res, 0, sizeof(res));

    if (len < 20) return res;

    int ip_hl = (pkt[0] & 0x0f) * 4;
    if ((uint32_t)ip_hl + 20 > len) return res;

    /* Must be TCP */
    if (pkt[9] != IPPROTO_TCP) return res;

    /* Source address of the IP header */
    struct in_addr src_ip;
    memcpy(&src_ip, pkt + 12, 4);
    inet_ntop(AF_INET, &src_ip, res.src_addr, sizeof(res.src_addr));

    const uint8_t *tcp = pkt + ip_hl;

    /* TCP dst_port identifies which job this reply belongs to */
    uint16_t dst_port;
    memcpy(&dst_port, tcp + 2, 2);
    res.job_src_port = ntohs(dst_port);

    /* TCP src_port (should match the job's tcp_port target) */
    /* uint16_t tcp_src_port; memcpy(&tcp_src_port, tcp + 0, 2); — not needed here */

    /* Check flags byte (offset 13) */
    uint8_t flags = tcp[13];
    int is_syn_ack = ((flags & TCP_FLAG_SYN) && (flags & TCP_FLAG_ACK));
    int is_rst     = !!(flags & TCP_FLAG_RST);

    if (!is_syn_ack && !is_rst) return res;  /* not a response we care about */

    res.is_rst   = is_rst;
    res.hop_seq  = 0;  /* Not encoded in seq for SYN-ACK; use job's cur_hop */
    res.valid    = 1;
    return res;
}

/* ------------------------------------------------------------------ */
/* Publishing                                                           */
/* ------------------------------------------------------------------ */

static void tcp_publish_hop(ps_module_ctx_t *ctx,
                             const struct tcp_trace_job *job,
                             int hop_number, const char *addr,
                             const char *hostname,
                             const struct tcp_probe_slot *probes,
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

static void tcp_publish_complete(ps_module_ctx_t *ctx,
                                  const struct tcp_trace_job *job,
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

static void tcp_resolve_hostname(int af, const char *addr_str,
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

static struct tcp_trace_job *tcp_find_free_job(struct tcp_tr_state *st)
{
    for (int i = 0; i < TCP_TR_MAX_JOBS; i++) {
        if (!st->jobs[i].active)
            return &st->jobs[i];
    }
    return NULL;
}

static void tcp_send_probes(ps_module_ctx_t *ctx, struct tcp_tr_state *st,
                             struct tcp_trace_job *job)
{
    uint64_t now = ps_platform_now_usec();
    uint8_t  buf[64];
    uint32_t pkt_len;

    uint16_t src_port = (uint16_t)(TCP_TR_BASE_SRC_PORT + job->job_index);

    for (int i = 0; i < TCP_TR_PROBES; i++) {
        job->probes[i].sent_usec = now;
        job->probes[i].replied   = 0;
        job->probes[i].rtt_ms    = 0.0;

        if (job->af == AF_INET) {
            pkt_len = build_tcpv4_probe(buf, sizeof(buf),
                                         (uint8_t)job->cur_hop,
                                         (const struct sockaddr_in *)&job->dest_sa,
                                         src_port,
                                         (uint16_t)job->tcp_port,
                                         (uint32_t)job->cur_hop);
            if (pkt_len == 0) {
                ps_warn("tcp_traceroute: failed to build TCPv4 probe");
                continue;
            }
            ctx->send_raw(ctx, st->tcp_sock4, (uint8_t)job->cur_hop,
                          (const struct sockaddr *)&job->dest_sa,
                          buf, pkt_len);
        } else {
            /*
             * IPv6 TCP SYN traceroute is not implemented in this version.
             * The IPv6 send path requires constructing raw IPv6+TCP which
             * differs significantly per platform. Skip for now.
             */
            ps_warn("tcp_traceroute: IPv6 TCP probes not yet implemented for job '%s'",
                    job->job_id);
        }
    }

    ps_debug("tcp_traceroute: sent %d probes for job '%s' hop %d (src_port=%u)",
             TCP_TR_PROBES, job->job_id, job->cur_hop, src_port);
}

static void tcp_advance_hop(ps_module_ctx_t *ctx, struct tcp_tr_state *st,
                             struct tcp_trace_job *job, const char *hop_addr,
                             int is_filtered)
{
    char hostname[NI_MAXHOST];
    if (is_filtered || hop_addr == NULL || hop_addr[0] == '\0') {
        hostname[0] = '\0';
    } else {
        tcp_resolve_hostname(job->af, hop_addr, hostname, sizeof(hostname));
    }

    tcp_publish_hop(ctx, job, job->cur_hop,
                    hop_addr ? hop_addr : "",
                    hostname,
                    job->probes, TCP_TR_PROBES,
                    is_filtered);

    if (job->reached || job->cur_hop >= job->max_hops) {
        tcp_publish_complete(ctx, job, job->reached, job->cur_hop);
        memset(job, 0, sizeof(*job));  /* free the slot */
        return;
    }

    job->cur_hop++;
    job->probes_replied = 0;
    memset(job->probes, 0, sizeof(job->probes));
    tcp_send_probes(ctx, st, job);
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int tcp_tr_init(ps_module_ctx_t *ctx)
{
    struct tcp_tr_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("tcp_traceroute: out of memory");
        return -1;
    }

    st->tcp_sock4  = -1;
    st->tcp_sock6  = -1;
    st->icmp_sock4 = -1;
    st->icmp_sock6 = -1;

    /* TCP raw socket for sending SYN probes (IPv4) */
    st->tcp_sock4 = ctx->create_raw_socket(ctx, AF_INET, IPPROTO_TCP);
    if (st->tcp_sock4 < 0) {
        ps_warn("tcp_traceroute: could not create IPv4 TCP raw socket (handle=%d)",
                st->tcp_sock4);
    } else {
        ps_info("tcp_traceroute: IPv4 TCP raw socket handle=%d", st->tcp_sock4);
    }

    /* ICMP raw socket for receiving Time Exceeded replies (IPv4) */
    st->icmp_sock4 = ctx->create_raw_socket(ctx, AF_INET, IPPROTO_ICMP);
    if (st->icmp_sock4 < 0) {
        ps_warn("tcp_traceroute: could not create IPv4 ICMP raw socket (handle=%d)",
                st->icmp_sock4);
    } else {
        ps_info("tcp_traceroute: IPv4 ICMP raw socket handle=%d", st->icmp_sock4);
    }

    /* ICMPv6 raw socket for receiving replies (IPv6) */
    st->icmp_sock6 = ctx->create_raw_socket(ctx, AF_INET6, 58 /* IPPROTO_ICMPV6 */);
    if (st->icmp_sock6 < 0) {
        ps_warn("tcp_traceroute: could not create IPv6 ICMPv6 raw socket (handle=%d)",
                st->icmp_sock6);
    } else {
        ps_info("tcp_traceroute: IPv6 ICMPv6 raw socket handle=%d", st->icmp_sock6);
    }

    ctx->userdata = st;
    ps_info("tcp_traceroute: initialized");
    return 0;
}

static void tcp_tr_shutdown(ps_module_ctx_t *ctx)
{
    free(ctx->userdata);
    ctx->userdata = NULL;
    ps_info("tcp_traceroute: shutdown");
}

static int tcp_tr_on_job(ps_module_ctx_t *ctx, const struct ps_job *job)
{
    struct tcp_tr_state *st = (struct tcp_tr_state *)ctx->userdata;
    if (!st) return -1;

    /* Only handle tcp method */
    if (job->method[0] == '\0' || strcmp(job->method, "tcp") != 0) {
        return 0;  /* not for us */
    }

    struct tcp_trace_job *tj = tcp_find_free_job(st);
    if (!tj) {
        ps_warn("tcp_traceroute: all %d job slots busy, dropping job '%s'",
                TCP_TR_MAX_JOBS, job->job_id);
        return -1;
    }

    /* Determine job index (needed for src port) */
    int job_index = (int)(tj - st->jobs);

    /* Resolve destination */
    int af_hint = AF_UNSPEC;
    if (job->af == 6) af_hint = AF_INET6;
    else if (job->af == 4) af_hint = AF_INET;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = af_hint;
    hints.ai_socktype = SOCK_RAW;

    int rc = getaddrinfo(job->destination, NULL, &hints, &res);
    if (rc != 0) {
        ps_warn("tcp_traceroute: getaddrinfo('%s') failed: %s",
                job->destination, gai_strerror(rc));
        return -1;
    }

    memset(tj, 0, sizeof(*tj));
    tj->job_index = job_index;
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

    /* Check we have the right send socket */
    if (tj->af == AF_INET && st->tcp_sock4 < 0) {
        ps_warn("tcp_traceroute: no IPv4 TCP socket for job '%s'", job->job_id);
        return -1;
    }
    if (tj->af == AF_INET6) {
        ps_warn("tcp_traceroute: IPv6 TCP traceroute not yet supported for job '%s'",
                job->job_id);
        return -1;
    }

    strncpy(tj->job_id,     job->job_id,     sizeof(tj->job_id) - 1);
    strncpy(tj->destination, job->destination, sizeof(tj->destination) - 1);
    tj->max_hops = job->max_hops > 0 ? job->max_hops : TCP_TR_DEFAULT_HOPS;
    tj->tcp_port = job->tcp_port > 0 ? job->tcp_port : TCP_TR_DEFAULT_PORT;
    tj->cur_hop  = 1;
    tj->active   = 1;

    ps_info("tcp_traceroute: starting job '%s' -> '%s' (%s) max_hops=%d tcp_port=%d af=%s",
            tj->job_id, tj->destination, tj->dest_addr_str, tj->max_hops, tj->tcp_port,
            tj->af == AF_INET ? "IPv4" : "IPv6");

    tcp_send_probes(ctx, st, tj);
    return 0;
}

static void tcp_tr_on_response(ps_module_ctx_t *ctx, const uint8_t *pkt,
                                uint32_t len, uint64_t ts_usec, int socket_id)
{
    struct tcp_tr_state *st = (struct tcp_tr_state *)ctx->userdata;
    if (!st) return;

    (void)ts_usec;

    if (socket_id == st->icmp_sock4) {
        /* ICMP Time Exceeded — router hop response */
        struct tcp_parse_result pr = parse_icmp_time_exceeded_v4(pkt, len);
        if (!pr.valid) return;

        /* Match job by src_port = 0x5053 + job_index */
        for (int i = 0; i < TCP_TR_MAX_JOBS; i++) {
            struct tcp_trace_job *tj = &st->jobs[i];
            if (!tj->active) continue;
            if (tj->af != AF_INET) continue;

            uint16_t expected_src_port = (uint16_t)(TCP_TR_BASE_SRC_PORT + tj->job_index);
            if (pr.job_src_port != expected_src_port) continue;

            /* Match hop by TCP sequence number */
            if (pr.hop_seq != (uint32_t)tj->cur_hop) continue;

            uint64_t now = ps_platform_now_usec();
            int recorded = 0;
            for (int k = 0; k < TCP_TR_PROBES; k++) {
                if (!tj->probes[k].replied && tj->probes[k].sent_usec > 0) {
                    tj->probes[k].replied = 1;
                    tj->probes[k].rtt_ms  = (double)(now - tj->probes[k].sent_usec) / 1000.0;
                    tj->probes_replied++;
                    recorded = 1;
                    break;
                }
            }
            if (!recorded) continue;

            /* Advance to next hop — not reached yet */
            tcp_advance_hop(ctx, st, tj, pr.src_addr, 0 /* not filtered */);
            break;
        }

    } else if (socket_id == st->tcp_sock4) {
        /* TCP SYN-ACK or RST — destination reached */
        struct tcp_parse_result pr = parse_tcp_reply_v4(pkt, len);
        if (!pr.valid) return;

        /* Match job by dst_port (which was our src_port) */
        for (int i = 0; i < TCP_TR_MAX_JOBS; i++) {
            struct tcp_trace_job *tj = &st->jobs[i];
            if (!tj->active) continue;
            if (tj->af != AF_INET) continue;

            uint16_t expected_src_port = (uint16_t)(TCP_TR_BASE_SRC_PORT + tj->job_index);
            if (pr.job_src_port != expected_src_port) continue;

            uint64_t now = ps_platform_now_usec();
            int recorded = 0;
            for (int k = 0; k < TCP_TR_PROBES; k++) {
                if (!tj->probes[k].replied && tj->probes[k].sent_usec > 0) {
                    tj->probes[k].replied = 1;
                    tj->probes[k].rtt_ms  = (double)(now - tj->probes[k].sent_usec) / 1000.0;
                    tj->probes_replied++;
                    recorded = 1;
                    break;
                }
            }
            if (!recorded) continue;

            tj->reached = 1;
            tcp_advance_hop(ctx, st, tj, pr.src_addr, 0 /* not filtered */);
            break;
        }
    }
    /* Other socket IDs are not ours */
}

static void tcp_tr_tick(ps_module_ctx_t *ctx, uint64_t now_usec)
{
    struct tcp_tr_state *st = (struct tcp_tr_state *)ctx->userdata;
    if (!st) return;

    for (int i = 0; i < TCP_TR_MAX_JOBS; i++) {
        struct tcp_trace_job *tj = &st->jobs[i];
        if (!tj->active) continue;
        if (tj->probes_replied > 0) continue;  /* already got a reply */

        int all_timed_out = 1;
        for (int k = 0; k < TCP_TR_PROBES; k++) {
            if (tj->probes[k].sent_usec == 0) continue;
            if ((now_usec - tj->probes[k].sent_usec) < TCP_TR_TIMEOUT_USEC) {
                all_timed_out = 0;
                break;
            }
        }

        if (all_timed_out) {
            ps_debug("tcp_traceroute: hop %d timed out for job '%s'",
                     tj->cur_hop, tj->job_id);
            tcp_advance_hop(ctx, st, tj, NULL, 1 /* filtered */);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

#ifndef PS_TCP_TRACEROUTE_TESTING

const ps_module_t ps_tcp_traceroute_module = {
    .name        = "tcp_traceroute",
    .description = "Dual-stack TCP SYN traceroute",
    .version     = "1.0",
    .flags       = PS_MOD_ACTIVE | PS_MOD_NEEDS_RAW,

    .init        = tcp_tr_init,
    .shutdown    = tcp_tr_shutdown,
    .on_packet   = NULL,
    .on_job      = tcp_tr_on_job,
    .on_response = tcp_tr_on_response,
    .tick        = tcp_tr_tick,
};

#endif /* PS_TCP_TRACEROUTE_TESTING */
