/*
 * dublin_traceroute.c — Multi-flow UDP traceroute for ECMP path enumeration
 *
 * Dublin Traceroute method: sends N UDP flows with different source ports per
 * TTL to enumerate distinct ECMP paths through load-balanced networks. Each
 * flow uses a unique source port so ECMP hash functions route packets
 * differently, revealing diamond topologies (divergence + convergence points).
 *
 * Probe identifier: source port varies per flow (33000 + flow_index * 1024).
 * Hop identification: destination port = 33434 + hop (1-based).
 * Payload: 2-byte flow_id (identifies which flow in the ICMP echo).
 *
 * State machine: probe all flows at TTL N before advancing to TTL N+1.
 *   cur_hop=1, cur_flow=0 → probe flow 0 at TTL 1
 *   → reply/timeout → record → advance cur_flow
 *   → all flows done at TTL 1 → cur_hop=2, cur_flow=0
 *   → repeat until all flows reached or max_hops
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>

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

#define DUBLIN_MAX_JOBS        4
#define DUBLIN_MAX_FLOWS       32
#define DUBLIN_DEFAULT_FLOWS   6
#define DUBLIN_TIMEOUT_USEC    (3 * 1000000ULL)
#define DUBLIN_BASE_SRC_PORT   33000
#define DUBLIN_PORT_STRIDE     1024
#define DUBLIN_BASE_DST_PORT   33434
#define DUBLIN_DEFAULT_HOPS    30

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

struct dublin_flow {
    uint16_t src_port;
    char     hop_ips[64][46];   /* recorded IP at each hop for diamond analysis */
    int      hop_count;
    int      reached;           /* destination responded (port unreachable) */
};

struct dublin_trace_job {
    int      active;
    int      job_index;
    char     job_id[64];
    char     destination[256];
    char     dest_addr_str[64];
    int      max_hops;
    int      af;                /* AF_INET only for v1 */

    struct sockaddr_storage dest_sa;
    socklen_t               dest_sa_len;

    int      flow_count;
    int      random_ports;
    struct dublin_flow flows[DUBLIN_MAX_FLOWS];

    int      cur_hop;           /* 1-based TTL currently being probed */
    int      cur_flow;          /* which flow is being probed at cur_hop */
    uint64_t probe_sent_usec;
    int      probe_replied;
    double   probe_rtt_ms;
    char     reply_addr[64];
    int      reply_is_dest;     /* ICMP port unreachable = destination reached */
};

struct dublin_state {
    int send_sock4;
    int recv_sock4;
    struct dublin_trace_job jobs[DUBLIN_MAX_JOBS];
};

/* ------------------------------------------------------------------ */
/* Port generation                                                      */
/* ------------------------------------------------------------------ */

/*
 * Generate source ports for all flows.
 * Spread (default): base + flow_index * stride → 33000, 34024, 35048...
 * Random: DJB hash of (destination + timestamp) seeded, then LCG into 33000-60000
 */
static void dublin_generate_ports(struct dublin_trace_job *job)
{
    if (!job->random_ports) {
        for (int i = 0; i < job->flow_count; i++) {
            job->flows[i].src_port = (uint16_t)(DUBLIN_BASE_SRC_PORT +
                                                i * DUBLIN_PORT_STRIDE);
        }
    } else {
        /* DJB hash seed from destination + timestamp */
        uint32_t seed = 5381;
        const char *p = job->destination;
        while (*p) {
            seed = ((seed << 5) + seed) ^ (uint8_t)*p++;
        }
        uint64_t now = ps_platform_now_usec();
        seed ^= (uint32_t)(now & 0xFFFFFFFF);

        /* LCG to generate distinct ports in 33000-60000 */
        uint32_t lcg = seed;
        for (int i = 0; i < job->flow_count; i++) {
            lcg = lcg * 1664525 + 1013904223;
            job->flows[i].src_port = (uint16_t)(33000 + (lcg >> 16) % 27000);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Probe building                                                        */
/* ------------------------------------------------------------------ */

/*
 * Build an IPv4 UDP probe with IP_HDRINCL:
 *   [20-byte IP header][8-byte UDP header][4-byte payload]
 *
 * src_port varies per flow. dst_port = 33434 + hop.
 * Payload encodes flow_id (2 bytes) + hop (2 bytes).
 * Returns total length (32), or 0 on error.
 */
static uint32_t build_dublin_udpv4_probe(uint8_t *buf, size_t bufsz,
                                          uint8_t ttl,
                                          const struct sockaddr_in *dst,
                                          int hop,
                                          uint16_t src_port,
                                          uint16_t flow_id)
{
    if (bufsz < 32) return 0;

    const uint16_t udp_total = 12;     /* 8 header + 4 payload */
    const uint16_t ip_total  = 20 + udp_total;
    const uint16_t dst_port  = (uint16_t)(DUBLIN_BASE_DST_PORT + hop);

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
    /* ip_sum left 0 — kernel fills with IP_HDRINCL set */

    /* UDP header (8 bytes) at offset 20 */
    uint8_t *udp = buf + 20;
    uint16_t sp = htons(src_port);
    uint16_t dp = htons(dst_port);
    uint16_t ul = htons(udp_total);
    memcpy(udp + 0, &sp, 2);
    memcpy(udp + 2, &dp, 2);
    memcpy(udp + 4, &ul, 2);
    udp[6] = 0;  /* checksum hi — disabled per RFC 768 */
    udp[7] = 0;  /* checksum lo */

    /* 4-byte payload: flow_id (2) + hop (2) */
    uint8_t *payload = buf + 28;
    uint16_t fi = htons(flow_id);
    uint16_t hn = htons((uint16_t)hop);
    memcpy(payload + 0, &fi, 2);
    memcpy(payload + 2, &hn, 2);

    return 32;
}

/* ------------------------------------------------------------------ */
/* Parse helpers                                                        */
/* ------------------------------------------------------------------ */

struct dublin_parse_result {
    int      valid;
    int      is_time_exceeded;   /* 1 = TTL expired, 0 = port unreachable */
    uint16_t src_port;           /* inner UDP src port (= flow's src_port) */
    uint16_t dst_port;           /* inner UDP dst port (= 33434 + hop) */
    char     src_addr[64];       /* source address of outer ICMP response */
};

/*
 * Parse IPv4 ICMP Time Exceeded or Port Unreachable.
 * Structure: [outer IP][ICMP hdr(8)][inner IP][inner UDP hdr(8)][inner payload]
 */
static struct dublin_parse_result parse_dublin_icmpv4(const uint8_t *pkt,
                                                       uint32_t len)
{
    struct dublin_parse_result res;
    memset(&res, 0, sizeof(res));

    if (len < 20) return res;

    int ip_hl = (pkt[0] & 0x0f) * 4;
    if ((uint32_t)ip_hl > len) return res;

    struct in_addr src_ip;
    memcpy(&src_ip, pkt + 12, 4);
    inet_ntop(AF_INET, &src_ip, res.src_addr, sizeof(res.src_addr));

    const uint8_t *icmp = pkt + ip_hl;
    uint32_t icmp_len = len - (uint32_t)ip_hl;

    if (icmp_len < 8) return res;

    uint8_t type = icmp[0];
    uint8_t code = icmp[1];

    int is_time_exceeded    = (type == ICMP_TYPE_TIME_EXCEEDED && code == 0);
    int is_port_unreachable = (type == ICMP_TYPE_DEST_UNREACHABLE &&
                               code == ICMP_CODE_PORT_UNREACHABLE);

    if (!is_time_exceeded && !is_port_unreachable) return res;

    if (icmp_len < 8 + 20 + 8) return res;

    const uint8_t *inner_ip = icmp + 8;
    int inner_hl = (inner_ip[0] & 0x0f) * 4;
    if ((uint32_t)(8 + inner_hl + 8) > icmp_len) return res;

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

/* ------------------------------------------------------------------ */
/* Reverse DNS                                                          */
/* ------------------------------------------------------------------ */

static void dublin_resolve_hostname(const char *addr_str,
                                     char *hostname_out, size_t hostname_len)
{
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    inet_pton(AF_INET, addr_str, &sin.sin_addr);

    int rc = getnameinfo((struct sockaddr *)&sin, sizeof(sin),
                         hostname_out, (socklen_t)hostname_len,
                         NULL, 0, NI_NAMEREQD);
    if (rc != 0) {
        strncpy(hostname_out, addr_str, hostname_len - 1);
        hostname_out[hostname_len - 1] = '\0';
    }
}

/* ------------------------------------------------------------------ */
/* Publishing                                                           */
/* ------------------------------------------------------------------ */

static void dublin_publish_hop(ps_module_ctx_t *ctx,
                                const struct dublin_trace_job *job,
                                int hop_number,
                                int flow_id,
                                const char *addr,
                                const char *hostname,
                                double rtt_ms,
                                int replied,
                                int is_filtered)
{
    char buf[1024];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "job_id",         job->job_id);
    ps_json_key_string(&j, "destination",    job->destination);
    ps_json_key_int   (&j, "hop_number",     hop_number);
    ps_json_key_string(&j, "address",        addr ? addr : "");
    ps_json_key_string(&j, "hostname",       hostname ? hostname : "");

    ps_json_array_begin(&j, "rtts");
    if (replied && !is_filtered) {
        ps_json_array_double(&j, rtt_ms);
    }
    ps_json_array_end(&j);

    ps_json_key_bool  (&j, "is_filtered",    is_filtered);
    ps_json_key_int   (&j, "flow_id",        flow_id);
    ps_json_key_int   (&j, "flow_count",     job->flow_count);
    ps_json_key_int   (&j, "flow_src_port",  job->flows[flow_id].src_port);
    ps_json_key_string(&j, "method",         "dublin");
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "traceroute.hop", buf, (uint32_t)j.len);
    }
}

/*
 * Analyze completed flows and publish dublin.complete with path diamond info.
 *
 * Divergence: hop H where IPs differ across flows (that were same at H-1).
 * Convergence: hop H where IPs are same across flows (that were different at H-1).
 */
static void dublin_publish_complete(ps_module_ctx_t *ctx,
                                     const struct dublin_trace_job *job)
{
    /* Find the deepest hop reached across all flows */
    int max_hop = 0;
    for (int f = 0; f < job->flow_count; f++) {
        if (job->flows[f].hop_count > max_hop)
            max_hop = job->flows[f].hop_count;
    }

    /* Count unique paths: two flows are different paths if any hop differs */
    int unique_paths = 0;
    int seen[DUBLIN_MAX_FLOWS] = {0};
    for (int f = 0; f < job->flow_count; f++) {
        if (seen[f]) continue;
        unique_paths++;
        for (int g = f + 1; g < job->flow_count; g++) {
            if (seen[g]) continue;
            /* Compare hop sequences */
            int same = 1;
            int compare_hops = job->flows[f].hop_count < job->flows[g].hop_count
                             ? job->flows[f].hop_count : job->flows[g].hop_count;
            for (int h = 0; h < compare_hops; h++) {
                if (strcmp(job->flows[f].hop_ips[h], job->flows[g].hop_ips[h]) != 0) {
                    same = 0;
                    break;
                }
            }
            if (same) seen[g] = 1;
        }
    }

    /* Find divergence and convergence hops */
    int divergence_hops[64];
    int convergence_hops[64];
    int ndiv = 0, nconv = 0;

    for (int h = 0; h < max_hop && h < 64; h++) {
        /* Check if all flows agree at this hop */
        int all_same = 1;
        for (int f = 1; f < job->flow_count; f++) {
            if (h >= job->flows[f].hop_count || h >= job->flows[0].hop_count) {
                /* Missing data — treat as different */
                all_same = 0;
                break;
            }
            if (strcmp(job->flows[0].hop_ips[h], job->flows[f].hop_ips[h]) != 0) {
                all_same = 0;
                break;
            }
        }

        int prev_all_same = 1;
        if (h > 0) {
            for (int f = 1; f < job->flow_count; f++) {
                if ((h-1) >= job->flows[f].hop_count || (h-1) >= job->flows[0].hop_count) {
                    prev_all_same = 0;
                    break;
                }
                if (strcmp(job->flows[0].hop_ips[h-1], job->flows[f].hop_ips[h-1]) != 0) {
                    prev_all_same = 0;
                    break;
                }
            }
        }

        /* Divergence: was same (or first hop), now different */
        if (!all_same && (h == 0 || prev_all_same)) {
            if (ndiv < 64) divergence_hops[ndiv++] = h + 1;  /* 1-based */
        }
        /* Convergence: was different, now same */
        if (all_same && h > 0 && !prev_all_same) {
            if (nconv < 64) convergence_hops[nconv++] = h + 1;  /* 1-based */
        }
    }

    int any_reached = 0;
    for (int f = 0; f < job->flow_count; f++) {
        if (job->flows[f].reached) { any_reached = 1; break; }
    }

    /* Build JSON */
    char buf[4096];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "job_id",              job->job_id);
    ps_json_key_string(&j, "destination",         job->destination);
    ps_json_key_int   (&j, "flow_count",          job->flow_count);
    ps_json_key_int   (&j, "unique_paths",        unique_paths);
    ps_json_key_bool  (&j, "reached_destination", any_reached);

    /* paths: array of per-flow summaries */
    ps_json_array_begin(&j, "paths");
    for (int f = 0; f < job->flow_count; f++) {
        /* Inline object using raw append — ps_json doesn't have array_object */
        char path_buf[1024];
        struct ps_json pj;
        ps_json_init(&pj, path_buf, sizeof(path_buf));
        ps_json_object_begin(&pj);
        ps_json_key_int   (&pj, "flow_id",   f);
        ps_json_key_int   (&pj, "src_port",  job->flows[f].src_port);
        ps_json_key_int   (&pj, "hop_count", job->flows[f].hop_count);
        ps_json_key_bool  (&pj, "reached",   job->flows[f].reached);
        ps_json_object_end(&pj);
        int plen = ps_json_finish(&pj);
        if (plen > 0) {
            if (j.needs_comma && j.len < j.cap - 1) j.buf[j.len++] = ',';
            size_t rem = j.cap - j.len;
            size_t cp  = (size_t)plen < rem ? (size_t)plen : rem - 1;
            if (cp > 0) { memcpy(j.buf + j.len, path_buf, cp); j.len += cp; }
            if (j.len < j.cap) j.buf[j.len] = '\0';
            j.needs_comma = 1;
        }
    }
    ps_json_array_end(&j);

    /* divergence_hops array */
    ps_json_array_begin(&j, "divergence_hops");
    for (int i = 0; i < ndiv; i++) {
        /* Inline int into array */
        if (j.needs_comma && j.len < j.cap - 1) j.buf[j.len++] = ',';
        j.len += (size_t)snprintf(j.buf + j.len, j.cap - j.len, "%d", divergence_hops[i]);
        if (j.len < j.cap) j.buf[j.len] = '\0';
        j.needs_comma = 1;
    }
    ps_json_array_end(&j);

    /* convergence_hops array */
    ps_json_array_begin(&j, "convergence_hops");
    for (int i = 0; i < nconv; i++) {
        if (j.needs_comma && j.len < j.cap - 1) j.buf[j.len++] = ',';
        j.len += (size_t)snprintf(j.buf + j.len, j.cap - j.len, "%d", convergence_hops[i]);
        if (j.len < j.cap) j.buf[j.len] = '\0';
        j.needs_comma = 1;
    }
    ps_json_array_end(&j);

    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "dublin.complete", buf, (uint32_t)j.len);
    }
}

/* ------------------------------------------------------------------ */
/* Job management                                                       */
/* ------------------------------------------------------------------ */

static struct dublin_trace_job *find_free_dublin_job(struct dublin_state *st)
{
    for (int i = 0; i < DUBLIN_MAX_JOBS; i++) {
        if (!st->jobs[i].active)
            return &st->jobs[i];
    }
    return NULL;
}

/*
 * Send a single probe for (cur_hop, cur_flow).
 */
static void dublin_send_probe(ps_module_ctx_t *ctx, struct dublin_state *st,
                               struct dublin_trace_job *job)
{
    uint8_t buf[64];
    int flow = job->cur_flow;
    int hop  = job->cur_hop;

    uint32_t pkt_len = build_dublin_udpv4_probe(
        buf, sizeof(buf),
        (uint8_t)hop,
        (const struct sockaddr_in *)&job->dest_sa,
        hop,
        job->flows[flow].src_port,
        (uint16_t)flow);

    if (pkt_len == 0) {
        ps_warn("dublin_traceroute: failed to build probe for job '%s' flow %d hop %d",
                job->job_id, flow, hop);
        /* Skip this probe — treat as timeout */
        job->probe_sent_usec = ps_platform_now_usec();
        job->probe_replied   = 0;
        return;
    }

    ctx->send_raw(ctx, st->send_sock4, (uint8_t)hop,
                  (const struct sockaddr *)&job->dest_sa, buf, pkt_len);

    job->probe_sent_usec = ps_platform_now_usec();
    job->probe_replied   = 0;
    job->probe_rtt_ms    = 0.0;
    job->reply_addr[0]   = '\0';
    job->reply_is_dest   = 0;

    ps_debug("dublin_traceroute: sent probe job='%s' flow=%d hop=%d src_port=%u dst_port=%u",
             job->job_id, flow, hop,
             job->flows[flow].src_port,
             DUBLIN_BASE_DST_PORT + hop);
}

/*
 * Finish the current (cur_hop, cur_flow) result, record it, publish the hop,
 * then advance to the next flow (or next hop if all flows done).
 */
static void dublin_advance(ps_module_ctx_t *ctx, struct dublin_state *st,
                             struct dublin_trace_job *job,
                             const char *hop_addr, int replied, int is_filtered)
{
    int flow = job->cur_flow;
    int hop  = job->cur_hop;

    /* Record hop IP for this flow */
    if (hop - 1 < 64) {
        if (hop_addr && hop_addr[0] && !is_filtered) {
            strncpy(job->flows[flow].hop_ips[hop - 1], hop_addr, 45);
            job->flows[flow].hop_ips[hop - 1][45] = '\0';
        } else {
            strncpy(job->flows[flow].hop_ips[hop - 1], "timeout", 45);
        }
        if (hop > job->flows[flow].hop_count)
            job->flows[flow].hop_count = hop;
    }

    /* Mark reached if destination responded */
    if (job->reply_is_dest || (!is_filtered && !replied)) {
        /* reply_is_dest set in on_response */
    }

    /* Resolve hostname (skip for timeouts) */
    char hostname[NI_MAXHOST] = {0};
    if (!is_filtered && hop_addr && hop_addr[0]) {
        dublin_resolve_hostname(hop_addr, hostname, sizeof(hostname));
    }

    /* Publish hop */
    dublin_publish_hop(ctx, job, hop, flow,
                       hop_addr, hostname,
                       job->probe_rtt_ms, replied, is_filtered);

    /* Check if all flows done at this hop, or job complete */
    int all_flows_reached = 1;
    for (int f = 0; f < job->flow_count; f++) {
        if (!job->flows[f].reached) { all_flows_reached = 0; break; }
    }

    /* Advance to next flow */
    job->cur_flow++;

    if (job->cur_flow >= job->flow_count) {
        /* All flows probed at this hop — advance hop */
        job->cur_hop++;
        job->cur_flow = 0;

        if (all_flows_reached || job->cur_hop > job->max_hops) {
            /* Done */
            ps_info("dublin_traceroute: job '%s' complete at hop %d (%d unique paths)",
                    job->job_id, hop, job->flow_count);
            dublin_publish_complete(ctx, job);
            memset(job, 0, sizeof(*job));
            return;
        }
    } else {
        /* More flows at this hop — check if already done */
        if (all_flows_reached) {
            /* All flows reached destination — wrap up */
            ps_info("dublin_traceroute: job '%s' all flows reached destination", job->job_id);
            dublin_publish_complete(ctx, job);
            memset(job, 0, sizeof(*job));
            return;
        }
    }

    /* Send next probe */
    dublin_send_probe(ctx, st, job);
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int dublin_init(ps_module_ctx_t *ctx)
{
    struct dublin_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("dublin_traceroute: out of memory");
        return -1;
    }

    st->send_sock4 = -1;
    st->recv_sock4 = -1;

    st->send_sock4 = ctx->create_raw_socket(ctx, AF_INET, IPPROTO_UDP);
    if (st->send_sock4 < 0) {
        ps_warn("dublin_traceroute: could not create IPv4 UDP send socket (handle=%d)",
                st->send_sock4);
    } else {
        ps_info("dublin_traceroute: IPv4 UDP send socket handle=%d", st->send_sock4);
    }

    st->recv_sock4 = ctx->create_raw_socket(ctx, AF_INET, IPPROTO_ICMP);
    if (st->recv_sock4 < 0) {
        ps_warn("dublin_traceroute: could not create IPv4 ICMP recv socket (handle=%d)",
                st->recv_sock4);
    } else {
        ps_info("dublin_traceroute: IPv4 ICMP recv socket handle=%d", st->recv_sock4);
    }

    ctx->userdata = st;
    ps_info("dublin_traceroute: initialized");
    return 0;
}

static void dublin_shutdown(ps_module_ctx_t *ctx)
{
    free(ctx->userdata);
    ctx->userdata = NULL;
    ps_info("dublin_traceroute: shutdown");
}

static int dublin_on_job(ps_module_ctx_t *ctx, const struct ps_job *job)
{
    struct dublin_state *st = (struct dublin_state *)ctx->userdata;
    if (!st) return -1;

    /* Only handle dublin method */
    if (strcmp(job->method, "dublin") != 0)
        return 0;  /* not for us */

    if (st->send_sock4 < 0 || st->recv_sock4 < 0) {
        ps_warn("dublin_traceroute: sockets not ready, dropping job '%s'", job->job_id);
        return -1;
    }

    struct dublin_trace_job *tj = find_free_dublin_job(st);
    if (!tj) {
        ps_warn("dublin_traceroute: all %d job slots busy, dropping job '%s'",
                DUBLIN_MAX_JOBS, job->job_id);
        return -1;
    }

    /* Resolve destination — IPv4 only for v1 */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int rc = getaddrinfo(job->destination, NULL, &hints, &res);
    if (rc != 0) {
        ps_warn("dublin_traceroute: getaddrinfo('%s') failed: %s",
                job->destination, gai_strerror(rc));
        return -1;
    }

    memset(tj, 0, sizeof(*tj));
    tj->af = AF_INET;
    memcpy(&tj->dest_sa, res->ai_addr, res->ai_addrlen);
    tj->dest_sa_len = res->ai_addrlen;

    {
        struct sockaddr_in *sin = (struct sockaddr_in *)&tj->dest_sa;
        inet_ntop(AF_INET, &sin->sin_addr,
                  tj->dest_addr_str, sizeof(tj->dest_addr_str));
    }
    freeaddrinfo(res);

    strncpy(tj->job_id,      job->job_id,      sizeof(tj->job_id) - 1);
    strncpy(tj->destination, job->destination, sizeof(tj->destination) - 1);
    tj->max_hops   = job->max_hops > 0 ? job->max_hops : DUBLIN_DEFAULT_HOPS;
    tj->job_index  = (int)(tj - st->jobs);
    tj->cur_hop    = 1;
    tj->cur_flow   = 0;
    tj->flow_count = DUBLIN_DEFAULT_FLOWS;
    tj->random_ports = 0;
    tj->active     = 1;

    /*
     * Parse dublin-specific fields from the raw payload.
     * The job struct doesn't carry arbitrary extra fields, so the caller
     * (on_ipc_frame in main.c) would need to pass them via ps_job extensions.
     * For now we use defaults; main.c will be updated to parse and set these
     * via the job struct in the future.  The IPC handler parses the raw JSON
     * directly, so we use DUBLIN_DEFAULT_FLOWS for the initial implementation.
     */

    dublin_generate_ports(tj);

    ps_info("dublin_traceroute: starting job '%s' -> '%s' (%s) max_hops=%d flows=%d random=%d",
            tj->job_id, tj->destination, tj->dest_addr_str,
            tj->max_hops, tj->flow_count, tj->random_ports);

    dublin_send_probe(ctx, st, tj);
    return 0;
}

static void dublin_on_response(ps_module_ctx_t *ctx, const uint8_t *pkt,
                                uint32_t len, uint64_t ts_usec, int socket_id)
{
    struct dublin_state *st = (struct dublin_state *)ctx->userdata;
    if (!st) return;

    (void)ts_usec;

    /* Only handle our ICMP recv socket */
    if (socket_id != st->recv_sock4) return;

    struct dublin_parse_result pr = parse_dublin_icmpv4(pkt, len);
    if (!pr.valid) return;

    /* Decode hop number from destination port */
    if (pr.dst_port < DUBLIN_BASE_DST_PORT) return;
    uint16_t hop_num = pr.dst_port - DUBLIN_BASE_DST_PORT;
    if (hop_num == 0 || hop_num > (uint16_t)DUBLIN_DEFAULT_HOPS) return;

    /* Find matching active job by src_port (identifies the flow) */
    for (int i = 0; i < DUBLIN_MAX_JOBS; i++) {
        struct dublin_trace_job *tj = &st->jobs[i];
        if (!tj->active) continue;
        if (tj->af != AF_INET) continue;
        if (hop_num != (uint16_t)tj->cur_hop) continue;
        if (tj->probe_replied) continue;  /* already handled */

        /* Match src_port against current flow */
        if (pr.src_port != tj->flows[tj->cur_flow].src_port) continue;

        uint64_t now = ps_platform_now_usec();
        tj->probe_replied = 1;
        tj->probe_rtt_ms  = (double)(now - tj->probe_sent_usec) / 1000.0;
        strncpy(tj->reply_addr, pr.src_addr, sizeof(tj->reply_addr) - 1);

        /* Port Unreachable = destination reached for this flow */
        if (!pr.is_time_exceeded) {
            tj->reply_is_dest = 1;
            tj->flows[tj->cur_flow].reached = 1;
        }

        dublin_advance(ctx, st, tj, pr.src_addr, 1, 0);
        break;
    }
}

static void dublin_tick(ps_module_ctx_t *ctx, uint64_t now_usec)
{
    struct dublin_state *st = (struct dublin_state *)ctx->userdata;
    if (!st) return;

    for (int i = 0; i < DUBLIN_MAX_JOBS; i++) {
        struct dublin_trace_job *tj = &st->jobs[i];
        if (!tj->active) continue;
        if (tj->probe_replied) continue;
        if (tj->probe_sent_usec == 0) continue;

        if ((now_usec - tj->probe_sent_usec) >= DUBLIN_TIMEOUT_USEC) {
            ps_debug("dublin_traceroute: flow %d hop %d timed out for job '%s'",
                     tj->cur_flow, tj->cur_hop, tj->job_id);
            dublin_advance(ctx, st, tj, NULL, 0, 1 /* filtered */);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

const ps_module_t dublin_traceroute_module = {
    .name        = "dublin_traceroute",
    .description = "Multi-flow UDP traceroute for ECMP path enumeration (Dublin method)",
    .version     = "1.0",
    .flags       = PS_MOD_ACTIVE | PS_MOD_NEEDS_RAW,

    .init        = dublin_init,
    .shutdown    = dublin_shutdown,
    .on_packet   = NULL,
    .on_job      = dublin_on_job,
    .on_response = dublin_on_response,
    .tick        = dublin_tick,
};
