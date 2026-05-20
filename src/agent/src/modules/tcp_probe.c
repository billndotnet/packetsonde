/*
 * tcp_probe.c — TCP SYN port scanner with optional banner grab for PacketSonde Agent
 *
 * Triggered by the "probe.request" IPC channel. Dispatches one job per port.
 * For each port:
 *   1. Sends a TCP SYN via raw socket (TTL=64 — reach destination, not walk hops)
 *   2. Listens for SYN-ACK (open) or RST (closed) on the raw TCP socket
 *   3. If SYN-ACK received on a well-known port, performs a non-blocking connect()
 *      + recv() banner grab with a 200 ms timeout
 *   4. No response after 3 s → filtered
 *
 * Probe identification:
 *   Source port = TCP_PROBE_BASE_SRC_PORT + job_slot_index
 *   Sequence number = TCP_PROBE_MAGIC (fixed sentinel for identification)
 *
 * Sockets:
 *   One IPPROTO_TCP  raw socket (IPv4) — sending SYN probes (IP_HDRINCL)
 *   One IPPROTO_ICMP raw socket (IPv4) — receiving ICMP port-unreachable / host-unreach
 *   Regular TCP sockets for banner grab (no special privileges needed)
 *
 * IPv6 support is deferred to a future revision; the module accepts AF_INET only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include "packetsonde/module_api.h"
#include "json.h"
#include "log.h"
#include "platform/platform.h"

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define TCP_PROBE_MAX_JOBS         16
#define TCP_PROBE_TIMEOUT_USEC     (3 * 1000000ULL)   /* 3 seconds */
#define TCP_PROBE_BANNER_TIMEOUT_MS 200                /* 200 ms */
#define TCP_PROBE_BASE_SRC_PORT    0x5070              /* "Pp" — probe */
#define TCP_PROBE_MAGIC_SEQ        0x50530001UL        /* "PS" probe sentinel */
#define TCP_PROBE_TTL              64

/* ICMP type constants (not always in system headers) */
#define ICMP_TYPE_TIME_EXCEEDED    11
#define ICMP_TYPE_DEST_UNREACH     3
#define ICMP_TYPE_ECHO_REPLY       0

/* TCP flag bits */
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_ACK  0x10

/* Well-known ports that warrant a banner grab attempt */
static const int BANNER_PORTS[] = { 21, 22, 25, 80, 110, 143, 443, 465, 587,
                                     993, 995, 3306, 5432, 6379, 8080, 8443, 0 };

/* ------------------------------------------------------------------ */
/* Structures                                                           */
/* ------------------------------------------------------------------ */

typedef enum {
    PROBE_STATE_IDLE = 0,
    PROBE_STATE_WAITING,      /* SYN sent, waiting for response */
    PROBE_STATE_DONE          /* result ready, pending cleanup */
} probe_state_t;

struct probe_job {
    probe_state_t  state;
    int            slot_index;    /* 0..TCP_PROBE_MAX_JOBS-1 */

    char           job_id[64];
    char           destination[256];    /* original hostname/IP */
    char           dest_addr_str[64];   /* resolved numeric IPv4 */
    int            tcp_port;

    struct sockaddr_in dest_sa;

    uint64_t       sent_usec;
    int            result_published;    /* guard against double-publish */
};

struct tcp_probe_state {
    int tcp_sock4;    /* raw TCP socket for sending SYN probes */
    int icmp_sock4;   /* raw ICMP socket for receiving ICMP errors */
    struct probe_job jobs[TCP_PROBE_MAX_JOBS];
};

/* ------------------------------------------------------------------ */
/* Checksum helpers                                                     */
/* ------------------------------------------------------------------ */

static uint16_t probe_checksum(const uint8_t *data, size_t len)
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
 * TCP checksum over IPv4 pseudo-header + TCP segment.
 * src_addr may be 0 (kernel will fill it; Linux recalculates).
 */
static uint16_t tcp_probe_checksum_v4(uint32_t src_addr,
                                       uint32_t dst_addr,
                                       const uint8_t *tcp_seg,
                                       uint16_t tcp_len)
{
    uint8_t pseudo[12 + 20];
    if (tcp_len > 20) tcp_len = 20;

    uint32_t src_be = src_addr;   /* already network byte order */
    uint32_t dst_be = dst_addr;
    memcpy(pseudo,      &src_be, 4);
    memcpy(pseudo + 4,  &dst_be, 4);
    pseudo[8] = 0;
    pseudo[9] = IPPROTO_TCP;
    uint16_t tlen_be = htons(tcp_len);
    memcpy(pseudo + 10, &tlen_be, 2);
    memcpy(pseudo + 12, tcp_seg, tcp_len);

    return probe_checksum(pseudo, 12 + tcp_len);
}

/* ------------------------------------------------------------------ */
/* SYN packet building                                                  */
/* ------------------------------------------------------------------ */

/*
 * Build a complete IP + TCP SYN packet.
 * TTL is fixed at TCP_PROBE_TTL (64) — we want to reach the destination.
 * The source port encodes the job slot index for reply matching.
 * The sequence number is TCP_PROBE_MAGIC_SEQ for identification.
 *
 * buf must be at least 40 bytes. Returns 40 on success, 0 on error.
 */
static uint32_t build_syn_probe_v4(uint8_t *buf, size_t bufsz,
                                    const struct sockaddr_in *dst,
                                    uint16_t src_port,
                                    uint16_t dst_port)
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
    iph->ip_ttl = TCP_PROBE_TTL;
    iph->ip_p   = IPPROTO_TCP;
    iph->ip_dst = dst->sin_addr;
    /* ip_src left 0 — kernel fills it */

    /* ---- TCP header (20 bytes) ---- */
    uint8_t *tcp = buf + 20;

    uint16_t sp = htons(src_port);
    uint16_t dp = htons(dst_port);
    uint32_t sq = htonl((uint32_t)TCP_PROBE_MAGIC_SEQ);

    memcpy(tcp + 0, &sp, 2);    /* source port */
    memcpy(tcp + 2, &dp, 2);    /* destination port */
    memcpy(tcp + 4, &sq, 4);    /* sequence number */
    tcp[12] = 0x50;              /* data offset = 5 words (20 bytes) */
    tcp[13] = TCP_FLAG_SYN;      /* flags: SYN only */
    uint16_t win = htons(65535);
    memcpy(tcp + 14, &win, 2);   /* window size */

    /* TCP checksum (src IP = 0; kernel recalculates on Linux) */
    uint16_t cksum = tcp_probe_checksum_v4(0, dst->sin_addr.s_addr, tcp, 20);
    memcpy(tcp + 16, &cksum, 2);

    return 40;
}

/* ------------------------------------------------------------------ */
/* Banner grab                                                          */
/* ------------------------------------------------------------------ */

static int is_banner_port(int port)
{
    for (int i = 0; BANNER_PORTS[i] != 0; i++) {
        if (BANNER_PORTS[i] == port) return 1;
    }
    return 0;
}

/*
 * Attempt a non-blocking connect to addr:port and read up to banner_len-1
 * bytes. Times out after TCP_PROBE_BANNER_TIMEOUT_MS milliseconds.
 * Returns 1 if a banner was read, 0 if nothing (timeout or refused).
 */
static int grab_banner(const struct sockaddr_in *addr, int port,
                       char *banner_out, size_t banner_len)
{
    banner_out[0] = '\0';

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;

    /* Non-blocking mode */
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) { close(s); return 0; }
    fcntl(s, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in sa;
    memcpy(&sa, addr, sizeof(sa));
    sa.sin_port = htons((uint16_t)port);

    (void)connect(s, (struct sockaddr *)&sa, sizeof(sa));
    /* Non-blocking connect — returns EINPROGRESS, which is expected */

    /* Wait for writable (connect complete) or timeout */
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = TCP_PROBE_BANNER_TIMEOUT_MS * 1000L;

    fd_set wfds, rfds;
    FD_ZERO(&wfds);
    FD_ZERO(&rfds);
    FD_SET(s, &wfds);
    FD_SET(s, &rfds);

    int rc = select(s + 1, &rfds, &wfds, NULL, &tv);
    if (rc <= 0) {
        close(s);
        return 0;
    }

    /* Check for connect errors */
    int err = 0;
    socklen_t errlen = sizeof(err);
    getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errlen);
    if (err != 0) {
        close(s);
        return 0;
    }

    /* Some protocols send a banner on connect (SSH, SMTP, FTP…).
     * Wait briefly for readable data. */
    if (!FD_ISSET(s, &rfds)) {
        /* Not readable yet — wait again with remaining timeout */
        FD_ZERO(&rfds);
        FD_SET(s, &rfds);
        tv.tv_sec  = 0;
        tv.tv_usec = TCP_PROBE_BANNER_TIMEOUT_MS * 500L;   /* half budget */
        rc = select(s + 1, &rfds, NULL, NULL, &tv);
        if (rc <= 0) {
            close(s);
            return 0;
        }
    }

    ssize_t n = recv(s, banner_out, (int)(banner_len - 1), 0);
    close(s);

    if (n <= 0) return 0;

    banner_out[n] = '\0';

    /* Strip trailing whitespace / control characters */
    for (ssize_t k = n - 1; k >= 0; k--) {
        if ((unsigned char)banner_out[k] < 0x20)
            banner_out[k] = '\0';
        else
            break;
    }

    return 1;
}

/* ------------------------------------------------------------------ */
/* Publishing                                                           */
/* ------------------------------------------------------------------ */

static void publish_result(ps_module_ctx_t *ctx,
                            const struct probe_job *job,
                            const char *state,
                            const char *banner)
{
    char buf[512];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "job_id",   job->job_id);
    ps_json_key_string(&j, "address",  job->dest_addr_str[0]
                                        ? job->dest_addr_str
                                        : job->destination);
    ps_json_key_int   (&j, "port",     job->tcp_port);
    ps_json_key_string(&j, "proto",    "tcp");
    ps_json_key_string(&j, "state",    state);
    ps_json_key_string(&j, "banner",   banner ? banner : "");
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "probe.result", buf, (uint32_t)j.len);
    }
}

/* ------------------------------------------------------------------ */
/* Response parsing                                                     */
/* ------------------------------------------------------------------ */

/*
 * Determine if a raw packet received on the TCP raw socket is a SYN-ACK or
 * RST directed at one of our probe source ports.
 *
 * Returns the source port that was targeted (our probe src port) and sets
 * *is_rst to 1 if it's a RST. Returns 0 if the packet is not relevant.
 */
static uint16_t parse_tcp_response_v4(const uint8_t *pkt, uint32_t len,
                                        int *is_rst,
                                        char *src_addr_out,
                                        size_t src_addr_len)
{
    *is_rst = 0;

    if (len < 40) return 0;

    int ip_hl = (pkt[0] & 0x0f) * 4;
    if ((uint32_t)ip_hl + 20 > len) return 0;
    if (pkt[9] != IPPROTO_TCP) return 0;

    /* Source address of the responder */
    struct in_addr src_ip;
    memcpy(&src_ip, pkt + 12, 4);
    inet_ntop(AF_INET, &src_ip, src_addr_out, (socklen_t)src_addr_len);

    const uint8_t *tcp = pkt + ip_hl;
    uint32_t tcp_len = len - (uint32_t)ip_hl;
    if (tcp_len < 14) return 0;

    /* dst_port of the response = our probe src_port */
    uint16_t dst_port;
    memcpy(&dst_port, tcp + 2, 2);
    dst_port = ntohs(dst_port);

    uint8_t flags = tcp[13];
    int is_syn_ack = ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK));
    int is_rst_flag = (flags & TCP_FLAG_RST) != 0;

    if (!is_syn_ack && !is_rst_flag) return 0;

    *is_rst = is_rst_flag;
    return dst_port;
}

/*
 * Check for ICMP Destination Unreachable carrying our probe.
 * Returns the probe src_port if matched, 0 otherwise.
 */
static uint16_t parse_icmp_unreach_v4(const uint8_t *pkt, uint32_t len)
{
    if (len < 20) return 0;

    int ip_hl = (pkt[0] & 0x0f) * 4;
    if ((uint32_t)ip_hl > len) return 0;

    const uint8_t *icmp = pkt + ip_hl;
    uint32_t icmp_len = len - (uint32_t)ip_hl;

    if (icmp_len < 8 + 20 + 8) return 0;

    uint8_t type = icmp[0];
    if (type != ICMP_TYPE_DEST_UNREACH) return 0;

    /* Inner IP + TCP */
    const uint8_t *inner_ip  = icmp + 8;
    int inner_hl = (inner_ip[0] & 0x0f) * 4;
    if ((uint32_t)(8 + inner_hl + 8) > icmp_len) return 0;
    if (inner_ip[9] != IPPROTO_TCP) return 0;

    const uint8_t *inner_tcp = inner_ip + inner_hl;

    /* src port of our probe (inner TCP src) */
    uint16_t src_port;
    memcpy(&src_port, inner_tcp + 0, 2);
    src_port = ntohs(src_port);

    return src_port;
}

/* ------------------------------------------------------------------ */
/* Job management                                                       */
/* ------------------------------------------------------------------ */

static struct probe_job *find_free_job(struct tcp_probe_state *st)
{
    for (int i = 0; i < TCP_PROBE_MAX_JOBS; i++) {
        if (st->jobs[i].state == PROBE_STATE_IDLE)
            return &st->jobs[i];
    }
    return NULL;
}

static struct probe_job *find_job_by_src_port(struct tcp_probe_state *st,
                                               uint16_t src_port)
{
    for (int i = 0; i < TCP_PROBE_MAX_JOBS; i++) {
        if (st->jobs[i].state != PROBE_STATE_WAITING) continue;
        uint16_t probe_src = (uint16_t)(TCP_PROBE_BASE_SRC_PORT + st->jobs[i].slot_index);
        if (probe_src == src_port) return &st->jobs[i];
    }
    return NULL;
}

static void complete_job(ps_module_ctx_t *ctx, struct probe_job *job,
                          const char *state)
{
    if (job->result_published) return;
    job->result_published = 1;

    char banner[256];
    banner[0] = '\0';

    if (strcmp(state, "open") == 0 && is_banner_port(job->tcp_port)) {
        grab_banner(&job->dest_sa, job->tcp_port, banner, sizeof(banner));
    }

    publish_result(ctx, job, state, banner);
    ps_info("tcp_probe: job '%s' %s:%d → %s%s%s",
            job->job_id, job->dest_addr_str, job->tcp_port, state,
            banner[0] ? " banner=" : "",
            banner[0] ? banner : "");

    memset(job, 0, sizeof(*job));
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int probe_init(ps_module_ctx_t *ctx)
{
    struct tcp_probe_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("tcp_probe: out of memory");
        return -1;
    }

    st->tcp_sock4  = -1;
    st->icmp_sock4 = -1;

    st->tcp_sock4 = ctx->create_raw_socket(ctx, AF_INET, IPPROTO_TCP);
    if (st->tcp_sock4 < 0) {
        ps_warn("tcp_probe: could not create IPv4 TCP raw socket (handle=%d)",
                st->tcp_sock4);
    } else {
        ps_info("tcp_probe: IPv4 TCP raw socket handle=%d", st->tcp_sock4);
    }

    st->icmp_sock4 = ctx->create_raw_socket(ctx, AF_INET, IPPROTO_ICMP);
    if (st->icmp_sock4 < 0) {
        ps_warn("tcp_probe: could not create IPv4 ICMP raw socket (handle=%d)",
                st->icmp_sock4);
    } else {
        ps_info("tcp_probe: IPv4 ICMP raw socket handle=%d", st->icmp_sock4);
    }

    for (int i = 0; i < TCP_PROBE_MAX_JOBS; i++) {
        st->jobs[i].slot_index = i;
    }

    ctx->userdata = st;
    ps_info("tcp_probe: initialized");
    return 0;
}

static void probe_shutdown(ps_module_ctx_t *ctx)
{
    free(ctx->userdata);
    ctx->userdata = NULL;
    ps_info("tcp_probe: shutdown");
}

static int probe_on_job(ps_module_ctx_t *ctx, const struct ps_job *job)
{
    struct tcp_probe_state *st = (struct tcp_probe_state *)ctx->userdata;
    if (!st) return -1;

    /* Only handle "probe" method or unset (but we are only dispatched
     * by the probe.request IPC channel, so method check is advisory) */
    if (job->method[0] != '\0' &&
        strcmp(job->method, "probe") != 0 &&
        strcmp(job->method, "tcp")   != 0) {
        return 0;   /* not for us */
    }

    if (st->tcp_sock4 < 0) {
        ps_warn("tcp_probe: no TCP raw socket — cannot probe");
        return -1;
    }

    struct probe_job *pj = find_free_job(st);
    if (!pj) {
        ps_warn("tcp_probe: all %d job slots busy, dropping job '%s'",
                TCP_PROBE_MAX_JOBS, job->job_id);
        return -1;
    }

    /* Resolve destination (IPv4 only for now) */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(job->destination, NULL, &hints, &res);
    if (rc != 0) {
        ps_warn("tcp_probe: getaddrinfo('%s') failed: %s",
                job->destination, gai_strerror(rc));
        return -1;
    }

    memset(pj, 0, sizeof(*pj));
    pj->slot_index = pj - st->jobs;   /* restore slot index */
    memcpy(&pj->dest_sa, res->ai_addr, sizeof(struct sockaddr_in));
    inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr,
              pj->dest_addr_str, sizeof(pj->dest_addr_str));
    freeaddrinfo(res);

    strncpy(pj->job_id,     job->job_id,     sizeof(pj->job_id) - 1);
    strncpy(pj->destination, job->destination, sizeof(pj->destination) - 1);
    pj->tcp_port = job->tcp_port > 0 ? job->tcp_port : 80;

    /* Build and send the SYN probe */
    uint16_t src_port = (uint16_t)(TCP_PROBE_BASE_SRC_PORT + pj->slot_index);
    uint8_t  pkt[40];
    uint32_t pkt_len = build_syn_probe_v4(pkt, sizeof(pkt),
                                           &pj->dest_sa,
                                           src_port,
                                           (uint16_t)pj->tcp_port);
    if (pkt_len == 0) {
        ps_warn("tcp_probe: failed to build SYN packet for job '%s'", pj->job_id);
        return -1;
    }

    rc = ctx->send_raw(ctx, st->tcp_sock4, TCP_PROBE_TTL,
                       (const struct sockaddr *)&pj->dest_sa, pkt, pkt_len);
    if (rc < 0) {
        ps_warn("tcp_probe: send_raw failed for job '%s' port %d",
                pj->job_id, pj->tcp_port);
        return -1;
    }

    pj->sent_usec = ps_platform_now_usec();
    pj->state     = PROBE_STATE_WAITING;

    ps_info("tcp_probe: sent SYN for job '%s' → %s:%d (src_port=%u)",
            pj->job_id, pj->dest_addr_str, pj->tcp_port, src_port);
    return 0;
}

static void probe_on_response(ps_module_ctx_t *ctx,
                               const uint8_t *pkt,
                               uint32_t len,
                               uint64_t ts_usec,
                               int socket_id)
{
    struct tcp_probe_state *st = (struct tcp_probe_state *)ctx->userdata;
    if (!st) return;

    (void)ts_usec;

    if (socket_id == st->tcp_sock4) {
        /* TCP response — could be SYN-ACK or RST */
        int is_rst = 0;
        char src_addr[64];
        uint16_t matched_src_port = parse_tcp_response_v4(pkt, len, &is_rst,
                                                            src_addr,
                                                            sizeof(src_addr));
        if (!matched_src_port) return;

        /* Check if it's in our probe src port range */
        if (matched_src_port < TCP_PROBE_BASE_SRC_PORT ||
            matched_src_port >= TCP_PROBE_BASE_SRC_PORT + TCP_PROBE_MAX_JOBS)
            return;

        struct probe_job *pj = find_job_by_src_port(st, matched_src_port);
        if (!pj) return;

        /* Send RST to tear down half-open connection on the remote */
        /* (best-effort; we don't track the ack number here) */

        complete_job(ctx, pj, is_rst ? "closed" : "open");
        return;
    }

    if (socket_id == st->icmp_sock4) {
        /* ICMP Destination Unreachable — port filtered at network layer */
        uint16_t probe_src = parse_icmp_unreach_v4(pkt, len);
        if (!probe_src) return;

        if (probe_src < TCP_PROBE_BASE_SRC_PORT ||
            probe_src >= TCP_PROBE_BASE_SRC_PORT + TCP_PROBE_MAX_JOBS)
            return;

        struct probe_job *pj = find_job_by_src_port(st, probe_src);
        if (!pj) return;

        complete_job(ctx, pj, "filtered");
        return;
    }
}

static void probe_tick(ps_module_ctx_t *ctx, uint64_t now_usec)
{
    struct tcp_probe_state *st = (struct tcp_probe_state *)ctx->userdata;
    if (!st) return;

    for (int i = 0; i < TCP_PROBE_MAX_JOBS; i++) {
        struct probe_job *pj = &st->jobs[i];
        if (pj->state != PROBE_STATE_WAITING) continue;
        if (pj->sent_usec == 0) continue;

        if ((now_usec - pj->sent_usec) >= TCP_PROBE_TIMEOUT_USEC) {
            ps_debug("tcp_probe: job '%s' port %d timed out → filtered",
                     pj->job_id, pj->tcp_port);
            complete_job(ctx, pj, "filtered");
        }
    }
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

#ifndef PS_TCP_PROBE_TESTING

const ps_module_t ps_tcp_probe_module = {
    .name        = "tcp_probe",
    .description = "TCP SYN scan with banner grab",
    .version     = "1.0",
    .flags       = PS_MOD_ACTIVE | PS_MOD_NEEDS_RAW,

    .init        = probe_init,
    .shutdown    = probe_shutdown,
    .on_packet   = NULL,
    .on_job      = probe_on_job,
    .on_response = probe_on_response,
    .tick        = probe_tick,
};

#endif /* PS_TCP_PROBE_TESTING */
