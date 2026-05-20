#include "traceroute.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
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

/* Walk a single UDP flow at increasing TTLs, recording hops into out.
 *
 * mode controls how each probe identifies itself on the wire:
 *
 *   CLASSIC — dst_port increments per TTL. Flow tuple changes every hop,
 *             so ECMP-balanced paths may differ between hops.
 *   PARIS   — dst_port held constant; src_port held constant (the socket
 *             is bound to src_port). ECMP hash is stable; every hop
 *             traverses the same path.
 *
 * Returns 0 on success. Stops early on ICMP unreachable from the destination. */
static int udp_flow_walk(int udp_fd, int icmp_fd,
                         struct sockaddr_in dst, enum ps_tr_mode mode,
                         const struct ps_traceroute_opts *opts,
                         struct ps_traceroute_result *out) {
    int max = opts->max_hops > 0 ? opts->max_hops : 30;
    if (max > PS_TRACEROUTE_MAX_HOPS) max = PS_TRACEROUTE_MAX_HOPS;
    if (out->hop_count + max > PS_TRACEROUTE_MAX_HOPS) {
        max = PS_TRACEROUTE_MAX_HOPS - out->hop_count;
        if (max <= 0) return 0;
    }

    for (int ttl = 1; ttl <= max; ttl++) {
        setsockopt(udp_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        struct sockaddr_in d = dst;
        if (mode == PS_TR_MODE_CLASSIC) {
            d.sin_port = htons(opts->dst_port + ttl - 1);
        } else {
            d.sin_port = htons(opts->dst_port);
        }

        struct timeval t0; gettimeofday(&t0, NULL);
        char payload[16] = "PSTR";
        sendto(udp_fd, payload, sizeof(payload), 0,
               (struct sockaddr *)&d, sizeof(d));

        struct sockaddr_in src; int kind = 0;
        if (recv_icmp_for(icmp_fd, opts->timeout_ms, &src, &kind) == 0) {
            struct timeval t1; gettimeofday(&t1, NULL);
            struct ps_tr_hop *h = &out->hops[out->hop_count++];
            h->ttl = ttl;
            inet_ntop(AF_INET, &src.sin_addr, h->addr, sizeof(h->addr));
            h->rtt_us = usec_diff(&t0, &t1);
            h->reached_dst = (kind == ICMP_UNREACH) ||
                             (src.sin_addr.s_addr == dst.sin_addr.s_addr);
            if (h->reached_dst) { out->reached = 1; return 0; }
        } else {
            struct ps_tr_hop *h = &out->hops[out->hop_count++];
            h->ttl = ttl;
            h->addr[0] = '\0';
            h->rtt_us = 0;
            h->reached_dst = 0;
        }
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
                          struct ps_traceroute_result *out) {
    struct sockaddr_in dst;
    if (resolve_v4(target, &dst) != 0) return -1;
    int icmp_fd = icmp_listener();
    if (icmp_fd < 0) return -1;
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) { close(icmp_fd); return -1; }
    int rc = udp_flow_walk(udp_fd, icmp_fd, dst, PS_TR_MODE_CLASSIC, opts, out);
    close(udp_fd); close(icmp_fd);
    return rc;
}

static int tr_udp_paris(const char *target,
                        const struct ps_traceroute_opts *opts,
                        struct ps_traceroute_result *out) {
    struct sockaddr_in dst;
    if (resolve_v4(target, &dst) != 0) return -1;
    int icmp_fd = icmp_listener();
    if (icmp_fd < 0) return -1;
    /* Bind src_port so the (src_ip, dst_ip, src_port, dst_port, proto) tuple
     * is stable across every probe in the run. */
    int udp_fd = udp_socket_bound(33500);
    if (udp_fd < 0) { close(icmp_fd); return -1; }
    int rc = udp_flow_walk(udp_fd, icmp_fd, dst, PS_TR_MODE_PARIS, opts, out);
    close(udp_fd); close(icmp_fd);
    return rc;
}

/* Dublin: enumerate ECMP paths by walking multiple Paris-style flows whose
 * src_port differs between flows. Each flow internally holds its tuple
 * constant (Paris-style), so each flow produces a coherent path; varying
 * src_port between flows makes the ECMP hash key differ, exposing alternative
 * paths.
 *
 * Result format: hops[] accumulates hops from every flow in order. The CLI
 * verb can dedupe by (ttl, addr) or render per-flow as it prefers. */
static int tr_udp_dublin(const char *target,
                         const struct ps_traceroute_opts *opts,
                         struct ps_traceroute_result *out) {
    struct sockaddr_in dst;
    if (resolve_v4(target, &dst) != 0) return -1;
    int icmp_fd = icmp_listener();
    if (icmp_fd < 0) return -1;

    int flows = opts->flow_count > 0 ? opts->flow_count : 8;
    if (flows > 32) flows = 32;

    for (int f = 0; f < flows; f++) {
        int udp_fd = udp_socket_bound((uint16_t)(33500 + f));
        if (udp_fd < 0) continue;
        struct ps_traceroute_result flow_out = {0};
        flow_out.hop_count = 0;
        udp_flow_walk(udp_fd, icmp_fd, dst, PS_TR_MODE_PARIS, opts, &flow_out);
        close(udp_fd);

        /* Append this flow's hops to the merged result, skipping duplicates
         * by (ttl, addr). */
        for (int i = 0; i < flow_out.hop_count; i++) {
            struct ps_tr_hop *h = &flow_out.hops[i];
            int dup = 0;
            for (int j = 0; j < out->hop_count; j++) {
                if (out->hops[j].ttl == h->ttl &&
                    strcmp(out->hops[j].addr, h->addr) == 0) {
                    dup = 1; break;
                }
            }
            if (dup) continue;
            if (out->hop_count >= PS_TRACEROUTE_MAX_HOPS) break;
            out->hops[out->hop_count++] = *h;
            if (h->reached_dst) out->reached = 1;
        }
        if (out->hop_count >= PS_TRACEROUTE_MAX_HOPS) break;
    }

    close(icmp_fd);
    return 0;
}

int ps_traceroute_run(const char *target,
                      const struct ps_traceroute_opts *opts,
                      struct ps_traceroute_result *out) {
    memset(out, 0, sizeof(*out));
    if (opts->proto == PS_TR_PROTO_UDP) {
        if (opts->mode == PS_TR_MODE_CLASSIC) return tr_udp_classic(target, opts, out);
        if (opts->mode == PS_TR_MODE_PARIS)   return tr_udp_paris  (target, opts, out);
        if (opts->mode == PS_TR_MODE_DUBLIN)  return tr_udp_dublin (target, opts, out);
    }
    /* TCP and ICMP traceroute remain follow-on work — they need additional
     * privilege (raw sockets on macOS, IP_RECVERR on Linux) plus protocol-
     * specific framing. */
    return -1;
}
