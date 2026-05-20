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

static int tr_udp_classic(const char *target,
                          const struct ps_traceroute_opts *opts,
                          struct ps_traceroute_result *out) {
    struct sockaddr_in dst;
    if (resolve_v4(target, &dst) != 0) return -1;

    int icmp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (icmp_fd < 0) {
        icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (icmp_fd < 0) return -1;
    }

    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) { close(icmp_fd); return -1; }

    int max = opts->max_hops > 0 ? opts->max_hops : 30;
    if (max > PS_TRACEROUTE_MAX_HOPS) max = PS_TRACEROUTE_MAX_HOPS;

    for (int ttl = 1; ttl <= max; ttl++) {
        setsockopt(udp_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        struct sockaddr_in d = dst;
        d.sin_port = htons(opts->dst_port + ttl - 1);

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
            if (h->reached_dst) { out->reached = 1; break; }
        } else {
            struct ps_tr_hop *h = &out->hops[out->hop_count++];
            h->ttl = ttl;
            h->addr[0] = '\0';
            h->rtt_us = 0;
            h->reached_dst = 0;
        }
    }

    close(icmp_fd); close(udp_fd);
    return 0;
}

int ps_traceroute_run(const char *target,
                      const struct ps_traceroute_opts *opts,
                      struct ps_traceroute_result *out) {
    memset(out, 0, sizeof(*out));
    if (opts->proto == PS_TR_PROTO_UDP && opts->mode == PS_TR_MODE_CLASSIC) {
        return tr_udp_classic(target, opts, out);
    }
    return -1;
}
