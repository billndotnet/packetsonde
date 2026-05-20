#include "traceroute.h"

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
                         struct ps_traceroute_result *out) {
    int max = opts->max_hops > 0 ? opts->max_hops : 30;
    if (max > PS_TRACEROUTE_MAX_HOPS) max = PS_TRACEROUTE_MAX_HOPS;
    if (out->hop_count + max > PS_TRACEROUTE_MAX_HOPS) {
        max = PS_TRACEROUTE_MAX_HOPS - out->hop_count;
        if (max <= 0) return 0;
    }

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
            /* Local failure (EADDRNOTAVAIL etc.) — skip this hop. */
            close(tcp_fd);
            struct ps_tr_hop *h = &out->hops[out->hop_count++];
            h->ttl = ttl; h->addr[0] = '\0'; h->rtt_us = 0; h->reached_dst = 0;
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

        struct ps_tr_hop *h = &out->hops[out->hop_count++];
        h->ttl = ttl; h->addr[0] = '\0'; h->rtt_us = 0; h->reached_dst = 0;

        if (sr <= 0) {
            /* timeout */
            close(tcp_fd);
            continue;
        }
        if (FD_ISSET(icmp_fd, &rfds)) {
            struct sockaddr_in src; int kind = 0;
            if (recv_icmp_for(icmp_fd, 0, &src, &kind) == 0) {
                struct timeval t1; gettimeofday(&t1, NULL);
                inet_ntop(AF_INET, &src.sin_addr, h->addr, sizeof(h->addr));
                h->rtt_us = usec_diff(&t0, &t1);
                h->reached_dst = (src.sin_addr.s_addr == dst.sin_addr.s_addr);
            }
        }
        if (h->reached_dst == 0 && FD_ISSET(tcp_fd, &wfds)) {
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
            h->rtt_us = usec_diff(&t0, &t1);
            if (err == 0 || err == ECONNREFUSED) {
                inet_ntop(AF_INET, &dst.sin_addr, h->addr, sizeof(h->addr));
                h->reached_dst = 1;
            }
            /* else: intermediate hop ate the SYN; addr stays blank. */
        }
        close(tcp_fd);
        if (h->reached_dst) { out->reached = 1; return 0; }
    }
    return 0;
}

static int tr_tcp_classic(const char *target,
                          const struct ps_traceroute_opts *opts,
                          struct ps_traceroute_result *out) {
    struct sockaddr_in dst;
    if (resolve_v4(target, &dst) != 0) return -1;
    dst.sin_port = htons(opts->dst_port);
    int icmp_fd = icmp_listener();
    if (icmp_fd < 0) return -1;
    int rc = tcp_flow_walk(icmp_fd, dst, PS_TR_MODE_CLASSIC, 0, opts, out);
    close(icmp_fd);
    return rc;
}

static int tr_tcp_paris(const char *target,
                        const struct ps_traceroute_opts *opts,
                        struct ps_traceroute_result *out) {
    struct sockaddr_in dst;
    if (resolve_v4(target, &dst) != 0) return -1;
    dst.sin_port = htons(opts->dst_port);
    int icmp_fd = icmp_listener();
    if (icmp_fd < 0) return -1;
    int rc = tcp_flow_walk(icmp_fd, dst, PS_TR_MODE_PARIS, 33500, opts, out);
    close(icmp_fd);
    return rc;
}

static int tr_tcp_dublin(const char *target,
                         const struct ps_traceroute_opts *opts,
                         struct ps_traceroute_result *out) {
    struct sockaddr_in dst;
    if (resolve_v4(target, &dst) != 0) return -1;
    dst.sin_port = htons(opts->dst_port);
    int icmp_fd = icmp_listener();
    if (icmp_fd < 0) return -1;
    int flows = opts->flow_count > 0 ? opts->flow_count : 8;
    if (flows > 32) flows = 32;
    for (int f = 0; f < flows; f++) {
        struct ps_traceroute_result flow_out = {0};
        tcp_flow_walk(icmp_fd, dst, PS_TR_MODE_PARIS,
                      (uint16_t)(33500 + f), opts, &flow_out);
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
                          struct ps_traceroute_result *out) {
    int max = opts->max_hops > 0 ? opts->max_hops : 30;
    if (max > PS_TRACEROUTE_MAX_HOPS) max = PS_TRACEROUTE_MAX_HOPS;

    uint16_t ident = (uint16_t)(getpid() & 0xffff);
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

        struct timeval tv = { opts->timeout_ms / 1000,
                              (opts->timeout_ms % 1000) * 1000 };
        setsockopt(icmp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        char rbuf[2048];
        struct sockaddr_in from; socklen_t flen = sizeof(from);
        ssize_t n = recvfrom(icmp_fd, rbuf, sizeof(rbuf), 0,
                             (struct sockaddr *)&from, &flen);

        struct ps_tr_hop *h = &out->hops[out->hop_count++];
        h->ttl = ttl; h->addr[0] = '\0'; h->rtt_us = 0; h->reached_dst = 0;
        if (n <= 0) continue;

        /* On macOS SOCK_DGRAM ICMP, the kernel strips the IP header on
         * receive; on Linux it varies. Walk past optional IP header. */
        uint8_t *icmp_hdr = (uint8_t *)rbuf;
        if (n >= (ssize_t)sizeof(struct ip) && (rbuf[0] & 0xf0) == 0x40) {
            int hl = (rbuf[0] & 0x0f) * 4;
            if (n >= hl + 8) icmp_hdr = (uint8_t *)rbuf + hl;
        }
        uint8_t type = icmp_hdr[0];
        struct timeval t1; gettimeofday(&t1, NULL);
        inet_ntop(AF_INET, &from.sin_addr, h->addr, sizeof(h->addr));
        h->rtt_us = usec_diff(&t0, &t1);
        if (type == 0) { /* echo reply */
            h->reached_dst = (from.sin_addr.s_addr == dst.sin_addr.s_addr);
        } else if (type == 11) { /* time exceeded */
            h->reached_dst = 0;
        }
        if (h->reached_dst) { out->reached = 1; return 0; }
    }
    return 0;
}

static int tr_icmp_classic(const char *target,
                           const struct ps_traceroute_opts *opts,
                           struct ps_traceroute_result *out) {
    struct sockaddr_in dst;
    if (resolve_v4(target, &dst) != 0) return -1;
    int icmp_fd = icmp_listener();
    if (icmp_fd < 0) return -1;
    int rc = icmp_flow_walk(icmp_fd, dst, opts, out);
    close(icmp_fd);
    return rc;
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
    if (opts->proto == PS_TR_PROTO_TCP) {
        if (opts->mode == PS_TR_MODE_CLASSIC) return tr_tcp_classic(target, opts, out);
        if (opts->mode == PS_TR_MODE_PARIS)   return tr_tcp_paris  (target, opts, out);
        if (opts->mode == PS_TR_MODE_DUBLIN)  return tr_tcp_dublin (target, opts, out);
    }
    if (opts->proto == PS_TR_PROTO_ICMP) {
        /* ICMP traceroute has only one mode in practice — the flow tuple is
         * (proto=icmp, id, seq) and varying seq is unavoidable. We treat all
         * three mode names as a single classic walk. */
        return tr_icmp_classic(target, opts, out);
    }
    return -1;
}
