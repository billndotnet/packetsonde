#include "../args.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../util/fail_on.h"
#include "finding.h"
#include "ulid.h"

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int ps_probe_icmp_run(int argc, char **argv, const struct ps_args *opts);

/*
 * probe icmp -- single-target ICMP echo reachability check.
 *
 * Uses SOCK_DGRAM / IPPROTO_ICMP (unprivileged on macOS, and on Linux
 * when /proc/sys/net/ipv4/ping_group_range admits the user -- same path
 * the agent's ICMP traceroute uses).
 *
 * Sends N echo requests, reports per-probe RTT + loss summary. Useful
 * as a "does this host even respond?" check before running real audits
 * against it -- when a target is unreachable you want to know that's
 * the failure mode, not have it mistaken for "service not running."
 *
 * Findings:
 *   probe.icmp.reply     info  one per successful echo reply (rtt, ttl, seq)
 *   probe.icmp.summary   info  always emitted; total sent/received, loss%,
 *                              min/avg/max rtt
 *   probe.icmp.unreachable medium  emitted when 100% loss across all probes
 */

static uint16_t icmp_checksum(const void *data, size_t len) {
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static long usec_diff(const struct timeval *a, const struct timeval *b) {
    return (b->tv_sec - a->tv_sec) * 1000000L + (b->tv_usec - a->tv_usec);
}

static void usage(void) {
    fprintf(stderr,
        "Usage: packetsonde probe icmp <target> [-c count] [-t timeout_ms]\n"
        "  -c, --count N      number of echo requests (default 4)\n"
        "  -t, --timeout MS   per-probe timeout (default 1000)\n");
}

int ps_probe_icmp_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }
    const char *target = argv[1];
    int count = 4;
    int timeout_ms = 1000;

    static const struct option longopts[] = {
        { "count",   required_argument, NULL, 'c' },
        { "timeout", required_argument, NULL, 't' },
        { NULL, 0, NULL, 0 }
    };
    optind = 2;
    int c;
    while ((c = getopt_long(argc, argv, "c:t:", longopts, NULL)) != -1) {
        switch (c) {
            case 'c': count      = atoi(optarg); break;
            case 't': timeout_ms = atoi(optarg); break;
            default:  usage(); return 2;
        }
    }
    if (count < 1)   count = 1;
    if (count > 256) count = 256;
    if (timeout_ms < 100)    timeout_ms = 100;
    if (timeout_ms > 60000)  timeout_ms = 60000;

    /* Resolve target. AF_UNSPEC picks v4 or v6 based on what the resolver
     * returns; getaddrinfo orders results per RFC 6724 / OS policy. */
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(target, NULL, &hints, &res) != 0) {
        fprintf(stderr, "probe icmp: cannot resolve '%s'\n", target);
        return 1;
    }
    int family = res->ai_family;
    struct sockaddr_storage dst; memset(&dst, 0, sizeof(dst));
    socklen_t dst_len = res->ai_addrlen;
    memcpy(&dst, res->ai_addr, dst_len);
    char ip[64] = "";
    if (family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in *)&dst)->sin_addr,
                  ip, sizeof(ip));
    } else {
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&dst)->sin6_addr,
                  ip, sizeof(ip));
    }
    freeaddrinfo(res);

    int proto = (family == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6;
    int fd = socket(family, SOCK_DGRAM, proto);
    if (fd < 0) {
        /* macOS allows unprivileged ICMP / ICMPv6 via SOCK_DGRAM; Linux
         * needs ping_group_range. Fall back to raw socket (caller needs
         * cap_net_raw / sudo). */
        fd = socket(family, SOCK_RAW, proto);
        if (fd < 0) {
            fprintf(stderr, "probe icmp: cannot open %s socket "
                            "(need ping_group_range or cap_net_raw): %s\n",
                    family == AF_INET ? "ICMP" : "ICMPv6",
                    strerror(errno));
            return 1;
        }
    }
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    /* ICMPv6 raw sockets: tell the kernel where the checksum goes so it
     * fills in the pseudo-header-aware checksum. Harmless on DGRAM where
     * the kernel already handles it. Offset 2 within the ICMP header. */
    if (family == AF_INET6) {
        int off = 2;
        setsockopt(fd, IPPROTO_IPV6, IPV6_CHECKSUM, &off, sizeof(off));
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    struct ps_output_opts oopts; memset(&oopts, 0, sizeof(oopts));
    switch (opts->fmt) {
        case PS_FMT_TEXT:  oopts.fmt_force = PS_OFMT_TEXT;  break;
        case PS_FMT_JSON:  oopts.fmt_force = PS_OFMT_JSON;  break;
        case PS_FMT_JSONL: oopts.fmt_force = PS_OFMT_JSONL; break;
        case PS_FMT_QUIET: oopts.fmt_force = PS_OFMT_QUIET; break;
        default:           oopts.fmt_force = 0;             break;
    }
    oopts.color = opts->no_color ? 0 : 1;
    struct ps_output out; ps_output_init(&out, &oopts);

    uint16_t ident = (uint16_t)(getpid() & 0xffff);
    int sent = 0, received = 0;
    long rtt_min = 0, rtt_max = 0, rtt_sum = 0;

    uint8_t echo_type  = (family == AF_INET) ? 8   : 128;
    uint8_t reply_type = (family == AF_INET) ? 0   : 129;

    for (int i = 0; i < count; i++) {
        struct {
            uint8_t  type, code;
            uint16_t checksum;
            uint16_t id, seq;
            char     payload[16];
        } pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.type = echo_type;
        pkt.code = 0;
        pkt.id = htons(ident);
        pkt.seq = htons((uint16_t)(i + 1));
        memcpy(pkt.payload, "PSPING", 6);
        pkt.checksum = 0;
        /* ICMPv4: we compute the 1's-complement checksum ourselves.
         * ICMPv6: requires a pseudo-header that includes the source IP,
         * which the kernel knows but we don't. Both Linux and macOS fill
         * it in automatically for ICMPv6 sockets, so we leave it zero. */
        if (family == AF_INET) pkt.checksum = icmp_checksum(&pkt, sizeof(pkt));

        struct timeval t0; gettimeofday(&t0, NULL);
        if (sendto(fd, &pkt, sizeof(pkt), 0,
                   (struct sockaddr *)&dst, dst_len) < 0) {
            continue;
        }
        sent++;

        /* On macOS, DGRAM/ICMPv6 to a loopback peer delivers the kernel's
         * looped-back copy of our outbound echo request (type 128) AND
         * the echo reply (type 129) on the same socket. We also need to
         * tolerate Neighbor Solicitation noise (type 135) and similar.
         * Keep reading until we get a real reply or the socket times out. */
        char rbuf[2048];
        uint8_t *icmp_hdr = NULL;
        int ttl = -1;
        ssize_t n = 0;
        for (;;) {
            struct sockaddr_storage from; socklen_t flen = sizeof(from);
            n = recvfrom(fd, rbuf, sizeof(rbuf), 0,
                         (struct sockaddr *)&from, &flen);
            if (n <= 0) break;

            /* v4 raw on Linux includes the IP header; macOS DGRAM/ICMP
             * and all v6 sockets strip it. Detect by version nibble. */
            icmp_hdr = (uint8_t *)rbuf;
            ttl = -1;
            if (family == AF_INET && n >= 20 && (rbuf[0] & 0xf0) == 0x40) {
                int hl = (rbuf[0] & 0x0f) * 4;
                if (n >= hl + 8) {
                    icmp_hdr = (uint8_t *)rbuf + hl;
                    ttl = (uint8_t)rbuf[8];
                }
            }
            if (icmp_hdr[0] == reply_type) break;
            /* not our reply — drop and try again within the same timeout */
        }
        if (n <= 0 || !icmp_hdr || icmp_hdr[0] != reply_type) continue;

        struct timeval t1; gettimeofday(&t1, NULL);
        long rtt = usec_diff(&t0, &t1);
        received++;
        if (received == 1 || rtt < rtt_min) rtt_min = rtt;
        if (rtt > rtt_max) rtt_max = rtt;
        rtt_sum += rtt;

        char title[160], ev[256];
        snprintf(title, sizeof(title),
                 "icmp reply from %s seq=%d rtt=%.2f ms",
                 ip, i + 1, rtt / 1000.0);
        if (ttl >= 0) {
            snprintf(ev, sizeof(ev),
                     "{\"seq\":%d,\"rtt_us\":%ld,\"ttl\":%d}", i + 1, rtt, ttl);
        } else {
            snprintf(ev, sizeof(ev),
                     "{\"seq\":%d,\"rtt_us\":%ld}", i + 1, rtt);
        }
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.probe.icmp", self_host,
                        "probe.icmp.reply", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, 0);
        ps_finding_set_target_hostname(&f, target, 0);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
    }

    close(fd);

    /* Summary -- always emitted. */
    {
        int loss_pct = sent > 0 ? (100 * (sent - received) / sent) : 100;
        long rtt_avg = received > 0 ? rtt_sum / received : 0;
        char ev[256];
        snprintf(ev, sizeof(ev),
                 "{\"sent\":%d,\"received\":%d,\"loss_pct\":%d,"
                 "\"rtt_min_us\":%ld,\"rtt_avg_us\":%ld,\"rtt_max_us\":%ld}",
                 sent, received, loss_pct, rtt_min, rtt_avg, rtt_max);
        char title[200];
        snprintf(title, sizeof(title),
                 "icmp summary: %d/%d received (%d%% loss), avg %.2f ms",
                 received, sent, loss_pct, rtt_avg / 1000.0);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.probe.icmp", self_host,
                        "probe.icmp.summary", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, 0);
        ps_finding_set_target_hostname(&f, target, 0);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
    }

    int unreachable = (received == 0 && sent > 0);
    if (unreachable) {
        char ev[160];
        snprintf(ev, sizeof(ev), "{\"sent\":%d,\"timeout_ms\":%d}", sent, timeout_ms);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.probe.icmp", self_host,
                        "probe.icmp.unreachable", PS_SEV_MEDIUM, PS_CONF_FIRM,
                        "Host did not respond to any ICMP echo request");
        ps_finding_set_target_ip(&f, ip, 0);
        ps_finding_set_target_hostname(&f, target, 0);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
    }

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return unreachable ? 1 : 0;
}
