#include "../args.h"
#include "../output/output.h"
#include "../runstate.h"
#include "finding.h"
#include "ulid.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int ps_probe_sweep_run(int argc, char **argv, const struct ps_args *opts);

/*
 * probe sweep -- bulk ICMP reachability sweep (fping-style).
 *
 * Sends one ICMP echo to EVERY target up front (en masse), then collects
 * replies in a single select()-driven window bounded by one overall
 * deadline -- so total time is ~the timeout, not sum-of-per-host timeouts.
 *
 * Reply->target correlation uses the ICMP sequence number = the target's
 * index (SOCK_DGRAM ICMP rewrites the id field, but echoes seq verbatim),
 * which caps a single sweep at 65535 targets.
 *
 * Targets come from argv (one or many). The UE client / agent passes a
 * target list this way; locally you can also pass them directly.
 *
 * Findings:
 *   probe.sweep.up           info    one per host that replied (rtt)
 *   probe.sweep.down         info    one per host that did not reply
 *   probe.sweep.unresolved   low     one per host that failed DNS
 *   probe.sweep.summary      info    totals: targets / up / down / loss%
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
        "Usage: packetsonde probe sweep <target> [<target>...] [-t timeout_ms]\n"
        "  -t, --timeout MS   overall reply window for the whole sweep (default 2000)\n"
        "Blasts one ICMP echo to every target, then collects replies en masse.\n");
}

struct tgt {
    const char *host;
    char ip[64];
    int family;                 /* AF_INET / AF_INET6, or -1 if unresolved */
    struct sockaddr_storage dst;
    socklen_t dlen;
    struct timeval sent;
    int sent_ok;
    int replied;
    long rtt;
};

/* Drain one datagram from fd (family known), match it to a target by seq. */
static void recv_one(int fd, int family, struct tgt *t, int n,
                     int *replied_count) {
    char rbuf[2048];
    struct sockaddr_storage from; socklen_t flen = sizeof(from);
    ssize_t r = recvfrom(fd, rbuf, sizeof(rbuf), 0,
                         (struct sockaddr *)&from, &flen);
    if (r <= 0) return;

    uint8_t *icmp = (uint8_t *)rbuf;
    if (family == AF_INET && r >= 20 && (rbuf[0] & 0xf0) == 0x40) {
        int hl = (rbuf[0] & 0x0f) * 4;          /* Linux raw v4 keeps IP hdr */
        if (r < hl + 8) return;
        icmp = (uint8_t *)rbuf + hl;
        r -= hl;
    }
    if (r < 8) return;
    uint8_t reply_type = (family == AF_INET) ? 0 : 129;
    if (icmp[0] != reply_type) return;          /* not an echo reply */

    int idx = (icmp[6] << 8) | icmp[7];         /* seq = target index */
    if (idx < 0 || idx >= n) return;
    if (t[idx].family != family || t[idx].replied) return;

    struct timeval now; gettimeofday(&now, NULL);
    t[idx].replied = 1;
    t[idx].rtt = usec_diff(&t[idx].sent, &now);
    (*replied_count)++;
}

int ps_probe_sweep_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }

    int timeout_ms = 2000;
    const char **hosts = calloc((size_t)argc, sizeof(*hosts));
    if (!hosts) { fprintf(stderr, "probe sweep: oom\n"); return 1; }
    int n = 0;
    /* Manual parse so flag/target order is free and behaviour matches on both
     * glibc (permuting) and BSD/macOS (non-permuting) getopt. */
    for (int a = 1; a < argc; a++) {
        const char *arg = argv[a];
        if (!strcmp(arg, "-t") || !strcmp(arg, "--timeout")) {
            if (a + 1 < argc) timeout_ms = atoi(argv[++a]);
        } else if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            usage(); free(hosts); return 0;
        } else if (arg[0] == '-') {
            fprintf(stderr, "probe sweep: unknown option '%s'\n", arg);
            usage(); free(hosts); return 2;
        } else if (n < 65535) {                  /* seq is 16-bit */
            hosts[n++] = arg;
        }
    }
    if (n < 1) { usage(); free(hosts); return 2; }
    if (timeout_ms < 100)    timeout_ms = 100;
    if (timeout_ms > 120000) timeout_ms = 120000;

    struct tgt *t = calloc((size_t)n, sizeof(*t));
    if (!t) { fprintf(stderr, "probe sweep: oom\n"); free(hosts); return 1; }

    /* Resolve every target up front. */
    int need4 = 0, need6 = 0;
    for (int i = 0; i < n; i++) {
        t[i].host = hosts[i];
        t[i].family = -1;
        struct addrinfo hints; memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM;
        struct addrinfo *res = NULL;
        if (getaddrinfo(t[i].host, NULL, &hints, &res) != 0 || !res) continue;
        t[i].family = res->ai_family;
        t[i].dlen = res->ai_addrlen;
        memcpy(&t[i].dst, res->ai_addr, res->ai_addrlen);
        if (t[i].family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)&t[i].dst)->sin_addr,
                      t[i].ip, sizeof(t[i].ip));
            need4 = 1;
        } else {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&t[i].dst)->sin6_addr,
                      t[i].ip, sizeof(t[i].ip));
            need6 = 1;
        }
        freeaddrinfo(res);
    }

    /* One socket per needed family (DGRAM, raw fallback -- as in probe icmp). */
    int fd4 = -1, fd6 = -1;
    if (need4) {
        fd4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if (fd4 < 0) fd4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    }
    if (need6) {
        fd6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
        if (fd6 < 0) fd6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (fd6 >= 0) {
            int off = 2;
            setsockopt(fd6, IPPROTO_IPV6, IPV6_CHECKSUM, &off, sizeof(off));
        }
    }
    if ((need4 && fd4 < 0) || (need6 && fd6 < 0)) {
        fprintf(stderr, "probe sweep: cannot open ICMP socket "
                        "(need ping_group_range or cap_net_raw): %s\n",
                strerror(errno));
        /* keep going with whatever opened; unopened-family targets count down */
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

    /* ---- send phase: blast one echo per target ---- */
    int sent_count = 0;
    for (int i = 0; i < n; i++) {
        if (t[i].family < 0) continue;
        int fd = (t[i].family == AF_INET) ? fd4 : fd6;
        if (fd < 0) continue;
        struct {
            uint8_t type, code; uint16_t checksum; uint16_t id, seq;
            char payload[16];
        } pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.type = (t[i].family == AF_INET) ? 8 : 128;
        pkt.id   = htons(ident);
        pkt.seq  = htons((uint16_t)i);          /* seq = target index */
        memcpy(pkt.payload, "PSSWEEP", 7);
        if (t[i].family == AF_INET)
            pkt.checksum = icmp_checksum(&pkt, sizeof(pkt));
        gettimeofday(&t[i].sent, NULL);
        if (sendto(fd, &pkt, sizeof(pkt), 0,
                   (struct sockaddr *)&t[i].dst, t[i].dlen) >= 0) {
            t[i].sent_ok = 1;
            sent_count++;
        }
    }

    /* ---- receive phase: one window, en masse ---- */
    struct timeval deadline; gettimeofday(&deadline, NULL);
    deadline.tv_sec  += timeout_ms / 1000;
    deadline.tv_usec += (timeout_ms % 1000) * 1000;
    if (deadline.tv_usec >= 1000000) { deadline.tv_sec++; deadline.tv_usec -= 1000000; }

    int replied = 0;
    while (replied < sent_count) {
        struct timeval now; gettimeofday(&now, NULL);
        long rem = usec_diff(&now, &deadline);
        if (rem <= 0) break;
        struct timeval tv = { rem / 1000000, rem % 1000000 };
        fd_set rfds; FD_ZERO(&rfds);
        int maxfd = -1;
        if (fd4 >= 0) { FD_SET(fd4, &rfds); if (fd4 > maxfd) maxfd = fd4; }
        if (fd6 >= 0) { FD_SET(fd6, &rfds); if (fd6 > maxfd) maxfd = fd6; }
        if (maxfd < 0) break;
        int s = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (s < 0) { if (errno == EINTR) continue; break; }
        if (s == 0) break;                       /* window elapsed */
        if (fd4 >= 0 && FD_ISSET(fd4, &rfds)) recv_one(fd4, AF_INET, t, n, &replied);
        if (fd6 >= 0 && FD_ISSET(fd6, &rfds)) recv_one(fd6, AF_INET6, t, n, &replied);
    }
    if (fd4 >= 0) close(fd4);
    if (fd6 >= 0) close(fd6);

    /* ---- emit per-target results + summary ---- */
    int up = 0, down = 0, unresolved = 0;
    for (int i = 0; i < n; i++) {
        struct ps_finding f;
        if (t[i].family < 0) {
            unresolved++;
            ps_finding_init(&f, run_id, "cli.probe.sweep", self_host,
                            "probe.sweep.unresolved", PS_SEV_LOW, PS_CONF_FIRM,
                            "Target did not resolve");
            ps_finding_set_target_hostname(&f, t[i].host, 0);
            ps_finding_set_evidence_json(&f, "{\"resolved\":false}");
            ps_output_emit(&out, &f);
            continue;
        }
        if (t[i].replied) {
            up++;
            char title[200], ev[160];
            snprintf(title, sizeof(title), "up %s (%s) rtt=%.2f ms",
                     t[i].host, t[i].ip, t[i].rtt / 1000.0);
            snprintf(ev, sizeof(ev), "{\"up\":true,\"rtt_us\":%ld}", t[i].rtt);
            ps_finding_init(&f, run_id, "cli.probe.sweep", self_host,
                            "probe.sweep.up", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
            ps_finding_set_target_ip(&f, t[i].ip, 0);
            ps_finding_set_target_hostname(&f, t[i].host, 0);
            ps_finding_set_evidence_json(&f, ev);
            ps_output_emit(&out, &f);
        } else {
            down++;
            char title[200];
            snprintf(title, sizeof(title), "down %s (%s) -- no reply", t[i].host, t[i].ip);
            ps_finding_init(&f, run_id, "cli.probe.sweep", self_host,
                            "probe.sweep.down", PS_SEV_INFO, PS_CONF_FIRM, title);
            ps_finding_set_target_ip(&f, t[i].ip, 0);
            ps_finding_set_target_hostname(&f, t[i].host, 0);
            ps_finding_set_evidence_json(&f, "{\"up\":false}");
            ps_output_emit(&out, &f);
        }
    }
    {
        int loss_pct = sent_count > 0 ? (100 * down / (up + down ? up + down : 1)) : 0;
        char ev[256], title[200];
        snprintf(ev, sizeof(ev),
                 "{\"targets\":%d,\"up\":%d,\"down\":%d,\"unresolved\":%d,"
                 "\"timeout_ms\":%d}", n, up, down, unresolved, timeout_ms);
        snprintf(title, sizeof(title),
                 "sweep: %d up, %d down, %d unresolved of %d (%d%% loss)",
                 up, down, unresolved, n, loss_pct);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.probe.sweep", self_host,
                        "probe.sweep.summary", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
    }

    free(t);
    free(hosts);
    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return (up > 0 || n == 0) ? 0 : 1;
}
