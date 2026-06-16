#include "udp.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../util/fail_on.h"
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
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    const char *colon = strrchr(spec, ':');
    if (!colon) return -1;
    size_t hl = (size_t)(colon - spec);
    if (hl == 0 || hl >= host_sz) return -1;
    memcpy(host, spec, hl); host[hl] = '\0';
    long p = strtol(colon + 1, NULL, 10);
    if (p <= 0 || p > 65535) return -1;
    *port = (uint16_t)p;
    return 0;
}

/* Classification of a single UDP datagram probe. */
#define UDP_OPEN          1   /* application-layer reply received */
#define UDP_CLOSED       -1   /* ICMP port-unreachable observed (ECONNREFUSED) */
#define UDP_OPEN_FILTERED 0   /* no reply within timeout (silent or filtered) */

/* Send one datagram to host:port over a connected UDP socket and wait for a
 * reply. Connecting the socket lets recv() surface ECONNREFUSED when the
 * kernel observes an ICMP port-unreachable — but only on raw-socket-free
 * platforms where the kernel tracks the error; otherwise this manifests as a
 * timeout (UDP_OPEN_FILTERED). See scan/udp.c for the same approach. */
static int probe(const char *host, uint16_t port, int timeout_ms,
                 char *ip_out, size_t ip_out_sz, long *rtt_us_out) {
    *rtt_us_out = 0;
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -2;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -2; }
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (ip_out && ip_out_sz) {
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &sin->sin_addr, ip_out, (socklen_t)ip_out_sz);
    }
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res); close(fd); return -2;
    }
    freeaddrinfo(res);

    /* A single generic payload byte. Unlike scan/udp.c we are a
     * single-target reachability probe, not a service prober, so we keep
     * the payload minimal and protocol-agnostic. */
    unsigned char payload = 0x00;
    struct timeval t0, t1; gettimeofday(&t0, NULL);
    if (send(fd, &payload, sizeof(payload), 0) < 0) {
        close(fd); return -2;
    }

    unsigned char resp[1024];
    ssize_t n = recv(fd, resp, sizeof(resp), 0);
    gettimeofday(&t1, NULL);
    *rtt_us_out = (t1.tv_sec - t0.tv_sec) * 1000000L + (t1.tv_usec - t0.tv_usec);

    int rc;
    if (n > 0) {
        rc = UDP_OPEN;
    } else if (n < 0 && errno == ECONNREFUSED) {
        rc = UDP_CLOSED;
    } else {
        rc = UDP_OPEN_FILTERED;
    }
    close(fd);
    return rc;
}

int ps_probe_udp_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde probe udp <host:port>\n");
        return 2;
    }
    char host[256]; uint16_t port = 0;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "probe udp: bad target '%s'\n", argv[1]);
        return 2;
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

    char ip[64] = ""; long rtt_us = 0;
    int state = probe(host, port, 4000, ip, sizeof(ip), &rtt_us);

    if (state == -2) {
        fprintf(stderr, "probe udp: %s:%u — %s\n", host, port, strerror(errno));
        ps_output_snapshot(&out, &g_last_run_counts);
        ps_output_close(&out);
        return 1;
    }

    const char *kind, *statestr;
    switch (state) {
        case UDP_OPEN:    kind = "probe.udp.open";          statestr = "open";          break;
        case UDP_CLOSED:  kind = "probe.udp.closed";        statestr = "closed";        break;
        default:          kind = "probe.udp.open_filtered"; statestr = "open|filtered"; break;
    }

    char title[256];
    snprintf(title, sizeof(title), "%s UDP: %s:%u (%.1f ms)",
             state == UDP_OPEN ? "Open" : state == UDP_CLOSED ? "Closed" : "Open|filtered",
             ip[0] ? ip : host, port, rtt_us / 1000.0);

    struct ps_finding f;
    ps_finding_init(&f, run_id, "cli.probe.udp", self_host,
                    kind, PS_SEV_INFO, PS_CONF_FIRM, title);
    if (ip[0]) ps_finding_set_target_ip(&f, ip, port);
    ps_finding_set_target_hostname(&f, host, port);
    char ev[256];
    snprintf(ev, sizeof(ev),
             "{\"proto\":\"udp\",\"state\":\"%s\",\"rtt_us\":%ld}",
             statestr, rtt_us);
    ps_finding_set_evidence_json(&f, ev);
    ps_output_emit(&out, &f);

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    /* Exit 0 on open, nonzero otherwise — mirror tcp's "open == success"
     * convention. closed/open|filtered are not affirmative reachability. */
    return state == UDP_OPEN ? 0 : 1;
}
