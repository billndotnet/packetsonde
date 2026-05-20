#include "tcp.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../util/fail_on.h"
#include "finding.h"
#include "ulid.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
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

static int probe(const char *host, uint16_t port, int timeout_ms,
                 char *ip_out, size_t ip_out_sz,
                 long *rtt_us_out, char *banner_out, size_t banner_sz) {
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (ip_out && ip_out_sz) {
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &sin->sin_addr, ip_out, (socklen_t)ip_out_sz);
    }

    struct timeval t0, t1; gettimeofday(&t0, NULL);
    int rc = connect(fd, res->ai_addr, res->ai_addrlen);
    gettimeofday(&t1, NULL);
    freeaddrinfo(res);
    if (rc != 0) { close(fd); return -1; }
    *rtt_us_out = (t1.tv_sec - t0.tv_sec) * 1000000L + (t1.tv_usec - t0.tv_usec);

    if (port == 80 || port == 8080) {
        const char *req = "HEAD / HTTP/1.0\r\n\r\n";
        send(fd, req, strlen(req), 0);
    }
    if (banner_out && banner_sz > 0) {
        ssize_t r = recv(fd, banner_out, banner_sz - 1, 0);
        if (r > 0) {
            banner_out[r] = '\0';
            for (ssize_t i = r - 1; i >= 0 && (banner_out[i] == '\r' || banner_out[i] == '\n'); i--)
                banner_out[i] = '\0';
        } else {
            banner_out[0] = '\0';
        }
    }
    close(fd);
    return 0;
}

int ps_probe_tcp_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde probe tcp <host:port>\n");
        return 2;
    }
    char host[256]; uint16_t port = 0;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "probe tcp: bad target '%s'\n", argv[1]);
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

    char ip[64] = ""; long rtt_us = 0; char banner[1024] = "";
    int rc = probe(host, port, 4000, ip, sizeof(ip), &rtt_us, banner, sizeof(banner));

    if (rc == 0) {
        char title[256];
        snprintf(title, sizeof(title), "Open: %s:%u (%.1f ms)",
                 ip[0] ? ip : host, port, rtt_us / 1000.0);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.probe.tcp", self_host,
                        "probe.tcp.open", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        if (ip[0]) ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        char banner_e[1024]; size_t bi = 0;
        for (size_t i = 0; banner[i] && bi + 2 < sizeof(banner_e); i++) {
            unsigned char c = (unsigned char)banner[i];
            if (c == '"' || c == '\\') { banner_e[bi++] = '\\'; banner_e[bi++] = (char)c; }
            else if (c >= 0x20 && c < 0x7f) { banner_e[bi++] = (char)c; }
        }
        banner_e[bi] = '\0';
        char ev[2048];
        snprintf(ev, sizeof(ev), "{\"rtt_us\":%ld,\"banner\":\"%s\"}", rtt_us, banner_e);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
    } else {
        fprintf(stderr, "probe tcp: %s:%u — %s\n", host, port, strerror(errno));
    }

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return rc == 0 ? 0 : 1;
}
