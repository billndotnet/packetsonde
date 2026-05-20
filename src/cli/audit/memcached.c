#include "memcached.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../util/fail_on.h"
#include "finding.h"
#include "ulid.h"

#include <arpa/inet.h>
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
    *port = 11211;
    const char *colon = strrchr(spec, ':');
    size_t hl = colon ? (size_t)(colon - spec) : strlen(spec);
    if (hl == 0 || hl >= host_sz) return -1;
    memcpy(host, spec, hl); host[hl] = '\0';
    if (colon) {
        long p = strtol(colon + 1, NULL, 10);
        if (p <= 0 || p > 65535) return -1;
        *port = (uint16_t)p;
    }
    return 0;
}

int ps_audit_memcached_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit memcached <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 11211;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit memcached: bad target '%s'\n", argv[1]);
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

    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        ps_output_close(&out); return 1;
    }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); ps_output_close(&out); return 1; }
    struct timeval tv = { 4, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    char ip[64] = "";
    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res); close(fd);
        fprintf(stderr, "audit memcached: cannot connect to %s:%u\n", host, port);
        ps_output_close(&out);
        return 1;
    }
    freeaddrinfo(res);

    const char *cmd = "version\r\nquit\r\n";
    if (send(fd, cmd, strlen(cmd), 0) != (ssize_t)strlen(cmd)) {
        close(fd); ps_output_close(&out); return 1;
    }

    char buf[1024]; size_t total = 0;
    for (;;) {
        if (total >= sizeof(buf) - 1) break;
        ssize_t r = recv(fd, buf + total, sizeof(buf) - 1 - total, 0);
        if (r <= 0) break;
        total += (size_t)r;
        if (strstr(buf, "\r\n")) {
            struct timeval nb = { 0, 100000 };
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &nb, sizeof(nb));
        }
    }
    buf[total] = '\0';
    close(fd);

    if (total == 0) {
        fprintf(stderr, "audit memcached: no response from %s:%u\n", host, port);
        ps_output_close(&out);
        return 1;
    }

    /* Expected: "VERSION 1.6.18\r\n" (or "ERROR" for unknown command) */
    int is_memcached = (strncmp(buf, "VERSION ", 8) == 0);

    if (!is_memcached) {
        char first[256]; size_t k = 0;
        for (size_t i = 0; buf[i] && i < 128 && k + 2 < sizeof(first); i++) {
            unsigned char c = (unsigned char)buf[i];
            if (c == '"' || c == '\\') { first[k++] = '\\'; first[k++] = (char)c; }
            else if (c >= 0x20 && c < 0x7f) first[k++] = (char)c;
        }
        first[k] = '\0';
        char ev[400];
        snprintf(ev, sizeof(ev), "{\"first_bytes\":\"%s\"}", first);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.memcached", self_host,
                        "memcached.unrecognized", PS_SEV_INFO, PS_CONF_TENTATIVE,
                        "Service does not look like memcached");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
        ps_output_snapshot(&out, &g_last_run_counts);
        ps_output_close(&out);
        return 0;
    }

    /* Extract version */
    char version[64] = "";
    const char *vp = buf + 8;
    size_t k = 0;
    while (*vp && *vp != '\r' && *vp != '\n' && k + 1 < sizeof(version)) {
        version[k++] = *vp++;
    }
    version[k] = '\0';

    /* Metadata */
    {
        char ev[128];
        snprintf(ev, sizeof(ev), "{\"version\":\"%s\"}", version);
        char title[160];
        snprintf(title, sizeof(title), "Memcached %s reachable", version);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.memcached", self_host,
                        "memcached.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
    }

    /* Memcached has no authentication in its default text protocol. Reaching
     * the port from outside the deployment boundary is the finding.
     * Additionally, the UDP variant has historically been an amplification
     * vector (CVE-2018-1000115); flag if running on the conventional UDP port
     * is something operators should consider. */
    {
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.memcached", self_host,
                        "memcached.noauth_exposed", PS_SEV_CRITICAL, PS_CONF_CONFIRMED,
                        "Memcached is reachable with no authentication");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        char ev[128];
        snprintf(ev, sizeof(ev), "{\"version\":\"%s\"}", version);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
    }

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
