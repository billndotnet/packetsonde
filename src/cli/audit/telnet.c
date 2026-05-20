#include "telnet.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../util/fail_on.h"
#include "finding.h"
#include "ulid.h"

#include <arpa/inet.h>
#include <ctype.h>
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
    *port = 23;
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

/* Read up to outsz-1 printable bytes from fd within the existing timeout.
 * Skips Telnet option-negotiation bytes (IAC sequences: 0xFF + 2 bytes). */
static int read_banner(int fd, char *out, size_t outsz) {
    unsigned char buf[2048];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) { out[0] = '\0'; return 0; }
    size_t o = 0;
    for (ssize_t i = 0; i < n && o + 1 < outsz; i++) {
        if (buf[i] == 0xFF) {
            /* IAC: skip command + option (2 more bytes). */
            i += 2;
            continue;
        }
        unsigned char c = buf[i];
        if (c == '\r') continue;
        if (c == '\n' || (c >= 0x20 && c < 0x7f)) {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
    return (int)o;
}

int ps_audit_telnet_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit telnet <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 23;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit telnet: bad target '%s'\n", argv[1]);
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

    /* Connect */
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        fprintf(stderr, "audit telnet: cannot resolve %s\n", host);
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
    int rc = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (rc != 0) {
        fprintf(stderr, "audit telnet: cannot connect to %s:%u\n", host, port);
        close(fd); ps_output_close(&out); return 1;
    }

    char banner[1024];
    read_banner(fd, banner, sizeof(banner));
    close(fd);

    /* If we got this far, the Telnet service accepted a TCP connection.
     * That itself is the finding — Telnet sends credentials in plaintext
     * and is obsolete for management interfaces in 2026. */
    char banner_e[1024]; size_t k = 0;
    for (size_t i = 0; banner[i] && k + 2 < sizeof(banner_e); i++) {
        unsigned char c = (unsigned char)banner[i];
        if (c == '"' || c == '\\') { banner_e[k++] = '\\'; banner_e[k++] = (char)c; }
        else if (c == '\n')        { banner_e[k++] = '\\'; banner_e[k++] = 'n'; }
        else if (c >= 0x20 && c < 0x7f) banner_e[k++] = (char)c;
    }
    banner_e[k] = '\0';

    {
        char ev[1200];
        snprintf(ev, sizeof(ev), "{\"banner\":\"%s\"}", banner_e);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.telnet", self_host,
                        "telnet.exposed", PS_SEV_HIGH, PS_CONF_CONFIRMED,
                        "Telnet service is reachable (plaintext, deprecated)");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
    }

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
