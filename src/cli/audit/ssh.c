#include "ssh.h"
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
    *port = 22;
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

static int read_banner(const char *host, uint16_t port, int timeout_ms,
                       char *ip_out, size_t ip_out_sz,
                       char *banner_out, size_t banner_sz) {
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
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res); close(fd); return -1;
    }
    freeaddrinfo(res);

    /* SSH server sends the version banner first. Read until first \n. */
    size_t got = 0;
    while (got < banner_sz - 1) {
        char c;
        ssize_t r = recv(fd, &c, 1, 0);
        if (r <= 0) break;
        if (c == '\n') break;
        if (c == '\r') continue;
        if (c >= 0x20 && c < 0x7f) banner_out[got++] = c;
    }
    banner_out[got] = '\0';
    close(fd);
    return banner_out[0] ? 0 : -1;
}

/* Returns 1 if the banner indicates a known-old / known-vulnerable OpenSSH.
 * Heuristic: OpenSSH < 7.4 is genuinely old (released 2016-12); flag those. */
static int openssh_is_old(const char *banner, char *ver_out, size_t ver_sz) {
    ver_out[0] = '\0';
    const char *p = strstr(banner, "OpenSSH_");
    if (!p) return 0;
    p += 8;
    /* Parse major.minor */
    int major = 0, minor = 0;
    if (sscanf(p, "%d.%d", &major, &minor) < 2) return 0;
    /* Copy version token */
    size_t k = 0;
    while (p[k] && (isdigit((unsigned char)p[k]) || p[k] == '.' || p[k] == 'p') && k < ver_sz - 1) {
        ver_out[k] = p[k]; k++;
    }
    ver_out[k] = '\0';
    if (major < 7) return 1;
    if (major == 7 && minor < 4) return 1;
    return 0;
}

int ps_audit_ssh_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit ssh <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 22;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit ssh: bad target '%s'\n", argv[1]);
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

    char ip[64] = "", banner[256] = "";
    int rc = read_banner(host, port, 4000, ip, sizeof(ip), banner, sizeof(banner));
    if (rc != 0) {
        fprintf(stderr, "audit ssh: no banner from %s:%u\n", host, port);
        ps_output_close(&out);
        return 1;
    }
    if (strncmp(banner, "SSH-", 4) != 0) {
        fprintf(stderr, "audit ssh: %s:%u does not speak SSH (got %.80s)\n",
                host, port, banner);
        ps_output_close(&out);
        return 1;
    }

    /* Banner format: SSH-protoversion-softwareversion[ comments] */
    char esc[256]; size_t k = 0;
    for (size_t i = 0; banner[i] && k + 2 < sizeof(esc); i++) {
        unsigned char c = (unsigned char)banner[i];
        if (c == '"' || c == '\\') { esc[k++] = '\\'; esc[k++] = (char)c; }
        else esc[k++] = (char)c;
    }
    esc[k] = '\0';

    /* tls.metadata equivalent — record what we saw. */
    {
        char ev[512];
        snprintf(ev, sizeof(ev), "{\"banner\":\"%s\"}", esc);
        char title[320];
        snprintf(title, sizeof(title), "SSH banner: %s", banner);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.ssh", self_host,
                        "ssh.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
    }

    /* Version disclosure — SSH banners always disclose software version per RFC,
     * so this is an info-severity acknowledgement, not a security finding. We
     * only flag if the version is identifiably old. */
    {
        char ver[64];
        if (openssh_is_old(banner, ver, sizeof(ver))) {
            char ev[256];
            snprintf(ev, sizeof(ev),
                     "{\"software\":\"OpenSSH\",\"version\":\"%s\","
                     "\"recommended_minimum\":\"7.4\"}", ver);
            char title[256];
            snprintf(title, sizeof(title),
                     "OpenSSH %s is older than 7.4 (released Dec 2016)", ver);
            struct ps_finding f;
            ps_finding_init(&f, run_id, "cli.audit.ssh", self_host,
                            "ssh.old_version", PS_SEV_MEDIUM, PS_CONF_FIRM, title);
            ps_finding_set_target_ip(&f, ip, port);
            ps_finding_set_target_hostname(&f, host, port);
            ps_finding_set_evidence_json(&f, ev);
            ps_output_emit(&out, &f);
        }
    }

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
