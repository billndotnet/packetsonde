#include "audit_module.h"
#include "../args.h"
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
    *port = 21;
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

/* Read one FTP response line (terminated by \r\n). Handles multi-line replies
 * where the first line has "NNN-" and subsequent lines have "NNN " on the
 * final line. Returns the numeric response code or 0 on error. */
static int ftp_read_response(int fd, char *line_out, size_t line_sz) {
    char buf[2048] = ""; size_t total = 0;
    int code = 0;
    char code_str[4] = "";
    for (;;) {
        if (total >= sizeof(buf) - 1) break;
        ssize_t r = recv(fd, buf + total, sizeof(buf) - 1 - total, 0);
        if (r <= 0) break;
        total += (size_t)r;
        buf[total] = '\0';

        /* Look for a line that starts with "NNN " (final line of a multi-line
         * response) or a single-line response. */
        char *p = buf;
        while (*p) {
            char *nl = strstr(p, "\r\n");
            if (!nl) break;
            *nl = '\0';
            if (strlen(p) >= 4 && p[3] == ' ') {
                /* Final line. */
                strncpy(code_str, p, 3); code_str[3] = '\0';
                code = atoi(code_str);
                if (line_out && line_sz > 0) {
                    snprintf(line_out, line_sz, "%s", p);
                }
                return code;
            }
            p = nl + 2;
        }
    }
    if (line_out && line_sz) line_out[0] = '\0';
    return 0;
}

static int ftp_send(int fd, const char *cmd) {
    return (int)send(fd, cmd, strlen(cmd), 0);
}

static int ftp_run(int argc, char **argv,
                      const struct ps_args *opts,
                      const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit ftp <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 21;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit ftp: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    /* Connect */
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) { return 1;
    }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return 1; }
    struct timeval tv = { 4, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    char ip[64] = "";
    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
    int rc = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (rc != 0) {
        fprintf(stderr, "audit ftp: cannot connect to %s:%u\n", host, port);
        close(fd); return 1;
    }

    /* Read greeting (220) */
    char greeting[1024] = "";
    int greet_code = ftp_read_response(fd, greeting, sizeof(greeting));
    if (greet_code != 220) {
        close(fd);
        fprintf(stderr, "audit ftp: %s:%u did not greet with 220 (got %d)\n",
                host, port, greet_code); return 1;
    }

    /* Emit metadata finding with banner. */
    char banner_e[1024]; size_t k = 0;
    for (size_t i = 0; greeting[i] && k + 2 < sizeof(banner_e); i++) {
        unsigned char c = (unsigned char)greeting[i];
        if (c == '"' || c == '\\') { banner_e[k++] = '\\'; banner_e[k++] = (char)c; }
        else if (c >= 0x20 && c < 0x7f) banner_e[k++] = (char)c;
    }
    banner_e[k] = '\0';
    {
        char ev[1100];
        snprintf(ev, sizeof(ev), "{\"banner\":\"%s\"}", banner_e);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.ftp", self_host,
                        "ftp.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED,
                        "FTP service reachable (plaintext protocol)");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    /* Try anonymous login. */
    ftp_send(fd, "USER anonymous\r\n");
    char r1[256] = ""; int c1 = ftp_read_response(fd, r1, sizeof(r1));
    int anon_allowed = 0;
    if (c1 == 230) {
        /* No password required — already logged in. */
        anon_allowed = 1;
    } else if (c1 == 331) {
        ftp_send(fd, "PASS anonymous@packetsonde\r\n");
        char r2[256] = ""; int c2 = ftp_read_response(fd, r2, sizeof(r2));
        if (c2 == 230) anon_allowed = 1;
    }
    /* Close politely */
    ftp_send(fd, "QUIT\r\n");
    close(fd);

    if (anon_allowed) {
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.ftp", self_host,
                        "ftp.anonymous_allowed", PS_SEV_HIGH, PS_CONF_CONFIRMED,
                        "FTP server permits anonymous login");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, "{\"user\":\"anonymous\"}");
        api->emit(&f);
    }

    /* Plaintext-protocol finding: FTP itself is the issue if exposed without
     * FTPS / SFTP. Lower severity than telnet (FTP servers often coexist with
     * legitimate read-only public file distribution use cases). */
    {
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.ftp", self_host,
                        "ftp.plaintext_exposed", PS_SEV_MEDIUM, PS_CONF_FIRM,
                        "FTP control channel is plaintext (use FTPS or SFTP)");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        api->emit(&f);
    }
    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "ftp",
    .summary     = "Audit FTP server: anonymous login, plaintext",
    .run         = ftp_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_ftp_module(void) { return &MODULE; }
