#include "audit_module.h"
#include "audit_common.h"
#include "../args.h"
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
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    return ps_audit_parse_target(spec, host, host_sz, 110, port);
}

static int read_line(int fd, char *out, size_t outsz) {
    size_t total = 0;
    while (total < outsz - 1) {
        char c;
        ssize_t r = recv(fd, &c, 1, 0);
        if (r <= 0) break;
        out[total++] = c;
        if (c == '\n') break;
    }
    out[total] = '\0';
    return (int)total;
}

static int pop3_run(int argc, char **argv,
                    const struct ps_args *opts,
                    const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit pop3 <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 110;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit pop3: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    char ip[64] = "";
    int fd = ps_audit_tcp_connect(host, port, 5000, ip, sizeof(ip));
    if (fd < 0) {
        fprintf(stderr, "audit pop3: cannot connect to %s:%u\n", host, port);
        return 1;
    }

    char greeting[1024] = "";
    read_line(fd, greeting, sizeof(greeting));
    if (strncmp(greeting, "+OK", 3) != 0) {
        close(fd);
        fprintf(stderr, "audit pop3: %s:%u not POP3 (greeting=%.50s)\n",
                host, port, greeting);
        return 1;
    }

    /* Ask for capabilities */
    send(fd, "CAPA\r\n", 6, 0);
    char caps[4096] = ""; size_t cap_len = 0;
    /* CAPA response is multi-line; ends with ".\r\n" */
    while (cap_len < sizeof(caps) - 1) {
        char line[256] = "";
        int n = read_line(fd, line, sizeof(line));
        if (n <= 0) break;
        if (cap_len + (size_t)n < sizeof(caps)) {
            memcpy(caps + cap_len, line, n);
            cap_len += (size_t)n;
        }
        if (strcmp(line, ".\r\n") == 0 || strcmp(line, ".\n") == 0) break;
    }
    caps[cap_len] = '\0';

    /* Logout politely */
    send(fd, "QUIT\r\n", 6, 0);
    close(fd);

    int stls = strcasestr(caps, "STLS") != NULL;

    char greet_e[256]; size_t gi = 0;
    for (size_t i = 0; greeting[i] && gi + 2 < sizeof(greet_e); i++) {
        unsigned char c = (unsigned char)greeting[i];
        if (c == '"' || c == '\\') { greet_e[gi++] = '\\'; greet_e[gi++] = (char)c; }
        else if (c >= 0x20 && c < 0x7f) greet_e[gi++] = (char)c;
    }
    greet_e[gi] = '\0';

    {
        char ev[400];
        snprintf(ev, sizeof(ev),
                 "{\"greeting\":\"%s\",\"stls\":%s}",
                 greet_e, stls ? "true" : "false");
        char title[200];
        snprintf(title, sizeof(title), "POP3 reachable (STLS=%s)",
                 stls ? "yes" : "no");
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.pop3", self_host,
                        "pop3.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    /* Port 110 should advertise STLS. Port 995 is implicit-TLS. */
    if (port == 110 && !stls) {
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.pop3", self_host,
                        "pop3.no_stls", PS_SEV_MEDIUM, PS_CONF_FIRM,
                        "POP3 server does not advertise STLS (plaintext only)");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        api->emit(&f);
    }

    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "pop3",
    .summary     = "Audit POP3: STLS support",
    .run         = pop3_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_pop3_module(void) { return &MODULE; }
