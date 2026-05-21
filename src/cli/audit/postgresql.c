#include "audit_module.h"
#include "audit_common.h"
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
    return ps_audit_parse_target(spec, host, host_sz, 5432, port);
}

static int postgresql_run(int argc, char **argv,
                      const struct ps_args *opts,
                      const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit postgresql <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 5432;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit postgresql: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

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
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res); close(fd);
        fprintf(stderr, "audit postgresql: cannot connect to %s:%u\n", host, port); return 1;
    }
    freeaddrinfo(res);

    /* PostgreSQL SSLRequest: 4 bytes length (8, BE) + 4 bytes magic (80877103, BE).
     * Response: single byte: 'S' (SSL supported, ready for TLS) or 'N' (no SSL
     * available, server still wants StartupMessage). */
    unsigned char req[8] = { 0x00, 0x00, 0x00, 0x08,
                              0x04, 0xD2, 0x16, 0x2F };
    if (send(fd, req, sizeof(req), 0) != (ssize_t)sizeof(req)) {
        close(fd); return 1;
    }

    unsigned char resp[16];
    ssize_t n = recv(fd, resp, sizeof(resp), 0);
    close(fd);

    if (n < 1) {
        fprintf(stderr, "audit postgresql: no SSLRequest response from %s:%u\n",
                host, port); return 1;
    }

    /* 'S' = SSL OK, 'N' = no SSL, 'E' = error response (probably not Postgres). */
    int ssl_supported = (resp[0] == 'S');
    int ssl_refused   = (resp[0] == 'N');
    int looks_like_pg = ssl_supported || ssl_refused;

    if (!looks_like_pg) {
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.postgresql", self_host,
                        "postgresql.unrecognized", PS_SEV_INFO, PS_CONF_TENTATIVE,
                        "Service does not look like PostgreSQL");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        api->emit(&f);
        return 0;
    }

    {
        char ev[160];
        snprintf(ev, sizeof(ev), "{\"ssl_supported\":%s}",
                 ssl_supported ? "true" : "false");
        char title[200];
        snprintf(title, sizeof(title), "PostgreSQL reachable (SSL=%s)",
                 ssl_supported ? "supported" : "not supported");
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.postgresql", self_host,
                        "postgresql.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    /* SSL refused — plaintext-only PostgreSQL. */
    if (ssl_refused) {
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.postgresql", self_host,
                        "postgresql.no_ssl", PS_SEV_HIGH, PS_CONF_FIRM,
                        "PostgreSQL server does not support SSL/TLS (plaintext only)");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, "{\"ssl_response\":\"N\"}");
        api->emit(&f);
    }

    /* PG reachable from auditor's position — informational posture marker. */
    {
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.postgresql", self_host,
                        "postgresql.reachable", PS_SEV_LOW, PS_CONF_CONFIRMED,
                        "PostgreSQL is reachable from the auditor's network position");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        api->emit(&f);
    }
    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "postgresql",
    .summary     = "Audit PostgreSQL: SSL support",
    .run         = postgresql_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_postgresql_module(void) { return &MODULE; }
