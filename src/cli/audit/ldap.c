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
    *port = 389;
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

/* LDAP BindRequest, version 3, anonymous (empty name, empty simple auth).
 * ASN.1 BER:
 *   30 0C SEQUENCE len=12
 *     02 01 01            INTEGER messageID = 1
 *     60 07 [APPLICATION 0] BindRequest len=7
 *       02 01 03           INTEGER version = 3
 *       04 00              OCTET STRING name (empty)
 *       80 00              [CONTEXT 0] simple auth (empty) */
static const unsigned char ANON_BIND[] = {
    0x30, 0x0C,
        0x02, 0x01, 0x01,
        0x60, 0x07,
            0x02, 0x01, 0x03,
            0x04, 0x00,
            0x80, 0x00
};

static int ldap_run(int argc, char **argv,
                    const struct ps_args *opts,
                    const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit ldap <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 389;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit ldap: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return 1;
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
        fprintf(stderr, "audit ldap: cannot connect to %s:%u\n", host, port);
        return 1;
    }
    freeaddrinfo(res);

    if (send(fd, ANON_BIND, sizeof(ANON_BIND), 0) != (ssize_t)sizeof(ANON_BIND)) {
        close(fd); return 1;
    }

    unsigned char resp[256];
    ssize_t n = recv(fd, resp, sizeof(resp), 0);
    close(fd);

    /* BindResponse parse:
     *   30 LL SEQUENCE
     *     02 01 01            messageID = 1
     *     61 LL [APPLICATION 1] BindResponse
     *       0a 01 <code>      INTEGER resultCode
     *       04 LL <matchedDN>
     *       04 LL <diagnosticMessage>
     *
     * We want resultCode (success = 0, invalidCredentials = 49, ...). */
    if (n < 14) {
        fprintf(stderr, "audit ldap: short/no response from %s:%u\n", host, port);
        return 1;
    }
    if (resp[0] != 0x30) {
        fprintf(stderr, "audit ldap: response not LDAP-shaped (first byte 0x%02x)\n", resp[0]);
        return 1;
    }
    /* Walk to the BindResponse tag (0x61) and pick up the resultCode byte
     * after the leading "0a 01" tag/length pair. */
    int result_code = -1;
    for (ssize_t i = 0; i < n - 3; i++) {
        if (resp[i] == 0x61) {
            /* skip length byte(s) — assume short form (length < 128) */
            ssize_t p = i + 2;
            if (p + 2 < n && resp[p] == 0x0A && resp[p+1] == 0x01) {
                result_code = resp[p+2];
            }
            break;
        }
    }
    if (result_code < 0) {
        fprintf(stderr, "audit ldap: could not parse BindResponse from %s:%u\n", host, port);
        return 1;
    }

    /* Metadata regardless of result. */
    {
        char ev[160];
        snprintf(ev, sizeof(ev), "{\"bind_result_code\":%d}", result_code);
        char title[200];
        snprintf(title, sizeof(title),
                 "LDAP reachable (anonymous bind result %d)", result_code);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.ldap", self_host,
                        "ldap.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    /* Anonymous bind succeeded (result 0). RFC4511 says servers MAY allow
     * anonymous binds; many directories DO allow them and then expose the
     * directory tree via subsequent searches. */
    if (result_code == 0) {
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.ldap", self_host,
                        "ldap.anonymous_bind", PS_SEV_MEDIUM, PS_CONF_CONFIRMED,
                        "LDAP server accepts anonymous bind");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, "{\"bind_result_code\":0}");
        api->emit(&f);
    }

    /* Plaintext LDAP (port 389) — should be LDAPS (636) or START_TLS. */
    if (port == 389) {
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.ldap", self_host,
                        "ldap.plaintext", PS_SEV_LOW, PS_CONF_FIRM,
                        "LDAP service on plaintext port 389 (use 636/LDAPS or START_TLS)");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        api->emit(&f);
    }

    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "ldap",
    .summary     = "Audit LDAP: anonymous bind, plaintext exposure",
    .run         = ldap_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_ldap_module(void) { return &MODULE; }
