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
    return ps_audit_parse_target(spec, host, host_sz, 143, port);
}

static int read_until(int fd, const char *needle, char *out, size_t outsz) {
    size_t total = 0;
    while (total < outsz - 1) {
        ssize_t r = recv(fd, out + total, outsz - 1 - total, 0);
        if (r <= 0) break;
        total += (size_t)r;
        out[total] = '\0';
        if (strstr(out, needle)) break;
    }
    return (int)total;
}

static int imap_run(int argc, char **argv,
                    const struct ps_args *opts,
                    const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit imap <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 143;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit imap: bad target '%s'\n", argv[1]);
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
    struct timeval tv = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    char ip[64] = "";
    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res); close(fd);
        fprintf(stderr, "audit imap: cannot connect to %s:%u\n", host, port);
        return 1;
    }
    freeaddrinfo(res);

    char greeting[1024] = "";
    read_until(fd, "\r\n", greeting, sizeof(greeting));
    if (strncmp(greeting, "* OK", 4) != 0) {
        close(fd);
        fprintf(stderr, "audit imap: %s:%u not IMAP (greeting=%.50s)\n",
                host, port, greeting);
        return 1;
    }

    /* Ask for capabilities */
    const char *cap_cmd = "A1 CAPABILITY\r\n";
    send(fd, cap_cmd, strlen(cap_cmd), 0);
    char caps[4096] = "";
    read_until(fd, "A1 OK", caps, sizeof(caps));

    /* Logout politely */
    send(fd, "A2 LOGOUT\r\n", 11, 0);
    close(fd);

    int starttls = strcasestr(caps, "STARTTLS") != NULL;
    int login_disabled = strcasestr(caps, "LOGINDISABLED") != NULL;

    /* Strip newlines from greeting for the metadata JSON. */
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
                 "{\"greeting\":\"%s\",\"starttls\":%s,\"logindisabled\":%s}",
                 greet_e, starttls ? "true" : "false",
                 login_disabled ? "true" : "false");
        char title[200];
        snprintf(title, sizeof(title), "IMAP reachable (STARTTLS=%s)",
                 starttls ? "yes" : "no");
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.imap", self_host,
                        "imap.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    /* Port 143 should advertise STARTTLS; if not, plaintext auth is the
     * only option. Port 993 is implicit-TLS, so the test is port-dependent. */
    if (port == 143 && !starttls) {
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.imap", self_host,
                        "imap.no_starttls", PS_SEV_MEDIUM, PS_CONF_FIRM,
                        "IMAP server does not advertise STARTTLS (plaintext only)");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        api->emit(&f);
    }

    /* Server allows LOGIN without TLS — easier to credential-harvest if STARTTLS
     * isn't enforced. */
    if (!login_disabled && !starttls && port == 143) {
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.imap", self_host,
                        "imap.plaintext_login", PS_SEV_HIGH, PS_CONF_FIRM,
                        "IMAP server allows plaintext LOGIN before any TLS");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        api->emit(&f);
    }

    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "imap",
    .summary     = "Audit IMAP: STARTTLS, plaintext LOGIN",
    .run         = imap_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_imap_module(void) { return &MODULE; }
