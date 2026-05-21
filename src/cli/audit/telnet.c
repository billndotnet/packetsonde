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
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    return ps_audit_parse_target(spec, host, host_sz, 23, port);
}

/* Read up to outsz-1 printable bytes from fd within the existing timeout.
 * Skips Telnet option-negotiation bytes (IAC sequences: 0xFF + 2 bytes). */
static int read_banner(int fd, char *out, size_t outsz) {
    unsigned char buf[2048];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) { out[0] = '\0'; return 0; }
    size_t o = 0;
    for (ssize_t i = 0; i < n && o + 1 < outsz; i++) {
        if (buf[i] == 0xFF) { i += 2; continue; }
        unsigned char c = buf[i];
        if (c == '\r') continue;
        if (c == '\n' || (c >= 0x20 && c < 0x7f)) out[o++] = (char)c;
    }
    out[o] = '\0';
    return (int)o;
}

static int telnet_run(int argc, char **argv,
                      const struct ps_args *opts,
                      const struct ps_audit_api *api) {
    (void)opts;
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

    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        fprintf(stderr, "audit telnet: cannot resolve %s\n", host);
        return 1;
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
        fprintf(stderr, "audit telnet: cannot connect to %s:%u\n", host, port);
        close(fd);
        return 1;
    }

    char banner[1024];
    read_banner(fd, banner, sizeof(banner));
    close(fd);

    char banner_e[1024]; size_t k = 0;
    for (size_t i = 0; banner[i] && k + 2 < sizeof(banner_e); i++) {
        unsigned char c = (unsigned char)banner[i];
        if (c == '"' || c == '\\') { banner_e[k++] = '\\'; banner_e[k++] = (char)c; }
        else if (c == '\n')        { banner_e[k++] = '\\'; banner_e[k++] = 'n'; }
        else if (c >= 0x20 && c < 0x7f) banner_e[k++] = (char)c;
    }
    banner_e[k] = '\0';

    char ev[1200];
    snprintf(ev, sizeof(ev), "{\"banner\":\"%s\"}", banner_e);
    struct ps_finding f;
    ps_finding_init(&f, run_id, "cli.audit.telnet", self_host,
                    "telnet.exposed", PS_SEV_HIGH, PS_CONF_CONFIRMED,
                    "Telnet service is reachable (plaintext, deprecated)");
    ps_finding_set_target_ip(&f, ip, port);
    ps_finding_set_target_hostname(&f, host, port);
    ps_finding_set_evidence_json(&f, ev);
    api->emit(&f);

    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "telnet",
    .summary     = "Audit Telnet exposure (plaintext, deprecated)",
    .run         = telnet_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) {
    return &MODULE;
}
#endif

/* Also expose a stable internal symbol for the static-link path so the
 * dispatcher's BUILTINS table can pick it up without dlopen. */
const struct ps_audit_module *ps_audit_telnet_module(void) {
    return &MODULE;
}
