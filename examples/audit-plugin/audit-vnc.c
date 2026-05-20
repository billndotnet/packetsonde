/* Example custom audit plugin for packetsonde.
 *
 * Detects a VNC server by reading the RFB ProtocolVersion handshake the
 * server sends immediately on TCP connect to port 5900. Emits a posture
 * finding because exposed VNC is a common engagement-find.
 *
 * Build (macOS):
 *   clang -shared -fPIC -DPS_AUDIT_PLUGIN_BUILD=1 \
 *     -I /path/to/packetsonde/src/lib \
 *     -L /path/to/packetsonde/build/src/lib -lpacketsonde_lib \
 *     -o audit-vnc.dylib audit-vnc.c
 *
 * Install:
 *   mkdir -p ~/.config/packetsonde/audits
 *   cp audit-vnc.dylib ~/.config/packetsonde/audits/
 *
 * Use:
 *   packetsonde audit vnc 10.0.0.42
 */

#include "audit_module.h"
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

/* Forward-declared in audit_module.h; we don't need its layout, just the
 * type name. */
struct ps_args;

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    *port = 5900;
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

static int vnc_run(int argc, char **argv,
                   const struct ps_args *opts,
                   const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit vnc <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 5900;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit vnc: bad target '%s'\n", argv[1]);
        return 2;
    }

    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return 1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return 1; }
    struct timeval tv = { 4, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char ip[64] = "";
    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res); close(fd); return 1;
    }
    freeaddrinfo(res);

    /* RFB ProtocolVersion is 12 ASCII bytes: "RFB 003.008\n" or similar. */
    char banner[16] = "";
    ssize_t n = recv(fd, banner, sizeof(banner) - 1, 0);
    close(fd);

    if (n < 12 || strncmp(banner, "RFB ", 4) != 0) {
        /* Not VNC — don't emit, exit clean. */
        return 0;
    }
    banner[12] = '\0';

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    /* Banner is fixed-format "RFB xxx.yyy" — capture as version. */
    char version[16] = "";
    snprintf(version, sizeof(version), "%.11s", banner);

    char ev[160];
    snprintf(ev, sizeof(ev), "{\"protocol\":\"%s\"}", version);
    char title[200];
    snprintf(title, sizeof(title), "VNC server reachable (%s)", version);

    struct ps_finding f;
    ps_finding_init(&f, run_id, "cli.audit.vnc", self_host,
                    "vnc.exposed", PS_SEV_HIGH, PS_CONF_CONFIRMED, title);
    ps_finding_set_target_ip(&f, ip, port);
    ps_finding_set_target_hostname(&f, host, port);
    ps_finding_set_evidence_json(&f, ev);
    api->emit(&f);

    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "vnc",
    .summary     = "Audit VNC exposure (RFB banner)",
    .run         = vnc_run,
};

/* The single symbol the loader dlsyms. */
const struct ps_audit_module *ps_audit_module(void) {
    return &MODULE;
}
