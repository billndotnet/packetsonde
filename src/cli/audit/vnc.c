#include "audit_module.h"
#include "audit_common.h"
#include "../args.h"
#include "finding.h"
#include "ulid.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * audit vnc -- RFB exposure + auth-posture detection on TCP/5900.
 *
 * Speaks the first two RFB handshake messages:
 *
 *   1. Server -> client: 12-byte ProtocolVersion ("RFB 003.008\n")
 *      We answer with our preferred version (3.008) to elicit the
 *      next phase.
 *   2. Server -> client: SecurityTypes message
 *      - RFB 3.7+:  1 byte count + count bytes of supported types
 *      - RFB 3.3:   4 bytes BE security type (single choice)
 *
 * RFB security type numbers (subset):
 *      0  Invalid (server is going to send an error and close)
 *      1  None        -- no auth at all (anyone who can reach it gets in)
 *      2  VNC         -- DES challenge (weak; standard for old AppleVNC)
 *      5  RA2 / RA2ne -- proprietary, RealVNC
 *     16  Tight       -- TightVNC's variants (still password-based)
 *     18  TLS / VeNCrypt-on-TLS
 *     19  VeNCrypt    -- explicit modern auth (TLS+SASL)
 *
 * Findings:
 *   vnc.metadata     info     reachable; reports protocol version + types
 *   vnc.no_auth      critical type 1 advertised -> any connector gets in
 *   vnc.weak_auth    medium   type 2 advertised, no better option -> DES
 *   vnc.exposed      medium   port reachable (posture marker; always
 *                             emitted when we can speak RFB)
 */

#define VNC_MAX_SECURITY_TYPES 64

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    return ps_audit_parse_target(spec, host, host_sz, 5900, port);
}

static int read_n(int fd, void *buf, size_t want) {
    size_t got = 0;
    while (got < want) {
        ssize_t r = recv(fd, (char *)buf + got, want - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static const char *sec_type_name(uint8_t t) {
    switch (t) {
        case  0: return "Invalid";
        case  1: return "None";
        case  2: return "VNC";
        case  5: return "RA2";
        case  6: return "RA2ne";
        case 16: return "Tight";
        case 17: return "Ultra";
        case 18: return "TLS";
        case 19: return "VeNCrypt";
        case 20: return "SASL";
        case 30: return "Apple Diffie-Hellman";
        default: return "unknown";
    }
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

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    char ip[64] = "";
    int fd = ps_audit_tcp_connect(host, port, 4000, ip, sizeof(ip));
    if (fd < 0) {
        fprintf(stderr, "audit vnc: cannot connect to %s:%u\n", host, port);
        return 1;
    }

    /* Step 1: server sends 12-byte ProtocolVersion. */
    char banner[16] = "";
    if (read_n(fd, banner, 12) != 0) {
        close(fd);
        fprintf(stderr, "audit vnc: short read on RFB banner from %s:%u\n", host, port);
        return 1;
    }
    if (memcmp(banner, "RFB ", 4) != 0) {
        close(fd);
        fprintf(stderr, "audit vnc: %s:%u not RFB (banner=%.12s)\n",
                host, port, banner);
        return 1;
    }
    char version[16] = "";
    /* "RFB xxx.yyy" -- 11 printable chars + newline. */
    memcpy(version, banner, 11); version[11] = '\0';

    int minor = 0;
    if (banner[7] == '.' && banner[4] == '0' && banner[5] == '0' && banner[6] == '3') {
        minor = (banner[8] - '0') * 100 + (banner[9] - '0') * 10 + (banner[10] - '0');
    }

    /* Reply with the server's version verbatim (most compatible) -- we're
     * never going past the security handshake so the protocol version
     * doesn't drive any feature negotiation we care about. */
    if (send(fd, banner, 12, 0) != 12) { close(fd); return 1; }

    /* Step 2: security types. RFB 3.3 = single 4-byte BE type; 3.7+ =
     * 1-byte count + count bytes. */
    uint8_t types[VNC_MAX_SECURITY_TYPES] = {0};
    int n_types = 0;
    int rfb33 = (minor >= 0 && minor < 7);

    if (rfb33) {
        uint8_t hdr[4];
        if (read_n(fd, hdr, 4) != 0) { close(fd); return 1; }
        uint32_t t = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                     ((uint32_t)hdr[2] <<  8) |  (uint32_t)hdr[3];
        if (t <= 0xff) { types[0] = (uint8_t)t; n_types = 1; }
    } else {
        uint8_t cnt = 0;
        if (read_n(fd, &cnt, 1) != 0) { close(fd); return 1; }
        if (cnt == 0) {
            /* Server is going to send a failure-reason string. We don't
             * care -- it just means the server refused us at the security
             * step. Emit metadata anyway. */
        } else {
            if (cnt > VNC_MAX_SECURITY_TYPES) cnt = VNC_MAX_SECURITY_TYPES;
            if (read_n(fd, types, cnt) != 0) { close(fd); return 1; }
            n_types = cnt;
        }
    }
    close(fd);

    /* Render security types as a JSON array for evidence. */
    char types_json[512]; size_t to = 0;
    types_json[to++] = '[';
    for (int i = 0; i < n_types && to < sizeof(types_json) - 32; i++) {
        if (i > 0) types_json[to++] = ',';
        int w = snprintf(types_json + to, sizeof(types_json) - to,
                         "{\"id\":%u,\"name\":\"%s\"}",
                         types[i], sec_type_name(types[i]));
        if (w < 0) break;
        to += (size_t)w;
    }
    types_json[to++] = ']';
    types_json[to] = '\0';

    /* Audit logic:
     *   None (1)   advertised  -> vnc.no_auth (critical)
     *   VNC (2)    AND nothing better -> vnc.weak_auth (medium)
     *   anything   reachable -> vnc.exposed (medium)
     *
     * "Nothing better" = no security type with id >= 16 (TLS / VeNCrypt /
     * SASL / etc). RA2 (5/6) is RealVNC-proprietary and challenge-based;
     * we treat it as comparable to VNC for posture purposes. */
    int has_none = 0, has_vnc = 0, has_strong = 0;
    for (int i = 0; i < n_types; i++) {
        if (types[i] == 1) has_none = 1;
        else if (types[i] == 2) has_vnc = 1;
        else if (types[i] >= 16) has_strong = 1;
    }

    {
        char ev[700];
        snprintf(ev, sizeof(ev),
                 "{\"protocol\":\"%s\",\"security_types\":%s}",
                 version, types_json);
        char title[200];
        snprintf(title, sizeof(title), "VNC server reachable (%s, %d security type%s)",
                 version, n_types, n_types == 1 ? "" : "s");
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.vnc", self_host,
                        "vnc.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    {
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.vnc", self_host,
                        "vnc.exposed", PS_SEV_MEDIUM, PS_CONF_FIRM,
                        "VNC service is reachable");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        api->emit(&f);
    }

    if (has_none) {
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.vnc", self_host,
                        "vnc.no_auth", PS_SEV_CRITICAL, PS_CONF_FIRM,
                        "VNC server advertises security type 'None' (no authentication)");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, "{\"security_type\":\"None\",\"id\":1}");
        api->emit(&f);
    }

    if (has_vnc && !has_strong) {
        /* DES-challenge VNC auth with no TLS/VeNCrypt option. Password
         * key space is 8 bytes truncated, DES-encrypted; trivially
         * crackable offline against a captured handshake. */
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.vnc", self_host,
                        "vnc.weak_auth", PS_SEV_MEDIUM, PS_CONF_FIRM,
                        "VNC server only offers DES-challenge auth (no TLS option)");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, "{\"security_type\":\"VNC\",\"id\":2}");
        api->emit(&f);
    }

    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "vnc",
    .summary     = "Audit VNC: exposure + auth posture",
    .run         = vnc_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_vnc_module(void) { return &MODULE; }
