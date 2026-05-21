#include "audit_module.h"
#include "../args.h"
#include "audit_common.h"
#include "finding.h"
#include "ulid.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * audit rdp -- RDP exposure + Network Level Authentication detection.
 *
 * Speaks just enough of the X.224 / TPKT handshake to read the
 * RDP_NEG_RSP. Sends an RDP_NEG_REQ in the X.224 Connection Request
 * advertising support for RDP, TLS, HYBRID (CredSSP/NLA), and HYBRID_EX.
 * The server's RDP_NEG_RSP picks one or returns RDP_NEG_FAILURE.
 *
 * Findings:
 *   rdp.metadata        info     reachable; reports selected protocol
 *   rdp.no_nla          high     server accepts standard RDP/TLS without
 *                                requiring NLA (BlueKeep-class exposure)
 *   rdp.exposed         medium   service is reachable on a wide-open port
 *
 * Wire format (selected fields only):
 *   TPKT header (4 bytes): 03 00 LL LL  -- LL = total length BE
 *   X.224 ConnReq:         <len> e0 <dst-ref> <src-ref> <class>
 *   trailing RDP_NEG_REQ:  01 00 08 00 <requestedProtocols u32 LE>
 *
 * Response is symmetric: TPKT + X.224 ConnConf (cdt byte 0xD0) + optional
 * trailing RDP_NEG_RSP (type 0x02) or RDP_NEG_FAILURE (type 0x03).
 */

static int read_n(int fd, void *buf, size_t want) {
    size_t got = 0;
    while (got < want) {
        ssize_t r = recv(fd, (char *)buf + got, want - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static const char *proto_name(uint32_t p) {
    switch (p) {
        case 0x00000000: return "RDP";          /* legacy RDP only */
        case 0x00000001: return "TLS";          /* PROTOCOL_SSL */
        case 0x00000002: return "HYBRID";       /* CredSSP / NLA */
        case 0x00000008: return "HYBRID_EX";    /* CredSSP + EUL */
        default:         return "unknown";
    }
}

static int rdp_run(int argc, char **argv,
                   const struct ps_args *opts,
                   const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit rdp <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 3389;
    if (ps_audit_parse_target(argv[1], host, sizeof(host), 3389, &port) != 0) {
        fprintf(stderr, "audit rdp: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    char ip[64] = "";
    int fd = ps_audit_tcp_connect(host, port, 5000, ip, sizeof(ip));
    if (fd < 0) {
        fprintf(stderr, "audit rdp: cannot connect to %s:%u\n", host, port);
        return 1;
    }

    /* Build the X.224 Connection Request with an RDP_NEG_REQ asking for
     * RDP, TLS, HYBRID, and HYBRID_EX (0x01 | 0x02 | 0x08 = 0x0b).
     *
     * Layout:
     *   03 00 00 13   -- TPKT version=3, len=19
     *   0e e0 00 00 00 00 00  -- X.224 ConnReq: len=14, code=0xE0, refs+class=0
     *   01 00 08 00 0b 00 00 00  -- RDP_NEG_REQ: type=1, flags=0, len=8, proto=0x0b
     */
    uint8_t req[19] = {
        0x03, 0x00, 0x00, 0x13,
        0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00
    };
    if (send(fd, req, sizeof(req), 0) < 0) {
        close(fd);
        fprintf(stderr, "audit rdp: send failed\n");
        return 1;
    }

    uint8_t tpkt[4];
    if (read_n(fd, tpkt, 4) != 0) {
        close(fd);
        fprintf(stderr, "audit rdp: %s:%u no TPKT response (not RDP?)\n", host, port);
        return 1;
    }
    if (tpkt[0] != 0x03) {
        close(fd);
        fprintf(stderr, "audit rdp: %s:%u response not TPKT (got 0x%02x)\n",
                host, port, tpkt[0]);
        return 1;
    }
    size_t total = ((size_t)tpkt[2] << 8) | tpkt[3];
    if (total < 4 || total > 1024) { close(fd); return 1; }
    uint8_t body[1024];
    size_t want = total - 4;
    if (read_n(fd, body, want) != 0) {
        close(fd);
        fprintf(stderr, "audit rdp: short read on body\n");
        return 1;
    }
    close(fd);

    /* body[0..6] is the X.224 ConnConf header. Tail (if present) is the
     * RDP_NEG_RSP / RDP_NEG_FAILURE starting at offset 7. */
    int has_neg = (want >= 7 + 8) ? 1 : 0;
    uint8_t neg_type = has_neg ? body[7] : 0;
    uint8_t neg_flags = has_neg ? body[8] : 0;
    uint32_t selected = 0;
    uint32_t failure_code = 0;
    if (has_neg) {
        if (neg_type == 0x02) {
            /* RDP_NEG_RSP: selectedProtocol u32 LE at offset 11 */
            selected = (uint32_t)body[11]
                     | ((uint32_t)body[12] << 8)
                     | ((uint32_t)body[13] << 16)
                     | ((uint32_t)body[14] << 24);
        } else if (neg_type == 0x03) {
            failure_code = (uint32_t)body[11]
                         | ((uint32_t)body[12] << 8)
                         | ((uint32_t)body[13] << 16)
                         | ((uint32_t)body[14] << 24);
        }
    }
    (void)neg_flags;

    {
        char ev[400];
        if (neg_type == 0x02) {
            snprintf(ev, sizeof(ev),
                     "{\"selected_protocol\":\"%s\",\"selected_protocol_code\":%u}",
                     proto_name(selected), selected);
        } else if (neg_type == 0x03) {
            snprintf(ev, sizeof(ev),
                     "{\"negotiation_failure_code\":%u}", failure_code);
        } else {
            snprintf(ev, sizeof(ev), "{\"x224_response\":\"no rdp_neg_rsp\"}");
        }
        char title[200];
        snprintf(title, sizeof(title),
                 "RDP reachable (%s)",
                 neg_type == 0x02 ? proto_name(selected) :
                 neg_type == 0x03 ? "negotiation failure" : "no negotiation");
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.rdp", self_host,
                        "rdp.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    /* Posture finding: the port is open. RDP exposed to untrusted networks
     * is a frequent ingress vector (RDP brute-force is the #1 IR initial
     * access vector per most reports). */
    {
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.rdp", self_host,
                        "rdp.exposed", PS_SEV_MEDIUM, PS_CONF_FIRM,
                        "RDP service is reachable");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        api->emit(&f);
    }

    /* No-NLA finding: server selected plain RDP (0) or TLS (1) but not
     * HYBRID (2) or HYBRID_EX (8). Pre-NLA RDP is the BlueKeep-class
     * exposure: pre-auth code on the listener. */
    if (neg_type == 0x02 && selected != 0x02 && selected != 0x08) {
        char ev[200];
        snprintf(ev, sizeof(ev), "{\"selected_protocol\":\"%s\"}",
                 proto_name(selected));
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.rdp", self_host,
                        "rdp.no_nla", PS_SEV_HIGH, PS_CONF_FIRM,
                        "RDP server does not require NLA");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "rdp",
    .summary     = "Audit RDP: exposure + NLA detection",
    .run         = rdp_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_rdp_module(void) { return &MODULE; }
