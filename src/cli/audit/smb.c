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
    return ps_audit_parse_target(spec, host, host_sz, 445, port);
}

static int tcp_connect(const char *host, uint16_t port, int timeout_ms,
                       char *ip_out, size_t ip_out_sz) {
    return ps_audit_tcp_connect(host, port, timeout_ms, ip_out, ip_out_sz);
}

/* SMB1 NEGOTIATE PROTOCOL packet, offering only the "NT LM 0.12" dialect.
 *
 * Wire format: NetBIOS session header (4B) + SMB1 header (32B) + WordCount (1B)
 * + ByteCount (2B) + dialect string ("\x02NT LM 0.12\x00", 14B). Total 53B,
 * NetBIOS length field carrying 0x31 (49B) for everything after the header. */
static const unsigned char SMB1_NEGOTIATE[] = {
    /* NetBIOS Session Service: type=session message, length=0x000031 */
    0x00, 0x00, 0x00, 0x31,
    /* SMB1 header */
    0xFF, 'S', 'M', 'B',                /* Magic */
    0x72,                                /* Command: Negotiate Protocol */
    0x00, 0x00, 0x00, 0x00,             /* NT Status */
    0x18,                                /* Flags */
    0x53, 0xC8,                          /* Flags2 (LE) */
    0x00, 0x00,                          /* PID High */
    0,0,0,0,0,0,0,0,                     /* Signature */
    0x00, 0x00,                          /* Reserved */
    0x00, 0x00,                          /* TID */
    0x2F, 0x4B,                          /* PID Low */
    0x00, 0x00,                          /* UID */
    0xC5, 0x5E,                          /* MID */
    /* SMB body */
    0x00,                                /* WordCount = 0 */
    0x0E, 0x00,                          /* ByteCount = 14 (LE) */
    /* Dialect: BufferFormat (0x02) + "NT LM 0.12" + NUL */
    0x02, 'N','T',' ','L','M',' ','0','.','1','2', 0x00
};

/* SMB2 NEGOTIATE packet. NetBIOS session header + 64-byte SMB2 header +
 * 36-byte NEGOTIATE_REQUEST advertising one dialect (0x0202 = SMB 2.0.2).
 * Servers that support SMB2 or higher will reply with the highest
 * mutually-supported dialect.
 *
 * Total length: 4 + 64 + 36 = 104 bytes; NetBIOS length field = 100 (0x64). */
static const unsigned char SMB2_NEGOTIATE[] = {
    /* NetBIOS Session Service header */
    0x00, 0x00, 0x00, 0x64,
    /* SMB2 header (64 bytes) */
    0xFE, 'S', 'M', 'B',                /* Magic */
    0x40, 0x00,                          /* StructureSize = 64 */
    0x00, 0x00,                          /* CreditCharge */
    0x00, 0x00, 0x00, 0x00,              /* Status */
    0x00, 0x00,                          /* Command = NEGOTIATE (0) */
    0x01, 0x00,                          /* CreditRequest = 1 */
    0x00, 0x00, 0x00, 0x00,              /* Flags */
    0x00, 0x00, 0x00, 0x00,              /* NextCommand */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* MessageId */
    0x00, 0x00, 0x00, 0x00,              /* Reserved */
    0xFF, 0xFE, 0x00, 0x00,              /* TreeId (any) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* SessionId */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* Signature (16 bytes) */
    /* NEGOTIATE_REQUEST (36 bytes) */
    0x24, 0x00,                          /* StructureSize = 36 */
    0x01, 0x00,                          /* DialectCount = 1 */
    0x01, 0x00,                          /* SecurityMode (signing enabled) */
    0x00, 0x00,                          /* Reserved */
    0x00, 0x00, 0x00, 0x00,              /* Capabilities */
    0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x6f,  /* ClientGuid */
    0x6e, 0x64, 0x65, 0x21, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* ClientStartTime */
    0x02, 0x02                           /* Dialect: SMB 2.0.2 */
};

/* One-shot connect + send + recv; the audit makes two of these (SMB1
 * probe then SMB2 probe), each on its own fresh TCP connection. */
static ssize_t smb_probe(const char *host, uint16_t port,
                         const unsigned char *req, size_t req_len,
                         unsigned char *resp, size_t resp_cap,
                         char *ip_out, size_t ip_out_sz) {
    int fd = tcp_connect(host, port, 4000, ip_out, ip_out_sz);
    if (fd < 0) return -1;
    if (send(fd, req, req_len, 0) != (ssize_t)req_len) { close(fd); return -1; }
    ssize_t n = recv(fd, resp, resp_cap, 0);
    close(fd);
    return n;
}

/* Inspect the response framing: 4-byte NetBIOS session header followed
 * by an SMB1 / SMB2 / SMB3-transform magic. Returns 1 = SMB1, 2 = SMB2/3,
 * 0 = unknown / not enough bytes. */
static int classify_smb(const unsigned char *resp, ssize_t n) {
    if (n < 8) return 0;
    if (resp[4] == 0xFF && resp[5] == 'S' && resp[6] == 'M' && resp[7] == 'B') return 1;
    if (resp[4] == 0xFE && resp[5] == 'S' && resp[6] == 'M' && resp[7] == 'B') return 2;
    return 0;
}

static int smb_run(int argc, char **argv,
                      const struct ps_args *opts,
                      const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit smb <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 445;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit smb: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    /* Probe 1: SMB1 NEGOTIATE. A modern hardened server (SMB1 disabled)
     * either drops the connection or replies with a non-SMB1 frame. */
    char ip[64] = "";
    unsigned char resp1[1024];
    ssize_t n1 = smb_probe(host, port, SMB1_NEGOTIATE, sizeof(SMB1_NEGOTIATE),
                           resp1, sizeof(resp1), ip, sizeof(ip));
    int smb1_class = (n1 > 0) ? classify_smb(resp1, n1) : 0;
    int smb1_accepted = (smb1_class == 1);

    /* Probe 2: SMB2 NEGOTIATE. Always run -- gives us a positive signal
     * for "SMB2/3 only" hosts that refuse SMB1, and confirms that an
     * SMB1-accepting host also supports modern dialects (most do). */
    unsigned char resp2[1024];
    ssize_t n2 = smb_probe(host, port, SMB2_NEGOTIATE, sizeof(SMB2_NEGOTIATE),
                           resp2, sizeof(resp2), NULL, 0);
    int smb2_class = (n2 > 0) ? classify_smb(resp2, n2) : 0;
    int smb2_accepted = (smb2_class == 2);

    if (!smb1_accepted && !smb2_accepted) {
        fprintf(stderr, "audit smb: no SMB1 or SMB2 response from %s:%u "
                        "(port open but not speaking SMB?)\n", host, port);
        /* Still emit a metadata finding so the auditor sees we tried. */
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.smb", self_host,
                        "smb.metadata", PS_SEV_INFO, PS_CONF_TENTATIVE,
                        "SMB port reachable but no negotiate response");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        char ev[128];
        snprintf(ev, sizeof(ev),
                 "{\"smb1_response\":%zd,\"smb2_response\":%zd,\"port\":%u}",
                 n1, n2, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
        return 1;
    }

    /* Metadata: what did the server negotiate, summarised. */
    {
        const char *proto = smb1_accepted ? (smb2_accepted ? "SMB1+SMB2/3" : "SMB1")
                          : "SMB2/3";
        char ev[256];
        snprintf(ev, sizeof(ev),
                 "{\"protocol\":\"%s\",\"smb1\":%s,\"smb2\":%s,\"port\":%u}",
                 proto, smb1_accepted ? "true" : "false",
                 smb2_accepted ? "true" : "false", port);
        char title[160];
        snprintf(title, sizeof(title), "SMB negotiate: %s", proto);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.smb", self_host,
                        "smb.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    if (smb1_accepted) {
        /* SMB1 is deprecated as of Windows 10/Server 2016 (off by default
         * since 1709) and is the WannaCry / NotPetya vector via EternalBlue. */
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.smb", self_host,
                        "smb.smb1_enabled", PS_SEV_HIGH, PS_CONF_FIRM,
                        "SMB1 protocol is enabled (EternalBlue / WannaCry surface)");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, "{\"dialect\":\"NT LM 0.12\"}");
        api->emit(&f);
    } else if (smb2_accepted) {
        /* Positive posture finding: server accepts SMB2/3 and refused
         * SMB1. This is the modern hardened configuration; emitting it
         * means an auditor sees an explicit "good" record rather than
         * having to interpret the absence of smb.smb1_enabled. */
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.smb", self_host,
                        "smb.smb2_only", PS_SEV_INFO, PS_CONF_FIRM,
                        "SMB server refuses SMB1; speaks SMB2/3 only");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f,
            "{\"smb1_refused\":true,\"smb2_accepted\":true}");
        api->emit(&f);
    }
    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "smb",
    .summary     = "Audit SMB server: SMB1 enabled (bad) vs SMB2/3 only (good)",
    .run         = smb_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_smb_module(void) { return &MODULE; }
