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

    char ip[64] = "";
    int fd = tcp_connect(host, port, 4000, ip, sizeof(ip));
    if (fd < 0) {
        fprintf(stderr, "audit smb: cannot connect to %s:%u\n", host, port); return 1;
    }

    if (send(fd, SMB1_NEGOTIATE, sizeof(SMB1_NEGOTIATE), 0) != (ssize_t)sizeof(SMB1_NEGOTIATE)) {
        close(fd); return 1;
    }

    unsigned char resp[1024];
    ssize_t n = recv(fd, resp, sizeof(resp), 0);
    close(fd);

    if (n < 5) {
        fprintf(stderr, "audit smb: no usable response from %s:%u\n", host, port); return 1;
    }

    /* Response framing:
     *   bytes 0..3: NetBIOS session header (type 0x00, length)
     *   bytes 4..7: SMB magic
     * SMB1 magic = 0xFF S M B; SMB2/3 magic = 0xFE S M B; SMB3 transform = 0xFD. */
    int is_smb1 = (n >= 8 && resp[4] == 0xFF && resp[5] == 'S' && resp[6] == 'M' && resp[7] == 'B');
    int is_smb2 = (n >= 8 && resp[4] == 0xFE && resp[5] == 'S' && resp[6] == 'M' && resp[7] == 'B');

    /* Build the metadata finding regardless. */
    {
        const char *proto = is_smb1 ? "SMB1" : is_smb2 ? "SMB2/3" : "unknown";
        char ev[256];
        snprintf(ev, sizeof(ev),
                 "{\"protocol\":\"%s\",\"port\":%u}", proto, port);
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

    if (is_smb1) {
        /* Server accepted an SMB1-only NEGOTIATE — SMB1 is enabled.
         * SMB1 is deprecated as of Windows 10/Server 2016 (off by default
         * since 1709) and is the WannaCry / NotPetya vector via EternalBlue. */
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.smb", self_host,
                        "smb.smb1_enabled", PS_SEV_HIGH, PS_CONF_FIRM,
                        "SMB1 protocol is enabled (EternalBlue / WannaCry surface)");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, "{\"dialect\":\"NT LM 0.12\"}");
        api->emit(&f);
    }
    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "smb",
    .summary     = "Audit SMB server: detect SMB1 (EternalBlue surface)",
    .run         = smb_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_smb_module(void) { return &MODULE; }
