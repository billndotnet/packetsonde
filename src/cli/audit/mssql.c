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

/*
 * audit mssql -- Microsoft SQL Server pre-login probe (TDS).
 *
 * Sends a TDS Pre-Login packet (PacketType 0x12) advertising client
 * version/encryption/instance/threadID. The server returns its own
 * Pre-Login response with:
 *   token 0 (VERSION):    4-byte major.minor.build + 2-byte subbuild
 *   token 1 (ENCRYPTION): 1 byte: 0=OFF, 1=ON, 2=NOT_SUP, 3=REQ
 *   token 2 (INSTOPT):    bytes
 *   token 3 (THREADID):   4 bytes
 *   token 4 (MARS):       1 byte
 *   FF terminator
 *
 * Findings:
 *   mssql.metadata     info     reachable; reports version + encryption posture
 *   mssql.no_encryption high    server says encryption is OFF or NOT_SUP
 *   mssql.old_version  medium   major < 13 (SQL Server 2016) -- EOL family
 *
 * Wire layout (header is 8 bytes):
 *   01 byte  PacketType  -- 0x12 pre-login
 *   01 byte  Status      -- 0x01 EOM
 *   02 byte  Length      -- BE, includes header
 *   02 byte  SPID        -- 0
 *   01 byte  PacketID    -- 1
 *   01 byte  Window      -- 0
 */

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    *port = 1433;
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

static int read_n(int fd, void *buf, size_t want) {
    size_t got = 0;
    while (got < want) {
        ssize_t r = recv(fd, (char *)buf + got, want - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static const char *enc_name(uint8_t e) {
    switch (e) {
        case 0: return "off";        /* available, not used unless client demands */
        case 1: return "on";         /* server requires encryption for login only */
        case 2: return "not_supported";
        case 3: return "required";   /* server requires encryption for all traffic */
        default: return "unknown";
    }
}

static int mssql_run(int argc, char **argv,
                     const struct ps_args *opts,
                     const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit mssql <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 1433;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit mssql: bad target '%s'\n", argv[1]);
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
        fprintf(stderr, "audit mssql: cannot connect to %s:%u\n", host, port);
        return 1;
    }
    freeaddrinfo(res);

    /* Build pre-login packet.
     *
     * Header (8) + 5 option entries (5 bytes each = 25) + terminator (1)
     * + data payload. We send version=9.0.0.0 (any modern client), encryption=
     * 0x01 (encrypt login only), threadID=0.
     *
     *   Option entry: u8 token, u16 offset (BE), u16 length (BE)
     *   Token list:   0=VERSION (6 bytes), 1=ENCRYPTION (1), 2=INSTOPT (1),
     *                 3=THREADID (4), 4=MARS (1), 0xff=terminator
     */
    uint8_t pkt[64];
    size_t p = 0;
    /* TDS header */
    pkt[p++] = 0x12;             /* type: pre-login */
    pkt[p++] = 0x01;             /* status: EOM */
    pkt[p++] = 0x00;             /* length high (fill later) */
    pkt[p++] = 0x00;             /* length low  (fill later) */
    pkt[p++] = 0x00; pkt[p++] = 0x00;  /* SPID */
    pkt[p++] = 0x01;             /* PacketID */
    pkt[p++] = 0x00;             /* Window */

    /* option table */
    size_t opt_start = p;
    /* placeholders: token, offset (filled later), length */
    pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x06; /* VERSION len=6 */
    pkt[p++] = 0x01; pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x01; /* ENCRYPTION len=1 */
    pkt[p++] = 0x02; pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x01; /* INSTOPT len=1 */
    pkt[p++] = 0x03; pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x04; /* THREADID len=4 */
    pkt[p++] = 0x04; pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x01; /* MARS len=1 */
    pkt[p++] = 0xff; /* terminator */

    /* data payload starts at offset = p relative to TDS header (offset 8) */
    size_t data_off_in_payload = p - 8;
    /* VERSION: 9.0.0.0 + 0 subbuild */
    pkt[p++] = 0x09; pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x00;
    pkt[p++] = 0x00; pkt[p++] = 0x00;
    /* ENCRYPTION: 0x01 = encrypt login */
    pkt[p++] = 0x01;
    /* INSTOPT: empty (0x00) */
    pkt[p++] = 0x00;
    /* THREADID: 0 */
    pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x00; pkt[p++] = 0x00;
    /* MARS: 0 (off) */
    pkt[p++] = 0x00;

    /* Backpatch option offsets. Each token entry is 5 bytes; offset BE u16. */
    size_t cur_off = data_off_in_payload;
    static const size_t lens[5] = { 6, 1, 1, 4, 1 };
    for (int i = 0; i < 5; i++) {
        size_t entry = opt_start + (size_t)i * 5;
        pkt[entry + 1] = (uint8_t)((cur_off >> 8) & 0xff);
        pkt[entry + 2] = (uint8_t)(cur_off & 0xff);
        cur_off += lens[i];
    }
    /* Total length backpatch */
    pkt[2] = (uint8_t)((p >> 8) & 0xff);
    pkt[3] = (uint8_t)(p & 0xff);

    if (send(fd, pkt, p, 0) < 0) {
        close(fd);
        fprintf(stderr, "audit mssql: send failed\n");
        return 1;
    }

    /* Read response. Same 8-byte TDS header, then payload up to (length-8). */
    uint8_t hdr[8];
    if (read_n(fd, hdr, 8) != 0) {
        close(fd);
        fprintf(stderr, "audit mssql: %s:%u no TDS response\n", host, port);
        return 1;
    }
    if (hdr[0] != 0x04) {
        /* type 0x04 is "tabular result" used for pre-login response */
        close(fd);
        fprintf(stderr, "audit mssql: %s:%u response type=0x%02x (not pre-login)\n",
                host, port, hdr[0]);
        return 1;
    }
    size_t total = ((size_t)hdr[2] << 8) | hdr[3];
    if (total < 8 || total > 1024) { close(fd); return 1; }
    uint8_t body[1024];
    size_t want = total - 8;
    if (read_n(fd, body, want) != 0) { close(fd); return 1; }
    close(fd);

    /* Walk the option table. Each entry: token (1) + offset (BE u16) + length
     * (BE u16). The data is at `offset` measured from the start of the body. */
    uint8_t version_maj = 0, version_min = 0;
    uint16_t version_build = 0;
    uint8_t encryption = 0xff;
    int saw_version = 0, saw_encryption = 0;

    for (size_t i = 0; i + 5 <= want; ) {
        uint8_t token = body[i];
        if (token == 0xff) break;
        if (i + 5 > want) break;
        size_t off = ((size_t)body[i + 1] << 8) | body[i + 2];
        size_t len = ((size_t)body[i + 3] << 8) | body[i + 4];
        if (off + len > want) break;
        if (token == 0 && len >= 6) {
            version_maj = body[off];
            version_min = body[off + 1];
            version_build = (uint16_t)((body[off + 2] << 8) | body[off + 3]);
            saw_version = 1;
        } else if (token == 1 && len >= 1) {
            encryption = body[off];
            saw_encryption = 1;
        }
        i += 5;
    }

    {
        char ev[400];
        snprintf(ev, sizeof(ev),
                 "{\"version_major\":%u,\"version_minor\":%u,\"version_build\":%u,\"encryption\":\"%s\"}",
                 version_maj, version_min, version_build,
                 saw_encryption ? enc_name(encryption) : "unknown");
        char title[200];
        if (saw_version) {
            snprintf(title, sizeof(title),
                     "Microsoft SQL Server %u.%u.%u (encryption=%s)",
                     version_maj, version_min, version_build,
                     saw_encryption ? enc_name(encryption) : "unknown");
        } else {
            snprintf(title, sizeof(title), "Microsoft SQL Server reachable");
        }
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.mssql", self_host,
                        "mssql.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    /* Encryption posture: OFF (0) and NOT_SUPPORTED (2) both mean traffic
     * can be plaintext on the wire. ON (1) means login is encrypted; data
     * payload may still be plaintext. REQUIRED (3) is the safe state. */
    if (saw_encryption && (encryption == 0 || encryption == 2)) {
        char ev[200];
        snprintf(ev, sizeof(ev), "{\"encryption\":\"%s\"}", enc_name(encryption));
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.mssql", self_host,
                        "mssql.no_encryption", PS_SEV_HIGH, PS_CONF_FIRM,
                        "MSSQL server does not support or require encryption");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    /* Version posture: SQL Server 2016 is internal version 13. Anything <13
     * is past mainstream support (2014=12 went out 2024-07). */
    if (saw_version && version_maj < 13) {
        char ev[200];
        snprintf(ev, sizeof(ev),
                 "{\"version_major\":%u,\"version_minor\":%u,\"version_build\":%u}",
                 version_maj, version_min, version_build);
        char title[160];
        snprintf(title, sizeof(title),
                 "MSSQL version %u.%u predates SQL Server 2016 (EOL)",
                 version_maj, version_min);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.mssql", self_host,
                        "mssql.old_version", PS_SEV_MEDIUM, PS_CONF_FIRM, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "mssql",
    .summary     = "Audit Microsoft SQL Server: version + encryption posture",
    .run         = mssql_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_mssql_module(void) { return &MODULE; }
