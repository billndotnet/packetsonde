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
 * audit snmp -- default-community detection for SNMP v1 / v2c on UDP/161.
 *
 * Sends a GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0) with a candidate
 * community string. A well-formed GetResponse (tag 0xa2) with matching
 * request-id and no error means the community is accepted -- that's the
 * finding. ICMP port-unreachable or timeout means we can't tell.
 *
 * The probe packet is hand-built BER: tiny, no dependency on net-snmp.
 */

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    *port = 161;
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

/* Build an SNMP GetRequest for sysDescr.0 with the given community string
 * and SNMP version. Returns total packet length, or -1 on overflow.
 *
 * Wire layout (BER):
 *   SEQUENCE {
 *     INTEGER version,                       -- 0=v1, 1=v2c
 *     OCTET STRING community,
 *     [0] IMPLICIT SEQUENCE {                -- GetRequest PDU, tag 0xa0
 *       INTEGER request-id,
 *       INTEGER 0,                           -- error-status
 *       INTEGER 0,                           -- error-index
 *       SEQUENCE {                           -- varbinds
 *         SEQUENCE {
 *           OID 1.3.6.1.2.1.1.1.0,
 *           NULL
 *         }
 *       }
 *     }
 *   }
 *
 * For short lengths (<128) BER uses a single byte, which is all we need.
 */
static int build_snmp_get(uint8_t *out, size_t outsz,
                          uint8_t version, const char *community,
                          uint32_t req_id) {
    size_t cl = strlen(community);
    if (cl > 64) return -1;

    /* sysDescr.0 OID: 1.3.6.1.2.1.1.1.0 -> {0x2b, 6, 1, 2, 1, 1, 1, 0} */
    static const uint8_t oid[] = { 0x2b, 6, 1, 2, 1, 1, 1, 0 };
    size_t oid_len = sizeof(oid);

    /* varbind: SEQUENCE { OID, NULL } */
    /* inner: OID + NULL = 2 + oid_len + 2 = oid_len + 4 */
    /* request-id encoded as INTEGER, minimal 4 bytes (we always use 4) */
    uint8_t req_id_b[4] = {
        (uint8_t)((req_id >> 24) & 0xff),
        (uint8_t)((req_id >> 16) & 0xff),
        (uint8_t)((req_id >>  8) & 0xff),
        (uint8_t)(req_id        & 0xff),
    };

    /* Compose from inside out into a scratch buffer, then copy. */
    uint8_t buf[256];
    size_t p = 0;

    /* Outer SEQUENCE */
    buf[p++] = 0x30;
    size_t outer_len_pos = p++;

    /* version INTEGER */
    buf[p++] = 0x02; buf[p++] = 0x01; buf[p++] = version;

    /* community OCTET STRING */
    buf[p++] = 0x04; buf[p++] = (uint8_t)cl;
    memcpy(buf + p, community, cl); p += cl;

    /* GetRequest PDU [0] IMPLICIT SEQUENCE */
    buf[p++] = 0xa0;
    size_t pdu_len_pos = p++;

    /* request-id INTEGER (4 bytes) */
    buf[p++] = 0x02; buf[p++] = 0x04;
    memcpy(buf + p, req_id_b, 4); p += 4;

    /* error-status INTEGER 0 */
    buf[p++] = 0x02; buf[p++] = 0x01; buf[p++] = 0x00;
    /* error-index INTEGER 0 */
    buf[p++] = 0x02; buf[p++] = 0x01; buf[p++] = 0x00;

    /* varbinds SEQUENCE */
    buf[p++] = 0x30;
    size_t vbs_len_pos = p++;

    /* one varbind: SEQUENCE { OID, NULL } */
    buf[p++] = 0x30;
    size_t vb_len_pos = p++;
    buf[p++] = 0x06; buf[p++] = (uint8_t)oid_len;
    memcpy(buf + p, oid, oid_len); p += oid_len;
    buf[p++] = 0x05; buf[p++] = 0x00;
    buf[vb_len_pos] = (uint8_t)(p - vb_len_pos - 1);

    buf[vbs_len_pos] = (uint8_t)(p - vbs_len_pos - 1);
    buf[pdu_len_pos] = (uint8_t)(p - pdu_len_pos - 1);
    buf[outer_len_pos] = (uint8_t)(p - outer_len_pos - 1);

    if (p > outsz) return -1;
    memcpy(out, buf, p);
    return (int)p;
}

/* Returns 1 if reply looks like a valid GetResponse (PDU tag 0xa2) with
 * the same request-id, 0 if not (auth fail / different community / etc).
 * extract_sysdescr fills out the sysDescr string if it's present in the
 * first varbind (best-effort). */
static int parse_snmp_response(const uint8_t *buf, size_t len,
                               uint32_t expect_req_id,
                               char *sysdescr, size_t sysdescr_sz) {
    if (len < 4 || buf[0] != 0x30) return 0;
    size_t p = 2; /* skip SEQUENCE tag+len (assume short-form) */
    /* version */
    if (p + 3 > len || buf[p] != 0x02 || buf[p+1] != 0x01) return 0;
    p += 3;
    /* community */
    if (p + 2 > len || buf[p] != 0x04) return 0;
    size_t cl = buf[p+1]; p += 2 + cl;
    if (p > len) return 0;
    /* PDU: expect 0xa2 = GetResponse */
    if (p + 2 > len || buf[p] != 0xa2) return 0;
    p += 2;
    /* request-id */
    if (p + 2 > len || buf[p] != 0x02) return 0;
    size_t rl = buf[p+1]; p += 2;
    if (rl > 4 || p + rl > len) return 0;
    uint32_t rid = 0;
    for (size_t i = 0; i < rl; i++) rid = (rid << 8) | buf[p+i];
    p += rl;
    if (rid != expect_req_id) return 0;
    /* error-status INTEGER */
    if (p + 3 > len || buf[p] != 0x02) return 1;
    p += 2 + buf[p+1];
    /* error-index INTEGER */
    if (p + 3 > len || buf[p] != 0x02) return 1;
    p += 2 + buf[p+1];
    /* varbinds SEQUENCE */
    if (p + 2 > len || buf[p] != 0x30) return 1;
    p += 2;
    /* first varbind SEQUENCE */
    if (p + 2 > len || buf[p] != 0x30) return 1;
    p += 2;
    /* OID */
    if (p + 2 > len || buf[p] != 0x06) return 1;
    p += 2 + buf[p+1];
    /* value: OCTET STRING for sysDescr */
    if (p + 2 > len) return 1;
    if (buf[p] == 0x04) {
        size_t vl = buf[p+1];
        if (p + 2 + vl > len) return 1;
        size_t copy = vl < sysdescr_sz - 1 ? vl : sysdescr_sz - 1;
        memcpy(sysdescr, buf + p + 2, copy);
        sysdescr[copy] = '\0';
    }
    return 1;
}

static int try_community(int fd, struct sockaddr *addr, socklen_t addrlen,
                         uint8_t version, const char *community,
                         char *sysdescr, size_t sysdescr_sz) {
    uint8_t pkt[256];
    uint32_t rid = 0x70616373; /* "pacs" */
    int n = build_snmp_get(pkt, sizeof(pkt), version, community, rid);
    if (n < 0) return 0;
    if (sendto(fd, pkt, (size_t)n, 0, addr, addrlen) < 0) return 0;
    uint8_t rbuf[1500];
    ssize_t r = recvfrom(fd, rbuf, sizeof(rbuf), 0, NULL, NULL);
    if (r <= 0) return 0;
    return parse_snmp_response(rbuf, (size_t)r, rid, sysdescr, sysdescr_sz);
}

static int snmp_run(int argc, char **argv,
                    const struct ps_args *opts,
                    const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit snmp <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 161;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit snmp: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return 1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return 1; }
    struct timeval tv = { 2, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    char ip[64] = "";
    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));

    /* Try v2c then v1, with "public" then "private". First hit wins.
     * Both common defaults are read-only on most stacks but their presence
     * still leaks sysDescr / topology / interface counters. */
    static const char *communities[] = { "public", "private" };
    static const uint8_t versions[] = { 1, 0 }; /* v2c=1, v1=0 */
    static const char *vlabels[] = { "v2c", "v1" };

    int matched = 0;
    const char *match_community = NULL;
    const char *match_version = NULL;
    char sysdescr[256] = "";

    for (size_t vi = 0; vi < sizeof(versions) && !matched; vi++) {
        for (size_t ci = 0; ci < sizeof(communities) / sizeof(communities[0]) && !matched; ci++) {
            char sd[256] = "";
            if (try_community(fd, res->ai_addr, res->ai_addrlen,
                              versions[vi], communities[ci], sd, sizeof(sd))) {
                matched = 1;
                match_community = communities[ci];
                match_version = vlabels[vi];
                memcpy(sysdescr, sd, sizeof(sysdescr));
            }
        }
    }

    freeaddrinfo(res);
    close(fd);

    if (!matched) {
        /* No response with any default community. Could be filtered, could
         * be silent, could just not be SNMP. No finding. */
        fprintf(stderr, "audit snmp: no response to default communities on %s:%u\n",
                host, port);
        return 1;
    }

    /* Escape sysDescr for JSON */
    char sd_e[512]; size_t si = 0;
    for (size_t i = 0; sysdescr[i] && si + 2 < sizeof(sd_e); i++) {
        unsigned char c = (unsigned char)sysdescr[i];
        if (c == '"' || c == '\\') { sd_e[si++] = '\\'; sd_e[si++] = (char)c; }
        else if (c >= 0x20 && c < 0x7f) sd_e[si++] = (char)c;
    }
    sd_e[si] = '\0';

    {
        char ev[700];
        snprintf(ev, sizeof(ev),
                 "{\"version\":\"%s\",\"community\":\"%s\",\"sysDescr\":\"%s\"}",
                 match_version, match_community, sd_e);
        char title[200];
        snprintf(title, sizeof(title),
                 "SNMP %s accepts default community \"%s\"",
                 match_version, match_community);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.snmp", self_host,
                        "snmp.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED,
                        "SNMP service responded to default community");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);

        struct ps_finding g;
        ps_finding_init(&g, run_id, "cli.audit.snmp", self_host,
                        "snmp.default_community", PS_SEV_HIGH, PS_CONF_CONFIRMED,
                        title);
        ps_finding_set_target_ip(&g, ip, port);
        ps_finding_set_target_hostname(&g, host, port);
        ps_finding_set_evidence_json(&g, ev);
        api->emit(&g);
    }

    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "snmp",
    .summary     = "Audit SNMP v1/v2c: default community detection",
    .run         = snmp_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_snmp_module(void) { return &MODULE; }
