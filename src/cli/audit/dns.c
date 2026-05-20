#include "audit_module.h"
#include "../args.h"
#include "finding.h"
#include "ulid.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static uint16_t g_txid = 0x1234;

static int append_name(uint8_t *buf, size_t *off, size_t cap, const char *name) {
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (len == 0 || len > 63) return -1;
        if (*off + len + 1 >= cap) return -1;
        buf[(*off)++] = (uint8_t)len;
        memcpy(buf + *off, p, len);
        *off += len;
        if (!dot) break;
        p = dot + 1;
    }
    if (*off + 1 >= cap) return -1;
    buf[(*off)++] = 0;
    return 0;
}

static int build_query(uint8_t *buf, size_t cap, const char *name,
                       uint16_t qtype, uint16_t qclass, int rd) {
    if (cap < 12) return -1;
    uint16_t txid = ++g_txid;
    buf[0] = (uint8_t)(txid >> 8); buf[1] = (uint8_t)(txid & 0xff);
    buf[2] = rd ? 0x01 : 0x00;
    buf[3] = 0x00;
    buf[4] = 0x00; buf[5] = 0x01;
    buf[6] = buf[7] = buf[8] = buf[9] = buf[10] = buf[11] = 0;
    size_t off = 12;
    if (append_name(buf, &off, cap, name) != 0) return -1;
    if (off + 4 >= cap) return -1;
    buf[off++] = (uint8_t)(qtype >> 8);  buf[off++] = (uint8_t)(qtype & 0xff);
    buf[off++] = (uint8_t)(qclass >> 8); buf[off++] = (uint8_t)(qclass & 0xff);
    return (int)off;
}

static int udp_query(const char *server, uint16_t port,
                     const uint8_t *q, size_t qlen,
                     uint8_t *resp, size_t resp_cap,
                     int timeout_ms) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in dst; memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    if (inet_pton(AF_INET, server, &dst.sin_addr) != 1) {
        close(fd); return -1;
    }
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (sendto(fd, q, qlen, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        close(fd); return -1;
    }
    ssize_t n = recv(fd, resp, resp_cap, 0);
    close(fd);
    return (int)n;
}

static int extract_txt(const uint8_t *resp, size_t n, char *out, size_t outsz) {
    if (n < 12) return -1;
    size_t pos = 12;
    int qd = (resp[4] << 8) | resp[5];
    while (qd-- > 0 && pos < n) {
        while (pos < n && resp[pos] != 0) {
            if ((resp[pos] & 0xC0) == 0xC0) { pos += 2; goto qdone; }
            pos += resp[pos] + 1;
        }
        if (pos < n) pos += 1;
qdone:  pos += 4;
    }
    int an = (resp[6] << 8) | resp[7];
    while (an-- > 0 && pos < n) {
        while (pos < n && resp[pos] != 0) {
            if ((resp[pos] & 0xC0) == 0xC0) { pos += 2; goto adone; }
            pos += resp[pos] + 1;
        }
        if (pos < n) pos += 1;
adone:  if (pos + 10 > n) return -1;
        uint16_t type = (resp[pos] << 8) | resp[pos+1];
        pos += 8;
        uint16_t rdlen = (resp[pos] << 8) | resp[pos+1];
        pos += 2;
        if (pos + rdlen > n) return -1;
        if (type == 16 /* TXT */) {
            uint8_t slen = resp[pos];
            if (slen > rdlen - 1) return -1;
            size_t k = slen < outsz - 1 ? slen : outsz - 1;
            memcpy(out, resp + pos + 1, k);
            out[k] = '\0';
            return 0;
        }
        pos += rdlen;
    }
    return -1;
}

static int dns_run(int argc, char **argv,
                      const struct ps_args *opts,
                      const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit dns <resolver-ip>[:port]\n");
        return 2;
    }
    char host[64] = ""; uint16_t port = 53;
    const char *colon = strrchr(argv[1], ':');
    if (colon) {
        size_t hl = (size_t)(colon - argv[1]);
        if (hl >= sizeof(host)) return 2;
        memcpy(host, argv[1], hl); host[hl] = '\0';
        port = (uint16_t)atoi(colon + 1);
    } else {
        snprintf(host, sizeof(host), "%s", argv[1]);
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    /* version.bind CHAOS TXT */
    {
        uint8_t q[512]; int qlen = build_query(q, sizeof(q), "version.bind", 16, 3, 1);
        uint8_t r[4096];
        int n = qlen > 0 ? udp_query(host, port, q, qlen, r, sizeof(r), 1500) : -1;
        char ver[256] = "";
        if (n > 0 && extract_txt(r, (size_t)n, ver, sizeof(ver)) == 0 && ver[0]) {
            char ev[320];
            snprintf(ev, sizeof(ev), "{\"version\":\"%s\"}", ver);
            char title[320];
            snprintf(title, sizeof(title), "Resolver discloses version: %s", ver);
            struct ps_finding f;
            ps_finding_init(&f, run_id, "cli.audit.dns", self_host,
                            "dns.version_leak", PS_SEV_LOW, PS_CONF_FIRM, title);
            ps_finding_set_target_ip(&f, host, port);
            ps_finding_set_evidence_json(&f, ev);
            api->emit(&f);
        }
    }

    /* Open-recursion check */
    {
        uint8_t q[512]; int qlen = build_query(q, sizeof(q), "example.com", 1, 1, 1);
        uint8_t r[4096];
        int n = qlen > 0 ? udp_query(host, port, q, qlen, r, sizeof(r), 2500) : -1;
        if (n >= 12) {
            int ancount = (r[6] << 8) | r[7];
            int ra      = (r[3] & 0x80) ? 1 : 0;
            if (ra && ancount > 0) {
                char ev[160];
                snprintf(ev, sizeof(ev), "{\"ra\":true,\"ancount\":%d}", ancount);
                struct ps_finding f;
                ps_finding_init(&f, run_id, "cli.audit.dns", self_host,
                                "dns.open_recursion", PS_SEV_HIGH, PS_CONF_FIRM,
                                "Resolver answers recursive queries from external clients");
                ps_finding_set_target_ip(&f, host, port);
                ps_finding_set_evidence_json(&f, ev);
                api->emit(&f);
            }
        }
    }
    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "dns",
    .summary     = "Audit DNS resolver: version leak, open recursion",
    .run         = dns_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_dns_module(void) { return &MODULE; }
