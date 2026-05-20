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

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    *port = 123;
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

/* NTP mode 7 (xntpd private) REQ_MON_GETLIST_1 request — the classic monlist
 * amplification probe. If the server responds with substantial data, the
 * server is vulnerable to CVE-2013-5211 amplification. */
static const unsigned char NTP_MONLIST[48] = {
    0x17, 0x00, 0x03, 0x2A,    /* LI=0 VN=2 Mode=7, seq=0, IMPL_XNTPD=3, REQ_MON_GETLIST_1=42 */
    /* 44 zero bytes */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0
};

/* Standard NTPv4 client query (mode 3) — used to confirm the server speaks
 * NTP at all. */
static const unsigned char NTP_CLIENT_QUERY[48] = {
    0x1B,                       /* LI=0 VN=3 Mode=3 */
    0,0,0,
    0,0,0,0,  0,0,0,0,
    0,0,0,0,  0,0,0,0,
    0,0,0,0,  0,0,0,0,
    0,0,0,0,  0,0,0,0,
    0,0,0,0,  0,0,0,0
};

static int udp_query(const char *host, uint16_t port,
                     const unsigned char *q, size_t qlen,
                     unsigned char *r, size_t r_cap,
                     int timeout_ms,
                     char *ip_out, size_t ip_out_sz) {
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (ip_out && ip_out_sz) {
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &sin->sin_addr, ip_out, (socklen_t)ip_out_sz);
    }
    ssize_t s = sendto(fd, q, qlen, 0, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (s != (ssize_t)qlen) { close(fd); return -1; }
    ssize_t n = recv(fd, r, r_cap, 0);
    close(fd);
    return (int)n;
}

static int ntp_run(int argc, char **argv,
                      const struct ps_args *opts,
                      const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit ntp <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 123;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit ntp: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    char ip[64] = "";
    unsigned char resp[2048];

    /* Confirm the server speaks NTP at all. */
    int n = udp_query(host, port, NTP_CLIENT_QUERY, sizeof(NTP_CLIENT_QUERY),
                      resp, sizeof(resp), 2500, ip, sizeof(ip));
    if (n < 48) {
        fprintf(stderr, "audit ntp: no NTP response from %s:%u\n", host, port); return 1;
    }

    /* Metadata finding — NTP service reachable. */
    int stratum = resp[1];
    char ev[256];
    snprintf(ev, sizeof(ev), "{\"stratum\":%d}", stratum);
    {
        char title[160];
        snprintf(title, sizeof(title), "NTP server reachable (stratum %d)", stratum);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.ntp", self_host,
                        "ntp.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    /* Mode 7 monlist probe. CVE-2013-5211: ntpd before 4.2.7p26 responded
     * with up to 600 packets, each ~440 bytes, to a single 234-byte query. */
    int m = udp_query(host, port, NTP_MONLIST, sizeof(NTP_MONLIST),
                      resp, sizeof(resp), 2500, NULL, 0);
    if (m >= 8) {
        /* If we got any substantial response to the monlist request, the
         * mode-7 interface is open. Some hardened ntpds respond with an
         * INFO_ERR_REQ rejection (still ~12 bytes) — that's also a leak
         * because it confirms mode-7 is enabled; flag at lower severity. */
        unsigned char rmvn = resp[0];
        int err = (resp[1] & 0x40) ? 1 : 0;
        if (m > 48 && !err) {
            char ev2[160];
            snprintf(ev2, sizeof(ev2),
                "{\"response_bytes\":%d,\"amplification_factor\":%.1f,"
                "\"cve\":\"CVE-2013-5211\"}",
                m, (double)m / sizeof(NTP_MONLIST));
            struct ps_finding f;
            ps_finding_init(&f, run_id, "cli.audit.ntp", self_host,
                            "ntp.monlist_amplification", PS_SEV_CRITICAL,
                            PS_CONF_CONFIRMED,
                            "NTP server responds to mode-7 MON_GETLIST_1 (amplification vector)");
            ps_finding_set_target_ip(&f, ip, port);
            ps_finding_set_target_hostname(&f, host, port);
            ps_finding_set_evidence_json(&f, ev2);
            api->emit(&f);
        } else if ((rmvn & 0x07) == 7) {
            /* Mode 7 enabled but request rejected — still a small information
             * leak about software identity. */
            struct ps_finding f;
            ps_finding_init(&f, run_id, "cli.audit.ntp", self_host,
                            "ntp.mode7_enabled", PS_SEV_LOW, PS_CONF_FIRM,
                            "NTP mode-7 (xntpd private) interface enabled");
            ps_finding_set_target_ip(&f, ip, port);
            ps_finding_set_target_hostname(&f, host, port);
            ps_finding_set_evidence_json(&f, "{\"mode7\":true}");
            api->emit(&f);
        }
    }
    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "ntp",
    .summary     = "Audit NTP: monlist amplification, mode-7 leak",
    .run         = ntp_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_ntp_module(void) { return &MODULE; }
