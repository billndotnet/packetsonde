#include "udp.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../signals.h"
#include "../util/fail_on.h"
#include "../util/targets.h"
#include "../workers/limiter.h"
#include "../workers/workers.h"
#include "finding.h"
#include "ulid.h"

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* Common UDP services worth probing by default. Each one gets a
 * protocol-specific payload (below) that elicits a response when the
 * service is actually there. */
static const uint16_t DEFAULT_PORTS[] = {
    53,      /* DNS */
    67,      /* DHCP server (rare to scan from outside) */
    69,      /* TFTP */
    123,     /* NTP */
    137,     /* NetBIOS Name Service */
    161,     /* SNMP */
    500,     /* IKE / IPsec */
    514,     /* syslog (rarely responsive but worth probing) */
    1900,    /* SSDP / UPnP */
    5353,    /* mDNS */
    11211,   /* Memcached UDP */
};
static const size_t DEFAULT_PORTS_N = sizeof(DEFAULT_PORTS) / sizeof(DEFAULT_PORTS[0]);

/* Per-port probe payloads that are more likely to elicit a response than an
 * empty packet. Anything not in this table gets a single 0x00 byte. */
struct port_probe {
    uint16_t              port;
    const unsigned char  *payload;
    size_t                payload_len;
    const char           *name;
};

/* DNS query for "version.bind" CHAOS TXT — small, elicits a response from
 * recursive resolvers and most authoritative servers. */
static const unsigned char DNS_PROBE[] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    /* version.bind */
    0x07, 'v','e','r','s','i','o','n',
    0x04, 'b','i','n','d',
    0x00,
    0x00, 0x10,                 /* TXT */
    0x00, 0x03                  /* CHAOS */
};

/* NTP mode 3 client query. */
static const unsigned char NTP_PROBE[] = {
    0x1B, 0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
};

/* SNMPv1 GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0) with community
 * "public". */
static const unsigned char SNMP_PROBE[] = {
    0x30, 0x26,                                      /* SEQUENCE */
    0x02, 0x01, 0x00,                                /* version (1) */
    0x04, 0x06, 'p','u','b','l','i','c',             /* community */
    0xA0, 0x19,                                      /* GetRequest */
    0x02, 0x04, 0x71, 0x82, 0xF5, 0xE2,              /* request-id */
    0x02, 0x01, 0x00,                                /* error-status */
    0x02, 0x01, 0x00,                                /* error-index */
    0x30, 0x0B, 0x30, 0x09,                          /* var-binds */
    0x06, 0x05, 0x2B, 0x06, 0x01, 0x02, 0x01,        /* OID 1.3.6.1.2.1 */
    0x05, 0x00                                       /* NULL */
};

/* SSDP M-SEARCH discovery. */
static const unsigned char SSDP_PROBE[] =
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 1\r\n"
    "ST: ssdp:all\r\n\r\n";

/* NetBIOS Name Service node status query for "*" (workstation lookup). */
static const unsigned char NBNS_PROBE[] = {
    0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x20,
    'C','K','A','A','A','A','A','A','A','A','A','A','A','A','A','A',
    'A','A','A','A','A','A','A','A','A','A','A','A','A','A','A','A',
    0x00,
    0x00, 0x21,                  /* NBSTAT */
    0x00, 0x01                   /* IN */
};

static const struct port_probe PROBES[] = {
    {    53, DNS_PROBE,  sizeof(DNS_PROBE),  "dns" },
    {   123, NTP_PROBE,  sizeof(NTP_PROBE),  "ntp" },
    {   137, NBNS_PROBE, sizeof(NBNS_PROBE), "nbns" },
    {   161, SNMP_PROBE, sizeof(SNMP_PROBE), "snmp" },
    {  1900, SSDP_PROBE, sizeof(SSDP_PROBE) - 1, "ssdp" },
    {  5353, DNS_PROBE,  sizeof(DNS_PROBE),  "mdns" },
    { 0, NULL, 0, NULL }
};

static const struct port_probe *find_probe(uint16_t port) {
    for (size_t i = 0; PROBES[i].payload; i++) {
        if (PROBES[i].port == port) return &PROBES[i];
    }
    return NULL;
}

struct scan_ctx {
    struct ps_output  *out;
    struct ps_workers *W;
    const char        *run_id;
    const char        *self_host;
    int                timeout_ms;
};

struct scan_item {
    struct scan_ctx *ctx;
    char     host[64];
    uint16_t port;
};

/* Send one probe to host:port over a connected UDP socket. Receive any
 * response within timeout. Returns one of:
 *   1 = OPEN (received data)
 *  -1 = CLOSED (ECONNREFUSED — kernel saw ICMP port-unreachable)
 *   0 = OPEN|FILTERED (no response, no ICMP — can't tell apart) */
static int udp_probe(const char *host, uint16_t port, int timeout_ms,
                     unsigned char *resp_out, size_t resp_cap, size_t *resp_n) {
    *resp_n = 0;
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return 0;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return 0; }
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    /* Connecting a UDP socket means recv() will surface ECONNREFUSED if
     * the kernel sees an ICMP port-unreachable. Async errors are
     * delivered via the next syscall. */
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res); close(fd); return 0;
    }
    freeaddrinfo(res);

    const struct port_probe *p = find_probe(port);
    unsigned char fallback = 0;
    const unsigned char *payload = p ? p->payload : &fallback;
    size_t payload_len = p ? p->payload_len : 1;
    if (send(fd, payload, payload_len, 0) < 0) {
        close(fd); return 0;
    }

    ssize_t n = recv(fd, resp_out, resp_cap, 0);
    int rc;
    if (n > 0) {
        *resp_n = (size_t)n;
        rc = 1;
    } else if (n < 0 && errno == ECONNREFUSED) {
        rc = -1;
    } else {
        rc = 0;
    }
    close(fd);
    return rc;
}

static void udp_scan_one(void *arg) {
    struct scan_item *it = (struct scan_item *)arg;
    if (ps_workers_cancelled(it->ctx->W)) { free(it); return; }

    unsigned char resp[1024]; size_t rn = 0;
    int state = udp_probe(it->host, it->port, it->ctx->timeout_ms,
                          resp, sizeof(resp), &rn);

    if (state == 1) {
        /* Open + responding. Render a short hex/ascii preview of the
         * response payload for evidence. */
        char preview[256]; size_t pi = 0;
        size_t to_show = rn < 32 ? rn : 32;
        for (size_t i = 0; i < to_show && pi + 4 < sizeof(preview); i++) {
            unsigned char c = resp[i];
            int n = snprintf(preview + pi, sizeof(preview) - pi, "%02x", c);
            if (n < 0 || (size_t)n >= sizeof(preview) - pi) break;
            pi += (size_t)n;
        }
        preview[pi] = '\0';
        const struct port_probe *p = find_probe(it->port);
        char ev[400];
        snprintf(ev, sizeof(ev),
                 "{\"response_bytes\":%zu,\"probe\":\"%s\","
                 "\"preview_hex\":\"%s\"}",
                 rn, p ? p->name : "raw", preview);
        char title[160];
        snprintf(title, sizeof(title), "Open UDP: %s:%u (%zu B response)",
                 it->host, it->port, rn);
        struct ps_finding f;
        ps_finding_init(&f, it->ctx->run_id, "cli.scan.udp",
                        it->ctx->self_host, "scan.udp.open",
                        PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, it->host, it->port);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(it->ctx->out, &f);
    }
    /* state == -1 (CLOSED) and state == 0 (OPEN|FILTERED) do not emit
     * findings — too noisy. Only the affirmative "open + responding"
     * case is a finding. */
    free(it);
}

static void usage(void) {
    fprintf(stderr,
        "Usage: packetsonde scan udp <target|cidr> [-p PORTS]\n"
        "  PORTS: comma list and dash ranges. Defaults to a curated list of\n"
        "  common UDP services (53, 123, 161, 1900, 5353, ...).\n"
        "\n"
        "Only ports that respond with payload are emitted as findings.\n"
        "Silent ports are indistinguishable from filtered; closed ports\n"
        "(observed via ICMP port-unreachable) are silently ignored.\n");
}

int ps_scan_udp_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }
    const char *target = argv[1];
    const char *ports_arg = NULL;
    optind = 2;
    int c;
    while ((c = getopt(argc, argv, "p:")) != -1) {
        if (c == 'p') ports_arg = optarg;
        else { usage(); return 2; }
    }

    struct ps_cidr cidr;
    if (ps_cidr_parse(target, &cidr) != 0) {
        fprintf(stderr, "scan udp: bad target '%s'\n", target);
        return 2;
    }

    struct ps_portset ports = {0};
    if (ports_arg) {
        if (ps_ports_parse(ports_arg, &ports) != 0) {
            fprintf(stderr, "scan udp: bad ports '%s'\n", ports_arg);
            return 2;
        }
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    struct ps_output_opts oopts; memset(&oopts, 0, sizeof(oopts));
    switch (opts->fmt) {
        case PS_FMT_TEXT:  oopts.fmt_force = PS_OFMT_TEXT;  break;
        case PS_FMT_JSON:  oopts.fmt_force = PS_OFMT_JSON;  break;
        case PS_FMT_JSONL: oopts.fmt_force = PS_OFMT_JSONL; break;
        case PS_FMT_QUIET: oopts.fmt_force = PS_OFMT_QUIET; break;
        default:           oopts.fmt_force = 0;             break;
    }
    oopts.color = opts->no_color ? 0 : 1;
    struct ps_output out; ps_output_init(&out, &oopts);

    struct ps_limiter L;
    int rate = opts->rate_pps > 0 ? opts->rate_pps : 100;
    ps_limiter_init(&L, rate);

    struct ps_workers W;
    int concur = opts->concurrency > 0 ? opts->concurrency : 16;
    ps_workers_init(&W, concur, &L);
    ps_signals_install(&W);

    struct scan_ctx ctx = { &out, &W, run_id, self_host, 1500 };

    const uint16_t *plist = ports_arg ? ports.ports : DEFAULT_PORTS;
    size_t          pcnt  = ports_arg ? ports.count : DEFAULT_PORTS_N;

    for (uint32_t i = 0; i < cidr.count && !ps_workers_cancelled(&W); i++) {
        char host[64];
        if (ps_cidr_addr(&cidr, i, host, sizeof(host)) != 0) continue;
        for (size_t pi = 0; pi < pcnt; pi++) {
            struct scan_item *it = calloc(1, sizeof(*it));
            it->ctx = &ctx;
            snprintf(it->host, sizeof(it->host), "%s", host);
            it->port = plist[pi];
            ps_workers_submit(&W, udp_scan_one, it);
        }
    }

    ps_workers_finish(&W);
    ps_workers_destroy(&W);
    ps_limiter_destroy(&L);
    ps_ports_destroy(&ports);

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
