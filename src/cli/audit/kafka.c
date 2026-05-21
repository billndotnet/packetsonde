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

/*
 * audit kafka -- Kafka broker reachability + unauthenticated metadata
 *                disclosure.
 *
 * Sends two requests on TCP/9092:
 *   1. ApiVersions v0  (api_key=18)  -- list of supported APIs / versions
 *   2. Metadata    v1  (api_key=3)   -- broker list + topic list
 *
 * If the Metadata request succeeds, the broker has a PLAINTEXT listener
 * without SASL or ACL gate -- in production this is the common "open kafka
 * cluster" exposure (CVE-class for anything in /tenant_*).
 *
 * Findings:
 *   kafka.metadata           info     reachable; reports node count
 *   kafka.unauthenticated    high     metadata fetch succeeds anonymously
 *
 * Kafka wire format (binary, big-endian, length-prefixed):
 *
 *   Request frame:
 *     int32  request_size      (excludes itself)
 *     int16  api_key
 *     int16  api_version
 *     int32  correlation_id
 *     string client_id         (int16 length, then UTF-8)
 *     <body>
 *
 *   Response frame:
 *     int32  response_size     (excludes itself)
 *     int32  correlation_id
 *     <body>
 */

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    return ps_audit_parse_target(spec, host, host_sz, 9092, port);
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

static void put_i16(uint8_t *p, int16_t v) {
    p[0] = (uint8_t)((v >> 8) & 0xff);
    p[1] = (uint8_t)(v & 0xff);
}
static void put_i32(uint8_t *p, int32_t v) {
    p[0] = (uint8_t)((v >> 24) & 0xff);
    p[1] = (uint8_t)((v >> 16) & 0xff);
    p[2] = (uint8_t)((v >>  8) & 0xff);
    p[3] = (uint8_t)(v & 0xff);
}
static int32_t get_i32(const uint8_t *p) {
    return (int32_t)(((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                     ((uint32_t)p[2] << 8)  |  (uint32_t)p[3]);
}
static int16_t get_i16(const uint8_t *p) {
    return (int16_t)((p[0] << 8) | p[1]);
}

/* Build a Kafka request frame in `out`. Returns total bytes (incl. size
 * prefix) or -1 on overflow. body/body_len is the request body. */
static int build_req(uint8_t *out, size_t outsz,
                     int16_t api_key, int16_t api_ver, int32_t corr_id,
                     const char *client_id,
                     const uint8_t *body, size_t body_len) {
    size_t cl = strlen(client_id);
    size_t total = 4 + 2 + 2 + 4 + 2 + cl + body_len;
    if (total > outsz) return -1;
    put_i32(out, (int32_t)(total - 4));
    put_i16(out + 4, api_key);
    put_i16(out + 6, api_ver);
    put_i32(out + 8, corr_id);
    put_i16(out + 12, (int16_t)cl);
    memcpy(out + 14, client_id, cl);
    if (body_len) memcpy(out + 14 + cl, body, body_len);
    return (int)total;
}

static int read_resp(int fd, uint8_t *buf, size_t bufsz) {
    uint8_t sz[4];
    if (read_n(fd, sz, 4) != 0) return -1;
    int32_t n = get_i32(sz);
    if (n < 4 || (size_t)n > bufsz) return -1;
    if (read_n(fd, buf, (size_t)n) != 0) return -1;
    return n;
}

static int kafka_run(int argc, char **argv,
                     const struct ps_args *opts,
                     const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit kafka <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 9092;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit kafka: bad target '%s'\n", argv[1]);
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
        fprintf(stderr, "audit kafka: cannot connect to %s:%u\n", host, port);
        return 1;
    }
    freeaddrinfo(res);

    /* ApiVersions v0: no body. */
    uint8_t req1[64];
    int n1 = build_req(req1, sizeof(req1), 18, 0, 1, "packetsonde", NULL, 0);
    if (n1 < 0 || send(fd, req1, (size_t)n1, 0) != (ssize_t)n1) {
        close(fd); return 1;
    }
    uint8_t resp[16384];
    int rn = read_resp(fd, resp, sizeof(resp));
    if (rn < 0) {
        close(fd);
        fprintf(stderr, "audit kafka: %s:%u no ApiVersions response (not kafka?)\n",
                host, port);
        return 1;
    }
    /* resp: int32 corr_id (4) + int16 error_code (2) + int32 array_count (4) */
    if (rn < 10) { close(fd); return 1; }
    int16_t apiversions_err = get_i16(resp + 4);
    int32_t apiv_count = get_i32(resp + 6);
    if (apiv_count < 0 || apiv_count > 200) apiv_count = 0; /* sanity */

    /* Metadata v1: body = int32 topic_count (-1 = all topics). */
    uint8_t metabody[4];
    put_i32(metabody, -1);
    uint8_t req2[64];
    int n2 = build_req(req2, sizeof(req2), 3, 1, 2, "packetsonde", metabody, 4);
    int metadata_ok = 0;
    int32_t broker_count = 0;
    int32_t topic_count = 0;
    if (n2 > 0 && send(fd, req2, (size_t)n2, 0) == (ssize_t)n2) {
        rn = read_resp(fd, resp, sizeof(resp));
        if (rn > 8) {
            /* Metadata v1 response:
             *   int32 corr_id (4)
             *   array brokers (int32 count, then per-broker records)
             *     each broker: int32 node_id, string host, int32 port, nullable_string rack
             *   nullable_string controller_id_string OR int32 controller_id (v1)
             *
             * We only read the broker count for the metadata finding. */
            const uint8_t *p = resp + 4; /* skip corr id */
            size_t left = (size_t)rn - 4;
            if (left >= 4) {
                broker_count = get_i32(p);
                p += 4; left -= 4;
                /* Walk through brokers to get to topics, best-effort */
                for (int32_t i = 0; i < broker_count && left > 0; i++) {
                    if (left < 4) { left = 0; break; }
                    p += 4; left -= 4; /* node_id */
                    if (left < 2) { left = 0; break; }
                    int16_t hl = get_i16(p); p += 2; left -= 2;
                    if (hl < 0 || (size_t)hl > left) { left = 0; break; }
                    p += hl; left -= (size_t)hl;
                    if (left < 4) { left = 0; break; }
                    p += 4; left -= 4; /* port */
                    /* rack is nullable_string; int16 len, or -1 for null */
                    if (left < 2) { left = 0; break; }
                    int16_t rl = get_i16(p); p += 2; left -= 2;
                    if (rl > 0 && (size_t)rl <= left) { p += rl; left -= (size_t)rl; }
                }
                if (left >= 4) {
                    /* controller_id (int32) */
                    p += 4; left -= 4;
                    if (left >= 4) topic_count = get_i32(p);
                }
            }
            metadata_ok = 1;
        }
    }
    close(fd);

    {
        char ev[400];
        snprintf(ev, sizeof(ev),
                 "{\"apiversions_error\":%d,\"apiversions_count\":%d,\"brokers\":%d,\"topics\":%d}",
                 apiversions_err, apiv_count, broker_count, topic_count);
        char title[200];
        snprintf(title, sizeof(title),
                 "Kafka broker reachable (%d brokers, %d topics)",
                 broker_count, topic_count);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.kafka", self_host,
                        "kafka.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    /* If we got cluster metadata back, the listener is unauthenticated
     * (PLAINTEXT, no SASL gate, no ACL on Metadata API). Brokers commonly
     * deploy a SASL_PLAINTEXT or SASL_SSL listener separately. */
    if (metadata_ok) {
        char ev[200];
        snprintf(ev, sizeof(ev),
                 "{\"brokers\":%d,\"topics\":%d}", broker_count, topic_count);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.kafka", self_host,
                        "kafka.unauthenticated", PS_SEV_HIGH, PS_CONF_FIRM,
                        "Kafka broker returns cluster metadata without authentication");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "kafka",
    .summary     = "Audit Kafka: reachability + unauthenticated metadata",
    .run         = kafka_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_kafka_module(void) { return &MODULE; }
