/*
 * udp_probe.c — UDP service probing module for PacketSonde Agent
 *
 * Sends UDP probes to target ports and listens for responses.
 * Supports protocol-aware payloads for DNS (port 53) and SNMP (port 161).
 * All other ports receive a generic 4-byte probe payload.
 *
 * Uses regular UDP sockets — no elevated privileges required.
 * Probe logic runs synchronously in on_job (blocking, 3s max per port).
 *
 * Up to 16 concurrent probe jobs (job slots reserved; probes run inline).
 *
 * Output channel: probe.result
 *   {"job_id":"...","address":"1.2.3.4","port":53,"proto":"udp",
 *    "state":"open","banner":"DNS responding"}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include "packetsonde/module_api.h"
#include "json.h"
#include "log.h"

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define UDP_PROBE_MAX_JOBS      16
#define UDP_PROBE_TIMEOUT_SEC   3
#define UDP_PROBE_RECV_BUF      512

/* Well-known ports */
#define PORT_DNS   53
#define PORT_SNMP  161

/* Generic probe magic: "\x00PS\x00" */
static const uint8_t UDP_PROBE_GENERIC[4] = { 0x00, 0x50, 0x53, 0x00 };

/* ------------------------------------------------------------------ */
/* DNS query builder                                                    */
/* ------------------------------------------------------------------ */

/*
 * Build a minimal DNS A query for "version.bind" (CHAOS class).
 * This is a standard service-detection trick — many DNS servers respond.
 *
 * Wire format:
 *   Header (12 bytes): ID=0x5053, QR=0, OPCODE=0, RD=1, QDCOUNT=1
 *   Question: \x07version\x04bind\x00, QTYPE=TXT(16), QCLASS=CHAOS(3)
 *
 * Returns the number of bytes written to buf, or 0 on error.
 */
static uint32_t build_dns_query(uint8_t *buf, size_t bufsz)
{
    /* Precomputed DNS query bytes */
    static const uint8_t dns_query[] = {
        /* Header */
        0x50, 0x53,  /* ID = 0x5053 "PS" */
        0x01, 0x00,  /* QR=0, OPCODE=0, AA=0, TC=0, RD=1 */
        0x00, 0x01,  /* QDCOUNT=1 */
        0x00, 0x00,  /* ANCOUNT=0 */
        0x00, 0x00,  /* NSCOUNT=0 */
        0x00, 0x00,  /* ARCOUNT=0 */
        /* Question: version.bind */
        0x07, 'v','e','r','s','i','o','n',
        0x04, 'b','i','n','d',
        0x00,        /* root label */
        0x00, 0x10,  /* QTYPE=TXT (16) */
        0x00, 0x03,  /* QCLASS=CHAOS (3) */
    };

    if (bufsz < sizeof(dns_query)) return 0;
    memcpy(buf, dns_query, sizeof(dns_query));
    return (uint32_t)sizeof(dns_query);
}

/* ------------------------------------------------------------------ */
/* SNMP v2c GetRequest builder                                          */
/* ------------------------------------------------------------------ */

/*
 * Build a minimal SNMPv2c GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0)
 * with community string "public".
 *
 * This is a pre-encoded BER/DER blob — SNMP encoding is fixed for this OID.
 *
 * Returns the number of bytes written to buf, or 0 on error.
 */
static uint32_t build_snmp_query(uint8_t *buf, size_t bufsz)
{
    /*
     * SNMPv2c GetRequest for sysDescr.0
     * Community: "public"
     * Request-ID: 0x5053 (0x00005053)
     *
     * Verified against RFC 3416 / RFC 3418.
     */
    static const uint8_t snmp_query[] = {
        0x30, 0x35,              /* SEQUENCE, length=53 */
          0x02, 0x01, 0x01,      /* INTEGER: version = 1 (SNMPv2c) */
          0x04, 0x06,            /* OCTET STRING: community */
            'p','u','b','l','i','c',
          0xa0, 0x28,            /* GetRequest-PDU, length=40 */
            0x02, 0x04,          /* INTEGER: request-id */
              0x00, 0x00, 0x50, 0x53,
            0x02, 0x01, 0x00,    /* INTEGER: error-status = 0 */
            0x02, 0x01, 0x00,    /* INTEGER: error-index = 0 */
            0x30, 0x1a,          /* SEQUENCE: variable-bindings */
              0x30, 0x18,        /* SEQUENCE: varbind */
                0x06, 0x09,      /* OID: 1.3.6.1.2.1.1.1.0 */
                  0x2b, 0x06, 0x01, 0x02,
                  0x01, 0x01, 0x01, 0x00,
                  0x00,          /* (trailing 0 for .0) */
                  /* NOTE: OID 1.3.6.1.2.1.1.1.0 encodes as:
                   *   2b 06 01 02 01 01 01 00 is 9 bytes but .0 suffix
                   *   actually the full encoding is:
                   *   1.3 → 0x2b, 6 → 0x06, 1 → 0x01, 2 → 0x02,
                   *   1 → 0x01, 1 → 0x01, 1 → 0x01, 0 → 0x00
                   */
                0x05, 0x00,      /* NULL: value */
    };

    /*
     * Re-encode cleanly.  The above has an ambiguous comment; use a fresh
     * hand-verified encoding for sysDescr.0.
     *
     * SNMPv2c GetRequest PDU structure (total outer SEQUENCE = 41 bytes):
     *
     * 30 27                         SEQUENCE (39)
     *   02 01 01                    version: 1 (v2c)
     *   04 06 70 75 62 6c 69 63    community: "public"
     *   a0 1a                       GetRequest-PDU (26)
     *     02 04 00 00 50 53         request-id: 0x5053
     *     02 01 00                  error-status: 0
     *     02 01 00                  error-index: 0
     *     30 0c                     VarBindList (12)
     *       30 0a                   VarBind (10)
     *         06 06 2b 06 01 02 01 01   OID: 1.3.6.1.2.1 (sysDescr.0 prefix — 8 bytes OID value)
     *         NO — sysDescr.0 = 1.3.6.1.2.1.1.1.0
     *         OID bytes: 2b 06 01 02 01 01 01 00  (8 bytes)
     *         05 00                 NULL value
     */

    /* Use a clean pre-built encoding verified byte-by-byte */
    static const uint8_t snmp_clean[] = {
        0x30, 0x29,                               /* SEQUENCE (41 bytes body) */
          0x02, 0x01, 0x01,                       /* version: 1 = v2c */
          0x04, 0x06, 'p','u','b','l','i','c',    /* community: "public" (8 bytes) */
          0xa0, 0x1c,                             /* GetRequest-PDU (28 bytes body) */
            0x02, 0x04, 0x00, 0x00, 0x50, 0x53,  /* request-id: 0x5053 (6 bytes) */
            0x02, 0x01, 0x00,                     /* error-status: 0 (3 bytes) */
            0x02, 0x01, 0x00,                     /* error-index: 0 (3 bytes) */
            0x30, 0x0e,                           /* VarBindList (14 bytes body) */
              0x30, 0x0c,                         /* VarBind (12 bytes body) */
                0x06, 0x08,                       /* OID (8 bytes) */
                  0x2b, 0x06, 0x01, 0x02,         /* 1.3.6.1.2 */
                  0x01, 0x01, 0x01, 0x00,         /* .1.1.0 = sysDescr.0 */
                0x05, 0x00,                       /* NULL (2 bytes) */
    };

    (void)snmp_query;  /* suppress unused warning — using snmp_clean */

    if (bufsz < sizeof(snmp_clean)) return 0;
    memcpy(buf, snmp_clean, sizeof(snmp_clean));
    return (uint32_t)sizeof(snmp_clean);
}

/* ------------------------------------------------------------------ */
/* Response banner extraction                                           */
/* ------------------------------------------------------------------ */

/*
 * Try to extract a human-readable banner from a DNS response.
 * A valid DNS response has ID 0x5053 (bytes 0-1) and QR=1 (byte 2 bit 7).
 * Returns a static banner string for the caller to copy.
 */
static const char *parse_dns_banner(const uint8_t *buf, uint32_t len)
{
    if (len < 12) return "DNS responding";

    uint16_t id;
    memcpy(&id, buf, 2);
    id = ntohs(id);

    uint8_t flags_hi = buf[2];
    int qr = (flags_hi >> 7) & 1;

    if (id == 0x5053 && qr == 1)
        return "DNS responding";

    /* Any response at all is a sign of life */
    return "UDP port open";
}

/*
 * Try to extract a banner from an SNMP response.
 * Valid SNMPv2c response PDU (0xa2) at the community/PDU level.
 */
static const char *parse_snmp_banner(const uint8_t *buf, uint32_t len)
{
    if (len < 8) return "SNMP responding";

    /* Top-level must be SEQUENCE (0x30) */
    if (buf[0] != 0x30) return "UDP port open";

    /* Walk: version, community, then look for GetResponse-PDU (0xa2) */
    if (len >= 5 && buf[0] == 0x30) {
        /* Search for GetResponse-PDU tag 0xa2 within first 64 bytes */
        uint32_t search = len < 64 ? len : 64;
        for (uint32_t i = 2; i < search; i++) {
            if (buf[i] == 0xa2)
                return "SNMP responding";
        }
    }

    return "UDP port open";
}

/* ------------------------------------------------------------------ */
/* State                                                                */
/* ------------------------------------------------------------------ */

struct udp_probe_job {
    int  active;
    char job_id[64];
};

struct udp_probe_state {
    struct udp_probe_job jobs[UDP_PROBE_MAX_JOBS];
};

/* ------------------------------------------------------------------ */
/* Result publishing                                                    */
/* ------------------------------------------------------------------ */

static void publish_result(ps_module_ctx_t *ctx,
                           const char *job_id,
                           const char *address,
                           int port,
                           const char *state,
                           const char *banner)
{
    char buf[512];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "job_id",  job_id);
    ps_json_key_string(&j, "address", address);
    ps_json_key_int   (&j, "port",    (int64_t)port);
    ps_json_key_string(&j, "proto",   "udp");
    ps_json_key_string(&j, "state",   state);
    ps_json_key_string(&j, "banner",  banner);
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "probe.result", buf, (uint32_t)j.len);
    }
}

/* ------------------------------------------------------------------ */
/* Core probe logic                                                     */
/* ------------------------------------------------------------------ */

/*
 * Probe a single (address, port) over UDP.
 * Creates a UDP socket, sends a protocol-appropriate payload,
 * waits up to UDP_PROBE_TIMEOUT_SEC for a response.
 * Publishes the result and closes the socket.
 */
static void probe_udp_port(ps_module_ctx_t *ctx,
                           const char *job_id,
                           const char *address,
                           int port,
                           int af,
                           const struct sockaddr *dest_sa,
                           socklen_t dest_sa_len)
{
    uint8_t  pkt[64];
    uint32_t pkt_len = 0;

    /* Build protocol-appropriate payload */
    if (port == PORT_DNS) {
        pkt_len = build_dns_query(pkt, sizeof(pkt));
    } else if (port == PORT_SNMP) {
        pkt_len = build_snmp_query(pkt, sizeof(pkt));
    }

    if (pkt_len == 0) {
        /* Generic probe */
        memcpy(pkt, UDP_PROBE_GENERIC, sizeof(UDP_PROBE_GENERIC));
        pkt_len = sizeof(UDP_PROBE_GENERIC);
    }

    /* Create UDP socket */
    int sock = socket(af, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ps_warn("udp_probe: socket() failed for %s:%d: %s",
                address, port, strerror(errno));
        publish_result(ctx, job_id, address, port, "no_response",
                       "socket error");
        return;
    }

    /* Set receive timeout */
    struct timeval tv;
    tv.tv_sec  = UDP_PROBE_TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        ps_warn("udp_probe: setsockopt SO_RCVTIMEO failed: %s", strerror(errno));
        /* Non-fatal — continue with default timeout behavior */
    }

    /* Send probe */
    ssize_t sent = sendto(sock, pkt, pkt_len, 0, dest_sa, dest_sa_len);
    if (sent < 0) {
        ps_warn("udp_probe: sendto %s:%d failed: %s",
                address, port, strerror(errno));
        close(sock);
        publish_result(ctx, job_id, address, port, "no_response",
                       "send error");
        return;
    }

    ps_debug("udp_probe: sent %u bytes to %s:%d", pkt_len, address, port);

    /* Wait for response using select for portability */
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);

    struct timeval timeout;
    timeout.tv_sec  = UDP_PROBE_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    int ready = select(sock + 1, &rfds, NULL, NULL, &timeout);
    if (ready < 0) {
        ps_warn("udp_probe: select() error for %s:%d: %s",
                address, port, strerror(errno));
        close(sock);
        publish_result(ctx, job_id, address, port, "no_response",
                       "select error");
        return;
    }

    if (ready == 0) {
        /* Timeout */
        ps_debug("udp_probe: timeout for %s:%d", address, port);
        close(sock);
        publish_result(ctx, job_id, address, port, "no_response", "");
        return;
    }

    /* Receive response */
    uint8_t  resp[UDP_PROBE_RECV_BUF];
    struct sockaddr_storage src_addr;
    socklen_t src_len = sizeof(src_addr);

    ssize_t n = recvfrom(sock, resp, sizeof(resp), 0,
                         (struct sockaddr *)&src_addr, &src_len);
    close(sock);

    if (n < 0) {
        ps_warn("udp_probe: recvfrom %s:%d failed: %s",
                address, port, strerror(errno));
        publish_result(ctx, job_id, address, port, "no_response",
                       "recv error");
        return;
    }

    /* Parse banner based on port */
    const char *banner;
    if (port == PORT_DNS) {
        banner = parse_dns_banner(resp, (uint32_t)n);
    } else if (port == PORT_SNMP) {
        banner = parse_snmp_banner(resp, (uint32_t)n);
    } else {
        banner = "UDP port open";
    }

    ps_info("udp_probe: %s:%d — open (%s)", address, port, banner);
    publish_result(ctx, job_id, address, port, "open", banner);
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int udp_probe_init(ps_module_ctx_t *ctx)
{
    struct udp_probe_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("udp_probe: out of memory");
        return -1;
    }
    ctx->userdata = st;
    ps_info("udp_probe: initialized (%d job slots)", UDP_PROBE_MAX_JOBS);
    return 0;
}

static void udp_probe_shutdown(ps_module_ctx_t *ctx)
{
    free(ctx->userdata);
    ctx->userdata = NULL;
    ps_info("udp_probe: shutdown");
}

static int udp_probe_on_job(ps_module_ctx_t *ctx, const struct ps_job *job)
{
    struct udp_probe_state *st = (struct udp_probe_state *)ctx->userdata;
    if (!st) return -1;

    /*
     * Accept jobs that:
     *  - are dispatched on probe.request with proto == "udp", or
     *  - have method == "udp_probe", or
     *  - have no method set (default to us when tcp_port is set and proto
     *    field isn't handled by another module — callers should set method).
     *
     * Reject jobs explicitly meant for other methods.
     */
    if (job->method[0] != '\0' &&
        strcmp(job->method, "udp_probe") != 0 &&
        strcmp(job->method, "udp") != 0) {
        return 0;  /* Not for us */
    }

    if (job->destination[0] == '\0') {
        ps_warn("udp_probe: job '%s' has no destination", job->job_id);
        return -1;
    }

    if (job->tcp_port <= 0 || job->tcp_port > 65535) {
        ps_warn("udp_probe: job '%s' has invalid port %d", job->job_id, job->tcp_port);
        return -1;
    }

    /* Find a free slot (tracks active jobs for future concurrency limiting) */
    struct udp_probe_job *slot = NULL;
    for (int i = 0; i < UDP_PROBE_MAX_JOBS; i++) {
        if (!st->jobs[i].active) {
            slot = &st->jobs[i];
            break;
        }
    }
    if (!slot) {
        ps_warn("udp_probe: all %d job slots busy, dropping job '%s'",
                UDP_PROBE_MAX_JOBS, job->job_id);
        return -1;
    }

    /* Claim the slot */
    slot->active = 1;
    strncpy(slot->job_id, job->job_id, sizeof(slot->job_id) - 1);
    slot->job_id[sizeof(slot->job_id) - 1] = '\0';

    /* Resolve destination */
    int af_hint = AF_UNSPEC;
    if (job->af == 4)      af_hint = AF_INET;
    else if (job->af == 6) af_hint = AF_INET6;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = af_hint;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", job->tcp_port);

    int rc = getaddrinfo(job->destination, port_str, &hints, &res);
    if (rc != 0) {
        ps_warn("udp_probe: getaddrinfo('%s') failed: %s",
                job->destination, gai_strerror(rc));
        slot->active = 0;
        return -1;
    }

    /* Extract numeric address string for result reporting */
    char addr_str[64];
    addr_str[0] = '\0';
    int af = res->ai_family;
    if (af == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
    } else if (af == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)res->ai_addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str, sizeof(addr_str));
    } else {
        strncpy(addr_str, job->destination, sizeof(addr_str) - 1);
    }

    ps_info("udp_probe: probing %s:%d (resolved: %s) for job '%s'",
            job->destination, job->tcp_port, addr_str, job->job_id);

    /* Run probe synchronously */
    probe_udp_port(ctx,
                   job->job_id,
                   addr_str,
                   job->tcp_port,
                   af,
                   res->ai_addr,
                   (socklen_t)res->ai_addrlen);

    freeaddrinfo(res);

    /* Release slot */
    slot->active = 0;

    return 0;
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

#ifndef PS_UDP_PROBE_TESTING

const ps_module_t ps_udp_probe_module = {
    .name        = "udp_probe",
    .description = "UDP service probing (DNS, SNMP, arbitrary)",
    .version     = "1.0",
    .flags       = PS_MOD_ACTIVE,   /* regular sockets — no root needed */

    .init        = udp_probe_init,
    .shutdown    = udp_probe_shutdown,
    .on_packet   = NULL,
    .on_job      = udp_probe_on_job,
    .on_response = NULL,            /* synchronous probe — no async response */
    .tick        = NULL,
};

#endif /* PS_UDP_PROBE_TESTING */
