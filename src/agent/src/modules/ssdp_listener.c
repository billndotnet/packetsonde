/*
 * ssdp_listener.c — Passive SSDP/UPnP listener for PacketSonde Agent
 *
 * Captures UDP packets on port 1900 (SSDP multicast and unicast responses).
 * Parses HTTP-like NOTIFY and RESPONSE messages to extract device type,
 * USN, location URL, and server strings.
 *
 * Publishes to channel: discovery.ssdp
 *
 * JSON output:
 *   {"type":"ssdp","src_ip":"...","nt":"...","usn":"...","location":"...",
 *    "server":"...","interface":"..."}
 */

#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "packetsonde/module_api.h"
#include "json.h"
#include "log.h"

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define ETH_HDR_LEN     14
#define IPV4_HDR_MIN    20
#define UDP_HDR_LEN     8

/* Offsets within IPv4 header (relative to start of IP header) */
#define IP_PROTO_OFFSET  9
#define IP_SRC_OFFSET   12

#define PROTO_UDP        17
#define SSDP_PORT       1900

/* ------------------------------------------------------------------ */
/* State                                                                */
/* ------------------------------------------------------------------ */

struct ssdp_state {
    char iface[64];
};

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

/*
 * Find end of line (CRLF) in buf starting at off, up to buf_len.
 * Returns index of '\r' or buf_len if not found.
 */
static uint32_t find_crlf(const uint8_t *buf, uint32_t off, uint32_t buf_len)
{
    while (off + 1 < buf_len) {
        if (buf[off] == '\r' && buf[off + 1] == '\n') return off;
        off++;
    }
    return buf_len;
}

/*
 * Case-insensitive prefix match. Returns pointer past the prefix in s,
 * or NULL if no match.
 */
static const char *istrprefix(const char *s, const char *prefix)
{
    while (*prefix) {
        char sc = *s;
        char pc = *prefix;
        if (sc >= 'A' && sc <= 'Z') sc += 32;
        if (pc >= 'A' && pc <= 'Z') pc += 32;
        if (sc != pc) return NULL;
        s++; prefix++;
    }
    return s;
}

/*
 * Trim leading whitespace from s (in-place pointer advance).
 */
static const char *ltrim(const char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

/* ------------------------------------------------------------------ */
/* Packet handler                                                       */
/* ------------------------------------------------------------------ */

static void ssdp_on_packet(ps_module_ctx_t *ctx,
                            const uint8_t *pkt, uint32_t len,
                            uint64_t ts_usec, int handle_id)
{
    (void)ts_usec;
    (void)handle_id;

    struct ssdp_state *st = (struct ssdp_state *)ctx->userdata;
    if (!st) return;

    /* Minimum: ETH + IP + UDP + 1 byte payload */
    if (len < (uint32_t)(ETH_HDR_LEN + IPV4_HDR_MIN + UDP_HDR_LEN + 1)) return;

    /* Check ethertype = IPv4 */
    if (read_be16(pkt + 12) != 0x0800) return;

    const uint8_t *ip = pkt + ETH_HDR_LEN;

    /* Check IP version and header length */
    uint8_t ip_version = ip[0] >> 4;
    if (ip_version != 4) return;

    uint8_t ihl = (ip[0] & 0x0f) * 4;
    if (ihl < IPV4_HDR_MIN) return;
    if ((uint32_t)(ETH_HDR_LEN + ihl + UDP_HDR_LEN + 1) > len) return;

    /* Check protocol = UDP */
    if (ip[IP_PROTO_OFFSET] != PROTO_UDP) return;

    /* Extract source IP */
    char src_ip[INET_ADDRSTRLEN] = {0};
    {
        struct in_addr a;
        memcpy(&a, ip + IP_SRC_OFFSET, 4);
        inet_ntop(AF_INET, &a, src_ip, sizeof(src_ip));
    }

    const uint8_t *udp = ip + ihl;
    uint16_t dst_port  = read_be16(udp + 2);
    uint16_t udp_len   = read_be16(udp + 4);

    /* Only interested in destination port 1900 */
    if (dst_port != SSDP_PORT) return;

    if (udp_len < UDP_HDR_LEN) return;
    uint32_t payload_len = (uint32_t)(udp_len - UDP_HDR_LEN);
    const uint8_t *payload = udp + UDP_HDR_LEN;

    /* Clamp payload to what was captured */
    uint32_t avail = len - (uint32_t)(ETH_HDR_LEN + ihl + UDP_HDR_LEN);
    if (payload_len > avail) payload_len = avail;
    if (payload_len == 0) return;

    /* Check for NOTIFY or HTTP/1.1 200 first line */
    if (payload_len < 4) return;
    int is_ssdp = 0;
    if (payload_len >= 6  && memcmp(payload, "NOTIFY", 6) == 0) is_ssdp = 1;
    if (payload_len >= 7  && memcmp(payload, "HTTP/1.", 7) == 0) is_ssdp = 1;
    if (payload_len >= 6  && memcmp(payload, "M-SEAR", 6) == 0) is_ssdp = 1;
    if (!is_ssdp) return;

    char nt[256]       = {0};
    char usn[256]      = {0};
    char location[512] = {0};
    char server[256]   = {0};

    /* Parse lines */
    uint32_t off = 0;
    /* Skip first line (request/status line) */
    uint32_t eol = find_crlf(payload, off, payload_len);
    off = (eol + 2 < payload_len) ? eol + 2 : payload_len;

    while (off < payload_len) {
        eol = find_crlf(payload, off, payload_len);
        uint32_t line_len = eol - off;

        if (line_len == 0) break; /* blank line = end of headers */

        /* NUL-terminate the line in a temp buffer */
        char line[1024];
        if (line_len >= sizeof(line)) line_len = sizeof(line) - 1;
        memcpy(line, payload + off, line_len);
        line[line_len] = '\0';

        const char *rest;
        if ((rest = istrprefix(line, "NT:")) != NULL) {
            rest = ltrim(rest);
            snprintf(nt, sizeof(nt), "%s", rest);
        } else if ((rest = istrprefix(line, "USN:")) != NULL) {
            rest = ltrim(rest);
            snprintf(usn, sizeof(usn), "%s", rest);
        } else if ((rest = istrprefix(line, "LOCATION:")) != NULL) {
            rest = ltrim(rest);
            snprintf(location, sizeof(location), "%s", rest);
        } else if ((rest = istrprefix(line, "SERVER:")) != NULL) {
            rest = ltrim(rest);
            snprintf(server, sizeof(server), "%s", rest);
        }

        off = (eol + 2 < payload_len) ? eol + 2 : payload_len;
    }

    /* Build JSON */
    char buf[4096];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "type",      "ssdp");
    ps_json_key_string(&j, "src_ip",   src_ip);
    ps_json_key_string(&j, "nt",       nt);
    ps_json_key_string(&j, "usn",      usn);
    ps_json_key_string(&j, "location", location);
    ps_json_key_string(&j, "server",   server);
    ps_json_key_string(&j, "interface", st->iface);
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "discovery.ssdp", buf, (uint32_t)j.len);
        ps_debug("ssdp_listener: published src=%s nt=%s", src_ip, nt);
    }
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int ssdp_init(ps_module_ctx_t *ctx)
{
    struct ssdp_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("ssdp_listener: out of memory");
        return -1;
    }

    const char *iface = getenv("PS_CAPTURE_INTERFACE");
    if (!iface) iface = "";
    snprintf(st->iface, sizeof(st->iface), "%s", iface);

    ctx->userdata = st;
    ps_info("ssdp_listener: initialized (iface=%s)", st->iface);
    return 0;
}

static void ssdp_shutdown(ps_module_ctx_t *ctx)
{
    free(ctx->userdata);
    ctx->userdata = NULL;
    ps_info("ssdp_listener: shutdown");
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

const ps_module_t ssdp_module = {
    .name        = "ssdp_listener",
    .description = "Passive SSDP/UPnP listener — device discovery via multicast",
    .version     = "1.0",
    .flags       = PS_MOD_PASSIVE,

    .init        = ssdp_init,
    .shutdown    = ssdp_shutdown,
    .on_packet   = ssdp_on_packet,
    .on_job      = NULL,
    .on_response = NULL,
    .tick        = NULL,
};

/* Self-registration via constructor was deleted -- main.c registers
 * this module explicitly so the global registry exists by then. */
