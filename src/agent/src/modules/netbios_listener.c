/*
 * netbios_listener.c — Passive NetBIOS/LLMNR listener for PacketSonde Agent
 *
 * Captures:
 *   UDP 137 — NetBIOS Name Service (NBNS): name responses, NBSTAT records
 *   UDP 138 — NetBIOS Datagram Service: source name extraction
 *   UDP 5355 — LLMNR: DNS-wire-format name queries/responses
 *
 * Publishes to channel: discovery.netbios
 *
 * JSON output:
 *   {"type":"netbios_ns","src_ip":"...","name":"...","name_type":"0x20",
 *    "workgroup":"...","interface":"..."}
 */

#include <stdio.h>
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

/* Offsets in IPv4 header */
#define IP_PROTO_OFFSET  9
#define IP_SRC_OFFSET   12

#define PROTO_UDP       17

#define NBNS_PORT       137
#define NBDG_PORT       138
#define LLMNR_PORT      5355

/* NBNS header layout (12 bytes) */
#define NBNS_HDR_LEN    12
#define NBNS_FLAG_QR    0x8000   /* bit 15: response */

/* NetBIOS name suffix types */
#define NB_TYPE_WORKSTATION    0x00
#define NB_TYPE_FILE_SERVER    0x20
#define NB_TYPE_DC             0x1C
#define NB_TYPE_MASTER_BROWSER 0x1D

/* ------------------------------------------------------------------ */
/* State                                                                */
/* ------------------------------------------------------------------ */

struct netbios_state {
    char iface[64];
};

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |
            (uint32_t)p[3];
}

/*
 * Decode a NetBIOS first-level encoded name.
 * Input: 32 uppercase ASCII letters (each pair encodes one byte via A=0 offset)
 * Output: name string (15 chars, trailing spaces trimmed) and suffix byte.
 * Returns 1 on success, 0 on error.
 */
static int decode_nb_name(const uint8_t *encoded, char *name_out, uint8_t *suffix_out)
{
    /* Expect 32 characters */
    uint8_t decoded[16];
    for (int i = 0; i < 16; i++) {
        uint8_t hi = encoded[i * 2];
        uint8_t lo = encoded[i * 2 + 1];
        if (hi < 'A' || hi > 'Z' || lo < 'A' || lo > 'Z') return 0;
        decoded[i] = (uint8_t)(((hi - 'A') << 4) | (lo - 'A'));
    }

    *suffix_out = decoded[15];

    /* Copy first 15 bytes as name, trim trailing spaces */
    int end = 14;
    while (end >= 0 && decoded[end] == ' ') end--;
    int name_len = end + 1;
    if (name_len < 0) name_len = 0;
    memcpy(name_out, decoded, name_len);
    name_out[name_len] = '\0';

    return 1;
}

/*
 * Decode a DNS label-encoded name from pkt at offset, up to pkt_len.
 * Fills out (NUL-terminated). Returns bytes consumed at offset (no pointer follow).
 * Returns -1 on error.
 */
static int dns_decode_name(const uint8_t *pkt, uint32_t pkt_len,
                            uint32_t offset, char *out, size_t outsz)
{
    size_t out_pos = 0;
    int bytes_consumed = -1;
    uint32_t off = offset;
    int jumps = 0;

    while (off < pkt_len) {
        uint8_t llen = pkt[off];

        if (llen == 0) {
            /* End of name */
            if (bytes_consumed < 0)
                bytes_consumed = (int)(off - offset + 1);
            break;
        }

        /* Compression pointer */
        if ((llen & 0xC0) == 0xC0) {
            if (off + 1 >= pkt_len) return -1;
            if (bytes_consumed < 0)
                bytes_consumed = (int)(off - offset + 2);
            off = (uint32_t)(((llen & 0x3F) << 8) | pkt[off + 1]);
            if (++jumps > 10) return -1;
            continue;
        }

        /* Normal label */
        off++;
        if (off + llen > pkt_len) return -1;

        if (out_pos > 0 && out_pos < outsz - 1)
            out[out_pos++] = '.';

        for (uint8_t i = 0; i < llen && out_pos < outsz - 1; i++)
            out[out_pos++] = (char)pkt[off + i];

        off += llen;
    }

    if (out_pos < outsz) out[out_pos] = '\0';
    return bytes_consumed;
}

/* ------------------------------------------------------------------ */
/* Publish helper                                                       */
/* ------------------------------------------------------------------ */

static void publish_netbios(ps_module_ctx_t *ctx,
                             const char *type_str,
                             const char *src_ip,
                             const char *name,
                             const char *name_type_str,
                             const char *workgroup,
                             const char *iface)
{
    char buf[2048];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "type",      type_str);
    ps_json_key_string(&j, "src_ip",    src_ip);
    ps_json_key_string(&j, "name",      name);
    ps_json_key_string(&j, "name_type", name_type_str);
    ps_json_key_string(&j, "workgroup", workgroup);
    ps_json_key_string(&j, "interface", iface);
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0)
        ctx->publish(ctx, "discovery.netbios", buf, (uint32_t)j.len);
}

/* ------------------------------------------------------------------ */
/* NBNS parser (UDP 137)                                               */
/* ------------------------------------------------------------------ */

static void parse_nbns(ps_module_ctx_t *ctx,
                        const uint8_t *payload, uint32_t payload_len,
                        const char *src_ip, const char *iface)
{
    if (payload_len < NBNS_HDR_LEN) return;

    uint16_t flags    = read_be16(payload + 2);
    uint16_t qdcount  = read_be16(payload + 4);
    uint16_t ancount  = read_be16(payload + 6);

    /* Only process responses (QR=1) with answers */
    if (!(flags & NBNS_FLAG_QR)) return;
    if (ancount == 0) return;

    /* Skip question section */
    uint32_t off = NBNS_HDR_LEN;
    for (uint16_t q = 0; q < qdcount && off < payload_len; q++) {
        /* NetBIOS names are encoded: 1-byte label len (always 0x20=32) + 32 bytes + 0 */
        if (off >= payload_len) break;
        uint8_t label_len = payload[off];
        off++;
        off += label_len; /* skip encoded name */
        if (off + 1 <= payload_len && payload[off] == 0) off++; /* root */
        off += 4; /* type + class */
    }

    /* Parse answer records */
    for (uint16_t a = 0; a < ancount && off < payload_len; a++) {
        if (off >= payload_len) break;

        /* Name field */
        uint8_t label_len = payload[off];
        off++;
        const uint8_t *encoded_name = NULL;
        if (label_len == 0x20 && off + 32 <= payload_len) {
            encoded_name = payload + off;
            off += 32;
        } else {
            off += label_len;
        }
        /* null terminator of name */
        if (off < payload_len && payload[off] == 0) off++;

        if (off + 10 > payload_len) break;

        uint16_t rtype  = read_be16(payload + off);     off += 2;
        /* uint16_t rclass = */ read_be16(payload + off); off += 2;
        /* uint32_t ttl   = */ read_be32(payload + off); off += 4;
        uint16_t rdlen  = read_be16(payload + off);     off += 2;

        if (off + rdlen > payload_len) break;
        const uint8_t *rdata = payload + off;
        off += rdlen;

        /* NBSTAT (type 0x0021) */
        if (rtype == 0x0021 && encoded_name && rdlen >= 1) {
            char name[16]      = {0};
            uint8_t suffix     = 0;
            char name_type[8]  = {0};
            char workgroup[16] = {0};

            decode_nb_name(encoded_name, name, &suffix);
            snprintf(name_type, sizeof(name_type), "0x%02x", suffix);

            /* NBSTAT rdata: num_names(1) + [name(16) + flags(2)] * num_names */
            uint8_t num_names = rdata[0];
            uint32_t nr_off   = 1;
            for (uint8_t n = 0; n < num_names && nr_off + 18 <= rdlen; n++) {
                char nb[16]       = {0};
                uint8_t nb_sfx    = 0;
                /* Each entry: 15 bytes name (space-padded) + 1 byte suffix + 2 bytes flags */
                /* Note: NOT level-1 encoded, just raw 15+1 bytes */
                int end = 14;
                while (end >= 0 && rdata[nr_off + end] == ' ') end--;
                int nlen = end + 1;
                if (nlen < 0) nlen = 0;
                if (nlen > 15) nlen = 15;
                memcpy(nb, rdata + nr_off, nlen);
                nb[nlen] = '\0';
                nb_sfx = rdata[nr_off + 15];

                /* group bit in flags byte 1, bit 7 (0x80) */
                uint8_t nb_flags_hi = rdata[nr_off + 16];
                int is_group = (nb_flags_hi & 0x80) ? 1 : 0;

                /* Use group entry with suffix 0x00 as workgroup */
                if (is_group && nb_sfx == 0x00 && workgroup[0] == '\0') {
                    snprintf(workgroup, sizeof(workgroup), "%s", nb);
                }

                nr_off += 18;
            }

            publish_netbios(ctx, "netbios_ns", src_ip, name,
                            name_type, workgroup, iface);
            ps_debug("netbios_listener: NBSTAT name=%s type=%s workgroup=%s",
                     name, name_type, workgroup);
        }
        /* NB (type 0x0020) — name query response */
        else if (rtype == 0x0020 && encoded_name) {
            char name[16]     = {0};
            uint8_t suffix    = 0;
            char name_type[8] = {0};

            decode_nb_name(encoded_name, name, &suffix);
            snprintf(name_type, sizeof(name_type), "0x%02x", suffix);

            publish_netbios(ctx, "netbios_ns", src_ip, name,
                            name_type, "", iface);
        }
    }
}

/* ------------------------------------------------------------------ */
/* LLMNR parser (UDP 5355)                                             */
/* ------------------------------------------------------------------ */

static void parse_llmnr(ps_module_ctx_t *ctx,
                         const uint8_t *payload, uint32_t payload_len,
                         const char *src_ip, const char *iface)
{
    /* DNS header: 12 bytes */
    if (payload_len < 12) return;

    uint16_t flags   = read_be16(payload + 2);
    uint16_t qdcount = read_be16(payload + 4);

    (void)flags;
    if (qdcount == 0) return;

    /* Parse first question name */
    char qname[256] = {0};
    uint32_t off = 12;
    int consumed = dns_decode_name(payload, payload_len, off, qname, sizeof(qname));
    if (consumed < 0 || qname[0] == '\0') return;

    publish_netbios(ctx, "llmnr", src_ip, qname, "", "", iface);
    ps_debug("netbios_listener: LLMNR query name=%s src=%s", qname, src_ip);
}

/* ------------------------------------------------------------------ */
/* NetBIOS Datagram parser (UDP 138)                                   */
/* ------------------------------------------------------------------ */

static void parse_nbdg(ps_module_ctx_t *ctx,
                        const uint8_t *payload, uint32_t payload_len,
                        const char *src_ip, const char *iface)
{
    /*
     * NetBIOS datagram header is 14 bytes:
     *   msg_type(1) flags(1) dgm_id(2) src_ip(4) src_port(2) dgm_len(2) pkt_off(2)
     * After header: source NetBIOS name (encoded 34 bytes) + dest name
     */
    if (payload_len < 14 + 34) return;

    /* Source name: label_len(1) + 32 bytes + null(1) */
    uint32_t off = 14;
    if (payload[off] != 0x20) return; /* expect 32-byte label */
    off++;

    const uint8_t *encoded = payload + off;
    off += 32;
    if (off >= payload_len || payload[off] != 0) return;

    char name[16]     = {0};
    uint8_t suffix    = 0;
    char name_type[8] = {0};

    if (!decode_nb_name(encoded, name, &suffix)) return;
    snprintf(name_type, sizeof(name_type), "0x%02x", suffix);

    publish_netbios(ctx, "netbios_dg", src_ip, name, name_type, "", iface);
}

/* ------------------------------------------------------------------ */
/* Packet handler                                                       */
/* ------------------------------------------------------------------ */

static void netbios_on_packet(ps_module_ctx_t *ctx,
                               const uint8_t *pkt, uint32_t len,
                               uint64_t ts_usec, int handle_id)
{
    (void)ts_usec;
    (void)handle_id;

    struct netbios_state *st = (struct netbios_state *)ctx->userdata;
    if (!st) return;

    if (len < (uint32_t)(ETH_HDR_LEN + IPV4_HDR_MIN + UDP_HDR_LEN + 1)) return;

    /* IPv4 only */
    if (read_be16(pkt + 12) != 0x0800) return;

    const uint8_t *ip = pkt + ETH_HDR_LEN;
    if ((ip[0] >> 4) != 4) return;

    uint8_t ihl = (ip[0] & 0x0f) * 4;
    if (ihl < IPV4_HDR_MIN) return;

    if (ip[IP_PROTO_OFFSET] != PROTO_UDP) return;

    /* Extract source IP */
    char src_ip[INET_ADDRSTRLEN] = {0};
    {
        struct in_addr a;
        memcpy(&a, ip + IP_SRC_OFFSET, 4);
        inet_ntop(AF_INET, &a, src_ip, sizeof(src_ip));
    }

    const uint8_t *udp = ip + ihl;
    if ((uint32_t)(ETH_HDR_LEN + ihl + UDP_HDR_LEN) > len) return;

    uint16_t dst_port  = read_be16(udp + 2);
    uint16_t udp_len   = read_be16(udp + 4);
    if (udp_len < UDP_HDR_LEN) return;

    uint32_t payload_len = (uint32_t)(udp_len - UDP_HDR_LEN);
    const uint8_t *payload = udp + UDP_HDR_LEN;

    uint32_t avail = len - (uint32_t)(ETH_HDR_LEN + ihl + UDP_HDR_LEN);
    if (payload_len > avail) payload_len = avail;

    switch (dst_port) {
    case NBNS_PORT:
        parse_nbns(ctx, payload, payload_len, src_ip, st->iface);
        break;
    case NBDG_PORT:
        parse_nbdg(ctx, payload, payload_len, src_ip, st->iface);
        break;
    case LLMNR_PORT:
        parse_llmnr(ctx, payload, payload_len, src_ip, st->iface);
        break;
    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int netbios_init(ps_module_ctx_t *ctx)
{
    struct netbios_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("netbios_listener: out of memory");
        return -1;
    }

    const char *iface = getenv("PS_CAPTURE_INTERFACE");
    if (!iface || iface[0] == '\0') iface = "en0";
    snprintf(st->iface, sizeof(st->iface), "%s", iface);

    ctx->userdata = st;
    ps_info("netbios_listener: initialized (iface=%s)", st->iface);
    return 0;
}

static void netbios_shutdown(ps_module_ctx_t *ctx)
{
    free(ctx->userdata);
    ctx->userdata = NULL;
    ps_info("netbios_listener: shutdown");
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

const ps_module_t netbios_module = {
    .name        = "netbios_listener",
    .description = "Passive NetBIOS/LLMNR listener — Windows host discovery",
    .version     = "1.0",
    .flags       = PS_MOD_PASSIVE,

    .init        = netbios_init,
    .shutdown    = netbios_shutdown,
    .on_packet   = netbios_on_packet,
    .on_job      = NULL,
    .on_response = NULL,
    .tick        = NULL,
};

__attribute__((constructor))
static void register_netbios(void)
{
    ps_module_register(&netbios_module);
}
