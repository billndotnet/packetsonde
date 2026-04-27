/*
 * cdp_listener.c — Passive CDP listener for PacketSonde Agent
 *
 * Captures LLC SNAP frames with OUI 00:00:0c and PID 0x2000 (CDP).
 * Parses Cisco Discovery Protocol TLVs to extract device identity,
 * addresses, capabilities, and platform information.
 *
 * Frame layout:
 *   Ethernet(14) + LLC SNAP header(8: AA AA 03 00 00 0C 20 00) +
 *   CDP header(4: version, TTL, checksum) + TLVs
 *
 * Publishes to channel: discovery.cdp
 *
 * JSON output:
 *   {"type":"cdp","device_id":"...","platform":"...","software_version":"...",
 *    "port_id":"...","capabilities":["router","switch"],"mgmt_ip":"...",
 *    "native_vlan":N,"interface":"..."}
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

#define ETH_HDR_LEN         14

/* LLC SNAP header: AA AA 03 00 00 0C 20 00 */
#define LLC_SNAP_LEN        8
#define CDP_HDR_LEN         4   /* version(1) + TTL(1) + checksum(2) */
#define CDP_HDR_OFFSET      (ETH_HDR_LEN + LLC_SNAP_LEN)
#define CDP_TLV_OFFSET      (CDP_HDR_OFFSET + CDP_HDR_LEN)

/* CDP TLV types */
#define CDP_TLV_DEVICE_ID   0x0001
#define CDP_TLV_ADDRESSES   0x0002
#define CDP_TLV_PORT_ID     0x0003
#define CDP_TLV_CAPABILITIES 0x0004
#define CDP_TLV_SW_VERSION  0x0005
#define CDP_TLV_PLATFORM    0x0006
#define CDP_TLV_NATIVE_VLAN 0x000a
#define CDP_TLV_MGMT_ADDRS  0x0016

/* Capability bits */
#define CDP_CAP_ROUTER  (1 << 0)
#define CDP_CAP_SWITCH  (1 << 2)
#define CDP_CAP_HOST    (1 << 6)

/* ------------------------------------------------------------------ */
/* State                                                                */
/* ------------------------------------------------------------------ */

struct cdp_state {
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

static void copy_string_tlv(const uint8_t *val, uint16_t vlen,
                              char *out, size_t outsz)
{
    if (outsz == 0) return;
    size_t n = vlen < outsz - 1 ? vlen : outsz - 1;
    memcpy(out, val, n);
    out[n] = '\0';
}

/*
 * Parse a CDP address block (used by TLV 0x0002 and 0x0016).
 * Extracts the first IPv4 address found.
 * Format: count(4) + [proto_type(1) proto_len(1) proto(proto_len)
 *                      addr_len(2) addr(addr_len)] ...
 */
static void parse_cdp_addresses(const uint8_t *val, uint16_t vlen,
                                  char *ip_out, size_t ip_outsz)
{
    if (vlen < 4) return;
    uint32_t count = read_be32(val);
    uint32_t off   = 4;

    for (uint32_t i = 0; i < count && off < vlen; i++) {
        if (off + 2 > vlen) break;
        uint8_t proto_type = val[off];
        uint8_t proto_len  = val[off + 1];
        off += 2;
        if (off + proto_len > vlen) break;
        const uint8_t *proto = val + off;
        off += proto_len;

        if (off + 2 > vlen) break;
        uint16_t addr_len = read_be16(val + off);
        off += 2;
        if (off + addr_len > vlen) break;
        const uint8_t *addr = val + off;
        off += addr_len;

        /* NLPID 0xCC = IPv4, proto_len = 1 */
        if (proto_type == 1 && proto_len == 1 && proto[0] == 0xCC &&
            addr_len == 4 && ip_out[0] == '\0') {
            struct in_addr a;
            memcpy(&a, addr, 4);
            inet_ntop(AF_INET, &a, ip_out, ip_outsz);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Packet handler                                                       */
/* ------------------------------------------------------------------ */

static void cdp_on_packet(ps_module_ctx_t *ctx,
                           const uint8_t *pkt, uint32_t len,
                           uint64_t ts_usec, int handle_id)
{
    (void)ts_usec;
    (void)handle_id;

    struct cdp_state *st = (struct cdp_state *)ctx->userdata;
    if (!st) return;

    /* Minimum: ETH + LLC SNAP + CDP hdr + 4 bytes TLV */
    if (len < (uint32_t)(CDP_TLV_OFFSET + 4)) return;

    /* Verify LLC SNAP header: AA AA 03 00 00 0C 20 00 */
    static const uint8_t llc_snap[8] = {
        0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00
    };
    if (memcmp(pkt + ETH_HDR_LEN, llc_snap, LLC_SNAP_LEN) != 0) return;

    /* TLV data starts at CDP_TLV_OFFSET */
    const uint8_t *tlvs    = pkt + CDP_TLV_OFFSET;
    uint32_t        tlv_len = len - CDP_TLV_OFFSET;
    uint32_t        off     = 0;

    char device_id[128]     = {0};
    char platform[128]      = {0};
    char sw_version[256]    = {0};
    char port_id[128]       = {0};
    char mgmt_ip[INET_ADDRSTRLEN] = {0};
    uint32_t capabilities   = 0;
    uint16_t native_vlan    = 0;

    /* Walk TLVs */
    while (off + 4 <= tlv_len) {
        uint16_t type = read_be16(tlvs + off);
        uint16_t tlen = read_be16(tlvs + off + 2); /* includes 4-byte header */

        if (tlen < 4) break;
        uint16_t vlen = tlen - 4;

        if (off + 4 + vlen > tlv_len) break;
        const uint8_t *val = tlvs + off + 4;

        switch (type) {
        case CDP_TLV_DEVICE_ID:
            copy_string_tlv(val, vlen, device_id, sizeof(device_id));
            break;

        case CDP_TLV_ADDRESSES:
            if (mgmt_ip[0] == '\0')
                parse_cdp_addresses(val, vlen, mgmt_ip, sizeof(mgmt_ip));
            break;

        case CDP_TLV_PORT_ID:
            copy_string_tlv(val, vlen, port_id, sizeof(port_id));
            break;

        case CDP_TLV_CAPABILITIES:
            if (vlen >= 4) capabilities = read_be32(val);
            break;

        case CDP_TLV_SW_VERSION:
            copy_string_tlv(val, vlen, sw_version, sizeof(sw_version));
            break;

        case CDP_TLV_PLATFORM:
            copy_string_tlv(val, vlen, platform, sizeof(platform));
            break;

        case CDP_TLV_NATIVE_VLAN:
            if (vlen >= 2) native_vlan = read_be16(val);
            break;

        case CDP_TLV_MGMT_ADDRS:
            if (mgmt_ip[0] == '\0')
                parse_cdp_addresses(val, vlen, mgmt_ip, sizeof(mgmt_ip));
            break;

        default:
            break;
        }

        off += tlen;
    }

    /* Build JSON */
    char buf[2048];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "type",             "cdp");
    ps_json_key_string(&j, "device_id",        device_id);
    ps_json_key_string(&j, "platform",         platform);
    ps_json_key_string(&j, "software_version", sw_version);
    ps_json_key_string(&j, "port_id",          port_id);

    /* capabilities array */
    ps_json_array_begin(&j, "capabilities");
    if (capabilities & CDP_CAP_ROUTER) ps_json_array_string(&j, "router");
    if (capabilities & CDP_CAP_SWITCH) ps_json_array_string(&j, "switch");
    if (capabilities & CDP_CAP_HOST)   ps_json_array_string(&j, "host");
    ps_json_array_end(&j);

    ps_json_key_string(&j, "mgmt_ip",      mgmt_ip);
    ps_json_key_int   (&j, "native_vlan",  (int64_t)native_vlan);
    ps_json_key_string(&j, "interface",    st->iface);
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "discovery.cdp", buf, (uint32_t)j.len);
        ps_debug("cdp_listener: published device=%s platform=%s",
                 device_id, platform);
    }
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int cdp_init(ps_module_ctx_t *ctx)
{
    struct cdp_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("cdp_listener: out of memory");
        return -1;
    }

    const char *iface = getenv("PS_CAPTURE_INTERFACE");
    if (!iface || iface[0] == '\0') iface = "en0";
    snprintf(st->iface, sizeof(st->iface), "%s", iface);

    ctx->userdata = st;
    ps_info("cdp_listener: initialized (iface=%s)", st->iface);
    return 0;
}

static void cdp_shutdown(ps_module_ctx_t *ctx)
{
    free(ctx->userdata);
    ctx->userdata = NULL;
    ps_info("cdp_listener: shutdown");
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

const ps_module_t cdp_module = {
    .name        = "cdp_listener",
    .description = "Passive CDP listener — Cisco device discovery",
    .version     = "1.0",
    .flags       = PS_MOD_PASSIVE,

    .init        = cdp_init,
    .shutdown    = cdp_shutdown,
    .on_packet   = cdp_on_packet,
    .on_job      = NULL,
    .on_response = NULL,
    .tick        = NULL,
};

__attribute__((constructor))
static void register_cdp(void)
{
    ps_module_register(&cdp_module);
}
