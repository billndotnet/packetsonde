/*
 * lldp_listener.c — Passive LLDP listener for PacketSonde Agent
 *
 * Captures Ethertype 0x88cc frames and parses Link Layer Discovery Protocol
 * TLVs to extract device identity, management addresses, and capabilities.
 *
 * Publishes to channel: discovery.lldp
 *
 * JSON output:
 *   {"type":"lldp","chassis_id":"...","port_id":"...","system_name":"...",
 *    "system_desc":"...","mgmt_ip":"...","ttl":N,"sys_cap":N,"en_cap":N,
 *    "interface":"...","capabilities":["bridge","router",...]}
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
#define ETHERTYPE_LLDP      0x88cc

/* LLDP TLV types */
#define LLDP_TLV_END        0
#define LLDP_TLV_CHASSIS_ID 1
#define LLDP_TLV_PORT_ID    2
#define LLDP_TLV_TTL        3
#define LLDP_TLV_SYS_NAME   5
#define LLDP_TLV_SYS_DESC   6
#define LLDP_TLV_SYS_CAP    7
#define LLDP_TLV_MGMT_ADDR  8

/* Chassis ID subtypes */
#define CHASSIS_SUBTYPE_MAC         4
#define CHASSIS_SUBTYPE_NET_ADDR    5

/* Port ID subtypes */
#define PORT_SUBTYPE_IFALIAS    1
#define PORT_SUBTYPE_MAC        3
#define PORT_SUBTYPE_NET_ADDR   4
#define PORT_SUBTYPE_IFNAME     5
#define PORT_SUBTYPE_LOCAL      7

/* System capability bits */
#define SYS_CAP_BRIDGE  (1 << 2)
#define SYS_CAP_ROUTER  (1 << 4)

/* ------------------------------------------------------------------ */
/* State                                                                */
/* ------------------------------------------------------------------ */

struct lldp_state {
    char iface[64];
};

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void mac_to_str(const uint8_t *mac, char *out, size_t outsz)
{
    snprintf(out, outsz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Copy at most (outsz-1) printable bytes from val to out, NUL-terminate. */
static void copy_string_tlv(const uint8_t *val, uint16_t vlen,
                             char *out, size_t outsz)
{
    if (outsz == 0) return;
    size_t n = vlen < outsz - 1 ? vlen : outsz - 1;
    memcpy(out, val, n);
    out[n] = '\0';
}

/* ------------------------------------------------------------------ */
/* Packet handler                                                       */
/* ------------------------------------------------------------------ */

static void lldp_on_packet(ps_module_ctx_t *ctx,
                            const uint8_t *pkt, uint32_t len,
                            uint64_t ts_usec, int handle_id)
{
    (void)ts_usec;
    (void)handle_id;

    struct lldp_state *st = (struct lldp_state *)ctx->userdata;
    if (!st) return;

    /* Need Ethernet header + at least 2 bytes of TLV */
    if (len < (uint32_t)(ETH_HDR_LEN + 2)) return;

    /* Check ethertype */
    if (read_be16(pkt + 12) != ETHERTYPE_LLDP) return;

    const uint8_t *payload = pkt + ETH_HDR_LEN;
    uint32_t payload_len   = len - ETH_HDR_LEN;
    uint32_t off           = 0;

    char chassis_id[128] = {0};
    char port_id[128]    = {0};
    char sys_name[128]   = {0};
    char sys_desc[256]   = {0};
    char mgmt_ip[INET_ADDRSTRLEN] = {0};
    uint16_t ttl     = 0;
    uint16_t sys_cap = 0;
    uint16_t en_cap  = 0;

    /* Walk TLVs */
    while (off + 2 <= payload_len) {
        uint16_t hdr    = read_be16(payload + off);
        uint8_t  type   = (uint8_t)(hdr >> 9);
        uint16_t vlen   = hdr & 0x01ff;

        off += 2;
        if (off + vlen > payload_len) break;

        const uint8_t *val = payload + off;

        switch (type) {
        case LLDP_TLV_END:
            off = payload_len; /* stop */
            break;

        case LLDP_TLV_CHASSIS_ID:
            if (vlen >= 1) {
                uint8_t subtype = val[0];
                if (subtype == CHASSIS_SUBTYPE_MAC && vlen == 7) {
                    mac_to_str(val + 1, chassis_id, sizeof(chassis_id));
                } else if (subtype == CHASSIS_SUBTYPE_NET_ADDR && vlen >= 6) {
                    /* subtype(1) + addr_family(1) + addr(4) for IPv4 */
                    uint8_t af = val[1];
                    if (af == 1 && vlen >= 6) { /* IPv4 */
                        struct in_addr a;
                        memcpy(&a, val + 2, 4);
                        inet_ntop(AF_INET, &a, chassis_id, sizeof(chassis_id));
                    } else {
                        copy_string_tlv(val + 1, vlen - 1,
                                        chassis_id, sizeof(chassis_id));
                    }
                } else {
                    copy_string_tlv(val + 1, vlen - 1,
                                    chassis_id, sizeof(chassis_id));
                }
            }
            break;

        case LLDP_TLV_PORT_ID:
            if (vlen >= 1) {
                uint8_t subtype = val[0];
                if (subtype == PORT_SUBTYPE_MAC && vlen == 7) {
                    mac_to_str(val + 1, port_id, sizeof(port_id));
                } else {
                    copy_string_tlv(val + 1, vlen - 1, port_id, sizeof(port_id));
                }
            }
            break;

        case LLDP_TLV_TTL:
            if (vlen >= 2) ttl = read_be16(val);
            break;

        case LLDP_TLV_SYS_NAME:
            copy_string_tlv(val, vlen, sys_name, sizeof(sys_name));
            break;

        case LLDP_TLV_SYS_DESC:
            copy_string_tlv(val, vlen, sys_desc, sizeof(sys_desc));
            break;

        case LLDP_TLV_SYS_CAP:
            if (vlen >= 4) {
                sys_cap = read_be16(val);
                en_cap  = read_be16(val + 2);
            }
            break;

        case LLDP_TLV_MGMT_ADDR:
            if (vlen >= 6) {
                uint8_t addr_len = val[0];   /* includes subtype byte */
                uint8_t subtype  = val[1];
                if (subtype == 1 && addr_len == 5) { /* IPv4 */
                    struct in_addr a;
                    memcpy(&a, val + 2, 4);
                    inet_ntop(AF_INET, &a, mgmt_ip, sizeof(mgmt_ip));
                }
            }
            break;

        default:
            break;
        }

        off += vlen;
    }

    /* Build JSON */
    char buf[2048];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "type",        "lldp");
    ps_json_key_string(&j, "chassis_id",  chassis_id);
    ps_json_key_string(&j, "port_id",     port_id);
    ps_json_key_string(&j, "system_name", sys_name);
    ps_json_key_string(&j, "system_desc", sys_desc);
    ps_json_key_string(&j, "mgmt_ip",     mgmt_ip);
    ps_json_key_int   (&j, "ttl",         (int64_t)ttl);
    ps_json_key_int   (&j, "sys_cap",     (int64_t)sys_cap);
    ps_json_key_int   (&j, "en_cap",      (int64_t)en_cap);
    ps_json_key_string(&j, "interface",   st->iface);

    /* capabilities array */
    ps_json_array_begin(&j, "capabilities");
    if (en_cap & SYS_CAP_BRIDGE) ps_json_array_string(&j, "bridge");
    if (en_cap & SYS_CAP_ROUTER) ps_json_array_string(&j, "router");
    ps_json_array_end(&j);

    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "discovery.lldp", buf, (uint32_t)j.len);
        ps_debug("lldp_listener: published chassis=%s name=%s",
                 chassis_id, sys_name);
    }
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int lldp_init(ps_module_ctx_t *ctx)
{
    struct lldp_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("lldp_listener: out of memory");
        return -1;
    }

    const char *iface = getenv("PS_CAPTURE_INTERFACE");
    if (!iface || iface[0] == '\0') iface = "en0";
    snprintf(st->iface, sizeof(st->iface), "%s", iface);

    ctx->userdata = st;
    ps_info("lldp_listener: initialized (iface=%s)", st->iface);
    return 0;
}

static void lldp_shutdown(ps_module_ctx_t *ctx)
{
    free(ctx->userdata);
    ctx->userdata = NULL;
    ps_info("lldp_listener: shutdown");
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

const ps_module_t lldp_module = {
    .name        = "lldp_listener",
    .description = "Passive LLDP listener — device identity and capabilities",
    .version     = "1.0",
    .flags       = PS_MOD_PASSIVE,

    .init        = lldp_init,
    .shutdown    = lldp_shutdown,
    .on_packet   = lldp_on_packet,
    .on_job      = NULL,
    .on_response = NULL,
    .tick        = NULL,
};

__attribute__((constructor))
static void register_lldp(void)
{
    ps_module_register(&lldp_module);
}
