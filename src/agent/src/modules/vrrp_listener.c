/*
 * vrrp_listener.c — Passive VRRP listener for PacketSonde Agent
 *
 * Captures IP protocol 112 (VRRP) packets from raw Ethernet frames.
 * Parses VRRP advertisement messages to discover virtual router groups
 * and virtual IP addresses.
 *
 * VRRP header (after IP header):
 *   version+type(1: top 4 = version, bottom 4 = type)
 *   VRID(1) priority(1) count_ip_addrs(1)
 *   auth_type(1) adv_interval(1) checksum(2)
 *   Then: count_ip_addrs × 4 bytes of virtual IPs
 *
 * Publishes to channel: discovery.vrrp
 *
 * JSON output:
 *   {"type":"vrrp","src_ip":"...","version":N,"vrid":N,"priority":N,
 *    "virtual_ips":["..."],"adv_interval":N,"interface":"..."}
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

/* IP header offsets */
#define IP_PROTO_OFFSET  9
#define IP_SRC_OFFSET   12

#define IP_PROTO_VRRP   112

/* VRRP header minimum size (fixed fields before VIP list) */
#define VRRP_HDR_MIN    8

/* Maximum virtual IPs we track */
#define MAX_VIPS        16

/* ------------------------------------------------------------------ */
/* State                                                                */
/* ------------------------------------------------------------------ */

struct vrrp_state {
    char iface[64];
};

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

/* ------------------------------------------------------------------ */
/* Packet handler                                                       */
/* ------------------------------------------------------------------ */

static void vrrp_on_packet(ps_module_ctx_t *ctx,
                            const uint8_t *pkt, uint32_t len,
                            uint64_t ts_usec, int handle_id)
{
    (void)ts_usec;
    (void)handle_id;

    struct vrrp_state *st = (struct vrrp_state *)ctx->userdata;
    if (!st) return;

    /* Need ETH + IPv4 + VRRP header */
    if (len < (uint32_t)(ETH_HDR_LEN + IPV4_HDR_MIN + VRRP_HDR_MIN)) return;

    /* IPv4 only */
    if (read_be16(pkt + 12) != 0x0800) return;

    const uint8_t *ip = pkt + ETH_HDR_LEN;
    if ((ip[0] >> 4) != 4) return;

    uint8_t ihl = (ip[0] & 0x0f) * 4;
    if (ihl < IPV4_HDR_MIN) return;

    /* Protocol must be VRRP (112) */
    if (ip[IP_PROTO_OFFSET] != IP_PROTO_VRRP) return;

    /* Source IP */
    char src_ip[INET_ADDRSTRLEN] = {0};
    {
        struct in_addr a;
        memcpy(&a, ip + IP_SRC_OFFSET, 4);
        inet_ntop(AF_INET, &a, src_ip, sizeof(src_ip));
    }

    if ((uint32_t)(ETH_HDR_LEN + ihl + VRRP_HDR_MIN) > len) return;

    const uint8_t *vrrp = ip + ihl;

    /* Parse VRRP header */
    uint8_t ver_type      = vrrp[0];
    uint8_t version       = ver_type >> 4;
    /* uint8_t type       = ver_type & 0x0f; */  /* type 1 = advertisement */
    uint8_t vrid          = vrrp[1];
    uint8_t priority      = vrrp[2];
    uint8_t count_ips     = vrrp[3];
    /* auth_type         = vrrp[4]; */
    uint8_t adv_interval  = vrrp[5];
    /* checksum(2)       = vrrp[6..7]; */

    uint32_t vrrp_avail = len - (uint32_t)(ETH_HDR_LEN + ihl);

    /* Verify we have enough bytes for the VIP list */
    if ((uint32_t)(VRRP_HDR_MIN + count_ips * 4) > vrrp_avail) {
        count_ips = (uint8_t)((vrrp_avail - VRRP_HDR_MIN) / 4);
    }
    if (count_ips > MAX_VIPS) count_ips = MAX_VIPS;

    /* Extract virtual IPs */
    char vips[MAX_VIPS][INET_ADDRSTRLEN];
    uint32_t vip_off = VRRP_HDR_MIN;

    for (uint8_t i = 0; i < count_ips; i++) {
        struct in_addr vip;
        memcpy(&vip, vrrp + vip_off, 4);
        inet_ntop(AF_INET, &vip, vips[i], INET_ADDRSTRLEN);
        vip_off += 4;
    }

    /* Build JSON */
    char buf[2048];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "type",         "vrrp");
    ps_json_key_string(&j, "src_ip",       src_ip);
    ps_json_key_int   (&j, "version",      (int64_t)version);
    ps_json_key_int   (&j, "vrid",         (int64_t)vrid);
    ps_json_key_int   (&j, "priority",     (int64_t)priority);

    ps_json_array_begin(&j, "virtual_ips");
    for (uint8_t i = 0; i < count_ips; i++)
        ps_json_array_string(&j, vips[i]);
    ps_json_array_end(&j);

    ps_json_key_int   (&j, "adv_interval", (int64_t)adv_interval);
    ps_json_key_string(&j, "interface",    st->iface);
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "discovery.vrrp", buf, (uint32_t)j.len);
        ps_debug("vrrp_listener: published vrid=%u priority=%u vips=%u",
                 vrid, priority, count_ips);
    }
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int vrrp_init(ps_module_ctx_t *ctx)
{
    struct vrrp_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("vrrp_listener: out of memory");
        return -1;
    }

    const char *iface = getenv("PS_CAPTURE_INTERFACE");
    if (!iface) iface = "";
    snprintf(st->iface, sizeof(st->iface), "%s", iface);

    ctx->userdata = st;
    ps_info("vrrp_listener: initialized (iface=%s)", st->iface);
    return 0;
}

static void vrrp_shutdown(ps_module_ctx_t *ctx)
{
    free(ctx->userdata);
    ctx->userdata = NULL;
    ps_info("vrrp_listener: shutdown");
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

const ps_module_t vrrp_module = {
    .name        = "vrrp_listener",
    .description = "Passive VRRP listener — virtual router discovery",
    .version     = "1.0",
    .flags       = PS_MOD_PASSIVE,

    .init        = vrrp_init,
    .shutdown    = vrrp_shutdown,
    .on_packet   = vrrp_on_packet,
    .on_job      = NULL,
    .on_response = NULL,
    .tick        = NULL,
};

/* Self-registration via constructor was deleted -- main.c registers
 * this module explicitly so the global registry exists by then. */
