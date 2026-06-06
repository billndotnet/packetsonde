/*
 * ospf_listener.c — Passive OSPF Hello listener for PacketSonde Agent
 *
 * Captures IP protocol 89 (OSPF) packets from raw Ethernet frames.
 * Parses OSPF Hello packets (type 1) to discover OSPF neighbors,
 * DR/BDR elections, and area membership.
 *
 * OSPF header (24 bytes after IP header):
 *   version(1) type(1) pkt_len(2) router_id(4) area_id(4)
 *   checksum(2) auth_type(2) auth(8)
 *
 * Hello body (after 24-byte OSPF header):
 *   network_mask(4) hello_interval(2) options(1) priority(1)
 *   dead_interval(4) dr(4) bdr(4) neighbors(4 each)...
 *
 * Publishes to channel: discovery.ospf
 *
 * JSON output:
 *   {"type":"ospf_hello","router_id":"...","area_id":"...","network_mask":"...",
 *    "hello_interval":N,"dead_interval":N,"dr":"...","bdr":"...",
 *    "neighbors":["..."],"interface":"..."}
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
#define IP_PROTO_OSPF   89

/* IP header offsets */
#define IP_PROTO_OFFSET  9
#define IP_SRC_OFFSET   12

/* OSPF header */
#define OSPF_HDR_LEN    24
#define OSPF_TYPE_HELLO 1

/* Hello body layout (offsets relative to start of Hello body) */
#define HELLO_NETMASK_OFF    0   /* 4 bytes */
#define HELLO_INTERVAL_OFF   4   /* 2 bytes */
#define HELLO_OPTIONS_OFF    6   /* 1 byte */
#define HELLO_PRIORITY_OFF   7   /* 1 byte */
#define HELLO_DEAD_INT_OFF   8   /* 4 bytes */
#define HELLO_DR_OFF        12   /* 4 bytes */
#define HELLO_BDR_OFF       16   /* 4 bytes */
#define HELLO_NBRS_OFF      20   /* 4 bytes each */
#define HELLO_MIN_LEN       20

#define MAX_NEIGHBORS       32

/* ------------------------------------------------------------------ */
/* State                                                                */
/* ------------------------------------------------------------------ */

struct ospf_state {
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

/* Convert a 4-byte big-endian IP (router-ID or address) to dotted quad. */
static void ip32_to_str(const uint8_t *ip4, char *out, size_t outsz)
{
    snprintf(out, outsz, "%u.%u.%u.%u",
             ip4[0], ip4[1], ip4[2], ip4[3]);
}

/* ------------------------------------------------------------------ */
/* Packet handler                                                       */
/* ------------------------------------------------------------------ */

static void ospf_on_packet(ps_module_ctx_t *ctx,
                            const uint8_t *pkt, uint32_t len,
                            uint64_t ts_usec, int handle_id)
{
    (void)ts_usec;
    (void)handle_id;

    struct ospf_state *st = (struct ospf_state *)ctx->userdata;
    if (!st) return;

    /* Need ETH + IPv4 + OSPF header */
    if (len < (uint32_t)(ETH_HDR_LEN + IPV4_HDR_MIN + OSPF_HDR_LEN)) return;

    /* IPv4 only */
    if (read_be16(pkt + 12) != 0x0800) return;

    const uint8_t *ip = pkt + ETH_HDR_LEN;
    if ((ip[0] >> 4) != 4) return;

    uint8_t ihl = (ip[0] & 0x0f) * 4;
    if (ihl < IPV4_HDR_MIN) return;

    /* Protocol must be OSPF (89) */
    if (ip[IP_PROTO_OFFSET] != IP_PROTO_OSPF) return;

    /* Source IP */
    char src_ip[INET_ADDRSTRLEN] = {0};
    {
        struct in_addr a;
        memcpy(&a, ip + IP_SRC_OFFSET, 4);
        inet_ntop(AF_INET, &a, src_ip, sizeof(src_ip));
    }

    if ((uint32_t)(ETH_HDR_LEN + ihl + OSPF_HDR_LEN) > len) return;

    const uint8_t *ospf = ip + ihl;

    /* OSPF header fields */
    uint8_t  ospf_version = ospf[0];
    uint8_t  ospf_type    = ospf[1];
    uint16_t ospf_pkt_len = read_be16(ospf + 2);

    (void)ospf_version;
    (void)ospf_pkt_len;

    /* Only handle Hello packets */
    if (ospf_type != OSPF_TYPE_HELLO) return;

    char router_id[INET_ADDRSTRLEN] = {0};
    char area_id[INET_ADDRSTRLEN]   = {0};
    ip32_to_str(ospf + 4, router_id, sizeof(router_id));
    ip32_to_str(ospf + 8, area_id,   sizeof(area_id));

    /* Hello body starts after 24-byte OSPF header */
    const uint8_t *hello = ospf + OSPF_HDR_LEN;
    uint32_t hello_avail = len - (uint32_t)(ETH_HDR_LEN + ihl + OSPF_HDR_LEN);

    if (hello_avail < HELLO_MIN_LEN) return;

    char netmask[INET_ADDRSTRLEN] = {0};
    ip32_to_str(hello + HELLO_NETMASK_OFF, netmask, sizeof(netmask));

    uint16_t hello_interval = read_be16(hello + HELLO_INTERVAL_OFF);
    uint32_t dead_interval  = read_be32(hello + HELLO_DEAD_INT_OFF);

    char dr[INET_ADDRSTRLEN]  = {0};
    char bdr[INET_ADDRSTRLEN] = {0};
    ip32_to_str(hello + HELLO_DR_OFF,  dr,  sizeof(dr));
    ip32_to_str(hello + HELLO_BDR_OFF, bdr, sizeof(bdr));

    /* Neighbor list: remaining bytes after fixed hello fields, 4 bytes each */
    uint32_t nbr_off   = HELLO_NBRS_OFF;
    uint32_t nbr_count = 0;
    char neighbors[MAX_NEIGHBORS][INET_ADDRSTRLEN];

    while (nbr_off + 4 <= hello_avail && nbr_count < MAX_NEIGHBORS) {
        ip32_to_str(hello + nbr_off, neighbors[nbr_count], INET_ADDRSTRLEN);
        nbr_count++;
        nbr_off += 4;
    }

    /* Build JSON */
    char buf[2048];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "type",           "ospf_hello");
    ps_json_key_string(&j, "router_id",      router_id);
    ps_json_key_string(&j, "area_id",        area_id);
    ps_json_key_string(&j, "network_mask",   netmask);
    ps_json_key_int   (&j, "hello_interval", (int64_t)hello_interval);
    ps_json_key_int   (&j, "dead_interval",  (int64_t)dead_interval);
    ps_json_key_string(&j, "dr",             dr);
    ps_json_key_string(&j, "bdr",            bdr);

    ps_json_array_begin(&j, "neighbors");
    for (uint32_t n = 0; n < nbr_count; n++)
        ps_json_array_string(&j, neighbors[n]);
    ps_json_array_end(&j);

    ps_json_key_string(&j, "interface", st->iface);
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "discovery.ospf", buf, (uint32_t)j.len);
        ps_debug("ospf_listener: published router=%s area=%s neighbors=%u",
                 router_id, area_id, nbr_count);
    }
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int ospf_init(ps_module_ctx_t *ctx)
{
    struct ospf_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("ospf_listener: out of memory");
        return -1;
    }

    const char *iface = getenv("PS_CAPTURE_INTERFACE");
    if (!iface) iface = "";
    snprintf(st->iface, sizeof(st->iface), "%s", iface);

    ctx->userdata = st;
    ps_info("ospf_listener: initialized (iface=%s)", st->iface);
    return 0;
}

static void ospf_shutdown(ps_module_ctx_t *ctx)
{
    free(ctx->userdata);
    ctx->userdata = NULL;
    ps_info("ospf_listener: shutdown");
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

const ps_module_t ospf_module = {
    .name        = "ospf_listener",
    .description = "Passive OSPF Hello listener — router and area discovery",
    .version     = "1.0",
    .flags       = PS_MOD_PASSIVE,

    .init        = ospf_init,
    .shutdown    = ospf_shutdown,
    .on_packet   = ospf_on_packet,
    .on_job      = NULL,
    .on_response = NULL,
    .tick        = NULL,
};

__attribute__((constructor))
static void register_ospf(void)
{
    ps_module_register(&ospf_module);
}
