/*
 * neighbor_listener.c — Unified ARP + NDP passive listener for PacketSonde Agent
 *
 * Passively captures ARP packets and ICMPv6 NDP messages (types 133-137) to
 * learn MAC/IP bindings and identify routers/gateways on the local network.
 *
 * BPF filter: arp or (icmp6 and (ip6[40] >= 133 and ip6[40] <= 137))
 *
 * Publishes to channel: discovery.neighbor
 *
 * JSON output:
 *   ARP:  {"ip":"...","mac":"...","interface":"...","proto":"arp","ndp_type":null,"router":false,"flags":0}
 *   NDP:  {"ip":"...","mac":"...","interface":"...","proto":"ndp","ndp_type":"na","router":true,"flags":96}
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

/* Ethernet ethertypes */
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_IPV6  0x86DD

/* ARP hardware/protocol types */
#define ARP_HW_ETHERNET  1
#define ARP_PROTO_IPV4   0x0800
#define ARP_HLEN_ETH     6
#define ARP_PLEN_IPV4    4
#define ARP_OP_REQUEST   1
#define ARP_OP_REPLY     2

/* ICMPv6 NDP types */
#define ICMPV6_RS   133  /* Router Solicitation    */
#define ICMPV6_RA   134  /* Router Advertisement   */
#define ICMPV6_NS   135  /* Neighbor Solicitation  */
#define ICMPV6_NA   136  /* Neighbor Advertisement */
#define ICMPV6_RD   137  /* Redirect               */

/* NDP option types */
#define NDP_OPT_SLLA   1   /* Source Link-Layer Address */
#define NDP_OPT_TLLA   2   /* Target Link-Layer Address */
#define NDP_OPT_PI     3   /* Prefix Information */

/* RA flags (in RA header byte) */
#define RA_FLAG_MANAGED  0x80
#define RA_FLAG_OTHER    0x40

/* NA flags (in first 4 bytes of NA body, network order) */
#define NA_FLAG_ROUTER    0x80000000UL
#define NA_FLAG_SOLICITED 0x40000000UL
#define NA_FLAG_OVERRIDE  0x20000000UL

/* Ethernet frame minimum size */
#define ETH_HDR_LEN  14

/* IPv6 fixed header length */
#define IPV6_HDR_LEN 40

/* ------------------------------------------------------------------ */
/* State                                                                */
/* ------------------------------------------------------------------ */

struct neighbor_state {
    char iface[64];  /* interface name, set during init (future: per-handle) */
};

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static void mac_to_str(const uint8_t *mac, char *out, size_t outsz)
{
    snprintf(out, outsz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*
 * Read a big-endian 16-bit value from an unaligned pointer.
 */
static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

/*
 * Read a big-endian 32-bit value from an unaligned pointer.
 */
static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |
            (uint32_t)p[3];
}

/* ------------------------------------------------------------------ */
/* Publish helpers                                                      */
/* ------------------------------------------------------------------ */

static void publish_neighbor(ps_module_ctx_t *ctx,
                              const char *ip_str,
                              const char *mac_str,
                              const char *iface,
                              const char *proto,       /* "arp" or "ndp" */
                              const char *ndp_type,    /* "rs","ra","ns","na","rd" or NULL */
                              int is_router,
                              uint32_t flags)
{
    char buf[512];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "ip",        ip_str);
    ps_json_key_string(&j, "mac",       mac_str);
    ps_json_key_string(&j, "interface", iface);
    ps_json_key_string(&j, "proto",     proto);

    if (ndp_type) {
        ps_json_key_string(&j, "ndp_type", ndp_type);
    } else {
        ps_json_key_null(&j, "ndp_type");
    }

    ps_json_key_bool(&j, "router", is_router);
    ps_json_key_int (&j, "flags",  (int64_t)flags);
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "discovery.neighbor", buf, (uint32_t)j.len);
    }
}

/* ------------------------------------------------------------------ */
/* ARP parser                                                           */
/* ------------------------------------------------------------------ */

/*
 * Parse an ARP packet.
 *
 * pkt     — pointer to start of Ethernet frame
 * len     — total captured length
 * iface   — interface name for publishing
 *
 * We learn from both requests and replies (sender MAC + IP in both cases).
 * ARP is 28 bytes after the 14-byte Ethernet header.
 */
static void parse_arp(ps_module_ctx_t *ctx,
                      const uint8_t *pkt, uint32_t len,
                      const char *iface)
{
    /* Ethernet header (14) + ARP (28) = 42 bytes minimum */
    if (len < ETH_HDR_LEN + 28) return;

    const uint8_t *arp = pkt + ETH_HDR_LEN;

    uint16_t hw_type   = read_be16(arp + 0);
    uint16_t proto     = read_be16(arp + 2);
    uint8_t  hlen      = arp[4];
    uint8_t  plen      = arp[5];
    uint16_t op        = read_be16(arp + 6);

    /* Sanity: Ethernet/IPv4 ARP only */
    if (hw_type != ARP_HW_ETHERNET) return;
    if (proto   != ARP_PROTO_IPV4)  return;
    if (hlen    != ARP_HLEN_ETH)    return;
    if (plen    != ARP_PLEN_IPV4)   return;

    /* Only process requests and replies */
    if (op != ARP_OP_REQUEST && op != ARP_OP_REPLY) return;

    /* Sender MAC (bytes 8..13), Sender IP (bytes 14..17) */
    const uint8_t *sender_mac = arp + 8;
    const uint8_t *sender_ip  = arp + 14;

    /* Skip packets from the zero MAC (gratuitous ARP probes before assignment) */
    if (sender_mac[0] == 0 && sender_mac[1] == 0 && sender_mac[2] == 0 &&
        sender_mac[3] == 0 && sender_mac[4] == 0 && sender_mac[5] == 0)
        return;

    /* Skip 0.0.0.0 sender IP (ARP probe, not yet assigned) */
    if (sender_ip[0] == 0 && sender_ip[1] == 0 &&
        sender_ip[2] == 0 && sender_ip[3] == 0)
        return;

    char mac_str[18];
    mac_to_str(sender_mac, mac_str, sizeof(mac_str));

    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr;
    memcpy(&addr.s_addr, sender_ip, 4);
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

    publish_neighbor(ctx, ip_str, mac_str, iface,
                     "arp", NULL, 0, (uint32_t)op);
}

/* ------------------------------------------------------------------ */
/* NDP option walker                                                    */
/* ------------------------------------------------------------------ */

/*
 * Walk NDP TLV options starting at opts_start, consuming opts_len bytes.
 * Fills in:
 *   ll_addr_out — 6-byte MAC from option type opt_ll_type (1 or 2), or zeroed
 *   has_ll_addr — set to 1 if a link-layer address option was found
 */
static void ndp_walk_options(const uint8_t *opts, uint32_t opts_len,
                              uint8_t opt_ll_type,
                              uint8_t ll_addr_out[6], int *has_ll_addr)
{
    uint32_t off = 0;
    while (off + 2 <= opts_len) {
        uint8_t type   = opts[off];
        uint8_t length = opts[off + 1];  /* in units of 8 bytes */

        if (length == 0) break;  /* malformed; stop */

        uint32_t opt_len_bytes = (uint32_t)length * 8;
        if (off + opt_len_bytes > opts_len) break;  /* truncated */

        if (type == opt_ll_type && opt_len_bytes >= 8) {
            /* Link-layer address: 6 bytes starting at opts[off+2] */
            memcpy(ll_addr_out, opts + off + 2, 6);
            *has_ll_addr = 1;
        }

        off += opt_len_bytes;
    }
}

/* ------------------------------------------------------------------ */
/* NDP parser                                                           */
/* ------------------------------------------------------------------ */

/*
 * Parse ICMPv6 NDP messages from a raw Ethernet frame.
 *
 * Frame layout:
 *   [0..13]   Ethernet header (dst MAC, src MAC, ethertype=0x86DD)
 *   [14..53]  IPv6 header (40 bytes)
 *   [54..]    ICMPv6 (type + code + checksum + body)
 *
 * We verify ethertype is IPv6, next-header is 58 (ICMPv6), and the
 * ICMPv6 type is in the NDP range 133-137.
 */
static void parse_ndp(ps_module_ctx_t *ctx,
                      const uint8_t *pkt, uint32_t len,
                      const char *iface)
{
    /* Need at least Ethernet + IPv6 + 4 bytes of ICMPv6 */
    if (len < ETH_HDR_LEN + IPV6_HDR_LEN + 4) return;

    const uint8_t *eth  = pkt;
    const uint8_t *ip6  = pkt + ETH_HDR_LEN;
    const uint8_t *icmp = pkt + ETH_HDR_LEN + IPV6_HDR_LEN;

    /* Verify IPv6 version */
    if ((ip6[0] >> 4) != 6) return;

    /* Verify next header is ICMPv6 (58) */
    if (ip6[6] != 58) return;

    /* ICMPv6 payload length from IPv6 header */
    uint16_t payload_len = read_be16(ip6 + 4);
    if (payload_len < 4) return;
    if ((uint32_t)(ETH_HDR_LEN + IPV6_HDR_LEN) + payload_len > len) {
        /* Use what we have — truncated capture */
        payload_len = (uint16_t)(len - ETH_HDR_LEN - IPV6_HDR_LEN);
    }

    uint8_t icmp_type = icmp[0];
    if (icmp_type < ICMPV6_RS || icmp_type > ICMPV6_RD) return;

    /* Source IPv6 from IPv6 header (bytes 8..23 of IP6 header) */
    char src_ip6[INET6_ADDRSTRLEN] = {0};
    struct in6_addr src6;
    memcpy(&src6, ip6 + 8, 16);
    inet_ntop(AF_INET6, &src6, src_ip6, sizeof(src_ip6));

    /* Source MAC from Ethernet header */
    char src_mac[18];
    mac_to_str(eth + 6, src_mac, sizeof(src_mac));

    switch (icmp_type) {

    /* ---- Router Solicitation (type 133) ---- */
    case ICMPV6_RS: {
        /*
         * RS body: 4 bytes reserved, then options.
         * We publish source IP/MAC (8 bytes minimum: 4 header + 4 reserved).
         */
        if (payload_len < 8) return;

        /* Look for Source Link-Layer Address option */
        uint8_t ll[6] = {0};
        int has_ll = 0;
        if (payload_len > 8) {
            ndp_walk_options(icmp + 8, payload_len - 8,
                             NDP_OPT_SLLA, ll, &has_ll);
        }

        const char *mac_out = src_mac;
        char opt_mac[18];
        if (has_ll) {
            mac_to_str(ll, opt_mac, sizeof(opt_mac));
            mac_out = opt_mac;
        }

        publish_neighbor(ctx, src_ip6, mac_out, iface,
                         "ndp", "rs", 0, 0);
        break;
    }

    /* ---- Router Advertisement (type 134) ---- */
    case ICMPV6_RA: {
        /*
         * RA body:
         *   [4]    hop limit
         *   [5]    flags (M=0x80, O=0x40)
         *   [6..7] router lifetime
         *   [8..11] reachable time
         *   [12..15] retrans timer
         *   [16..] options
         *
         * Minimum 16 bytes body (4 ICMPv6 hdr + 12 RA fixed fields).
         */
        if (payload_len < 16) return;

        uint8_t ra_flags    = icmp[5];
        uint32_t flags_out  = (uint32_t)ra_flags;

        /* Walk options for Source Link-Layer Address */
        uint8_t ll[6] = {0};
        int has_ll = 0;
        if (payload_len > 16) {
            ndp_walk_options(icmp + 16, payload_len - 16,
                             NDP_OPT_SLLA, ll, &has_ll);
        }

        const char *mac_out = src_mac;
        char opt_mac[18];
        if (has_ll) {
            mac_to_str(ll, opt_mac, sizeof(opt_mac));
            mac_out = opt_mac;
        }

        publish_neighbor(ctx, src_ip6, mac_out, iface,
                         "ndp", "ra", 1 /* sender is a router */, flags_out);
        break;
    }

    /* ---- Neighbor Solicitation (type 135) ---- */
    case ICMPV6_NS: {
        /*
         * NS body:
         *   [4..7]   reserved
         *   [8..23]  target address (IPv6)
         *   [24..]   options
         *
         * Minimum 24 bytes body.
         */
        if (payload_len < 24) return;

        /* Target address */
        char target_ip6[INET6_ADDRSTRLEN] = {0};
        struct in6_addr target6;
        memcpy(&target6, icmp + 8, 16);
        inet_ntop(AF_INET6, &target6, target_ip6, sizeof(target_ip6));

        /* Source link-layer address option */
        uint8_t ll[6] = {0};
        int has_ll = 0;
        if (payload_len > 24) {
            ndp_walk_options(icmp + 24, payload_len - 24,
                             NDP_OPT_SLLA, ll, &has_ll);
        }

        const char *mac_out = src_mac;
        char opt_mac[18];
        if (has_ll) {
            mac_to_str(ll, opt_mac, sizeof(opt_mac));
            mac_out = opt_mac;
        }

        /* Publish the solicitor's binding (src_ip6 → mac) */
        publish_neighbor(ctx, src_ip6, mac_out, iface,
                         "ndp", "ns", 0, 0);

        /* Also note the target as solicited (IP only, no MAC learned yet) */
        (void)target_ip6; /* consumed by solicit — target MAC learned from NA */
        break;
    }

    /* ---- Neighbor Advertisement (type 136) ---- */
    case ICMPV6_NA: {
        /*
         * NA body:
         *   [4..7]   flags (R=bit31, S=bit30, O=bit29) big-endian
         *   [8..23]  target address
         *   [24..]   options
         *
         * Minimum 24 bytes body.
         */
        if (payload_len < 24) return;

        uint32_t na_flags_raw = read_be32(icmp + 4);
        int is_router   = (na_flags_raw & NA_FLAG_ROUTER)    ? 1 : 0;

        /* Target address */
        char target_ip6[INET6_ADDRSTRLEN] = {0};
        struct in6_addr target6;
        memcpy(&target6, icmp + 8, 16);
        inet_ntop(AF_INET6, &target6, target_ip6, sizeof(target_ip6));

        /* Target Link-Layer Address option */
        uint8_t ll[6] = {0};
        int has_ll = 0;
        if (payload_len > 24) {
            ndp_walk_options(icmp + 24, payload_len - 24,
                             NDP_OPT_TLLA, ll, &has_ll);
        }

        /* Fall back to Ethernet source MAC if no TLLA option */
        const char *mac_out = src_mac;
        char opt_mac[18];
        if (has_ll) {
            mac_to_str(ll, opt_mac, sizeof(opt_mac));
            mac_out = opt_mac;
        }

        /* Publish target address binding (more authoritative than solicitor) */
        uint8_t flags_byte = (uint8_t)(na_flags_raw >> 24);
        publish_neighbor(ctx, target_ip6, mac_out, iface,
                         "ndp", "na", is_router, (uint32_t)flags_byte);
        break;
    }

    /* ---- Redirect (type 137) ---- */
    case ICMPV6_RD: {
        /*
         * We note the sender (router) but don't learn target bindings from
         * Redirect messages — that's a routing update, not a neighbor binding.
         */
        publish_neighbor(ctx, src_ip6, src_mac, iface,
                         "ndp", "rd", 1 /* sender is a router */, 0);
        break;
    }

    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int neighbor_init(ps_module_ctx_t *ctx)
{
    struct neighbor_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("neighbor_listener: out of memory");
        return -1;
    }

    ctx->userdata = st;

    ps_info("neighbor_listener: initialized");
    return 0;
}

static void neighbor_shutdown(ps_module_ctx_t *ctx)
{
    free(ctx->userdata);
    ctx->userdata = NULL;
    ps_info("neighbor_listener: shutdown");
}

/*
 * on_packet — called by the dispatcher for each captured Ethernet frame.
 *
 * pkt points to the start of the Ethernet frame (DLT_EN10MB).
 * We dispatch on the EtherType field at bytes 12..13.
 */
static void neighbor_on_packet(ps_module_ctx_t *ctx,
                                const uint8_t *pkt, uint32_t len,
                                uint64_t ts_usec, int handle_id)
{
    (void)ts_usec;
    (void)handle_id;

    struct neighbor_state *st = (struct neighbor_state *)ctx->userdata;
    if (!st) return;

    /* Need at least the Ethernet header */
    if (len < ETH_HDR_LEN) return;

    uint16_t ethertype = read_be16(pkt + 12);

    switch (ethertype) {
    case ETHERTYPE_ARP:
        parse_arp(ctx, pkt, len, st->iface[0] ? st->iface : "unknown");
        break;
    case ETHERTYPE_IPV6:
        parse_ndp(ctx, pkt, len, st->iface[0] ? st->iface : "unknown");
        break;
    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

#ifndef PS_NEIGHBOR_LISTENER_TESTING

const ps_module_t ps_neighbor_listener_module = {
    .name        = "neighbor_listener",
    .description = "Unified ARP + NDP for MAC/IP learning and gateway discovery",
    .version     = "1.0",
    .flags       = PS_MOD_PASSIVE | PS_MOD_NEEDS_PCAP,

    .init        = neighbor_init,
    .shutdown    = neighbor_shutdown,
    .on_packet   = neighbor_on_packet,
    .on_job      = NULL,
    .on_response = NULL,
    .tick        = NULL,
};

#endif /* PS_NEIGHBOR_LISTENER_TESTING */
