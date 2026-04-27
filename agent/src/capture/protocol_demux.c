#include "capture/protocol_demux.h"
#include "log.h"
#include <string.h>

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

/* Read a big-endian 16-bit value from an arbitrary byte offset. */
static inline uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

/* Ethernet header layout constants */
#define ETH_HDR_LEN     14   /* 6 dst + 6 src + 2 ethertype */
#define ETH_ETHERTYPE   12   /* byte offset of EtherType field */

/* IPv4 layout (relative to start of IP header) */
#define IP4_PROTO_OFF    9   /* protocol field byte offset */
#define IP4_IHL_MASK  0x0f   /* lower nibble of first byte = IHL */

/* IPv6 layout (relative to start of IPv6 header) */
#define IP6_NEXTHDR_OFF  6   /* next-header byte offset */
#define IP6_HDR_LEN     40   /* fixed header length */

/* UDP layout (relative to start of UDP header) */
#define UDP_DSTPORT_OFF  2   /* destination port byte offset */

#define ETHERTYPE_IPV4  0x0800u
#define ETHERTYPE_IPV6  0x86DDu
#define IP_PROTO_UDP    17u

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

void ps_demux_init(struct ps_protocol_demux *dmx)
{
    memset(dmx, 0, sizeof(*dmx));
}

int ps_demux_register(struct ps_protocol_demux *dmx,
                      const char *name,
                      enum ps_proto_match_type match_type,
                      uint32_t match_value,
                      ps_demux_handler_fn handler,
                      void *userdata)
{
    if (dmx->count >= PS_DEMUX_MAX_HANDLERS) {
        ps_error("protocol_demux: handler table full (max %d)", PS_DEMUX_MAX_HANDLERS);
        return -1;
    }
    struct ps_demux_entry *e = &dmx->entries[dmx->count++];
    strncpy(e->name, name, sizeof(e->name) - 1);
    e->name[sizeof(e->name) - 1] = '\0';
    e->match_type  = match_type;
    e->match_value = match_value;
    e->match_fn    = NULL;
    e->handler     = handler;
    e->userdata    = userdata;
    e->enabled     = true;
    ps_debug("protocol_demux: registered handler '%s' type=%d value=0x%04x",
             name, match_type, match_value);
    return 0;
}

int ps_demux_register_custom(struct ps_protocol_demux *dmx,
                              const char *name,
                              ps_demux_match_fn match_fn,
                              ps_demux_handler_fn handler,
                              void *userdata)
{
    if (dmx->count >= PS_DEMUX_MAX_HANDLERS) {
        ps_error("protocol_demux: handler table full (max %d)", PS_DEMUX_MAX_HANDLERS);
        return -1;
    }
    struct ps_demux_entry *e = &dmx->entries[dmx->count++];
    strncpy(e->name, name, sizeof(e->name) - 1);
    e->name[sizeof(e->name) - 1] = '\0';
    e->match_type  = PS_MATCH_CUSTOM;
    e->match_value = 0;
    e->match_fn    = match_fn;
    e->handler     = handler;
    e->userdata    = userdata;
    e->enabled     = true;
    ps_debug("protocol_demux: registered custom handler '%s'", name);
    return 0;
}

int ps_demux_set_enabled(struct ps_protocol_demux *dmx,
                         const char *name, bool enabled)
{
    for (int i = 0; i < dmx->count; i++) {
        if (strncmp(dmx->entries[i].name, name, sizeof(dmx->entries[i].name)) == 0) {
            dmx->entries[i].enabled = enabled;
            ps_debug("protocol_demux: handler '%s' %s",
                     name, enabled ? "enabled" : "disabled");
            return 0;
        }
    }
    ps_warn("protocol_demux: set_enabled — handler '%s' not found", name);
    return -1;
}

bool ps_demux_is_enabled(const struct ps_protocol_demux *dmx,
                          const char *name)
{
    for (int i = 0; i < dmx->count; i++) {
        if (strncmp(dmx->entries[i].name, name, sizeof(dmx->entries[i].name)) == 0) {
            return dmx->entries[i].enabled;
        }
    }
    return false;
}

void ps_demux_dispatch(struct ps_protocol_demux *dmx,
                       const uint8_t *pkt, uint32_t len,
                       uint64_t ts_usec, int handle_id)
{
    if (len < ETH_HDR_LEN)
        return;

    /* Extract EtherType (bytes 12-13). */
    uint16_t ethertype = read_be16(pkt + ETH_ETHERTYPE);

    /* Decode IP protocol and UDP destination port, if applicable. */
    uint8_t  ip_proto   = 0;
    uint16_t udp_dstport = 0;

    if (ethertype == ETHERTYPE_IPV4) {
        /* Need at least IP header's protocol byte. */
        if (len >= ETH_HDR_LEN + IP4_PROTO_OFF + 1) {
            const uint8_t *ip = pkt + ETH_HDR_LEN;
            ip_proto = ip[IP4_PROTO_OFF];
            if (ip_proto == IP_PROTO_UDP) {
                /* IHL is in the lower 4 bits of the first byte (in 32-bit words). */
                uint32_t ihl_bytes = (uint32_t)(ip[0] & IP4_IHL_MASK) * 4;
                uint32_t udp_off = ETH_HDR_LEN + ihl_bytes;
                if (len >= udp_off + UDP_DSTPORT_OFF + 2)
                    udp_dstport = read_be16(pkt + udp_off + UDP_DSTPORT_OFF);
            }
        }
    } else if (ethertype == ETHERTYPE_IPV6) {
        if (len >= ETH_HDR_LEN + IP6_NEXTHDR_OFF + 1) {
            const uint8_t *ip6 = pkt + ETH_HDR_LEN;
            ip_proto = ip6[IP6_NEXTHDR_OFF];
            if (ip_proto == IP_PROTO_UDP) {
                uint32_t udp_off = ETH_HDR_LEN + IP6_HDR_LEN;
                if (len >= udp_off + UDP_DSTPORT_OFF + 2)
                    udp_dstport = read_be16(pkt + udp_off + UDP_DSTPORT_OFF);
            }
        }
    }

    /* Walk the handler table and dispatch to matching, enabled entries. */
    for (int i = 0; i < dmx->count; i++) {
        struct ps_demux_entry *e = &dmx->entries[i];
        if (!e->enabled)
            continue;

        bool matched = false;
        switch (e->match_type) {
        case PS_MATCH_ETHERTYPE:
            matched = (ethertype == (uint16_t)e->match_value);
            break;
        case PS_MATCH_IP_PROTO:
            matched = (ip_proto != 0 && ip_proto == (uint8_t)e->match_value);
            break;
        case PS_MATCH_UDP_PORT:
            matched = (udp_dstport != 0 && udp_dstport == (uint16_t)e->match_value);
            break;
        case PS_MATCH_CUSTOM:
            matched = (e->match_fn != NULL && e->match_fn(pkt, len));
            break;
        }

        if (matched)
            e->handler(pkt, len, ts_usec, handle_id, e->userdata);
    }
}
