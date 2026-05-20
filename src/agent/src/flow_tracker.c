/*
 * flow_tracker.c — Bidirectional flow tracking engine for PacketSonde Agent
 *
 * Parses raw Ethernet frames (IPv4, IPv6, 802.1Q), extracts flow keys,
 * maintains an RB-tree of active flows, and expires them based on
 * per-protocol idle timeouts.
 *
 * Design informed by softflowd (BSD, Damien Miller) but implemented fresh.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include "flow_tracker.h"
#include "compat/tree.h"
#include "log.h"

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define PS_DEFAULT_MAX_FLOWS     65536

/* Timeouts in microseconds */
#define PS_TIMEOUT_TCP_EST       (3600ULL  * 1000000)
#define PS_TIMEOUT_TCP_SHORT     (30ULL    * 1000000)   /* SYN/FIN/RST */
#define PS_TIMEOUT_UDP           (300ULL   * 1000000)
#define PS_TIMEOUT_ICMP          (60ULL    * 1000000)
#define PS_TIMEOUT_GENERAL       (3600ULL  * 1000000)
#define PS_TIMEOUT_MAX_LIFETIME  (86400ULL * 1000000)

/* Ethernet */
#define ETH_HLEN        14
#define ETH_P_IP        0x0800
#define ETH_P_IPV6      0x86DD
#define ETH_P_8021Q     0x8100

/* IP protocols */
#define PS_IPPROTO_TCP     6
#define PS_IPPROTO_UDP    17
#define PS_IPPROTO_ICMP    1
#define PS_IPPROTO_ICMPV6 58

/* TCP flags */
#define PS_TH_FIN  0x01
#define PS_TH_SYN  0x02
#define PS_TH_RST  0x04

/* IPv6 extension header types to walk through */
#define PS_IP6_NH_HOP_BY_HOP  0
#define PS_IP6_NH_ROUTING     43
#define PS_IP6_NH_FRAGMENT    44
#define PS_IP6_NH_DEST_OPTS   60
#define PS_IP6_NH_AH          51
#define PS_IP6_NH_ESP         50
#define PS_IP6_NH_NONE        59

/* ------------------------------------------------------------------ */
/* Internal flow node (extends ps_flow with tree linkage)               */
/* ------------------------------------------------------------------ */

struct flow_node {
    struct ps_flow flow;
    RB_ENTRY(flow_node) rb_entry;
};

/* ------------------------------------------------------------------ */
/* RB-tree comparison                                                   */
/* ------------------------------------------------------------------ */

static int
flow_compare(struct flow_node *a, struct flow_node *b)
{
    return memcmp(&a->flow.key, &b->flow.key, sizeof(struct ps_flow_key));
}

RB_HEAD(flow_tree, flow_node);
RB_GENERATE_STATIC(flow_tree, flow_node, rb_entry, flow_compare)

/* ------------------------------------------------------------------ */
/* Flow table                                                           */
/* ------------------------------------------------------------------ */

struct ps_flow_table {
    struct flow_tree tree;
    int              num_flows;
    int              max_flows;
    int              track_level;

    /* Timeouts (microseconds) */
    uint64_t timeout_tcp_est;
    uint64_t timeout_tcp_short;
    uint64_t timeout_udp;
    uint64_t timeout_icmp;
    uint64_t timeout_general;
    uint64_t timeout_max_lifetime;

    /* Statistics */
    uint64_t total_packets;
    uint64_t bad_packets;
    uint64_t flows_expired;
    uint64_t flows_dropped;
};

/* ------------------------------------------------------------------ */
/* Parsed packet info                                                   */
/* ------------------------------------------------------------------ */

struct parsed_packet {
    uint8_t  af;
    uint8_t  proto;
    uint8_t  src_addr[16];
    uint8_t  dst_addr[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t vlan_id;
    uint8_t  tos;
    uint32_t flow_label;
    uint32_t payload_len;   /* IP total length */
    uint8_t  tcp_flags;
    int      valid;
};

/* ------------------------------------------------------------------ */
/* Packet parsing                                                       */
/* ------------------------------------------------------------------ */

static uint16_t read_u16_be(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static int is_ipv6_ext_header(uint8_t nh)
{
    return nh == PS_IP6_NH_HOP_BY_HOP ||
           nh == PS_IP6_NH_ROUTING     ||
           nh == PS_IP6_NH_FRAGMENT    ||
           nh == PS_IP6_NH_DEST_OPTS   ||
           nh == PS_IP6_NH_AH;
}

static void
parse_transport(const uint8_t *pkt, uint32_t remaining, uint8_t proto,
                struct parsed_packet *pp)
{
    pp->proto = proto;

    if ((proto == PS_IPPROTO_TCP) && remaining >= 14) {
        pp->src_port  = read_u16_be(pkt);
        pp->dst_port  = read_u16_be(pkt + 2);
        pp->tcp_flags = pkt[13];
    } else if ((proto == PS_IPPROTO_UDP) && remaining >= 4) {
        pp->src_port = read_u16_be(pkt);
        pp->dst_port = read_u16_be(pkt + 2);
    }
    /* ICMP/ICMPv6: no ports, proto already set */
}

static int
parse_ipv4(const uint8_t *pkt, uint32_t len, struct parsed_packet *pp)
{
    if (len < 20) return -1;

    uint8_t  ver_ihl = pkt[0];
    uint8_t  version = ver_ihl >> 4;
    if (version != 4) return -1;

    int ihl = (ver_ihl & 0x0f) * 4;
    if (ihl < 20 || (uint32_t)ihl > len) return -1;

    uint16_t total_len = read_u16_be(pkt + 2);
    if (total_len < (uint16_t)ihl) return -1;
    /* Clamp to actual captured length */
    if (total_len > len) total_len = (uint16_t)len;

    pp->af  = AF_INET;
    pp->tos = pkt[1];
    pp->payload_len = total_len;

    memcpy(pp->src_addr, pkt + 12, 4);
    memcpy(pp->dst_addr, pkt + 16, 4);

    uint8_t proto = pkt[9];

    if (len > (uint32_t)ihl) {
        parse_transport(pkt + ihl, len - (uint32_t)ihl, proto, pp);
    } else {
        pp->proto = proto;
    }

    pp->valid = 1;
    return 0;
}

static int
parse_ipv6(const uint8_t *pkt, uint32_t len, struct parsed_packet *pp)
{
    if (len < 40) return -1;

    uint8_t version = pkt[0] >> 4;
    if (version != 6) return -1;

    /* Traffic class: 4 bits from byte 0, 4 bits from byte 1 */
    pp->tos = (uint8_t)(((pkt[0] & 0x0f) << 4) | (pkt[1] >> 4));

    /* Flow label: 20 bits from bytes 1-3 */
    pp->flow_label = ((uint32_t)(pkt[1] & 0x0f) << 16) |
                     ((uint32_t)pkt[2] << 8) |
                     (uint32_t)pkt[3];

    uint16_t payload_len = read_u16_be(pkt + 4);
    pp->af = AF_INET6;
    pp->payload_len = 40 + (uint32_t)payload_len;
    if (pp->payload_len > len) pp->payload_len = len;

    memcpy(pp->src_addr, pkt + 8,  16);
    memcpy(pp->dst_addr, pkt + 24, 16);

    uint8_t  next_header = pkt[6];
    uint32_t offset = 40;

    /* Walk extension headers */
    int safety = 10;
    while (is_ipv6_ext_header(next_header) && safety-- > 0 && offset + 2 <= len) {
        uint8_t ext_nh  = pkt[offset];
        uint8_t ext_len = pkt[offset + 1];

        uint32_t ext_size;
        if (next_header == PS_IP6_NH_FRAGMENT) {
            ext_size = 8;  /* Fragment header is always 8 bytes */
        } else if (next_header == PS_IP6_NH_AH) {
            ext_size = (uint32_t)(ext_len + 2) * 4;
        } else {
            ext_size = (uint32_t)(ext_len + 1) * 8;
        }

        offset += ext_size;
        next_header = ext_nh;
    }

    if (next_header == PS_IP6_NH_ESP || next_header == PS_IP6_NH_NONE) {
        /* Can't parse further */
        pp->proto = next_header;
        pp->valid = 1;
        return 0;
    }

    if (offset < len) {
        parse_transport(pkt + offset, len - offset, next_header, pp);
    } else {
        pp->proto = next_header;
    }

    pp->valid = 1;
    return 0;
}

static int
parse_ethernet(const uint8_t *pkt, uint32_t len, struct parsed_packet *pp)
{
    memset(pp, 0, sizeof(*pp));

    if (len < ETH_HLEN) return -1;

    uint16_t ethertype = read_u16_be(pkt + 12);
    const uint8_t *payload = pkt + ETH_HLEN;
    uint32_t remaining = len - ETH_HLEN;

    /* Handle 802.1Q VLAN tag */
    if (ethertype == ETH_P_8021Q) {
        if (remaining < 4) return -1;
        pp->vlan_id = read_u16_be(payload) & 0x0FFF;
        ethertype = read_u16_be(payload + 2);
        payload  += 4;
        remaining -= 4;
    }

    if (ethertype == ETH_P_IP) {
        return parse_ipv4(payload, remaining, pp);
    } else if (ethertype == ETH_P_IPV6) {
        return parse_ipv6(payload, remaining, pp);
    }

    return -1;  /* Not an IP packet */
}

/* ------------------------------------------------------------------ */
/* Flow key canonicalization                                            */
/* ------------------------------------------------------------------ */

/*
 * Build a canonical flow key from parsed packet info.
 * Returns the direction: 0 = forward (packet matches canonical order),
 *                        1 = reverse (we swapped src/dst).
 */
static int
make_flow_key(const struct parsed_packet *pp, int track_level,
              struct ps_flow_key *key)
{
    memset(key, 0, sizeof(*key));
    key->af    = pp->af;
    key->proto = (track_level >= PS_TRACK_IP_PROTO) ? pp->proto : 0;

    if (track_level >= PS_TRACK_FULL) {
        key->tos = pp->tos;
    }
    if (track_level >= PS_TRACK_FULL_VLAN) {
        key->vlan_id = pp->vlan_id;
    }

    /* Compare addresses to determine canonical order */
    int addr_len = (pp->af == AF_INET) ? 4 : 16;
    int cmp = memcmp(pp->src_addr, pp->dst_addr, addr_len);

    if (cmp < 0 || (cmp == 0 && pp->src_port <= pp->dst_port)) {
        /* src < dst: forward direction */
        memcpy(key->src_addr, pp->src_addr, addr_len);
        memcpy(key->dst_addr, pp->dst_addr, addr_len);
        if (track_level >= PS_TRACK_IP_PROTO_PORT) {
            key->src_port = pp->src_port;
            key->dst_port = pp->dst_port;
        }
        return 0;
    } else {
        /* dst < src: swap — this is the reverse direction */
        memcpy(key->src_addr, pp->dst_addr, addr_len);
        memcpy(key->dst_addr, pp->src_addr, addr_len);
        if (track_level >= PS_TRACK_IP_PROTO_PORT) {
            key->src_port = pp->dst_port;
            key->dst_port = pp->src_port;
        }
        return 1;
    }
}

/* ------------------------------------------------------------------ */
/* Timeout selection                                                    */
/* ------------------------------------------------------------------ */

static uint64_t
flow_idle_timeout(const struct ps_flow_table *ft, const struct ps_flow *f)
{
    if (f->key.proto == PS_IPPROTO_TCP) {
        uint8_t all_flags = f->tcp_flags[0] | f->tcp_flags[1];
        if (all_flags & (PS_TH_FIN | PS_TH_RST)) {
            return ft->timeout_tcp_short;
        }
        if (!(all_flags & PS_TH_SYN)) {
            /* No SYN seen — might be midstream, use general */
            return ft->timeout_general;
        }
        return ft->timeout_tcp_est;
    }

    if (f->key.proto == PS_IPPROTO_UDP) {
        return ft->timeout_udp;
    }

    if (f->key.proto == PS_IPPROTO_ICMP || f->key.proto == PS_IPPROTO_ICMPV6) {
        return ft->timeout_icmp;
    }

    return ft->timeout_general;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

struct ps_flow_table *
ps_flow_table_create(int max_flows, int track_level)
{
    struct ps_flow_table *ft = calloc(1, sizeof(*ft));
    if (!ft) return NULL;

    RB_INIT(&ft->tree);
    ft->max_flows = (max_flows > 0) ? max_flows : PS_DEFAULT_MAX_FLOWS;
    ft->track_level = track_level;

    ft->timeout_tcp_est      = PS_TIMEOUT_TCP_EST;
    ft->timeout_tcp_short    = PS_TIMEOUT_TCP_SHORT;
    ft->timeout_udp          = PS_TIMEOUT_UDP;
    ft->timeout_icmp         = PS_TIMEOUT_ICMP;
    ft->timeout_general      = PS_TIMEOUT_GENERAL;
    ft->timeout_max_lifetime = PS_TIMEOUT_MAX_LIFETIME;

    return ft;
}

void
ps_flow_table_destroy(struct ps_flow_table *ft)
{
    if (!ft) return;

    struct flow_node *node, *next;
    RB_FOREACH_SAFE(node, flow_tree, &ft->tree, next) {
        RB_REMOVE(flow_tree, &ft->tree, node);
        free(node);
    }

    free(ft);
}

int
ps_flow_table_process_packet(struct ps_flow_table *ft,
                              const uint8_t *pkt, uint32_t len,
                              uint64_t ts_usec)
{
    if (!ft || !pkt || len == 0) return -1;

    ft->total_packets++;

    struct parsed_packet pp;
    if (parse_ethernet(pkt, len, &pp) < 0 || !pp.valid) {
        ft->bad_packets++;
        return -1;
    }

    struct ps_flow_key key;
    int direction = make_flow_key(&pp, ft->track_level, &key);

    /* Look up existing flow */
    struct flow_node lookup;
    memset(&lookup, 0, sizeof(lookup));
    lookup.flow.key = key;

    struct flow_node *found = RB_FIND(flow_tree, &ft->tree, &lookup);

    if (found) {
        /* Update existing flow */
        found->flow.packets[direction]++;
        found->flow.octets[direction] += pp.payload_len;
        found->flow.tcp_flags[direction] |= pp.tcp_flags;
        found->flow.flow_last = ts_usec;
        return 0;
    }

    /* Create new flow */
    if (ft->num_flows >= ft->max_flows) {
        ft->flows_dropped++;
        return -1;
    }

    struct flow_node *node = calloc(1, sizeof(*node));
    if (!node) return -1;

    node->flow.key = key;
    node->flow.packets[direction] = 1;
    node->flow.octets[direction]  = pp.payload_len;
    node->flow.tcp_flags[direction] = pp.tcp_flags;
    node->flow.flow_start = ts_usec;
    node->flow.flow_last  = ts_usec;
    node->flow.flow_label = pp.flow_label;

    RB_INSERT(flow_tree, &ft->tree, node);
    ft->num_flows++;

    return 0;
}

int
ps_flow_table_expire(struct ps_flow_table *ft, uint64_t now_usec,
                      struct ps_flow *out, int max_out)
{
    if (!ft) return 0;

    int expired = 0;
    struct flow_node *node, *next;

    RB_FOREACH_SAFE(node, flow_tree, &ft->tree, next) {
        if (expired >= max_out) break;

        uint64_t idle    = flow_idle_timeout(ft, &node->flow);
        uint64_t elapsed = (now_usec > node->flow.flow_last)
                         ? (now_usec - node->flow.flow_last) : 0;
        uint64_t age     = (now_usec > node->flow.flow_start)
                         ? (now_usec - node->flow.flow_start) : 0;

        if (elapsed > idle || age > ft->timeout_max_lifetime) {
            if (out) {
                out[expired] = node->flow;
            }
            RB_REMOVE(flow_tree, &ft->tree, node);
            free(node);
            ft->num_flows--;
            ft->flows_expired++;
            expired++;
        }
    }

    return expired;
}

int
ps_flow_table_count(const struct ps_flow_table *ft)
{
    if (!ft) return 0;
    return ft->num_flows;
}

int
ps_flow_table_snapshot(struct ps_flow_table *ft, uint64_t last_export_usec,
                       struct ps_flow *out, int max_out)
{
    if (!ft || !out || max_out <= 0) return 0;

    int count = 0;
    struct flow_node *node;

    RB_FOREACH(node, flow_tree, &ft->tree) {
        if (count >= max_out) break;
        /* Only export flows updated since last snapshot */
        if (node->flow.flow_last > last_export_usec) {
            out[count++] = node->flow;
        }
    }

    return count;
}
