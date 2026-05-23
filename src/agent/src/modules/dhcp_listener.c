/*
 * dhcp_listener.c — Passive DHCPv4/DHCPv6 listener for PacketSonde Agent
 *
 * Captures DHCP traffic on ports 67/68 (DHCPv4) and 546/547 (DHCPv6).
 * Publishes IP assignments to the "discovery.dhcp" channel on ACK/Reply.
 *
 * DHCPv4: publishes on DHCP ACK (option 53 = 5).
 * DHCPv6: publishes on Reply message (msg_type = 7) with IA_NA/IAADDR option.
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
#include "platform/platform.h"

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define DHCP_DEFAULT_IFACE       ""
#define DHCP_SNAPLEN             1500

/* Ethernet header */
#define ETH_HDR_LEN              14

/* DHCPv4 fixed header length */
#define DHCP4_HDR_LEN            236   /* op..file fields */
#define DHCP4_MAGIC_OFFSET       236
#define DHCP4_MAGIC              0x63825363u
#define DHCP4_OPTIONS_OFFSET     240   /* after magic cookie */

/* DHCPv4 option codes */
#define DHCP4_OPT_SUBNET_MASK    1
#define DHCP4_OPT_HOSTNAME       12
#define DHCP4_OPT_REQ_IP         50
#define DHCP4_OPT_LEASE_TIME     51
#define DHCP4_OPT_MSG_TYPE       53
#define DHCP4_OPT_SERVER_ID      54
#define DHCP4_OPT_END            255
#define DHCP4_OPT_PAD            0

#define DHCP4_MSG_ACK            5

/* DHCPv4 field offsets within DHCP payload */
#define DHCP4_OFF_CHADDR         28    /* client hardware address */
#define DHCP4_OFF_YIADDR         16    /* your (client) IP address */

/* DHCPv6 message types */
#define DHCP6_MSG_REPLY          7

/* DHCPv6 option codes */
#define DHCP6_OPT_CLIENTID       1
#define DHCP6_OPT_IA_NA          3
#define DHCP6_OPT_IAADDR         5
#define DHCP6_OPT_DNS_SERVERS    23

/* DUID types for MAC extraction */
#define DUID_TYPE_LLT            1
#define DUID_TYPE_LL             3

/* IPv6 header length */
#define IPV6_HDR_LEN             40

/* UDP header length */
#define UDP_HDR_LEN              8

/* ------------------------------------------------------------------ */
/* State                                                                */
/* ------------------------------------------------------------------ */

struct dhcp_state {
    int      pcap_handle;
    uint64_t packets_seen;
    uint64_t events_published;
};

/* ------------------------------------------------------------------ */
/* MAC formatting                                                       */
/* ------------------------------------------------------------------ */

static void format_mac(const uint8_t *mac, char *out, size_t outsz)
{
    snprintf(out, outsz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ------------------------------------------------------------------ */
/* DHCPv4 parsing                                                       */
/* ------------------------------------------------------------------ */

static void parse_dhcp4(ps_module_ctx_t *ctx, const uint8_t *dhcp, uint32_t len)
{
    /* Need at least fixed header + magic cookie + 1 option byte */
    if (len < DHCP4_OPTIONS_OFFSET + 1)
        return;

    /* Verify magic cookie */
    uint32_t magic = 0;
    memcpy(&magic, dhcp + DHCP4_MAGIC_OFFSET, 4);
    if (ntohl(magic) != DHCP4_MAGIC)
        return;

    /* Extract yiaddr (assigned IP) */
    struct in_addr yiaddr;
    memcpy(&yiaddr, dhcp + DHCP4_OFF_YIADDR, 4);

    /* Extract chaddr (MAC, first 6 bytes) */
    const uint8_t *chaddr = dhcp + DHCP4_OFF_CHADDR;

    /* Parse options */
    uint8_t  msg_type    = 0;
    uint32_t lease_time  = 0;
    uint32_t server_ip   = 0;
    char     hostname[64];
    hostname[0] = '\0';

    uint32_t off = DHCP4_OPTIONS_OFFSET;
    while (off < len) {
        uint8_t opt = dhcp[off++];
        if (opt == DHCP4_OPT_PAD) continue;
        if (opt == DHCP4_OPT_END) break;
        if (off >= len) break;

        uint8_t olen = dhcp[off++];
        if (off + olen > len) break;

        switch (opt) {
            case DHCP4_OPT_MSG_TYPE:
                if (olen >= 1)
                    msg_type = dhcp[off];
                break;
            case DHCP4_OPT_HOSTNAME: {
                uint8_t copy_len = (olen < (uint8_t)(sizeof(hostname) - 1))
                                   ? olen : (uint8_t)(sizeof(hostname) - 1);
                memcpy(hostname, dhcp + off, copy_len);
                hostname[copy_len] = '\0';
                break;
            }
            case DHCP4_OPT_LEASE_TIME:
                if (olen >= 4) {
                    memcpy(&lease_time, dhcp + off, 4);
                    lease_time = ntohl(lease_time);
                }
                break;
            case DHCP4_OPT_SERVER_ID:
                if (olen >= 4)
                    memcpy(&server_ip, dhcp + off, 4);
                break;
            default:
                break;
        }

        off += olen;
    }

    /* Only publish on ACK */
    if (msg_type != DHCP4_MSG_ACK)
        return;

    /* Format addresses */
    char mac_str[18];
    format_mac(chaddr, mac_str, sizeof(mac_str));

    char yiaddr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &yiaddr, yiaddr_str, sizeof(yiaddr_str));

    char server_str[INET_ADDRSTRLEN];
    struct in_addr srv;
    memcpy(&srv, &server_ip, 4);
    inet_ntop(AF_INET, &srv, server_str, sizeof(server_str));

    /* Build JSON */
    char buf[512];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "mac",            mac_str);
    ps_json_key_string(&j, "assigned_ip",    yiaddr_str);
    ps_json_key_string(&j, "hostname",       hostname);
    ps_json_key_int   (&j, "lease_seconds",  (int64_t)lease_time);
    ps_json_key_string(&j, "server_ip",      server_str);
    ps_json_key_string(&j, "proto",          "v4");
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "discovery.dhcp", buf, (uint32_t)j.len);
        struct dhcp_state *st = (struct dhcp_state *)ctx->userdata;
        if (st) st->events_published++;
        ps_debug("dhcp_listener: published DHCPv4 ACK mac=%s ip=%s",
                 mac_str, yiaddr_str);
    }
}

/* ------------------------------------------------------------------ */
/* DHCPv6 parsing                                                       */
/* ------------------------------------------------------------------ */

static void parse_dhcp6(ps_module_ctx_t *ctx, const uint8_t *dhcp6, uint32_t len)
{
    /* Need at least 4-byte header (msg_type + 3-byte xid) */
    if (len < 4) return;

    uint8_t msg_type = dhcp6[0];
    if (msg_type != DHCP6_MSG_REPLY) return;

    /* Parse top-level options (type=2, len=2, data) */
    uint32_t off = 4;

    char     assigned_ip[INET6_ADDRSTRLEN];
    char     mac_str[18];
    uint32_t valid_lifetime = 0;
    int      found_addr     = 0;
    int      found_mac      = 0;

    assigned_ip[0] = '\0';
    mac_str[0]     = '\0';

    while (off + 4 <= len) {
        uint16_t opt_type, opt_len;
        memcpy(&opt_type, dhcp6 + off,     2); opt_type = ntohs(opt_type);
        memcpy(&opt_len,  dhcp6 + off + 2, 2); opt_len  = ntohs(opt_len);
        off += 4;

        if (off + opt_len > len) break;

        if (opt_type == DHCP6_OPT_IA_NA && opt_len >= 12) {
            /*
             * IA_NA: IAID(4) + T1(4) + T2(4) + sub-options
             * Sub-options start at offset 12 within IA_NA data
             */
            uint32_t sub_off = 12;
            while (sub_off + 4 <= opt_len) {
                uint16_t sub_type, sub_len;
                memcpy(&sub_type, dhcp6 + off + sub_off,     2); sub_type = ntohs(sub_type);
                memcpy(&sub_len,  dhcp6 + off + sub_off + 2, 2); sub_len  = ntohs(sub_len);
                sub_off += 4;

                if (sub_off + sub_len > opt_len) break;

                if (sub_type == DHCP6_OPT_IAADDR && sub_len >= 24) {
                    /* IAADDR: IPv6 address(16) + preferred_lifetime(4) + valid_lifetime(4) */
                    struct in6_addr addr6;
                    memcpy(&addr6, dhcp6 + off + sub_off, 16);
                    inet_ntop(AF_INET6, &addr6, assigned_ip, sizeof(assigned_ip));

                    uint32_t vl = 0;
                    memcpy(&vl, dhcp6 + off + sub_off + 20, 4);
                    valid_lifetime = ntohl(vl);
                    found_addr = 1;
                }
                sub_off += sub_len;
            }
        } else if (opt_type == DHCP6_OPT_CLIENTID && opt_len >= 4) {
            /*
             * DUID-LLT: type(2) + hw_type(2) + time(4) + link_addr
             * DUID-LL:  type(2) + hw_type(2) + link_addr
             */
            uint16_t duid_type;
            memcpy(&duid_type, dhcp6 + off, 2); duid_type = ntohs(duid_type);

            uint32_t mac_offset = 0;
            uint32_t needed     = 0;

            if (duid_type == DUID_TYPE_LLT) {
                /* type(2) + hw_type(2) + time(4) + mac(6) = 14 bytes minimum */
                mac_offset = 8;
                needed     = 8 + 6;
            } else if (duid_type == DUID_TYPE_LL) {
                /* type(2) + hw_type(2) + mac(6) = 10 bytes minimum */
                mac_offset = 4;
                needed     = 4 + 6;
            }

            if (needed > 0 && opt_len >= needed) {
                format_mac(dhcp6 + off + mac_offset, mac_str, sizeof(mac_str));
                found_mac = 1;
            }
        }

        off += opt_len;
    }

    if (!found_addr) return;

    /* Build JSON */
    char buf[512];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "mac",            found_mac ? mac_str : "");
    ps_json_key_string(&j, "assigned_ip",    assigned_ip);
    ps_json_key_string(&j, "hostname",       "");
    ps_json_key_int   (&j, "lease_seconds",  (int64_t)valid_lifetime);
    ps_json_key_string(&j, "server_ip",      "");
    ps_json_key_string(&j, "proto",          "v6");
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "discovery.dhcp", buf, (uint32_t)j.len);
        struct dhcp_state *st = (struct dhcp_state *)ctx->userdata;
        if (st) st->events_published++;
        ps_debug("dhcp_listener: published DHCPv6 Reply ip=%s", assigned_ip);
    }
}

/* ------------------------------------------------------------------ */
/* Packet dispatcher                                                    */
/* ------------------------------------------------------------------ */

static void dhcp_on_packet(ps_module_ctx_t *ctx,
                            const uint8_t *pkt, uint32_t len,
                            uint64_t ts_usec, int handle_id)
{
    struct dhcp_state *st = (struct dhcp_state *)ctx->userdata;
    if (!st) return;
    if (handle_id != st->pcap_handle) return;

    (void)ts_usec;
    st->packets_seen++;

    /* Need at least Ethernet header */
    if (len < ETH_HDR_LEN + 1) return;

    uint16_t ethertype;
    memcpy(&ethertype, pkt + 12, 2);
    ethertype = ntohs(ethertype);

    if (ethertype == 0x0800) {
        /* IPv4 */
        if (len < ETH_HDR_LEN + 20 + UDP_HDR_LEN) return;

        const uint8_t *ip = pkt + ETH_HDR_LEN;
        int ip_hl = (ip[0] & 0x0f) * 4;
        if (ip[9] != 17 /* UDP */) return;
        if ((uint32_t)(ETH_HDR_LEN + ip_hl + UDP_HDR_LEN) > len) return;

        const uint8_t *udp = ip + ip_hl;
        uint16_t dport;
        memcpy(&dport, udp + 2, 2); dport = ntohs(dport);

        /* DHCPv4: server on 67, client on 68 */
        if (dport != 67 && dport != 68) return;

        uint32_t dhcp_off = (uint32_t)(ETH_HDR_LEN + ip_hl + UDP_HDR_LEN);
        if (dhcp_off >= len) return;
        parse_dhcp4(ctx, pkt + dhcp_off, len - dhcp_off);

    } else if (ethertype == 0x86DD) {
        /* IPv6 */
        if (len < ETH_HDR_LEN + IPV6_HDR_LEN + UDP_HDR_LEN) return;

        const uint8_t *ip6 = pkt + ETH_HDR_LEN;
        uint8_t next_hdr = ip6[6];
        if (next_hdr != 17 /* UDP */) return;

        const uint8_t *udp = ip6 + IPV6_HDR_LEN;
        uint16_t dport;
        memcpy(&dport, udp + 2, 2); dport = ntohs(dport);

        /* DHCPv6: server on 547, client on 546 */
        if (dport != 546 && dport != 547) return;

        uint32_t dhcp6_off = ETH_HDR_LEN + IPV6_HDR_LEN + UDP_HDR_LEN;
        if (dhcp6_off >= len) return;
        parse_dhcp6(ctx, pkt + dhcp6_off, len - dhcp6_off);
    }
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int dhcp_init(ps_module_ctx_t *ctx)
{
    struct dhcp_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("dhcp_listener: out of memory");
        return -1;
    }
    st->pcap_handle = -1;

    ctx->userdata = st;
    ps_info("dhcp_listener: initialized");
    return 0;
}

static void dhcp_shutdown(ps_module_ctx_t *ctx)
{
    struct dhcp_state *st = (struct dhcp_state *)ctx->userdata;
    if (!st) return;

    ps_info("dhcp_listener: shutdown (seen=%llu published=%llu)",
            (unsigned long long)st->packets_seen,
            (unsigned long long)st->events_published);

    free(st);
    ctx->userdata = NULL;
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

const ps_module_t ps_dhcp_listener_module = {
    .name        = "dhcp_listener",
    .description = "Passive DHCPv4/DHCPv6 listener — publishes IP assignments",
    .version     = "1.0",
    .flags       = PS_MOD_PASSIVE | PS_MOD_NEEDS_PCAP,

    .init        = dhcp_init,
    .shutdown    = dhcp_shutdown,
    .on_packet   = dhcp_on_packet,
    .on_job      = NULL,
    .on_response = NULL,
    .tick        = NULL,
};
