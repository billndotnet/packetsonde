/*
 * mld_listener.c — Passive MLD (Multicast Listener Discovery) listener
 *                  for PacketSonde Agent
 *
 * Captures ICMPv6 MLD messages:
 *   Type 130 — Multicast Listener Query
 *   Type 131 — MLDv1 Report (join)
 *   Type 132 — MLDv1 Done  (leave)
 *   Type 143 — MLDv2 Report
 *
 * Publishes to the "discovery.mld" channel.
 *
 * Frame structure:
 *   Ethernet(14) + IPv6(40) + ICMPv6(variable)
 *
 * The BPF filter ensures we only see MLD packets, so we skip checking
 * the ICMPv6 type in the IP next-header (it's always 58 = ICMPv6).
 */

#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "packetsonde/module_api.h"
#include "json.h"
#include "log.h"

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define MLD_DEFAULT_IFACE        ""
#define MLD_SNAPLEN              512

/* Header lengths */
#define ETH_HDR_LEN              14
#define IPV6_HDR_LEN             40

/* ICMPv6 MLD message types */
#define MLD_TYPE_QUERY           130
#define MLD_TYPE_V1_REPORT       131
#define MLD_TYPE_V1_DONE         132
#define MLD_TYPE_V2_REPORT       143

/*
 * MLDv1 message layout (ICMPv6 payload, after type+code+cksum = 4 bytes):
 *   max_response_delay(2) + reserved(2) + group_address(16) = 20 bytes total
 *   Group address starts at ICMPv6 offset 8 (type(1)+code(1)+cksum(2)+max_resp(2)+rsvd(2))
 */
#define MLD1_GROUP_OFFSET        8    /* offset from ICMPv6 start to group address */
#define MLD1_MIN_LEN             24   /* 8 header + 16 group address */

/*
 * MLDv2 Report layout:
 *   type(1) + code(1) + cksum(2) + reserved(2) + num_group_records(2) = 8 bytes
 *   Then group records: record_type(1) + aux_data_len(1) + num_sources(2) + mcast_addr(16) + srcs
 */
#define MLD2_HDR_LEN             8
#define MLD2_RECORD_HDR_LEN      20   /* record_type(1)+aux(1)+nsrc(2)+mcast(16) */

/* ------------------------------------------------------------------ */
/* State                                                                */
/* ------------------------------------------------------------------ */

struct mld_state {
    int      pcap_handle;
    char     iface[64];
    uint64_t packets_seen;
    uint64_t events_published;
};

/* ------------------------------------------------------------------ */
/* Publishing helper                                                    */
/* ------------------------------------------------------------------ */

static void publish_mld_event(ps_module_ctx_t *ctx,
                               const char *group,
                               const char *source_ip,
                               const char *type_str,
                               const char *iface)
{
    char buf[256];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "group",      group);
    ps_json_key_string(&j, "source_ip",  source_ip);
    ps_json_key_string(&j, "type",       type_str);
    ps_json_key_string(&j, "interface",  iface);
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "discovery.mld", buf, (uint32_t)j.len);
        struct mld_state *st = (struct mld_state *)ctx->userdata;
        if (st) st->events_published++;
        ps_debug("mld_listener: %s group=%s src=%s", type_str, group, source_ip);
    }
}

/* ------------------------------------------------------------------ */
/* Packet handler                                                       */
/* ------------------------------------------------------------------ */

static void mld_on_packet(ps_module_ctx_t *ctx,
                           const uint8_t *pkt, uint32_t len,
                           uint64_t ts_usec, int handle_id)
{
    struct mld_state *st = (struct mld_state *)ctx->userdata;
    if (!st) return;
    if (handle_id != st->pcap_handle) return;

    (void)ts_usec;
    st->packets_seen++;

    /* Need at least Ethernet + IPv6 + ICMPv6 type byte */
    if (len < (uint32_t)(ETH_HDR_LEN + IPV6_HDR_LEN + 1))
        return;

    /* Verify IPv6 ethertype */
    uint16_t ethertype;
    memcpy(&ethertype, pkt + 12, 2);
    if (ntohs(ethertype) != 0x86DD) return;

    const uint8_t *ip6 = pkt + ETH_HDR_LEN;

    /* Verify IPv6 version */
    if ((ip6[0] >> 4) != 6) return;

    /* Extract source IPv6 address from outer IPv6 header (bytes 8-23) */
    struct in6_addr src6;
    memcpy(&src6, ip6 + 8, 16);
    char source_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &src6, source_ip, sizeof(source_ip));

    /* Next header should be ICMPv6 (58). MLD may have hop-by-hop options
     * prepended (next_hdr=0), but BPF filter already qualifies these, so
     * we walk extension headers to find ICMPv6. */
    uint8_t next_hdr = ip6[6];
    const uint8_t *cur = ip6 + IPV6_HDR_LEN;
    uint32_t remaining = len - ETH_HDR_LEN - IPV6_HDR_LEN;

    /* Walk hop-by-hop and destination extension headers to reach ICMPv6 */
    while (next_hdr != 58 /* ICMPv6 */ && remaining >= 8) {
        /* Extension headers: next(1) + len_in_8oct(1) + data */
        if (next_hdr == 0   /* Hop-by-Hop */ ||
            next_hdr == 60  /* Destination options */ ||
            next_hdr == 43  /* Routing */ ||
            next_hdr == 44  /* Fragment */) {
            uint8_t ext_len = (cur[1] + 1) * 8;
            if (ext_len > remaining) return;
            next_hdr  = cur[0];
            cur      += ext_len;
            remaining -= ext_len;
        } else {
            /* Unknown extension header or non-ICMPv6 — stop */
            return;
        }
    }

    if (next_hdr != 58 || remaining < 1) return;

    /* ICMPv6 payload */
    const uint8_t *icmp6 = cur;
    uint32_t icmp6_len   = remaining;

    uint8_t mld_type = icmp6[0];

    if (mld_type == MLD_TYPE_QUERY ||
        mld_type == MLD_TYPE_V1_REPORT ||
        mld_type == MLD_TYPE_V1_DONE) {

        /* MLDv1 — group address at offset 8 */
        if (icmp6_len < (uint32_t)MLD1_MIN_LEN) return;

        struct in6_addr group6;
        memcpy(&group6, icmp6 + MLD1_GROUP_OFFSET, 16);
        char group_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &group6, group_str, sizeof(group_str));

        const char *type_str = (mld_type == MLD_TYPE_QUERY)     ? "query"  :
                               (mld_type == MLD_TYPE_V1_REPORT)  ? "report" : "done";

        publish_mld_event(ctx, group_str, source_ip, type_str, st->iface);

    } else if (mld_type == MLD_TYPE_V2_REPORT) {

        /* MLDv2 Report */
        if (icmp6_len < MLD2_HDR_LEN + 2) return;

        uint16_t num_records;
        memcpy(&num_records, icmp6 + 6, 2);
        num_records = ntohs(num_records);

        uint32_t off = MLD2_HDR_LEN;

        for (uint16_t r = 0; r < num_records; r++) {
            if (off + MLD2_RECORD_HDR_LEN > icmp6_len) break;

            /* uint8_t record_type = icmp6[off]; */
            uint8_t  aux_data_len  = icmp6[off + 1];
            uint16_t num_sources   = 0;
            memcpy(&num_sources, icmp6 + off + 2, 2);
            num_sources = ntohs(num_sources);

            /* Multicast address at offset 4 within record */
            struct in6_addr mcast6;
            memcpy(&mcast6, icmp6 + off + 4, 16);
            char group_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &mcast6, group_str, sizeof(group_str));

            publish_mld_event(ctx, group_str, source_ip, "v2report", st->iface);

            /* Advance past this record: header(20) + sources(16*N) + aux_data(8*aux_len) */
            uint32_t record_len = MLD2_RECORD_HDR_LEN
                                  + (uint32_t)num_sources * 16
                                  + (uint32_t)aux_data_len * 4;
            off += record_len;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int mld_init(ps_module_ctx_t *ctx)
{
    struct mld_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("mld_listener: out of memory");
        return -1;
    }
    st->pcap_handle = -1;

    const char *iface = getenv("PS_CAPTURE_INTERFACE");
    if (!iface || iface[0] == '\0')
        iface = MLD_DEFAULT_IFACE;

    strncpy(st->iface, iface, sizeof(st->iface) - 1);
    st->iface[sizeof(st->iface) - 1] = '\0';

    ctx->userdata = st;
    ps_info("mld_listener: initialized");
    return 0;
}

static void mld_shutdown(ps_module_ctx_t *ctx)
{
    struct mld_state *st = (struct mld_state *)ctx->userdata;
    if (!st) return;

    ps_info("mld_listener: shutdown (seen=%llu published=%llu)",
            (unsigned long long)st->packets_seen,
            (unsigned long long)st->events_published);

    free(st);
    ctx->userdata = NULL;
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

const ps_module_t ps_mld_listener_module = {
    .name        = "mld_listener",
    .description = "Passive MLD listener — multicast group membership discovery",
    .version     = "1.0",
    .flags       = PS_MOD_PASSIVE | PS_MOD_NEEDS_PCAP,

    .init        = mld_init,
    .shutdown    = mld_shutdown,
    .on_packet   = mld_on_packet,
    .on_job      = NULL,
    .on_response = NULL,
    .tick        = NULL,
};
