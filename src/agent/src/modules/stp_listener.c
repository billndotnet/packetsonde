/*
 * stp_listener.c — Passive STP/RSTP BPDU listener for PacketSonde Agent
 *
 * Captures STP frames destined to the STP multicast address 01:80:c2:00:00:00.
 * Parses Config BPDUs (0x00), TCN BPDUs (0x80), and RSTP BPDUs (0x02).
 * Publishes bridge topology events to the "discovery.stp" channel.
 *
 * Frame structure:
 *   Ethernet(14) + LLC(3: DSAP=0x42, SSAP=0x42, Ctrl=0x03) + BPDU
 */

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include <arpa/inet.h>

#include "packetsonde/module_api.h"
#include "json.h"
#include "log.h"

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define STP_DEFAULT_IFACE        ""
#define STP_SNAPLEN              128

/* Ethernet header length */
#define ETH_HDR_LEN              14

/* LLC header length (DSAP + SSAP + Control) */
#define LLC_HDR_LEN              3
#define LLC_DSAP_STP             0x42
#define LLC_SSAP_STP             0x42
#define LLC_CTRL_STP             0x03

/* BPDU layout (after LLC header) */
#define BPDU_OFF_PROTO_ID        0   /* 2 bytes, must be 0x0000 */
#define BPDU_OFF_VERSION         2   /* 1 byte  */
#define BPDU_OFF_TYPE            3   /* 1 byte  */
#define BPDU_OFF_FLAGS           4   /* 1 byte  */
#define BPDU_OFF_ROOT_ID         5   /* 8 bytes: priority(2) + mac(6) */
#define BPDU_OFF_ROOT_COST       13  /* 4 bytes */
#define BPDU_OFF_BRIDGE_ID       17  /* 8 bytes: priority(2) + mac(6) */
#define BPDU_OFF_PORT_ID         25  /* 2 bytes */
#define BPDU_OFF_MSG_AGE         27  /* 2 bytes (in 1/256 sec) */
#define BPDU_OFF_MAX_AGE         29  /* 2 bytes */
#define BPDU_OFF_HELLO_TIME      31  /* 2 bytes */
#define BPDU_OFF_FWD_DELAY       33  /* 2 bytes */
#define BPDU_MIN_LEN             35  /* minimum for Config/RSTP BPDU */

/* BPDU types */
#define BPDU_TYPE_CONFIG         0x00
#define BPDU_TYPE_TCN            0x80
#define BPDU_TYPE_RSTP           0x02

/* STP versions */
#define STP_VERSION_STP          0
#define STP_VERSION_RSTP         2

/* Flag bits */
#define BPDU_FLAG_TC             0x01  /* Topology Change */
#define BPDU_FLAG_TC_ACK         0x80  /* Topology Change Acknowledgment */

/* BPDU header minimum for any type */
#define BPDU_HDR_MIN             4

/* ------------------------------------------------------------------ */
/* State                                                                */
/* ------------------------------------------------------------------ */

struct stp_state {
    int      pcap_handle;
    uint64_t packets_seen;
    uint64_t events_published;
};

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

/*
 * Format a Bridge ID (8 bytes: priority(2) + MAC(6)) as
 * "XXXX.aabbccddeeff" where XXXX is the decimal priority.
 */
static void format_bridge_id(const uint8_t *id, char *out, size_t outsz)
{
    uint16_t priority;
    memcpy(&priority, id, 2);
    priority = ntohs(priority);
    snprintf(out, outsz, "%04x.%02x%02x%02x%02x%02x%02x",
             priority,
             id[2], id[3], id[4], id[5], id[6], id[7]);
}

/* ------------------------------------------------------------------ */
/* Packet handler                                                       */
/* ------------------------------------------------------------------ */

static void stp_on_packet(ps_module_ctx_t *ctx,
                           const uint8_t *pkt, uint32_t len,
                           uint64_t ts_usec, int handle_id)
{
    struct stp_state *st = (struct stp_state *)ctx->userdata;
    if (!st) return;
    if (handle_id != st->pcap_handle) return;

    (void)ts_usec;
    st->packets_seen++;

    /* Minimum: Ethernet + LLC + BPDU header */
    if (len < (uint32_t)(ETH_HDR_LEN + LLC_HDR_LEN + BPDU_HDR_MIN))
        return;

    /* Verify destination MAC = 01:80:c2:00:00:00 */
    static const uint8_t stp_dst[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00};
    if (memcmp(pkt, stp_dst, 6) != 0)
        return;

    /* Verify LLC header */
    const uint8_t *llc = pkt + ETH_HDR_LEN;
    if (llc[0] != LLC_DSAP_STP ||
        llc[1] != LLC_SSAP_STP ||
        llc[2] != LLC_CTRL_STP)
        return;

    /* BPDU starts after LLC */
    const uint8_t *bpdu = llc + LLC_HDR_LEN;
    uint32_t bpdu_len   = len - ETH_HDR_LEN - LLC_HDR_LEN;

    if (bpdu_len < BPDU_HDR_MIN) return;

    /* Protocol ID must be 0 */
    uint16_t proto_id;
    memcpy(&proto_id, bpdu + BPDU_OFF_PROTO_ID, 2);
    if (ntohs(proto_id) != 0) return;

    uint8_t version   = bpdu[BPDU_OFF_VERSION];
    uint8_t bpdu_type = bpdu[BPDU_OFF_TYPE];

    /* TCN BPDU: 4 bytes, no bridge/port fields */
    if (bpdu_type == BPDU_TYPE_TCN) {
        /* Source MAC = sender's bridge ID proxy */
        char src_mac[18];
        snprintf(src_mac, sizeof(src_mac),
                 "%02x:%02x:%02x:%02x:%02x:%02x",
                 pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11]);

        char buf[384];
        struct ps_json j;
        ps_json_init(&j, buf, sizeof(buf));

        ps_json_object_begin(&j);
        ps_json_key_string(&j, "bridge_id",        src_mac);
        ps_json_key_string(&j, "root_id",          "");
        ps_json_key_string(&j, "port_id",          "");
        ps_json_key_string(&j, "state",            "tcn");
        ps_json_key_bool  (&j, "topology_change",  1);
        ps_json_key_int   (&j, "cost",             0);
        ps_json_object_end(&j);

        if (ps_json_finish(&j) > 0) {
            ctx->publish(ctx, "discovery.stp", buf, (uint32_t)j.len);
            st->events_published++;
        }
        return;
    }

    /* Config / RSTP BPDU: need full fields */
    if (bpdu_type != BPDU_TYPE_CONFIG && bpdu_type != BPDU_TYPE_RSTP)
        return;

    if (bpdu_len < (uint32_t)BPDU_MIN_LEN) return;

    uint8_t  flags      = bpdu[BPDU_OFF_FLAGS];
    uint32_t root_cost  = 0;
    memcpy(&root_cost, bpdu + BPDU_OFF_ROOT_COST, 4);
    root_cost = ntohl(root_cost);

    uint16_t port_id_raw = 0;
    memcpy(&port_id_raw, bpdu + BPDU_OFF_PORT_ID, 2);
    port_id_raw = ntohs(port_id_raw);

    char bridge_id_str[32];
    char root_id_str[32];
    char port_id_str[12];

    format_bridge_id(bpdu + BPDU_OFF_BRIDGE_ID, bridge_id_str, sizeof(bridge_id_str));
    format_bridge_id(bpdu + BPDU_OFF_ROOT_ID,   root_id_str,   sizeof(root_id_str));
    snprintf(port_id_str, sizeof(port_id_str), "%04x", port_id_raw);

    /* Derive port state from flags (RSTP carries role/state in flags bits 2-5) */
    const char *state_str = "learning";
    if (version == STP_VERSION_RSTP) {
        uint8_t port_role = (flags >> 2) & 0x03;
        int     learning  = (flags >> 4) & 0x01;
        int     forwarding = (flags >> 5) & 0x01;
        if (forwarding)      state_str = "forwarding";
        else if (learning)   state_str = "learning";
        else if (port_role == 3) state_str = "blocking";
        else                 state_str = "discarding";
    } else {
        /* STP: forwarding is inferred — Config BPDUs are sent by forwarding ports */
        state_str = "forwarding";
    }

    int topology_change = (flags & BPDU_FLAG_TC) ? 1 : 0;

    /* Build JSON */
    char buf[384];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "bridge_id",        bridge_id_str);
    ps_json_key_string(&j, "root_id",          root_id_str);
    ps_json_key_string(&j, "port_id",          port_id_str);
    ps_json_key_string(&j, "state",            state_str);
    ps_json_key_bool  (&j, "topology_change",  topology_change);
    ps_json_key_int   (&j, "cost",             (int64_t)root_cost);
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "discovery.stp", buf, (uint32_t)j.len);
        st->events_published++;
        ps_debug("stp_listener: published BPDU bridge=%s root=%s cost=%u",
                 bridge_id_str, root_id_str, root_cost);
    }
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int stp_init(ps_module_ctx_t *ctx)
{
    struct stp_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("stp_listener: out of memory");
        return -1;
    }
    st->pcap_handle = -1;

    ctx->userdata = st;
    ps_info("stp_listener: initialized");
    return 0;
}

static void stp_shutdown(ps_module_ctx_t *ctx)
{
    struct stp_state *st = (struct stp_state *)ctx->userdata;
    if (!st) return;

    ps_info("stp_listener: shutdown (seen=%llu published=%llu)",
            (unsigned long long)st->packets_seen,
            (unsigned long long)st->events_published);

    free(st);
    ctx->userdata = NULL;
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

const ps_module_t ps_stp_listener_module = {
    .name        = "stp_listener",
    .description = "Passive STP/RSTP BPDU listener — publishes bridge topology",
    .version     = "1.0",
    .flags       = PS_MOD_PASSIVE | PS_MOD_NEEDS_PCAP,

    .init        = stp_init,
    .shutdown    = stp_shutdown,
    .on_packet   = stp_on_packet,
    .on_job      = NULL,
    .on_response = NULL,
    .tick        = NULL,
};
