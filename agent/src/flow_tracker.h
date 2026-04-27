/*
 * flow_tracker.h — Bidirectional flow tracking engine for PacketSonde Agent
 *
 * Processes raw Ethernet frames, maintains a table of active flows keyed by
 * canonical 5-tuple (+ optional VLAN/ToS), and expires idle flows based on
 * per-protocol timeouts.
 *
 * Replaces softflowd for PacketSonde's passive flow collection needs.
 */

#ifndef PS_FLOW_TRACKER_H
#define PS_FLOW_TRACKER_H

#include <stdint.h>
#include <sys/socket.h>   /* AF_INET, AF_INET6 */

/* ------------------------------------------------------------------ */
/* Track levels                                                         */
/* ------------------------------------------------------------------ */

#define PS_TRACK_IP_ONLY        0   /* src/dst addr only */
#define PS_TRACK_IP_PROTO       1   /* + protocol */
#define PS_TRACK_IP_PROTO_PORT  2   /* + ports (default) */
#define PS_TRACK_FULL           3   /* + ToS */
#define PS_TRACK_FULL_VLAN      4   /* + VLAN ID */

/* ------------------------------------------------------------------ */
/* Flow key (canonical form — lower address in slot 0)                  */
/* ------------------------------------------------------------------ */

struct ps_flow_key {
    uint8_t  af;             /* AF_INET or AF_INET6 */
    uint8_t  proto;          /* IPPROTO_TCP, IPPROTO_UDP, etc. */
    uint8_t  src_addr[16];   /* IPv4 uses first 4 bytes */
    uint8_t  dst_addr[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t vlan_id;        /* 0 if not tracking */
    uint8_t  tos;            /* 0 if not tracking */
};

/* ------------------------------------------------------------------ */
/* Flow record                                                          */
/* ------------------------------------------------------------------ */

struct ps_flow {
    struct ps_flow_key key;
    uint64_t packets[2];     /* [0]=forward, [1]=reverse */
    uint64_t octets[2];
    uint8_t  tcp_flags[2];   /* OR'd TCP flags per direction */
    uint64_t flow_start;     /* microseconds since epoch */
    uint64_t flow_last;      /* microseconds since epoch */
    uint32_t flow_label;     /* IPv6 Flow Label */
};

/* ------------------------------------------------------------------ */
/* Flow table (opaque)                                                  */
/* ------------------------------------------------------------------ */

struct ps_flow_table;

/*
 * Create a flow table.
 *   max_flows   — maximum concurrent flows (0 = default 65536)
 *   track_level — one of PS_TRACK_* constants
 */
struct ps_flow_table *ps_flow_table_create(int max_flows, int track_level);

/* Destroy a flow table and free all resources. */
void ps_flow_table_destroy(struct ps_flow_table *ft);

/*
 * Process a raw Ethernet frame.
 *   pkt     — pointer to first byte of Ethernet header
 *   len     — total frame length
 *   ts_usec — packet timestamp in microseconds since epoch
 *
 * Returns 0 on success, -1 on error (unparseable, table full, etc.)
 */
int ps_flow_table_process_packet(struct ps_flow_table *ft,
                                  const uint8_t *pkt, uint32_t len,
                                  uint64_t ts_usec);

/*
 * Expire flows past their timeout.
 *   now_usec — current time in microseconds
 *   out      — output array for expired flows
 *   max_out  — capacity of output array
 *
 * Returns number of expired flows written to out.
 */
int ps_flow_table_expire(struct ps_flow_table *ft, uint64_t now_usec,
                          struct ps_flow *out, int max_out);

/* Get current active flow count. */
int ps_flow_table_count(const struct ps_flow_table *ft);

/*
 * Snapshot active flows for periodic export (non-destructive).
 * Copies flows that have been updated since last_export_usec.
 * Returns number of flows written to out.
 */
int ps_flow_table_snapshot(struct ps_flow_table *ft, uint64_t last_export_usec,
                           struct ps_flow *out, int max_out);

#endif /* PS_FLOW_TRACKER_H */
