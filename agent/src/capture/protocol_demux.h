#ifndef PS_PROTOCOL_DEMUX_H
#define PS_PROTOCOL_DEMUX_H

#include <stdint.h>
#include <stdbool.h>

/* Maximum number of registered handlers */
#define PS_DEMUX_MAX_HANDLERS 32

/* How a handler is matched against an incoming frame */
enum ps_proto_match_type {
    PS_MATCH_ETHERTYPE,   /* match on 16-bit EtherType                  */
    PS_MATCH_IP_PROTO,    /* match on IPv4/IPv6 next-header byte         */
    PS_MATCH_UDP_PORT,    /* match on UDP destination port               */
    PS_MATCH_CUSTOM       /* caller-supplied predicate function           */
};

/*
 * Packet handler callback.
 *   pkt       — pointer to start of Ethernet frame
 *   len       — total frame length in bytes
 *   ts_usec   — capture timestamp (microseconds since epoch)
 *   handle_id — pcap handle ID the frame arrived on
 *   userdata  — opaque pointer registered with the handler
 */
typedef void (*ps_demux_handler_fn)(const uint8_t *pkt, uint32_t len,
                                    uint64_t ts_usec, int handle_id,
                                    void *userdata);

/*
 * Custom match predicate.
 * Returns true if this handler should process the frame.
 */
typedef bool (*ps_demux_match_fn)(const uint8_t *pkt, uint32_t len);

struct ps_demux_entry {
    char                    name[64];
    enum ps_proto_match_type match_type;
    uint32_t                match_value;   /* ethertype / ip_proto / udp_port */
    ps_demux_match_fn       match_fn;      /* used when type == PS_MATCH_CUSTOM */
    ps_demux_handler_fn     handler;
    void                   *userdata;
    bool                    enabled;
};

struct ps_protocol_demux {
    struct ps_demux_entry entries[PS_DEMUX_MAX_HANDLERS];
    int                   count;
};

/* Initialise a demuxer (zero-fill). */
void ps_demux_init(struct ps_protocol_demux *dmx);

/*
 * Register a handler matched by ethertype, IP protocol, or UDP destination
 * port.  Returns 0 on success, -1 if the table is full.
 */
int ps_demux_register(struct ps_protocol_demux *dmx,
                      const char *name,
                      enum ps_proto_match_type match_type,
                      uint32_t match_value,
                      ps_demux_handler_fn handler,
                      void *userdata);

/*
 * Register a handler with a custom match predicate.
 * Returns 0 on success, -1 if the table is full.
 */
int ps_demux_register_custom(struct ps_protocol_demux *dmx,
                              const char *name,
                              ps_demux_match_fn match_fn,
                              ps_demux_handler_fn handler,
                              void *userdata);

/*
 * Enable or disable a handler by name.
 * Returns 0 on success, -1 if not found.
 */
int ps_demux_set_enabled(struct ps_protocol_demux *dmx,
                         const char *name, bool enabled);

/*
 * Query whether a named handler is currently enabled.
 * Returns true if enabled, false if disabled or not found.
 */
bool ps_demux_is_enabled(const struct ps_protocol_demux *dmx,
                          const char *name);

/*
 * Dispatch a captured frame to all matching enabled handlers.
 */
void ps_demux_dispatch(struct ps_protocol_demux *dmx,
                       const uint8_t *pkt, uint32_t len,
                       uint64_t ts_usec, int handle_id);

#endif /* PS_PROTOCOL_DEMUX_H */
