#ifndef PS_HONEYPOT_LISTENER_H
#define PS_HONEYPOT_LISTENER_H

/*
 * honeypot_listener.h — Public API for the PacketSonde honeypot trap listener.
 *
 * Defines the configuration structures and module export symbol used by the
 * honeypot_listener module. The module opens passive TCP traps on configured
 * ports, captures inbound connection payloads, and publishes probe events to
 * Redis for real-time alerting and historical analysis.
 */

#include <stdint.h>
#include "module_api.h"

/* ------------------------------------------------------------------ */
/* Compile-time limits                                                  */
/* ------------------------------------------------------------------ */

/** Maximum number of trap port definitions in one config. */
#define HP_MAX_TRAPS        32

/** Maximum banner string length (including NUL). */
#define HP_MAX_BANNER       512

/** Maximum inbound payload bytes captured per connection.
 *  4096 accommodates nikto-style long URLs and HTTP basic auth headers. */
#define HP_MAX_PAYLOAD      4096

/** Maximum raw packets buffered per session before flush. */
#define HP_MAX_PACKETS      128

/** Maximum concurrent half-open sessions tracked. */
#define HP_MAX_SESSIONS     64

/**
 * Deduplication window in milliseconds.
 * Probes from the same source IP to the same port within this window
 * are coalesced into a single event.
 */
#define HP_DEDUP_WINDOW_MS  500

/* ------------------------------------------------------------------ */
/* Configuration structures                                             */
/* ------------------------------------------------------------------ */

/**
 * Per-port trap configuration.
 *
 * port       — TCP port number to listen on.
 * banner     — Bytes sent to the connecting probe immediately after accept.
 *              May be empty (banner_len == 0) for a silent trap.
 * banner_len — Length of valid data in banner[], NOT including NUL.
 *              Stored separately because banners can contain embedded NULs
 *              (e.g. MySQL protocol greetings).
 */
struct hp_trap_config {
    uint16_t port;
    char     banner[HP_MAX_BANNER];
    int      banner_len;
};

/**
 * Top-level honeypot configuration, populated by hp_parse_config_string().
 *
 * enabled         — Non-zero to activate the module.
 * timeout_sec     — Seconds to hold a connection open (default: 10).
 * max_payload     — Max bytes of inbound data to capture (default: 4096).
 * max_events      — Max probe events retained in Redis list (default: 10000).
 *                    Oldest trimmed on insert. 0 = unlimited.
 * redis_key       — Redis list key for probe records (RPUSH).
 * redis_channel   — Redis pub/sub channel for real-time probe events.
 * traps[]         — Array of per-port trap definitions.
 * trap_count      — Number of valid entries in traps[].
 */
struct hp_config {
    int    enabled;
    int    timeout_sec;
    int    max_payload;
    int    max_events;
    char   redis_key[256];
    char   redis_channel[64];
    struct hp_trap_config traps[HP_MAX_TRAPS];
    int    trap_count;
};

/* ------------------------------------------------------------------ */
/* Config parser                                                        */
/* ------------------------------------------------------------------ */

/**
 * hp_parse_config_string — Parse an INI-format config string into cfg.
 *
 * Reads the [honeypot] section. Known scalar keys:
 *   enabled, timeout, max_payload, redis_key, redis_channel
 *
 * Numeric keys (e.g. "22", "80") are treated as trap port definitions;
 * their values are the banner strings. Banner values support \r\n unescaping.
 *
 * Defaults applied when a key is absent:
 *   timeout     = 10
 *   max_payload = 1024
 *   redis_key   = packetsonde:honeypot:probes
 *   redis_channel = honeypot.probe
 *
 * Returns 0 on success, -1 on parse error.
 */
int hp_parse_config_string(struct hp_config *cfg, const char *text);

/* ------------------------------------------------------------------ */
/* Module export                                                        */
/* ------------------------------------------------------------------ */

/** Module descriptor for registration with the PacketSonde agent. */
extern const ps_module_t ps_honeypot_listener_module;

#endif /* PS_HONEYPOT_LISTENER_H */
