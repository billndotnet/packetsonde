#ifndef PS_COLLECT_H
#define PS_COLLECT_H
#include <stddef.h>
#include <stdint.h>

struct ps_collect_result { int verified; int relay_chain_verified; int has_relay; };

/* Verify one envelope JSON against the authorized pubkey set (try-all) and build a
 * JSONL line (the event enriched with agent_id/verified/relay_chain_verified/transport/
 * received_ts) into out. Returns line length (no newline), or -1 on a malformed
 * envelope. Never fails on verification — verified flags are recorded in *res. */
int ps_collect_process(const char *envelope_json, const uint8_t (*pubkeys)[32], size_t npk,
                       const char *received_ts, char *out, size_t cap,
                       struct ps_collect_result *res);
#endif
