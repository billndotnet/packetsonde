#ifndef PS_RELAY_ATTEST_H
#define PS_RELAY_ATTEST_H
#include <stddef.h>
#include "keystore.h"

/* "<env_sig_b64>|<received_from>|<ts>" — the exact bytes a relay signs.
 * Central rebuilds this identically (no JSON canonicalization). */
int ps_relay_attest_string(const char *env_sig_b64, const char *received_from,
                           const char *ts, char *out, size_t cap);

/* Build a relay_path entry JSON object:
 *   {"relay_agent_id":"<self>","received_from":"<rf>","ts":"<now>","sig":"<b64>"}
 * ts = current UTC ISO-8601; sig = base64 Ed25519 over ps_relay_attest_string(...).
 * Returns bytes written, or -1. */
int ps_relay_attest_entry(const struct ps_keypair *kp, const char *self_agent_id,
                          const char *env_sig_b64, const char *received_from,
                          char *out, size_t cap);
#endif
