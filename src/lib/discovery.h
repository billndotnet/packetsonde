#ifndef PS_DISCOVERY_H
#define PS_DISCOVERY_H

/*
 * Agent discovery wire format + signing helpers.
 *
 * Probe and reply packets are fixed-size for trivial parsing and so that
 * the reply is always strictly smaller than the probe (the agent cannot be
 * used as a UDP amplifier).
 *
 * See docs/specs/agent-discovery-brainstorm.md for the threat model.
 */

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define PS_DISCOVERY_MAGIC_PROBE  "PSDP"
#define PS_DISCOVERY_MAGIC_REPLY  "PSDR"
#define PS_DISCOVERY_VERSION      0x01
#define PS_DISCOVERY_PROBE_SIZE   144
#define PS_DISCOVERY_REPLY_SIZE   136
/* sign prefix = packet size minus signature; what's covered by the sig. */
#define PS_DISCOVERY_PROBE_SIGN_LEN  80
#define PS_DISCOVERY_REPLY_SIGN_LEN  72

#define PS_DISCOVERY_PUBKEY_SIZE  32   /* Ed25519 */
#define PS_DISCOVERY_SECKEY_SIZE  32   /* Ed25519 seed; openssl raw layout */
#define PS_DISCOVERY_SIG_SIZE     64
#define PS_DISCOVERY_NONCE_SIZE   16

#define PS_DISCOVERY_DEFAULT_SKEW_MS  2000
#define PS_DISCOVERY_HARDCAP_SKEW_MS 30000

/* Probe `flags` byte. Bit 0 = "open a session listener and tell me the
 * port" -- knock-then-listen stealth mode. Bits 1-7 reserved. */
#define PS_DISCOVERY_FLAG_REQUEST_SESSION  0x01

struct ps_discovery_probe {
    uint8_t  version;          /* PS_DISCOVERY_VERSION */
    uint8_t  flags;            /* reserved */
    uint16_t max_skew_ms;      /* client-requested replay window */
    uint64_t timestamp_ms;     /* ms since UTC epoch */
    uint8_t  nonce[PS_DISCOVERY_NONCE_SIZE];
    uint8_t  reserved[16];     /* zeroed; pads probe larger than reply */
    uint8_t  pubkey[PS_DISCOVERY_PUBKEY_SIZE];
    uint8_t  signature[PS_DISCOVERY_SIG_SIZE];
};

struct ps_discovery_reply {
    uint8_t  version;
    uint8_t  flags;
    uint8_t  nonce[PS_DISCOVERY_NONCE_SIZE]; /* echoed from probe */
    uint8_t  listen_ip[16];                  /* v6, v4-mapped for v4 */
    uint16_t listen_port;
    uint8_t  agent_pub[PS_DISCOVERY_PUBKEY_SIZE];
    uint8_t  signature[PS_DISCOVERY_SIG_SIZE];
};

/* Pack/unpack between struct form and the on-wire byte layout. The buf
 * must be exactly PS_DISCOVERY_PROBE_SIZE / PS_DISCOVERY_REPLY_SIZE bytes.
 * Returns 0 on success, -1 on layout violation (e.g. bad magic on unpack). */
int ps_discovery_probe_pack  (const struct ps_discovery_probe *p, uint8_t *buf);
int ps_discovery_probe_unpack(struct ps_discovery_probe *p, const uint8_t *buf);
int ps_discovery_reply_pack  (const struct ps_discovery_reply *r, uint8_t *buf);
int ps_discovery_reply_unpack(struct ps_discovery_reply *r, const uint8_t *buf);

/* Sign / verify. Each operates over the canonical byte layout (i.e. the
 * 'packed' form) so we don't depend on host endianness or padding. Sign
 * fills .signature in place; verify returns 1 if signature is valid, 0
 * otherwise. */
int ps_discovery_probe_sign  (struct ps_discovery_probe *p,
                              const uint8_t *seckey32);
int ps_discovery_probe_verify(const struct ps_discovery_probe *p);
int ps_discovery_reply_sign  (struct ps_discovery_reply *r,
                              const uint8_t *seckey32);
int ps_discovery_reply_verify(const struct ps_discovery_reply *r);

/* Current UTC time in milliseconds. */
uint64_t ps_discovery_now_ms(void);

/* Fill `out` with cryptographically random bytes. Returns 0 on success. */
int ps_discovery_random(uint8_t *out, size_t n);

/* ---- Replay LRU ----
 *
 * Bounded by PS_DISCOVERY_REPLAY_CAP entries; under flood, oldest evict.
 * Worst-case per-probe cost is one Ed25519 verify (~50 us) plus an O(N)
 * cache scan; N is small (4096) so this is a few microseconds.
 */
#define PS_DISCOVERY_REPLAY_CAP 4096

struct ps_discovery_replay_entry {
    uint8_t  pubkey[PS_DISCOVERY_PUBKEY_SIZE];
    uint8_t  nonce [PS_DISCOVERY_NONCE_SIZE];
    uint64_t expires_at_ms;
};

struct ps_discovery_replay {
    struct ps_discovery_replay_entry entries[PS_DISCOVERY_REPLAY_CAP];
    size_t                           count;
};

void ps_discovery_replay_init  (struct ps_discovery_replay *r);

/* Returns 1 if (pubkey, nonce) was already seen and not yet expired; the
 * caller should silently drop in that case. Otherwise records the pair
 * with `expires_at_ms` and returns 0.
 *
 * `now_ms` is passed in (not read from the clock) so tests can be
 * deterministic. */
int  ps_discovery_replay_check(struct ps_discovery_replay *r,
                               const uint8_t *pubkey,
                               const uint8_t *nonce,
                               uint64_t expires_at_ms,
                               uint64_t now_ms);

#endif
