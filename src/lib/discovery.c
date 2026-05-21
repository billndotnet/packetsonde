#include "discovery.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <sys/time.h>

/* ---- Wire format ----
 *
 * Probe (144 B):
 *   0   4    magic "PSDP"
 *   4   1    version
 *   5   1    flags
 *   6   2    max_skew_ms BE
 *   8   8    timestamp_ms BE
 *   16  16   nonce
 *   32  16   reserved (zeroed; padding so probe > reply)
 *   48  32   pubkey
 *   80  64   signature  (covers bytes [0..80))
 *
 * Reply (136 B):
 *   0   4    magic "PSDR"
 *   4   1    version
 *   5   1    flags
 *   6   16   nonce (echo)              -- starts immediately after flags
 *   22  16   listen_ip (v6, v4-mapped for v4)
 *   38  2    listen_port BE
 *   40  32   agent_pub
 *   72  64   signature  (covers bytes [0..72))
 */

static void put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)((v >> 8) & 0xff);
    p[1] = (uint8_t)(v & 0xff);
}
static void put_u64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (56 - 8 * i)) & 0xff);
}
static uint16_t get_u16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}
static uint64_t get_u64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

int ps_discovery_probe_pack(const struct ps_discovery_probe *p, uint8_t *buf) {
    memcpy(buf, PS_DISCOVERY_MAGIC_PROBE, 4);
    buf[4] = p->version;
    buf[5] = p->flags;
    put_u16(buf + 6, p->max_skew_ms);
    put_u64(buf + 8, p->timestamp_ms);
    memcpy(buf + 16, p->nonce, PS_DISCOVERY_NONCE_SIZE);
    memcpy(buf + 32, p->reserved, 16);
    memcpy(buf + 48, p->pubkey, PS_DISCOVERY_PUBKEY_SIZE);
    memcpy(buf + 80, p->signature, PS_DISCOVERY_SIG_SIZE);
    return 0;
}

int ps_discovery_probe_unpack(struct ps_discovery_probe *p, const uint8_t *buf) {
    if (memcmp(buf, PS_DISCOVERY_MAGIC_PROBE, 4) != 0) return -1;
    p->version = buf[4];
    p->flags = buf[5];
    p->max_skew_ms = get_u16(buf + 6);
    p->timestamp_ms = get_u64(buf + 8);
    memcpy(p->nonce, buf + 16, PS_DISCOVERY_NONCE_SIZE);
    memcpy(p->reserved, buf + 32, 16);
    memcpy(p->pubkey, buf + 48, PS_DISCOVERY_PUBKEY_SIZE);
    memcpy(p->signature, buf + 80, PS_DISCOVERY_SIG_SIZE);
    return 0;
}

int ps_discovery_reply_pack(const struct ps_discovery_reply *r, uint8_t *buf) {
    memcpy(buf, PS_DISCOVERY_MAGIC_REPLY, 4);
    buf[4] = r->version;
    buf[5] = r->flags;
    memcpy(buf + 6, r->nonce, PS_DISCOVERY_NONCE_SIZE);
    memcpy(buf + 22, r->listen_ip, 16);
    put_u16(buf + 38, r->listen_port);
    memcpy(buf + 40, r->agent_pub, PS_DISCOVERY_PUBKEY_SIZE);
    memcpy(buf + 72, r->signature, PS_DISCOVERY_SIG_SIZE);
    return 0;
}

int ps_discovery_reply_unpack(struct ps_discovery_reply *r, const uint8_t *buf) {
    if (memcmp(buf, PS_DISCOVERY_MAGIC_REPLY, 4) != 0) return -1;
    r->version = buf[4];
    r->flags = buf[5];
    memcpy(r->nonce, buf + 6, PS_DISCOVERY_NONCE_SIZE);
    memcpy(r->listen_ip, buf + 22, 16);
    r->listen_port = get_u16(buf + 38);
    memcpy(r->agent_pub, buf + 40, PS_DISCOVERY_PUBKEY_SIZE);
    memcpy(r->signature, buf + 72, PS_DISCOVERY_SIG_SIZE);
    return 0;
}

/* ---- Ed25519 sign / verify via OpenSSL's EVP_DigestSign one-shot API.
 *
 * The signed prefix is everything in the canonical packed form before the
 * signature field: probe = first 64 bytes, reply = first 74 bytes. */

static int ed25519_sign(const uint8_t *seckey32,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t *sig64) {
    EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                seckey32, PS_DISCOVERY_SECKEY_SIZE);
    if (!pk) return -1;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int rc = -1;
    size_t sl = PS_DISCOVERY_SIG_SIZE;
    if (EVP_DigestSignInit(m, NULL, NULL, NULL, pk) == 1 &&
        EVP_DigestSign(m, sig64, &sl, msg, msg_len) == 1 &&
        sl == PS_DISCOVERY_SIG_SIZE) {
        rc = 0;
    }
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(pk);
    return rc;
}

static int ed25519_verify(const uint8_t *pubkey32,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig64) {
    EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                               pubkey32, PS_DISCOVERY_PUBKEY_SIZE);
    if (!pk) return 0;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = 0;
    if (EVP_DigestVerifyInit(m, NULL, NULL, NULL, pk) == 1 &&
        EVP_DigestVerify(m, sig64, PS_DISCOVERY_SIG_SIZE, msg, msg_len) == 1) {
        ok = 1;
    }
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(pk);
    return ok;
}

int ps_discovery_probe_sign(struct ps_discovery_probe *p, const uint8_t *seckey32) {
    uint8_t buf[PS_DISCOVERY_PROBE_SIZE];
    memset(p->signature, 0, PS_DISCOVERY_SIG_SIZE);
    ps_discovery_probe_pack(p, buf);
    if (ed25519_sign(seckey32, buf, PS_DISCOVERY_PROBE_SIGN_LEN, p->signature) != 0) return -1;
    return 0;
}

int ps_discovery_probe_verify(const struct ps_discovery_probe *p) {
    uint8_t buf[PS_DISCOVERY_PROBE_SIZE];
    struct ps_discovery_probe tmp = *p;
    memset(tmp.signature, 0, PS_DISCOVERY_SIG_SIZE);
    ps_discovery_probe_pack(&tmp, buf);
    return ed25519_verify(p->pubkey, buf, PS_DISCOVERY_PROBE_SIGN_LEN, p->signature);
}

int ps_discovery_reply_sign(struct ps_discovery_reply *r, const uint8_t *seckey32) {
    uint8_t buf[PS_DISCOVERY_REPLY_SIZE];
    memset(r->signature, 0, PS_DISCOVERY_SIG_SIZE);
    ps_discovery_reply_pack(r, buf);
    if (ed25519_sign(seckey32, buf, PS_DISCOVERY_REPLY_SIGN_LEN, r->signature) != 0) return -1;
    return 0;
}

int ps_discovery_reply_verify(const struct ps_discovery_reply *r) {
    uint8_t buf[PS_DISCOVERY_REPLY_SIZE];
    struct ps_discovery_reply tmp = *r;
    memset(tmp.signature, 0, PS_DISCOVERY_SIG_SIZE);
    ps_discovery_reply_pack(&tmp, buf);
    return ed25519_verify(r->agent_pub, buf, PS_DISCOVERY_REPLY_SIGN_LEN, r->signature);
}

uint64_t ps_discovery_now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;
}

int ps_discovery_random(uint8_t *out, size_t n) {
    return RAND_bytes(out, (int)n) == 1 ? 0 : -1;
}

/* ---- Replay LRU ----
 *
 * Tiny, scan-the-array implementation. With cap 4096 and per-probe O(N)
 * scan this is ~4 microseconds at full table — cheap next to a signature
 * verify. */

void ps_discovery_replay_init(struct ps_discovery_replay *r) {
    memset(r, 0, sizeof(*r));
}

static void replay_purge_expired(struct ps_discovery_replay *r, uint64_t now_ms) {
    size_t w = 0;
    for (size_t i = 0; i < r->count; i++) {
        if (r->entries[i].expires_at_ms > now_ms) {
            if (w != i) r->entries[w] = r->entries[i];
            w++;
        }
    }
    r->count = w;
}

static void record_eviction(struct ps_discovery_replay *r,
                            const uint8_t *pubkey, const uint8_t *nonce) {
    struct ps_discovery_replay_evict *e = &r->evicted[r->evicted_head];
    memcpy(e->pubkey, pubkey, PS_DISCOVERY_PUBKEY_SIZE);
    memcpy(e->nonce,  nonce,  PS_DISCOVERY_NONCE_SIZE);
    r->evicted_head = (r->evicted_head + 1) % PS_DISCOVERY_REPLAY_EVICT;
    if (r->evicted_count < PS_DISCOVERY_REPLAY_EVICT) r->evicted_count++;
}

static int seen_in_evicted(const struct ps_discovery_replay *r,
                           const uint8_t *pubkey, const uint8_t *nonce) {
    for (size_t i = 0; i < r->evicted_count; i++) {
        if (memcmp(r->evicted[i].pubkey, pubkey, PS_DISCOVERY_PUBKEY_SIZE) == 0 &&
            memcmp(r->evicted[i].nonce,  nonce,  PS_DISCOVERY_NONCE_SIZE) == 0) {
            return 1;
        }
    }
    return 0;
}

int ps_discovery_replay_check(struct ps_discovery_replay *r,
                              const uint8_t *pubkey,
                              const uint8_t *nonce,
                              uint64_t expires_at_ms,
                              uint64_t now_ms) {
    /* O(N) scan for a duplicate in the primary table. */
    for (size_t i = 0; i < r->count; i++) {
        if (r->entries[i].expires_at_ms <= now_ms) continue;
        if (memcmp(r->entries[i].pubkey, pubkey, PS_DISCOVERY_PUBKEY_SIZE) == 0 &&
            memcmp(r->entries[i].nonce,  nonce,  PS_DISCOVERY_NONCE_SIZE) == 0) {
            return 1; /* replay */
        }
    }
    /* H-2: also reject any (pubkey,nonce) that we recently evicted from
     * the primary table -- otherwise an attacker can flood the cache to
     * force the eviction of a victim's nonce and then replay it. */
    if (seen_in_evicted(r, pubkey, nonce)) return 1;

    /* Insert; purge expired first if we're at capacity. */
    if (r->count >= PS_DISCOVERY_REPLAY_CAP) {
        replay_purge_expired(r, now_ms);
    }
    if (r->count < PS_DISCOVERY_REPLAY_CAP) {
        struct ps_discovery_replay_entry *e = &r->entries[r->count++];
        memcpy(e->pubkey, pubkey, PS_DISCOVERY_PUBKEY_SIZE);
        memcpy(e->nonce,  nonce,  PS_DISCOVERY_NONCE_SIZE);
        e->expires_at_ms = expires_at_ms;
    } else {
        /* Cache full of unexpired entries. Evict oldest-by-expiry to
         * make room AND record the evicted (pubkey,nonce) in the
         * tail ring so it can't be replayed. */
        size_t oldest = 0;
        for (size_t i = 1; i < r->count; i++) {
            if (r->entries[i].expires_at_ms < r->entries[oldest].expires_at_ms) {
                oldest = i;
            }
        }
        struct ps_discovery_replay_entry *e = &r->entries[oldest];
        record_eviction(r, e->pubkey, e->nonce);
        memcpy(e->pubkey, pubkey, PS_DISCOVERY_PUBKEY_SIZE);
        memcpy(e->nonce,  nonce,  PS_DISCOVERY_NONCE_SIZE);
        e->expires_at_ms = expires_at_ms;
    }
    return 0;
}
