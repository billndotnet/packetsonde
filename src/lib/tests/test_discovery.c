#include "discovery.h"
#include "keystore.h"

#include <stdio.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); return 1; } \
} while (0)

static int test_probe_roundtrip(void) {
    struct ps_keypair kp;
    CHECK(ps_keystore_generate(&kp) == 0);

    struct ps_discovery_probe p = {0};
    p.version = PS_DISCOVERY_VERSION;
    p.max_skew_ms = 2000;
    p.timestamp_ms = 1700000000000ULL;
    for (int i = 0; i < PS_DISCOVERY_NONCE_SIZE; i++) p.nonce[i] = (uint8_t)(i * 7);
    memcpy(p.pubkey, kp.pubkey, PS_DISCOVERY_PUBKEY_SIZE);
    CHECK(ps_discovery_probe_sign(&p, kp.seckey) == 0);

    /* Signature must verify. */
    CHECK(ps_discovery_probe_verify(&p) == 1);

    /* Round-trip through wire format. */
    uint8_t wire[PS_DISCOVERY_PROBE_SIZE];
    CHECK(ps_discovery_probe_pack(&p, wire) == 0);
    struct ps_discovery_probe p2;
    CHECK(ps_discovery_probe_unpack(&p2, wire) == 0);
    CHECK(ps_discovery_probe_verify(&p2) == 1);

    /* Tampering breaks verification. */
    wire[60] ^= 0xff;
    struct ps_discovery_probe p3;
    CHECK(ps_discovery_probe_unpack(&p3, wire) == 0);
    CHECK(ps_discovery_probe_verify(&p3) == 0);

    /* Wrong magic = unpack fails. */
    wire[0] = 'X';
    CHECK(ps_discovery_probe_unpack(&p3, wire) == -1);

    return 0;
}

static int test_reply_roundtrip(void) {
    struct ps_keypair kp;
    CHECK(ps_keystore_generate(&kp) == 0);

    struct ps_discovery_reply r = {0};
    r.version = PS_DISCOVERY_VERSION;
    for (int i = 0; i < PS_DISCOVERY_NONCE_SIZE; i++) r.nonce[i] = (uint8_t)(i + 1);
    /* v4-mapped 192.0.2.1 */
    memset(r.listen_ip, 0, 16);
    r.listen_ip[10] = 0xff; r.listen_ip[11] = 0xff;
    r.listen_ip[12] = 192; r.listen_ip[13] = 0; r.listen_ip[14] = 2; r.listen_ip[15] = 1;
    r.listen_port = 7421;
    memcpy(r.agent_pub, kp.pubkey, PS_DISCOVERY_PUBKEY_SIZE);
    CHECK(ps_discovery_reply_sign(&r, kp.seckey) == 0);
    CHECK(ps_discovery_reply_verify(&r) == 1);

    uint8_t wire[PS_DISCOVERY_REPLY_SIZE];
    CHECK(ps_discovery_reply_pack(&r, wire) == 0);
    struct ps_discovery_reply r2;
    CHECK(ps_discovery_reply_unpack(&r2, wire) == 0);
    CHECK(ps_discovery_reply_verify(&r2) == 1);
    CHECK(r2.listen_port == 7421);

    /* Reply must be strictly smaller than probe -- amplifier check. */
    CHECK(PS_DISCOVERY_REPLY_SIZE < PS_DISCOVERY_PROBE_SIZE);
    return 0;
}

/* H-2 regression: an evicted (pubkey,nonce) must NOT be replayable
 * even after flood traffic pushes it out of the primary LRU. */
static int test_replay_eviction_is_remembered(void) {
    struct ps_discovery_replay r;
    ps_discovery_replay_init(&r);

    uint8_t pk[PS_DISCOVERY_PUBKEY_SIZE]; memset(pk, 0xaa, sizeof(pk));
    uint8_t victim_nonce[PS_DISCOVERY_NONCE_SIZE];
    memset(victim_nonce, 0x42, sizeof(victim_nonce));

    /* Victim probe. */
    CHECK(ps_discovery_replay_check(&r, pk, victim_nonce, 1000, 0) == 0);

    /* Flood: fill the primary table with PS_DISCOVERY_REPLAY_CAP fresh
     * (pubkey,nonce) entries, all with a LATER expiry than the victim.
     * The victim entry (with the earliest expiry) is the oldest, so
     * eviction picks it first. */
    uint8_t flood_pk[PS_DISCOVERY_PUBKEY_SIZE]; memset(flood_pk, 0xbb, sizeof(flood_pk));
    for (int i = 0; i < PS_DISCOVERY_REPLAY_CAP; i++) {
        uint8_t n[PS_DISCOVERY_NONCE_SIZE]; memset(n, 0, sizeof(n));
        n[0] = (uint8_t)(i & 0xff);
        n[1] = (uint8_t)((i >> 8) & 0xff);
        n[2] = 0xcc; /* distinguish from victim_nonce */
        CHECK(ps_discovery_replay_check(&r, flood_pk, n, 9999, 0) == 0);
    }

    /* The victim's slot should have been evicted -- now try to replay. */
    CHECK(ps_discovery_replay_check(&r, pk, victim_nonce, 1000, 0) == 1);
    return 0;
}

static int test_replay_lru(void) {
    struct ps_discovery_replay r;
    ps_discovery_replay_init(&r);

    uint8_t pk[PS_DISCOVERY_PUBKEY_SIZE] = {1};
    uint8_t n1[PS_DISCOVERY_NONCE_SIZE]  = {2};
    uint8_t n2[PS_DISCOVERY_NONCE_SIZE]  = {3};

    /* First seen: 0. Second: 1 (replay). */
    CHECK(ps_discovery_replay_check(&r, pk, n1, 100, 0) == 0);
    CHECK(ps_discovery_replay_check(&r, pk, n1, 100, 0) == 1);
    /* Different nonce: 0. */
    CHECK(ps_discovery_replay_check(&r, pk, n2, 100, 0) == 0);

    /* After expiry, the nonce can be reused. */
    CHECK(ps_discovery_replay_check(&r, pk, n1, 200, 200) == 0);

    return 0;
}

static int test_wrong_key_fails_verify(void) {
    struct ps_keypair k1, k2;
    CHECK(ps_keystore_generate(&k1) == 0);
    CHECK(ps_keystore_generate(&k2) == 0);

    struct ps_discovery_probe p = {0};
    p.version = PS_DISCOVERY_VERSION;
    p.max_skew_ms = 2000;
    p.timestamp_ms = 1700000000000ULL;
    memcpy(p.pubkey, k1.pubkey, PS_DISCOVERY_PUBKEY_SIZE);
    CHECK(ps_discovery_probe_sign(&p, k1.seckey) == 0);
    CHECK(ps_discovery_probe_verify(&p) == 1);

    /* Signed by k1 but pubkey field replaced with k2's: verify fails. */
    memcpy(p.pubkey, k2.pubkey, PS_DISCOVERY_PUBKEY_SIZE);
    CHECK(ps_discovery_probe_verify(&p) == 0);

    return 0;
}

static int test_keystore_fingerprint_deterministic(void) {
    uint8_t pk[PS_KEYSTORE_PUBKEY_SIZE];
    memset(pk, 0xab, sizeof(pk));
    char h1[PS_KEYSTORE_FPR_HEX_SIZE];
    char h2[PS_KEYSTORE_FPR_HEX_SIZE];
    ps_keystore_fingerprint(pk, h1);
    ps_keystore_fingerprint(pk, h2);
    CHECK(strcmp(h1, h2) == 0);
    CHECK(strlen(h1) == 64);
    /* Different input, different fingerprint. */
    pk[0] = 0xac;
    char h3[PS_KEYSTORE_FPR_HEX_SIZE];
    ps_keystore_fingerprint(pk, h3);
    CHECK(strcmp(h1, h3) != 0);
    return 0;
}

int main(void) {
    if (test_probe_roundtrip()) return 1;
    if (test_reply_roundtrip()) return 1;
    if (test_replay_lru()) return 1;
    if (test_replay_eviction_is_remembered()) return 1;
    if (test_wrong_key_fails_verify()) return 1;
    if (test_keystore_fingerprint_deterministic()) return 1;
    fprintf(stderr, "test_discovery: OK\n");
    return 0;
}
