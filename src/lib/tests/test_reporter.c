/* src/lib/tests/test_reporter.c */
#include "reporter.h"
#include "keystore.h"
#include <openssl/evp.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

static void test_extract_ts(void) {
    char ts[32];
    assert(ps_reporter_extract_ts("{\"v\":1,\"id\":\"A\",\"ts\":\"2026-05-22T10:00:00Z\",\"kind\":\"tls\"}", ts, sizeof ts) == 0);
    assert(strcmp(ts, "2026-05-22T10:00:00Z") == 0);
}

static void test_build_payload(void) {
    char p[512];
    int n = ps_reporter_build_payload(p, sizeof p, "edge-07", "2026-05-22T10:00:00Z",
                                      "{\"v\":1,\"kind\":\"tls\"}");
    assert(n > 0);
    assert(strcmp(p, "{\"origin_agent_id\":\"edge-07\",\"ts\":\"2026-05-22T10:00:00Z\",\"event\":{\"v\":1,\"kind\":\"tls\"}}") == 0);
}

static void test_payload_signs_and_verifies(void) {
    struct ps_keypair kp; assert(ps_keystore_generate(&kp) == 0);
    char p[512];
    ps_reporter_build_payload(p, sizeof p, "edge-07", "t", "{\"v\":1}");
    uint8_t sig[64];
    assert(ps_keystore_sign(&kp, (const uint8_t*)p, strlen(p), sig) == 0);
    EVP_PKEY *pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, kp.pubkey, 32);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(m, NULL, NULL, NULL, pub);
    assert(EVP_DigestVerify(m, sig, 64, (const uint8_t*)p, strlen(p)) == 1);
    EVP_MD_CTX_free(m); EVP_PKEY_free(pub);
}

int main(void) {
    test_extract_ts(); test_build_payload(); test_payload_signs_and_verifies();
    printf("test_reporter: OK\n");
    return 0;
}
