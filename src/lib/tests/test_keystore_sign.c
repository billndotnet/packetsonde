/* src/lib/tests/test_keystore_sign.c */
#include "keystore.h"
#include <openssl/evp.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    struct ps_keypair kp;
    assert(ps_keystore_generate(&kp) == 0);

    const char *msg = "{\"origin_agent_id\":\"edge-07\",\"ts\":\"t\",\"event\":{}}";
    uint8_t sig[64];
    assert(ps_keystore_sign(&kp, (const uint8_t*)msg, strlen(msg), sig) == 0);

    /* Verify with OpenSSL directly against the public key. */
    EVP_PKEY *pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                                kp.pubkey, PS_KEYSTORE_PUBKEY_SIZE);
    assert(pub);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    assert(EVP_DigestVerifyInit(m, NULL, NULL, NULL, pub) == 1);
    assert(EVP_DigestVerify(m, sig, 64, (const uint8_t*)msg, strlen(msg)) == 1);

    /* A flipped byte must fail. */
    sig[0] ^= 0xff;
    EVP_MD_CTX *m2 = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(m2, NULL, NULL, NULL, pub);
    assert(EVP_DigestVerify(m2, sig, 64, (const uint8_t*)msg, strlen(msg)) != 1);

    EVP_MD_CTX_free(m); EVP_MD_CTX_free(m2); EVP_PKEY_free(pub);
    printf("test_keystore_sign: OK\n");
    return 0;
}
