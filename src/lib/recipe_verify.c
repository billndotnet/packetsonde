#include "recipe.h"
#include "keystore.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Recipe signature verification — spec §6.
 *
 * The signed input is exactly 72 bytes:
 *
 *   recipe_sha256 (32)  ||  author_pub (32)  ||  signed_at_ms (8, big-endian)
 *
 * Fixed layout. No JSON canonicalization in the verification path; the
 * envelope parser is responsible for recomputing recipe_sha256 from the
 * inner bytes (already done in ps_recipe_envelope_parse), and the pubkey
 * + timestamp are pulled directly from the envelope fields.
 *
 * This function tells the caller *only* whether the signature is
 * mathematically valid. Trust — i.e. whether author_pub is one we'll
 * actually run code from — is a keystore-side decision (recipe_author
 * flag on the entry) handled separately.
 */

int ps_recipe_envelope_verify_sig(const struct ps_recipe_envelope *env) {
    if (!env) return 0;

    uint8_t input[72];
    memcpy(input,        env->recipe_sha256, 32);
    memcpy(input + 32,   env->author_pub,    32);
    int64_t ms = env->signed_at_ms;
    /* Big-endian encoding of signed_at_ms — must match what the signer used. */
    for (int i = 0; i < 8; i++) {
        input[64 + i] = (uint8_t)((uint64_t)ms >> (56 - i * 8)) & 0xff;
    }

    EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                               env->author_pub, 32);
    if (!pk) return 0;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = 0;
    if (EVP_DigestVerifyInit(m, NULL, NULL, NULL, pk) == 1 &&
        EVP_DigestVerify(m, env->signature, 64, input, sizeof(input)) == 1) {
        ok = 1;
    }
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(pk);
    return ok;
}

int ps_recipe_envelope_build(const uint8_t *recipe_bytes, size_t recipe_len,
                             const struct ps_keypair *kp, int64_t signed_at_ms,
                             char *out, size_t out_cap) {
    uint8_t sha[32];
    SHA256(recipe_bytes, recipe_len, sha);

    uint8_t input[72];
    memcpy(input, sha, 32);
    memcpy(input + 32, kp->pubkey, 32);
    for (int i = 0; i < 8; i++) input[64 + i] = (uint8_t)((uint64_t)signed_at_ms >> (56 - 8 * i));

    uint8_t sig[64];
    if (ps_keystore_sign(kp, input, sizeof(input), sig) != 0) return -1;

    /* base64-encode the (potentially large) recipe bytes on the heap; the two
     * 32/64-byte fields fit fixed buffers. */
    size_t rb_cap = 4 * ((recipe_len + 2) / 3) + 1;
    char *recipe_b64 = malloc(rb_cap);
    if (!recipe_b64) return -1;
    EVP_EncodeBlock((unsigned char *)recipe_b64, recipe_bytes, (int)recipe_len);

    char pub_b64[64], sig_b64[128], sha_hex[65];
    EVP_EncodeBlock((unsigned char *)pub_b64, kp->pubkey, 32);
    EVP_EncodeBlock((unsigned char *)sig_b64, sig, 64);
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { sha_hex[i * 2] = H[sha[i] >> 4]; sha_hex[i * 2 + 1] = H[sha[i] & 0xf]; }
    sha_hex[64] = '\0';

    int n = snprintf(out, out_cap,
        "{\"schema\":1,\"recipe_b64\":\"%s\",\"recipe_sha256\":\"%s\","
        "\"author_pub\":\"%s\",\"signed_at_ms\":%lld,\"signature\":\"%s\"}",
        recipe_b64, sha_hex, pub_b64, (long long)signed_at_ms, sig_b64);
    free(recipe_b64);
    if (n < 0 || (size_t)n >= out_cap) return -1;
    return n;
}
