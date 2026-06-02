#include "recipe.h"

#include <openssl/evp.h>
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
