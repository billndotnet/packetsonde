/* Regression: a malicious recipe envelope whose base64 fields are longer than
 * the expected 44/88 chars must be rejected cleanly, never decoded into the
 * fixed-size author_pub/signature stack buffers (which would smash the stack).
 * ps_recipe_envelope_parse runs on untrusted input (`recipe verify`/`info`/`run`)
 * BEFORE any signature check, so this is reachable pre-auth. */
#include "recipe.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define CHECK(c) do{ if(!(c)){ fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c); return 1; } }while(0)

/* Build an envelope with an over-long base64 value in one field and parse it.
 * A correct parser returns non-zero (reject) and does not corrupt memory. */
static int parse_with_field(const char *field, size_t b64_len) {
    char *big = malloc(b64_len + 1);
    if (!big) return -2;
    memset(big, 'A', b64_len);        /* 'A' => 0x00; len % 4 == 0 keeps decode happy */
    big[b64_len] = '\0';

    const char *sha =
        "0000000000000000000000000000000000000000000000000000000000000000"; /* 64 hex */
    const char *good_pub = "QQ==", *good_sig = "QQ==", *good_recipe = "QQ==";
    const char *pub    = (strcmp(field, "author_pub") == 0) ? big : good_pub;
    const char *sig    = (strcmp(field, "signature")  == 0) ? big : good_sig;
    const char *recipe = (strcmp(field, "recipe_b64") == 0) ? big : good_recipe;

    size_t cap = b64_len + 512;
    char *env = malloc(cap);
    if (!env) { free(big); return -2; }
    int m = snprintf(env, cap,
        "{\"schema\":1,\"recipe_b64\":\"%s\",\"recipe_sha256\":\"%s\","
        "\"author_pub\":\"%s\",\"signature\":\"%s\",\"signed_at_ms\":0}",
        recipe, sha, pub, sig);

    struct ps_recipe_envelope e; char err[256] = "";
    int rc = ps_recipe_envelope_parse((const uint8_t *)env, (size_t)m, &e, err, sizeof(err));
    if (rc == 0) ps_recipe_envelope_free(&e);
    free(big); free(env);
    return rc;
}

int main(void) {
    /* 200000 b64 chars -> would decode to 150000 bytes: far past the 48/72-byte
     * temp buffers. Must be rejected, not written. */
    CHECK(parse_with_field("author_pub", 200000) != 0);
    CHECK(parse_with_field("signature",  200000) != 0);
    printf("ok\n");
    return 0;
}
