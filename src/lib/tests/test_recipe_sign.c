#include "recipe.h"
#include "keystore.h"
#include <stdio.h>
#include <string.h>
#define CHECK(c) do{ if(!(c)){ fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c); return 1; } }while(0)

static const char *RECIPE =
  "{\"schema\":1,\"name\":\"t\",\"version\":1,\"kind_prefix\":\"t\",\"steps\":["
  "{\"op\":\"connect_tcp\",\"host\":\"h\",\"port\":443,\"timeout_ms\":1000,\"out\":\"c\"}]}";

int main(void) {
    struct ps_keypair kp;
    CHECK(ps_keystore_generate(&kp) == 0);

    char env[8192];
    int n = ps_recipe_envelope_build((const uint8_t *)RECIPE, strlen(RECIPE),
                                     &kp, 1733400000000LL, env, sizeof(env));
    CHECK(n > 0);

    struct ps_recipe_envelope e; char err[256] = "";
    CHECK(ps_recipe_envelope_parse((const uint8_t *)env, (size_t)n, &e, err, sizeof(err)) == 0);
    CHECK(e.inner_json_len == strlen(RECIPE));
    CHECK(memcmp(e.inner_json, RECIPE, e.inner_json_len) == 0);
    CHECK(e.signed_at_ms == 1733400000000LL);
    CHECK(ps_recipe_envelope_verify_sig(&e) == 1);
    /* signature tamper -> verify fails */
    e.signature[0] ^= 0xff;
    CHECK(ps_recipe_envelope_verify_sig(&e) == 0);
    ps_recipe_envelope_free(&e);

    /* recipe-bytes tamper: mutate a char inside recipe_b64 -> sha256 re-check fails */
    char env2[8192]; memcpy(env2, env, (size_t)n + 1);
    char *rb = strstr(env2, "\"recipe_b64\":\"");
    CHECK(rb != NULL);
    rb += strlen("\"recipe_b64\":\"") + 4;   /* a char well inside the b64 value */
    *rb = (*rb == 'A') ? 'B' : 'A';
    struct ps_recipe_envelope e2;
    CHECK(ps_recipe_envelope_parse((const uint8_t *)env2, strlen(env2), &e2, err, sizeof(err)) != 0);

    /* output overflow -> -1, no write past out_cap */
    char tiny[16];
    CHECK(ps_recipe_envelope_build((const uint8_t *)RECIPE, strlen(RECIPE), &kp, 1, tiny, sizeof(tiny)) == -1);

    printf("ok\n");
    return 0;
}
