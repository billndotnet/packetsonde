#include "keystore.h"
#include "recipe.h"

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); return 1; } \
} while (0)

/* The canonical VNC recipe from the spec's strawman, hand-canonicalized:
 * sorted keys, integer port, no whitespace. */
static const char VNC_RECIPE[] =
    "{\"default_port\":5900,\"description\":\"VNC reachability + RFB version\","
    "\"kind_prefix\":\"vnc\",\"name\":\"vnc\",\"schema\":1,"
    "\"steps\":["
      "{\"host\":\"$target.host\",\"op\":\"connect_tcp\",\"out\":\"c\","
       "\"port\":\"$target.port\",\"timeout_ms\":4000},"
      "{\"conn\":\"c\",\"max_bytes\":64,\"op\":\"recv\",\"out\":\"banner\","
       "\"until\":\"newline\"},"
      "{\"captures\":["
        "{\"as\":\"int\",\"name\":\"major\"},"
        "{\"as\":\"int\",\"name\":\"minor\"}"
      "],\"in\":\"banner\",\"op\":\"match\","
       "\"regex\":\"^RFB ([0-9]{3})\\\\.([0-9]{3})\"},"
      "{\"evidence\":{"
         "\"rfb_major\":{\"as\":\"int\",\"value\":\"$major\"},"
         "\"rfb_minor\":{\"as\":\"int\",\"value\":\"$minor\"}"
       "},\"kind\":\"vnc.metadata\",\"op\":\"emit\",\"severity\":\"info\","
       "\"confidence\":\"firm\","
       "\"title\":\"VNC server (RFB $major.$minor)\"},"
      "{\"conn\":\"c\",\"op\":\"close\"}"
    "],\"version\":1}";

static int test_parse_ok(void) {
    char err[256] = "";
    struct ps_recipe *r = ps_recipe_parse_json((const uint8_t *)VNC_RECIPE,
                                               sizeof(VNC_RECIPE) - 1,
                                               err, sizeof(err));
    if (!r) fprintf(stderr, "parse error: %s\n", err);
    CHECK(r != NULL);
    CHECK(r->schema == 1);
    CHECK(strcmp(r->name, "vnc") == 0);
    CHECK(r->default_port == 5900);
    CHECK(r->steps_n == 5);
    CHECK(r->steps[0]->op == PS_OP_CONNECT_TCP);
    CHECK(r->steps[0]->u.connect.timeout_ms == 4000);
    CHECK(r->steps[1]->op == PS_OP_RECV);
    CHECK(r->steps[1]->u.recv.until == PS_UNTIL_NEWLINE);
    CHECK(r->steps[1]->u.recv.max_bytes == 64);
    CHECK(r->steps[2]->op == PS_OP_MATCH);
    CHECK(r->steps[2]->u.match.captures_n == 2);
    CHECK(r->steps[2]->u.match.captures[0].as == PS_BT_INT);
    CHECK(r->steps[3]->op == PS_OP_EMIT);
    CHECK(strcmp(r->steps[3]->u.emit.kind, "vnc.metadata") == 0);
    CHECK(r->steps[3]->u.emit.fields_n == 2);
    CHECK(r->steps[3]->u.emit.fields[0].as == PS_BT_INT);
    CHECK(r->steps[4]->op == PS_OP_CLOSE);
    /* Default budgets applied. */
    CHECK(r->budgets.max_steps == 200);
    CHECK(r->budgets.max_recv_bytes == 65536);
    ps_recipe_free(r);
    return 0;
}

static int test_parse_rejects_bad_kind(void) {
    /* emit.kind doesn't match kind_prefix. */
    static const char BAD[] =
        "{\"kind_prefix\":\"vnc\",\"name\":\"x\",\"schema\":1,"
        "\"steps\":[{\"op\":\"emit\",\"kind\":\"http.bad\","
        "\"severity\":\"info\",\"confidence\":\"firm\",\"title\":\"t\"}],"
        "\"version\":1}";
    char err[256] = "";
    struct ps_recipe *r = ps_recipe_parse_json((const uint8_t *)BAD,
                                               sizeof(BAD) - 1, err, sizeof(err));
    CHECK(r == NULL);
    CHECK(strstr(err, "kind") != NULL);
    return 0;
}

static int test_parse_rejects_unknown_binding(void) {
    /* $nope is not defined anywhere. */
    static const char BAD[] =
        "{\"kind_prefix\":\"x\",\"name\":\"x\",\"schema\":1,"
        "\"steps\":[{\"op\":\"emit\",\"kind\":\"x.t\",\"severity\":\"info\","
        "\"confidence\":\"firm\",\"title\":\"hello $nope\"}],"
        "\"version\":1}";
    char err[256] = "";
    struct ps_recipe *r = ps_recipe_parse_json((const uint8_t *)BAD,
                                               sizeof(BAD) - 1, err, sizeof(err));
    CHECK(r == NULL);
    CHECK(strstr(err, "nope") != NULL);
    return 0;
}

static int test_parse_rejects_bad_schema(void) {
    static const char BAD[] = "{\"schema\":99,\"name\":\"x\",\"version\":1,"
                              "\"kind_prefix\":\"x\",\"steps\":[]}";
    char err[256] = "";
    struct ps_recipe *r = ps_recipe_parse_json((const uint8_t *)BAD,
                                               sizeof(BAD) - 1, err, sizeof(err));
    CHECK(r == NULL);
    CHECK(strstr(err, "schema") != NULL);
    return 0;
}

/* Produce a base64 string (NUL-terminated, no newlines) from a byte buffer.
 * out must hold at least 4 * ceil(n/3) + 1 bytes. */
static void b64enc(const uint8_t *in, size_t n, char *out) {
    int written = EVP_EncodeBlock((unsigned char *)out, in, (int)n);
    out[written] = '\0';
}

static int test_envelope_roundtrip(void) {
    struct ps_keypair kp;
    CHECK(ps_keystore_generate(&kp) == 0);

    /* SHA-256 the inner recipe. */
    const uint8_t *inner = (const uint8_t *)VNC_RECIPE;
    size_t inner_len = sizeof(VNC_RECIPE) - 1;
    uint8_t sha[32];
    SHA256(inner, inner_len, sha);

    /* Build the 72-byte signing input. */
    int64_t ms = 1717000000000LL;
    uint8_t signin[72];
    memcpy(signin, sha, 32);
    memcpy(signin + 32, kp.pubkey, 32);
    for (int i = 0; i < 8; i++)
        signin[64 + i] = (uint8_t)((uint64_t)ms >> (56 - i * 8)) & 0xff;

    /* Sign. */
    uint8_t sig[64] = {0};
    EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, kp.seckey, 32);
    CHECK(pk != NULL);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    size_t sl = 64;
    CHECK(EVP_DigestSignInit(m, NULL, NULL, NULL, pk) == 1);
    CHECK(EVP_DigestSign(m, sig, &sl, signin, sizeof(signin)) == 1);
    CHECK(sl == 64);
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(pk);

    /* Encode envelope. */
    char inner_b64[2048], pub_b64[64], sig_b64[128], sha_hex[65];
    b64enc(inner, inner_len, inner_b64);
    b64enc(kp.pubkey, 32, pub_b64);
    b64enc(sig, 64, sig_b64);
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        sha_hex[i * 2]     = H[sha[i] >> 4];
        sha_hex[i * 2 + 1] = H[sha[i] & 0x0f];
    }
    sha_hex[64] = '\0';

    char envelope[4096];
    int el = snprintf(envelope, sizeof(envelope),
        "{\"schema\":1,\"recipe_b64\":\"%s\",\"recipe_sha256\":\"%s\","
        "\"author_pub\":\"%s\",\"signed_at_ms\":%lld,\"signature\":\"%s\"}",
        inner_b64, sha_hex, pub_b64, (long long)ms, sig_b64);
    CHECK(el > 0 && (size_t)el < sizeof(envelope));

    struct ps_recipe_envelope env;
    char err[256] = "";
    int rc = ps_recipe_envelope_parse((const uint8_t *)envelope, (size_t)el,
                                      &env, err, sizeof(err));
    if (rc != 0) fprintf(stderr, "envelope parse: %s\n", err);
    CHECK(rc == 0);
    CHECK(env.signed_at_ms == ms);
    CHECK(env.inner_json_len == inner_len);
    CHECK(memcmp(env.inner_json, inner, inner_len) == 0);
    CHECK(ps_recipe_envelope_verify_sig(&env) == 1);

    /* The inner JSON should also parse cleanly. */
    struct ps_recipe *r = ps_recipe_parse_json(env.inner_json, env.inner_json_len,
                                               err, sizeof(err));
    CHECK(r != NULL);
    ps_recipe_free(r);

    /* Tamper with the signature → verify fails. */
    env.signature[0] ^= 0xff;
    CHECK(ps_recipe_envelope_verify_sig(&env) == 0);
    env.signature[0] ^= 0xff;

    /* Tamper with the sha → verify fails (different message bytes). */
    env.recipe_sha256[0] ^= 0xff;
    CHECK(ps_recipe_envelope_verify_sig(&env) == 0);
    env.recipe_sha256[0] ^= 0xff;

    ps_recipe_envelope_free(&env);
    return 0;
}

static int test_envelope_rejects_sha_mismatch(void) {
    /* Encode an envelope where recipe_sha256 doesn't match the inner bytes. */
    const uint8_t *inner = (const uint8_t *)VNC_RECIPE;
    size_t inner_len = sizeof(VNC_RECIPE) - 1;
    char inner_b64[2048]; b64enc(inner, inner_len, inner_b64);
    /* All-zero pub/sig/sha — they're shape-checked, not verified yet. */
    char pub_b64[64], sig_b64[128];
    uint8_t z32[32] = {0}, z64[64] = {0};
    b64enc(z32, 32, pub_b64);
    b64enc(z64, 64, sig_b64);
    char bad_sha[65];
    memset(bad_sha, '0', 64); bad_sha[64] = '\0';
    char envelope[4096];
    int el = snprintf(envelope, sizeof(envelope),
        "{\"schema\":1,\"recipe_b64\":\"%s\",\"recipe_sha256\":\"%s\","
        "\"author_pub\":\"%s\",\"signed_at_ms\":1,\"signature\":\"%s\"}",
        inner_b64, bad_sha, pub_b64, sig_b64);
    CHECK(el > 0);
    struct ps_recipe_envelope env;
    char err[256] = "";
    int rc = ps_recipe_envelope_parse((const uint8_t *)envelope, (size_t)el,
                                      &env, err, sizeof(err));
    CHECK(rc != 0);
    CHECK(strstr(err, "sha256") != NULL);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_parse_ok();
    rc |= test_parse_rejects_bad_kind();
    rc |= test_parse_rejects_unknown_binding();
    rc |= test_parse_rejects_bad_schema();
    rc |= test_envelope_roundtrip();
    rc |= test_envelope_rejects_sha_mismatch();
    if (rc == 0) printf("test_recipe: OK\n");
    return rc;
}
