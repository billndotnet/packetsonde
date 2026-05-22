/* src/lib/tests/test_json_extract.c */
#include "json_extract.h"
#include "json.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static void test_basic(void) {
    char out[256];
    int n = ps_json_extract_string("{\"a\":\"x\",\"b\":\"hello\"}", "b", out, sizeof out);
    assert(n == 5 && strcmp(out, "hello") == 0);
    assert(ps_json_extract_string("{\"a\":\"x\"}", "missing", out, sizeof out) == -1);
}

static void test_unescape(void) {
    char out[256];
    assert(ps_json_extract_string("{\"p\":\"he\\\"llo\\\\\\n\"}", "p", out, sizeof out) > 0);
    assert(strcmp(out, "he\"llo\\\n") == 0);
}

static void test_roundtrip_with_ps_json(void) {
    const char *payload = "{\"origin_agent_id\":\"e\",\"ts\":\"t\",\"event\":{\"v\":1}}";
    char env[512]; struct ps_json j; ps_json_init(&j, env, sizeof env);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "payload", payload);
    ps_json_object_end(&j);
    assert(ps_json_finish(&j) > 0);
    char out[512];
    int n = ps_json_extract_string(env, "payload", out, sizeof out);
    assert(n == (int)strlen(payload));
    assert(strcmp(out, payload) == 0);
}

int main(void) { test_basic(); test_unescape(); test_roundtrip_with_ps_json();
    printf("test_json_extract: OK\n"); return 0; }
