/* src/lib/tests/test_collect.c */
#include "collect.h"
#include "keystore.h"
#include "reporter.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    struct ps_keypair kp; assert(ps_keystore_generate(&kp) == 0);
    char dir[] = "/tmp/ps_coll_XXXXXX"; assert(mkdtemp(dir));
    assert(ps_keystore_save(dir, "agent", &kp) == 0);
    struct ps_central_config cc; memset(&cc, 0, sizeof cc);
    cc.url = "http://x"; cc.agent_id = "edge-07"; cc.key_dir = dir;
    const char *events[] = { "{\"v\":1,\"kind\":\"tls\",\"ts\":\"2026-05-22T10:00:00Z\"}" };
    char arr[8192];
    assert(ps_reporter_build_envelopes(&cc, events, 1, arr, sizeof arr) > 0);
    char env[8192];
    int alen = (int)strlen(arr);
    assert(arr[0] == '[' && arr[alen-1] == ']');
    memcpy(env, arr + 1, (size_t)(alen - 2)); env[alen - 2] = '\0';

    uint8_t pks[2][32];
    memcpy(pks[0], kp.pubkey, 32);
    for (int i = 0; i < 32; i++) pks[1][i] = 0xAA;

    char out[8192]; struct ps_collect_result r;
    int n = ps_collect_process(env, pks, 2, "2026-05-22T11:00:00Z", out, sizeof out, &r);
    assert(n > 0);
    assert(r.verified == 1);
    assert(strstr(out, "\"agent_id\":\"edge-07\""));
    assert(strstr(out, "\"verified\":true"));
    assert(strstr(out, "\"transport\":\"direct\""));
    assert(strstr(out, "\"kind\":\"tls\""));

    char out2[8192]; struct ps_collect_result r2;
    assert(ps_collect_process(env, pks + 1, 1, "t", out2, sizeof out2, &r2) > 0);
    assert(r2.verified == 0);
    assert(strstr(out2, "\"verified\":false"));

    printf("test_collect: OK\n");
    return 0;
}
