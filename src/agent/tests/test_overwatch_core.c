#include "policy_overwatch.h"
#include "systemd_policy.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static int loader(const char *unit, char *out, size_t cap) {
    if (!strcmp(unit, "app.service"))
        snprintf(out, cap, "FragmentPath=/x.service\nProtectHome=true\nProtectSystem=strict\nReadWritePaths=/var/lib/app\n");
    else out[0] = 0;
    return 0;
}
static int g_emits = 0; static char g_last[4096];
static void emit(void *c, const char *json, size_t len) { (void)c;(void)len; g_emits++; snprintf(g_last,sizeof g_last,"%s",json); }

static const char *REC(const char *event, const char *path) {
    static char b[2048];
    snprintf(b, sizeof b,
      "{\"v\":1,\"event\":\"%s\",\"path\":\"%s\",\"process\":{\"pid\":9,\"comm\":\"app\",\"exe\":\"/usr/bin/app\","
      "\"cgroup\":\"/system.slice/app.service\",\"mac\":{\"label\":\"unconfined\",\"mode\":\"unconfined\"}}}", event, path);
    return b;
}

int main(void) {
    void *seen = ps_overwatch_seen_new();
    g_emits = 0;
    /* op mapping */
    assert(ps_overwatch_op_for_event("write") == PS_OP_WRITE);
    assert(ps_overwatch_op_for_event("exec")  == PS_OP_EXEC);
    assert(ps_overwatch_op_for_event("access")== PS_OP_READ);
    assert(ps_overwatch_op_for_event("open")  == PS_OP_READ);

    /* write to /home under ProtectHome=true -> 1 finding */
    ps_overwatch_process_record(REC("write","/home/x/secret"), loader, seen, emit, NULL, 100);
    assert(g_emits == 1);
    assert(strstr(g_last, "\"directive\":\"ProtectHome\""));
    assert(strstr(g_last, "\"unit\":\"app.service\""));
    /* same (unit,path,op,directive) again -> deduped, no new finding */
    ps_overwatch_process_record(REC("write","/home/x/secret"), loader, seen, emit, NULL, 101);
    assert(g_emits == 1);
    /* write inside ReadWritePaths -> allowed, no finding */
    ps_overwatch_process_record(REC("write","/var/lib/app/db"), loader, seen, emit, NULL, 102);
    assert(g_emits == 1);
    /* record with no unit (user slice) -> skipped */
    const char *nounit = "{\"event\":\"write\",\"path\":\"/home/x\",\"process\":{\"cgroup\":\"/user.slice\"}}";
    ps_overwatch_process_record(nounit, loader, seen, emit, NULL, 103);
    assert(g_emits == 1);
    ps_overwatch_seen_free(seen);
    printf("test_overwatch_core: OK\n");
    return 0;
}
