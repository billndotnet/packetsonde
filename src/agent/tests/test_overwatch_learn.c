#include "policy_overwatch.h"
#include "unit_envelope.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static const char *REC(const char *event, const char *path, const char *cg) {
    static char b[2048];
    snprintf(b, sizeof b,
      "{\"event\":\"%s\",\"path\":\"%s\",\"process\":{\"cgroup\":\"%s\"}}", event, path, cg);
    return b;
}

int main(void) {
    struct ps_unit_envelope envs[8]; int n = 0;
    /* two units accumulate independently */
    int i1 = ps_overwatch_learn_record(REC("write","/var/lib/app/1","/system.slice/app.service"), envs, &n, 8);
    assert(i1 == 0 && n == 1);
    ps_overwatch_learn_record(REC("write","/var/lib/app/2","/system.slice/app.service"), envs, &n, 8);
    int i2 = ps_overwatch_learn_record(REC("exec","/usr/sbin/db","/system.slice/db.service"), envs, &n, 8);
    assert(i2 == 1 && n == 2);
    assert(strcmp(envs[0].unit, "app.service") == 0 && envs[0].n_write == 2);
    assert(strcmp(envs[1].unit, "db.service") == 0 && envs[1].n_exec == 1);
    /* non-unit cgroup -> skipped */
    int sk = ps_overwatch_learn_record(REC("write","/x","/user.slice"), envs, &n, 8);
    assert(sk == -1 && n == 2);
    printf("test_overwatch_learn: OK\n");
    return 0;
}
