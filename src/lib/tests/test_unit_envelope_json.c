#include "unit_envelope.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    struct ps_unit_envelope a;
    ps_envelope_init(&a, "app.service");
    ps_envelope_add(&a, "write", "/var/lib/app/1");
    ps_envelope_add(&a, "write", "/var/lib/app/2");
    ps_envelope_add(&a, "open",  "/etc/app.conf");
    ps_envelope_add(&a, "exec",  "/usr/bin/app");
    ps_envelope_add(&a, "write", "/tmp/x");   /* used_tmp */

    char buf[16384];
    int n = ps_envelope_to_json(&a, buf, sizeof buf);
    assert(n > 0);
    assert(strstr(buf, "\"unit\":\"app.service\""));
    assert(strstr(buf, "\"used_tmp\":1"));
    assert(strstr(buf, "/var/lib/app/1"));

    struct ps_unit_envelope b;
    assert(ps_envelope_from_json(buf, &b) == 0);
    assert(strcmp(b.unit, "app.service") == 0);
    assert(b.n_write == 3 && b.n_read == 1 && b.n_exec == 1);
    assert(b.used_tmp == 1 && b.touched_home == 0);
    assert(strcmp(b.wr[0], "/var/lib/app/1") == 0);
    assert(strcmp(b.ex[0], "/usr/bin/app") == 0);
    printf("test_unit_envelope_json: OK\n");
    return 0;
}
