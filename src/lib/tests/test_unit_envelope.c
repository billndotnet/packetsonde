#include "unit_envelope.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    struct ps_unit_envelope e;
    ps_envelope_init(&e, "app.service");
    assert(strcmp(e.unit, "app.service") == 0);
    assert(e.n_read == 0 && e.records == 0);

    ps_envelope_add(&e, "write", "/var/lib/app/db/1.dat");
    ps_envelope_add(&e, "write", "/var/lib/app/db/1.dat");   /* dup -> deduped */
    ps_envelope_add(&e, "write", "/var/lib/app/db/2.dat");
    ps_envelope_add(&e, "open",  "/etc/app.conf");
    ps_envelope_add(&e, "access","/usr/share/app/x");
    ps_envelope_add(&e, "exec",  "/usr/bin/app");
    ps_envelope_add(&e, "open",  "/home/svc/.cache/y");      /* sets touched_home */
    ps_envelope_add(&e, "write", "/tmp/scratch");            /* sets used_tmp */

    assert(e.n_write == 3);                                  /* 2 db files + /tmp/scratch (dedup worked) */
    assert(e.n_read == 3);                                   /* etc.conf, usr/share, home cache */
    assert(e.n_exec == 1);
    assert(e.touched_home == 1);
    assert(e.used_tmp == 1);
    assert(e.records == 8);
    printf("test_unit_envelope: OK\n");
    return 0;
}
