#include "sandbox_synth.h"
#include "unit_envelope.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    struct ps_unit_envelope e;
    ps_envelope_init(&e, "app.service");
    /* 3 files under /var/lib/app/db -> rolls up to the dir (threshold 3) */
    ps_envelope_add(&e, "write", "/var/lib/app/db/1.dat");
    ps_envelope_add(&e, "write", "/var/lib/app/db/2.dat");
    ps_envelope_add(&e, "write", "/var/lib/app/db/3.dat");
    /* 1 file under /run -> stays exact */
    ps_envelope_add(&e, "write", "/run/app.sock");
    ps_envelope_add(&e, "exec",  "/usr/bin/app");           /* exec from read-only -> MDWE ok */
    /* no /home access, no /tmp */

    char out[8192];
    int n = ps_sandbox_synth(&e, 3, out, sizeof out);
    assert(n > 0);
    assert(strstr(out, "[Service]"));
    assert(strstr(out, "ProtectSystem=strict"));
    assert(strstr(out, "ProtectHome=true"));               /* touched_home == 0 */
    assert(strstr(out, "MemoryDenyWriteExecute=yes"));      /* no exec from writable */
    assert(strstr(out, "ReadWritePaths=/var/lib/app/db"));  /* rolled up */
    assert(strstr(out, "generalized: 3 files"));
    assert(strstr(out, "ReadWritePaths=/run/app.sock"));    /* exact */
    assert(strstr(out, "# exact"));
    /* threshold boundary: with threshold 4, the 3-file dir stays exact */
    char out2[8192];
    ps_sandbox_synth(&e, 4, out2, sizeof out2);
    assert(strstr(out2, "ReadWritePaths=/var/lib/app/db/1.dat"));
    assert(!strstr(out2, "ReadWritePaths=/var/lib/app/db\n") && !strstr(out2, "ReadWritePaths=/var/lib/app/db "));

    /* a unit that touches /home + execs from a writable dir -> no ProtectHome/MDWE */
    struct ps_unit_envelope h;
    ps_envelope_init(&h, "web.service");
    ps_envelope_add(&h, "write", "/var/www/cache/a");
    ps_envelope_add(&h, "open",  "/home/www/data");         /* touched_home */
    ps_envelope_add(&h, "exec",  "/var/www/cache/a");       /* exec under a write path */
    char out3[8192];
    ps_sandbox_synth(&h, 3, out3, sizeof out3);
    assert(!strstr(out3, "ProtectHome=true"));
    assert(!strstr(out3, "MemoryDenyWriteExecute=yes"));
    printf("test_sandbox_synth: OK\n");
    return 0;
}
