#include "policy_eval.h"
#include "systemd_policy.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static struct ps_unit_policy mk(void) {
    struct ps_unit_policy p; memset(&p, 0, sizeof p);
    p.known = 1; p.protect_system = PS_PROTSYS_STRICT; p.protect_home = PS_PROTHOME_INACCESSIBLE;
    p.mdwe = 1;
    p.n_rw = 1; snprintf(p.rw[0], PS_POL_PATHLEN, "/var/lib/app");
    p.n_inacc = 1; snprintf(p.inacc[0], PS_POL_PATHLEN, "/etc/ssl/private");
    return p;
}

int main(void) {
    struct ps_unit_policy p = mk();
    struct ps_eval_result r;

    /* write outside ReadWritePaths under ProtectSystem=strict -> violation */
    assert(ps_policy_eval(&p, "/etc/passwd", PS_OP_WRITE, &r) == 1);
    assert(strcmp(r.directive, "ProtectSystem") == 0 && r.heuristic == 0);
    /* write INSIDE ReadWritePaths -> allowed */
    assert(ps_policy_eval(&p, "/var/lib/app/db/0001.dat", PS_OP_WRITE, &r) == 0);
    /* prefix boundary: /var/lib/appX is NOT under /var/lib/app */
    assert(ps_policy_eval(&p, "/var/lib/appX/y", PS_OP_WRITE, &r) == 1);
    /* read of a normal protected path under ProtectSystem -> allowed (reads ok) */
    assert(ps_policy_eval(&p, "/etc/passwd", PS_OP_READ, &r) == 0);
    /* read under ProtectHome=inaccessible -> violation */
    assert(ps_policy_eval(&p, "/home/alice/.ssh/id_rsa", PS_OP_READ, &r) == 1);
    assert(strcmp(r.directive, "ProtectHome") == 0);
    /* any access under InaccessiblePaths -> violation */
    assert(ps_policy_eval(&p, "/etc/ssl/private/key.pem", PS_OP_READ, &r) == 1);
    assert(strcmp(r.directive, "InaccessiblePaths") == 0);
    /* exec from a ReadWritePath under mdwe -> heuristic violation */
    assert(ps_policy_eval(&p, "/var/lib/app/dropped.bin", PS_OP_EXEC, &r) == 1);
    assert(strcmp(r.directive, "exec_from_writable") == 0 && r.heuristic == 1);
    /* exec from a normal read-only path -> allowed */
    assert(ps_policy_eval(&p, "/usr/bin/python3", PS_OP_EXEC, &r) == 0);

    /* a permissive unit (no directives) -> never a violation */
    struct ps_unit_policy perm; memset(&perm, 0, sizeof perm); perm.known = 1;
    assert(ps_policy_eval(&perm, "/etc/passwd", PS_OP_WRITE, &r) == 0);
    printf("test_policy_eval: OK\n");
    return 0;
}
