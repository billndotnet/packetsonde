#include "systemd_policy.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static const char *SHOW =
    "FragmentPath=/usr/lib/systemd/system/app.service\n"
    "ProtectSystem=strict\n"
    "ProtectHome=true\n"
    "PrivateTmp=yes\n"
    "MemoryDenyWriteExecute=yes\n"
    "ReadWritePaths=/var/lib/app /var/log/app\n"
    "ReadOnlyPaths=\n"
    "InaccessiblePaths=/etc/ssl/private\n";

int main(void) {
    struct ps_unit_policy p;
    assert(ps_unit_policy_derive(SHOW, &p) == 0);
    assert(p.known == 1);
    assert(p.protect_system == PS_PROTSYS_STRICT);
    assert(p.protect_home == PS_PROTHOME_INACCESSIBLE);
    assert(p.private_tmp == 1);
    assert(p.mdwe == 1);
    assert(p.n_rw == 2);
    assert(strcmp(p.rw[0], "/var/lib/app") == 0 && strcmp(p.rw[1], "/var/log/app") == 0);
    assert(p.n_ro == 0);
    assert(p.n_inacc == 1 && strcmp(p.inacc[0], "/etc/ssl/private") == 0);

    /* unset/default -> known but permissive */
    struct ps_unit_policy d;
    assert(ps_unit_policy_derive("FragmentPath=/x.service\nProtectSystem=no\nProtectHome=no\n", &d) == 0);
    assert(d.known == 1 && d.protect_system == PS_PROTSYS_NO && d.protect_home == PS_PROTHOME_NO);

    /* no FragmentPath (unit not found) -> not known */
    struct ps_unit_policy n;
    assert(ps_unit_policy_derive("", &n) == 0 && n.known == 0);
    printf("test_systemd_policy: OK\n");
    return 0;
}
