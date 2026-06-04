#include "cgroup_unit.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char u[128];
    assert(ps_cgroup_to_unit("/system.slice/smbd.service", u, sizeof u) == 0);
    assert(strcmp(u, "smbd.service") == 0);
    /* nested slice */
    assert(ps_cgroup_to_unit("/system.slice/system-getty.slice/getty@tty1.service", u, sizeof u) == 0);
    assert(strcmp(u, "getty@tty1.service") == 0);
    /* .socket / .scope / .mount accepted */
    assert(ps_cgroup_to_unit("/system.slice/sshd.socket", u, sizeof u) == 0);
    assert(strcmp(u, "sshd.socket") == 0);
    /* a .slice tail is NOT a unit we evaluate -> -1 */
    assert(ps_cgroup_to_unit("/system.slice", u, sizeof u) == -1);
    /* .scope is a unit */
    assert(ps_cgroup_to_unit("/user.slice/user-1000.slice/session-3.scope/init.scope", u, sizeof u) == 0);
    assert(ps_cgroup_to_unit("", u, sizeof u) == -1);
    printf("test_cgroup_unit: OK\n");
    return 0;
}
