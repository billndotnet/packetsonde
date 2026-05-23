#include "iface_enum.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    assert(ps_iface_excluded("lo", NULL) == 1);
    assert(ps_iface_excluded("lo", "") == 1);
    assert(ps_iface_excluded("lo", "docker") == 1);
    assert(ps_iface_excluded("ens18", NULL) == 0);
    assert(ps_iface_excluded("ens18", "") == 0);
    assert(ps_iface_excluded("veth1a2b", "veth") == 1);
    assert(ps_iface_excluded("docker0", "docker,veth") == 1);
    assert(ps_iface_excluded("br-abc", "docker,veth") == 0);
    assert(ps_iface_excluded("br-abc", "docker,veth,br-") == 1);
    assert(ps_iface_excluded("enp3s0", "docker,veth") == 0);

    char names[8][64];
    int n = ps_iface_enumerate(NULL, names, 8);
    assert(n >= 1);
    for (int i = 0; i < n; i++) assert(strcmp(names[i], "lo") != 0);
    printf("test_iface_enum: OK\n");
    return 0;
}
