#include "proc_parse.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    /* /proc/<pid>/stat: "pid (comm) state ppid ..." — comm may contain spaces/parens */
    const char *stat = "1234 (smb d) S 1190 1234 1190 0 -1 ...";
    assert(ps_proc_parse_ppid(stat) == 1190);
    char comm[64];
    assert(ps_proc_parse_comm(stat, comm, sizeof comm) == 0);
    assert(strcmp(comm, "smb d") == 0);

    /* cgroup v2: "0::/system.slice/smbd.service" -> unit basename */
    char unit[128];
    assert(ps_proc_parse_unit("0::/system.slice/smbd.service\n", unit, sizeof unit) == 0);
    assert(strcmp(unit, "/system.slice/smbd.service") == 0);

    /* attr/current AppArmor: "/usr/sbin/smbd (complain)" */
    char label[128], mode[32];
    assert(ps_proc_parse_mac("/usr/sbin/smbd (complain)\n", label, sizeof label, mode, sizeof mode) == 0);
    assert(strcmp(label, "/usr/sbin/smbd") == 0);
    assert(strcmp(mode, "complain") == 0);
    /* unconfined */
    assert(ps_proc_parse_mac("unconfined\n", label, sizeof label, mode, sizeof mode) == 0);
    assert(strcmp(label, "unconfined") == 0);
    assert(strcmp(mode, "unconfined") == 0);

    printf("test_proc_parse: OK\n");
    return 0;
}
