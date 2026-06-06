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

    /* starttime is field 22 of /proc/<pid>/stat (clock ticks since boot).
     * Fields after the ')': state ppid pgrp session tty_nr tpgid flags
     * minflt cminflt majflt cmajflt utime stime cutime cstime priority nice
     * num_threads itrealvalue starttime(=22) ... */
    const char *full =
        "1234 (bash) S 1190 1234 1190 34816 1234 4194304 1000 0 0 0 "
        "5 2 0 0 20 0 1 0 8675309 1234567 ...";
    unsigned long long st = 0;
    assert(ps_proc_parse_starttime(full, &st) == 0);
    assert(st == 8675309ULL);
    /* comm containing spaces and digits must not confuse field counting */
    const char *spc = "42 (a b c) R 7 42 7 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 99 0 0";
    assert(ps_proc_parse_starttime(spc, &st) == 0);
    assert(st == 99ULL);
    /* truncated stat (no field 22) -> -1, out left unchanged */
    unsigned long long keep = 7;
    assert(ps_proc_parse_starttime("1 (x) S 0 1 1", &keep) == -1);
    assert(keep == 7ULL);

    printf("test_proc_parse: OK\n");
    return 0;
}
