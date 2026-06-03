#include "activity_record.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    struct ps_activity a;
    memset(&a, 0, sizeof a);
    snprintf(a.ts, sizeof a.ts, "2026-06-03T14:22:10Z");
    snprintf(a.event, sizeof a.event, "open");
    snprintf(a.path, sizeof a.path, "/etc/shadow");
    a.proc.pid = 1234; a.proc.ppid = 1190; a.proc.uid = 0; a.proc.sid = 1190;
    snprintf(a.proc.comm, sizeof a.proc.comm, "sh");
    snprintf(a.proc.exe, sizeof a.proc.exe, "/usr/bin/dash");
    snprintf(a.proc.cmdline, sizeof a.proc.cmdline, "sh");
    snprintf(a.proc.cgroup, sizeof a.proc.cgroup, "/system.slice/smbd.service");
    snprintf(a.proc.mac_label, sizeof a.proc.mac_label, "/usr/sbin/smbd");
    snprintf(a.proc.mac_mode, sizeof a.proc.mac_mode, "complain");
    a.nanc = 1;
    a.anc[0].pid = 1190; a.anc[0].depth = 1; snprintf(a.anc[0].comm, sizeof a.anc[0].comm, "smbd");
    a.nsock = 1;
    a.sock[0].owner_pid = 1190; a.sock[0].depth = 1;
    snprintf(a.sock[0].owner_comm, sizeof a.sock[0].owner_comm, "smbd");
    snprintf(a.sock[0].proto, sizeof a.sock[0].proto, "tcp");
    snprintf(a.sock[0].laddr, sizeof a.sock[0].laddr, "10.0.0.5:445");
    snprintf(a.sock[0].raddr, sizeof a.sock[0].raddr, "203.0.113.5:51344");
    snprintf(a.sock[0].state, sizeof a.sock[0].state, "ESTABLISHED");

    char buf[4096];
    int n = ps_activity_to_json(&a, buf, sizeof buf);
    assert(n > 0);
    assert(strstr(buf, "\"event\":\"open\""));
    assert(strstr(buf, "\"path\":\"/etc/shadow\""));
    assert(strstr(buf, "\"comm\":\"sh\""));
    assert(strstr(buf, "\"cgroup\":\"/system.slice/smbd.service\""));
    assert(strstr(buf, "\"mode\":\"complain\""));
    assert(strstr(buf, "\"raddr\":\"203.0.113.5:51344\""));
    assert(strstr(buf, "\"depth\":1"));
    printf("test_activity_record: OK\n");
    return 0;
}
