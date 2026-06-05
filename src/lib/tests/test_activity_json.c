#include "activity_record.h"
#include <stdio.h>
#include <string.h>
#define CHECK(c) do{ if(!(c)){ fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c); return 1; } }while(0)

int main(void) {
    struct ps_activity a; memset(&a, 0, sizeof(a));
    snprintf(a.ts, sizeof a.ts, "2026-06-05T19:00:41Z");
    snprintf(a.event, sizeof a.event, "open");
    snprintf(a.path, sizeof a.path, "/etc/shadow");
    a.partial = 0;
    a.proc.pid = 4242; a.proc.ppid = 900; a.proc.uid = 0; a.proc.sid = 900;
    snprintf(a.proc.comm, sizeof a.proc.comm, "suspect");
    snprintf(a.proc.exe, sizeof a.proc.exe, "/usr/bin/suspect");
    snprintf(a.proc.cgroup, sizeof a.proc.cgroup, "/system.slice/sshd.service");
    snprintf(a.proc.mac_label, sizeof a.proc.mac_label, "unconfined");
    snprintf(a.proc.mac_mode, sizeof a.proc.mac_mode, "enforcing");
    a.nanc = 2;
    a.anc[0].pid = 1; a.anc[0].depth = 2; snprintf(a.anc[0].comm, 64, "systemd");
    a.anc[1].pid = 900; a.anc[1].depth = 1; snprintf(a.anc[1].comm, 64, "sshd");
    a.nsock = 1;
    a.sock[0].owner_pid = 4242; a.sock[0].depth = 0;
    snprintf(a.sock[0].owner_comm, 64, "suspect");
    snprintf(a.sock[0].proto, 4, "tcp");
    snprintf(a.sock[0].laddr, 64, "10.0.0.5:55012");
    snprintf(a.sock[0].raddr, 64, "10.0.0.9:443");
    snprintf(a.sock[0].state, 16, "ESTAB");

    char buf[4096];
    CHECK(ps_activity_to_json(&a, buf, sizeof buf) > 0);

    struct ps_activity b; memset(&b, 0, sizeof(b));
    CHECK(ps_activity_from_json(buf, &b) == 0);
    CHECK(strcmp(b.ts, a.ts) == 0);
    CHECK(strcmp(b.event, a.event) == 0);
    CHECK(strcmp(b.path, a.path) == 0);
    CHECK(b.proc.pid == 4242 && b.proc.ppid == 900 && b.proc.uid == 0);
    CHECK(strcmp(b.proc.exe, a.proc.exe) == 0);
    CHECK(strcmp(b.proc.comm, a.proc.comm) == 0);
    CHECK(strcmp(b.proc.cgroup, a.proc.cgroup) == 0);
    CHECK(strcmp(b.proc.mac_label, "unconfined") == 0);
    CHECK(b.nanc == 2);
    CHECK(b.anc[0].pid == 1 && strcmp(b.anc[0].comm, "systemd") == 0);
    CHECK(b.anc[1].pid == 900 && strcmp(b.anc[1].comm, "sshd") == 0);
    CHECK(b.nsock == 1);
    CHECK(strcmp(b.sock[0].raddr, "10.0.0.9:443") == 0);
    CHECK(strcmp(b.sock[0].state, "ESTAB") == 0);
    CHECK(strcmp(b.sock[0].proto, "tcp") == 0);

    struct ps_activity c;
    CHECK(ps_activity_from_json("not json", &c) == -1);
    printf("ok\n");
    return 0;
}
