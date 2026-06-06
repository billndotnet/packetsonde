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

    printf("test_provenance: OK\n");
    return 0;
}
