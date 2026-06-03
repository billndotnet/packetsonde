#include "proc_enrich.h"
#include "activity_record.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void wr(const char *path, const char *content) {
    FILE *f = fopen(path, "w"); assert(f); fputs(content, f); fclose(f);
}
static void mkpid(const char *root, int pid, const char *stat, const char *cgroup,
                  const char *attr, const char *exe, const char *cmdline) {
    char d[256], p[320];
    snprintf(d, sizeof d, "%s/%d", root, pid); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/%d/stat", root, pid); wr(p, stat);
    snprintf(p, sizeof p, "%s/%d/cgroup", root, pid); wr(p, cgroup);
    snprintf(d, sizeof d, "%s/%d/attr", root, pid); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/%d/attr/current", root, pid); wr(p, attr);
    snprintf(p, sizeof p, "%s/%d/cmdline", root, pid); wr(p, cmdline);
    (void)exe;
}

int main(void) {
    char root[] = "/tmp/ps_proc_XXXXXX"; assert(mkdtemp(root));
    mkpid(root, 1234, "1234 (sh) S 1190 1234 1190 0\n",
          "0::/system.slice/smbd.service\n", "/usr/sbin/smbd (complain)\n",
          "/usr/bin/dash", "sh");
    mkpid(root, 1190, "1190 (smbd) S 1 1190 1190 0\n",
          "0::/system.slice/smbd.service\n", "/usr/sbin/smbd (complain)\n",
          "/usr/sbin/smbd", "/usr/sbin/smbd");

    struct ps_activity a; memset(&a, 0, sizeof a);
    int rc = ps_proc_enrich(root, 1234, &a, 16);
    assert(rc == 0);
    assert(a.proc.pid == 1234 && a.proc.ppid == 1190);
    assert(strcmp(a.proc.comm, "sh") == 0);
    assert(strcmp(a.proc.cgroup, "/system.slice/smbd.service") == 0);
    assert(strcmp(a.proc.mac_mode, "complain") == 0);
    /* ancestry: 1190 (smbd) at depth 1; stop before pid 1 */
    assert(a.nanc == 1);
    assert(a.anc[0].pid == 1190 && a.anc[0].depth == 1);
    assert(strcmp(a.anc[0].comm, "smbd") == 0);
    printf("test_proc_enrich: OK\n");
    return 0;
}
