#include "proc_enrich.h"
#include "proc_parse.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static int slurp(const char *root, int pid, const char *file, char *out, size_t cap) {
    char path[320];
    snprintf(path, sizeof path, "%s/%d/%s", root, pid, file);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(out, 1, cap - 1, f);
    fclose(f);
    out[n] = 0;
    return (int)n;
}

/* /proc/<pid>/cmdline is NUL-separated; turn NULs into spaces. */
static void cmdline_spaces(char *s, int n) {
    for (int i = 0; i < n - 1; i++) if (s[i] == 0) s[i] = ' ';
}

static int read_meta(const char *root, int pid, struct ps_act_proc *p) {
    char stat[512];
    if (slurp(root, pid, "stat", stat, sizeof stat) < 0) return -1;
    p->pid = pid;
    p->ppid = ps_proc_parse_ppid(stat);
    ps_proc_parse_comm(stat, p->comm, sizeof p->comm);
    { unsigned long long st = 0; if (ps_proc_parse_starttime(stat, &st) == 0) p->start_time = st; }

    char cg[512];
    if (slurp(root, pid, "cgroup", cg, sizeof cg) >= 0)
        ps_proc_parse_unit(cg, p->cgroup, sizeof p->cgroup);
    char attr[512];
    if (slurp(root, pid, "attr/current", attr, sizeof attr) >= 0)
        ps_proc_parse_mac(attr, p->mac_label, sizeof p->mac_label,
                          p->mac_mode, sizeof p->mac_mode);
    char cl[512];
    int cn = slurp(root, pid, "cmdline", cl, sizeof cl);
    if (cn > 0) { cmdline_spaces(cl, cn); snprintf(p->cmdline, sizeof p->cmdline, "%s", cl); }
    /* uid from status (Uid:\t<real> ...) */
    char status[1024];
    if (slurp(root, pid, "status", status, sizeof status) >= 0) {
        char *u = strstr(status, "Uid:");
        if (u) p->uid = atoi(u + 4);
    }
    /* exe: readlink /proc/<pid>/exe (a symlink to the binary) */
    char exep[320];
    snprintf(exep, sizeof exep, "%s/%d/exe", root, pid);
    ssize_t er = readlink(exep, p->exe, sizeof p->exe - 1);
    if (er > 0) p->exe[er] = 0;
    return 0;
}

int ps_proc_enrich(const char *proc_root, int pid, struct ps_activity *a, int max_depth) {
    const char *root = (proc_root && proc_root[0]) ? proc_root : "/proc";
    if (read_meta(root, pid, &a->proc) != 0) return -1;

    a->nanc = 0;
    int cur = a->proc.ppid;
    int depth = 1;
    while (cur > 1 && depth <= max_depth && a->nanc < PS_ACT_MAX_ANC) {
        struct ps_act_proc tmp; memset(&tmp, 0, sizeof tmp);
        if (read_meta(root, cur, &tmp) != 0) break;
        if (tmp.ppid == cur) break;   /* self-parent cycle guard (malformed /proc) */
        /* skip kernel threads (kthreadd lineage: ppid 2 or comm in brackets style) */
        if (tmp.ppid == 2) break;
        a->anc[a->nanc].pid = cur;
        a->anc[a->nanc].depth = depth;
        snprintf(a->anc[a->nanc].comm, sizeof a->anc[a->nanc].comm, "%s", tmp.comm);
        a->anc[a->nanc].start_time = tmp.start_time;
        a->nanc++;
        if (tmp.ppid <= 1) break;   /* parent is init -> cur was the session/service root */
        cur = tmp.ppid;
        depth++;
    }
    return 0;
}
