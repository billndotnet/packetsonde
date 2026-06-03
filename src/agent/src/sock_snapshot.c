#include "sock_snapshot.h"
#include "sock_parse.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>

#define MAX_EPS 4096

static int load_net(const char *root, struct ps_sock_ep *eps, int cap) {
    const char *names[4] = {"tcp","tcp6","udp","udp6"};
    const char *protos[4] = {"tcp","tcp","udp","udp"};
    int n = 0;
    for (int i = 0; i < 4 && n < cap; i++) {
        char path[320]; snprintf(path, sizeof path, "%s/net/%s", root, names[i]);
        FILE *f = fopen(path, "r"); if (!f) continue;
        static char buf[1 << 20];
        size_t rd = fread(buf, 1, sizeof buf - 1, f); fclose(f); buf[rd] = 0;
        n += ps_sock_parse_procnet(protos[i], buf, eps + n, cap - n);
    }
    return n;
}

/* collect socket inodes from <root>/<pid>/fd/* symlinks ("socket:[N]") */
static int pid_sock_inodes(const char *root, int pid, unsigned long *out, int max) {
    char dir[320]; snprintf(dir, sizeof dir, "%s/%d/fd", root, pid);
    DIR *d = opendir(dir); if (!d) return 0;
    int n = 0; struct dirent *e;
    while ((e = readdir(d)) && n < max) {
        if (e->d_name[0] == '.') continue;
        char lp[400], tgt[128];
        snprintf(lp, sizeof lp, "%s/%s", dir, e->d_name);
        ssize_t r = readlink(lp, tgt, sizeof tgt - 1);
        if (r <= 0) continue; tgt[r] = 0;
        if (strncmp(tgt, "socket:[", 8) == 0)
            out[n++] = strtoul(tgt + 8, NULL, 10);
    }
    closedir(d);
    return n;
}

int ps_sock_snapshot(const char *proc_root, const int *pids, int npids,
                     const char *comms[], const int *depths,
                     struct ps_act_socket *out, int max) {
    const char *root = (proc_root && proc_root[0]) ? proc_root : "/proc";
    static struct ps_sock_ep eps[MAX_EPS];
    int neps = load_net(root, eps, MAX_EPS);
    int count = 0;
    /* iterate pids root-first (npids-1 .. 0) so nearest-to-root owner wins dedup */
    for (int i = npids - 1; i >= 0 && count < max; i--) {
        unsigned long inodes[256];
        int ni = pid_sock_inodes(root, pids[i], inodes, 256);
        for (int k = 0; k < ni && count < max; k++) {
            struct ps_sock_ep ep;
            if (ps_sock_find_by_inode(eps, neps, inodes[k], &ep) != 0) continue;
            /* dedup: skip if this laddr+raddr pair was already recorded
             * (collapses the same endpoint seen across multiple ancestor pids) */
            int dup = 0;
            for (int j = 0; j < count; j++)
                if (out[j].owner_pid && strcmp(out[j].raddr, ep.raddr) == 0 &&
                    strcmp(out[j].laddr, ep.laddr) == 0) { dup = 1; break; }
            if (dup) continue;
            struct ps_act_socket *s = &out[count++];
            memset(s, 0, sizeof *s);
            s->owner_pid = pids[i];
            s->depth = depths[i];
            snprintf(s->owner_comm, sizeof s->owner_comm, "%s", comms[i] ? comms[i] : "");
            snprintf(s->proto, sizeof s->proto, "%s", ep.proto);
            snprintf(s->laddr, sizeof s->laddr, "%s", ep.laddr);
            snprintf(s->raddr, sizeof s->raddr, "%s", ep.raddr);
            snprintf(s->state, sizeof s->state, "%s", ep.state);
        }
    }
    return count;
}
