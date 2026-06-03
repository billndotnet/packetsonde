#include "fan_monitor.h"
#include "proc_enrich.h"
#include "sock_snapshot.h"
#include "suppress.h"
#include "activity_record.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

static void now_iso(char *out, size_t cap) {
    struct timeval tv; gettimeofday(&tv, NULL);
    time_t t = tv.tv_sec; struct tm tm; gmtime_r(&t, &tm);
    strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

int ps_fan_build_record(const char *proc_root, int pid, const char *path,
                        const char *event, int is_read, const char *suppress,
                        int max_depth, char *out, size_t cap) {
    /* comm needed for suppression: cheap read via enrich's leaf, but to gate
     * BEFORE full enrich we read just the leaf comm. Reuse enrich for the leaf. */
    struct ps_activity a; memset(&a, 0, sizeof a);
    if (ps_proc_enrich(proc_root, pid, &a, max_depth) != 0) {
        /* process gone: emit a partial record with what we have (path/event) */
        a.partial = 1;
    }
    if (ps_suppress_match(suppress, a.proc.comm, path, is_read)) return 0;

    now_iso(a.ts, sizeof a.ts);
    snprintf(a.event, sizeof a.event, "%s", event);
    snprintf(a.path, sizeof a.path, "%s", path);

    /* socket snapshot over {leaf} ∪ ancestry */
    int pids[1 + PS_ACT_MAX_ANC]; const char *comms[1 + PS_ACT_MAX_ANC]; int depths[1 + PS_ACT_MAX_ANC];
    int np = 0;
    pids[np] = a.proc.pid; comms[np] = a.proc.comm; depths[np] = 0; np++;
    for (int i = 0; i < a.nanc && np < 1 + PS_ACT_MAX_ANC; i++) {
        pids[np] = a.anc[i].pid; comms[np] = a.anc[i].comm; depths[np] = a.anc[i].depth; np++;
    }
    a.nsock = ps_sock_snapshot(proc_root, pids, np, comms, depths, a.sock, PS_ACT_MAX_SOCK);

    return ps_activity_to_json(&a, out, cap);
}
