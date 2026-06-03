#include "fan_monitor.h"
#include "proc_enrich.h"
#include "sock_snapshot.h"
#include "suppress.h"
#include "activity_record.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/fanotify.h>

#define PS_ACT_ITEM_SERIALIZE_MAX 8192

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

int ps_fan_monitor_run(const struct ps_fan_cfg *cfg,
                       void (*emit)(const char *, size_t, void *), void *ctx) {
    int fan = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, O_RDONLY | O_CLOEXEC);
    if (fan < 0) return -1;
    /* mark each watch path: opens, accesses, exec-opens (notification only) */
    char paths[4096]; snprintf(paths, sizeof paths, "%s", cfg->watch_paths ? cfg->watch_paths : "");
    for (char *p = strtok(paths, ","); p; p = strtok(NULL, ",")) {
        fanotify_mark(fan, FAN_MARK_ADD,
                      FAN_OPEN | FAN_ACCESS | FAN_OPEN_EXEC, AT_FDCWD, p);
    }
    /* Mount-wide exec mark: catch ANY execve regardless of dir (the unifying
     * post-exploitation signal). Independent of watch_paths. */
    fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN_EXEC, AT_FDCWD, "/");
    int max_depth = cfg->max_depth > 0 ? cfg->max_depth : 16;
    for (;;) {
        struct pollfd pfd = { fan, POLLIN, 0 };
        if (poll(&pfd, 1, 500) <= 0) continue;
        char buf[8192];
        ssize_t len = read(fan, buf, sizeof buf);
        if (len <= 0) continue;
        struct fanotify_event_metadata *m = (void *)buf;
        for (; FAN_EVENT_OK(m, len); m = FAN_EVENT_NEXT(m, len)) {
            if (m->vers != FANOTIFY_METADATA_VERSION) { if (m->fd >= 0) close(m->fd); continue; }
            if (m->fd < 0) continue;
            char link[64], path[512];
            snprintf(link, sizeof link, "/proc/self/fd/%d", m->fd);
            ssize_t r = readlink(link, path, sizeof path - 1);
            close(m->fd);
            if (r <= 0) continue; path[r] = 0;
            const char *event = (m->mask & FAN_OPEN_EXEC) ? "exec"
                              : (m->mask & FAN_ACCESS) ? "access" : "open";
            int is_read = !(m->mask & FAN_OPEN_EXEC);  /* exec-opens never suppressed */
            char json[PS_ACT_ITEM_SERIALIZE_MAX];
            int n = ps_fan_build_record("", (int)m->pid, path, event, is_read,
                                        cfg->suppress, max_depth, json, sizeof json);
            if (n > 0 && emit) emit(json, (size_t)n, ctx);
        }
    }
    return 0;
}
