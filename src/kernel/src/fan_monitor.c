#include "fan_monitor.h"
#include "proc_enrich.h"
#include "sock_snapshot.h"
#include "suppress.h"
#include "activity_record.h"
#include "log.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <stdlib.h>
#include <errno.h>
#ifdef __linux__
#include <sys/fanotify.h>
#endif

#define PS_ACT_ITEM_SERIALIZE_MAX 8192

#ifdef __linux__
const char *ps_fan_event_for_mask(unsigned long long mask, int *is_read) {
    if (mask & FAN_OPEN_EXEC)   { if (is_read) *is_read = 0; return "exec"; }
    if (mask & FAN_CLOSE_WRITE) { if (is_read) *is_read = 0; return "write"; }
    if (mask & FAN_ACCESS)      { if (is_read) *is_read = 1; return "access"; }
    if (is_read) *is_read = 1;  return "open";
}
#endif

static void now_iso(char *out, size_t cap) {
    struct timeval tv; gettimeofday(&tv, NULL);
    time_t t = tv.tv_sec; struct tm tm; gmtime_r(&t, &tm);
    strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

int ps_fan_build_record(const char *proc_root, int pid, const char *path,
                        const char *event, int is_read, const char *suppress,
                        int max_depth, const struct ps_prov_cfg *prov,
                        char *out, size_t cap) {
    /* comm needed for suppression: cheap read via enrich's leaf, but to gate
     * BEFORE full enrich we read just the leaf comm. Reuse enrich for the leaf. */
    struct ps_activity a; memset(&a, 0, sizeof a);
    if (ps_proc_enrich(proc_root, pid, &a, max_depth) != 0) {
        /* process gone: emit a partial record with what we have (path/event/pid) */
        a.partial = 1;
        a.proc.pid = pid;   /* carry the fanotify pid even when /proc is gone */
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

    /* Provenance classification: stamp prov_trigger so the brain ships this
     * record as a detect.file_provenance observation. Only write/exec events
     * can trigger; for writes, stat the path for the executable bit. */
    if (prov && prov->enabled) {
        unsigned int mode = 0;
        /* For writes, stat the real path for the executable bit. `path` is the
         * absolute file path (proc_root only redirects /proc reads, not this).
         * The priv worker runs as root, so the stat succeeds. */
        if (strcmp(event, "write") == 0) {
            struct stat st;
            if (stat(path, &st) == 0) mode = st.st_mode;
        }
        const char *trig = ps_provenance_classify(event, path, mode, prov);
        if (trig[0]) snprintf(a.prov_trigger, sizeof a.prov_trigger, "%s", trig);
    }

    return ps_activity_to_json(&a, out, cap);
}

#ifdef __linux__
/* True if `path` equals, or is nested under, any of the comma-separated roots
 * in `csv`. Boundary-aware: "/etc" matches "/etc" and "/etc/passwd", never
 * "/etcfoo". Used to filter mount-wide fanotify events down to the configured
 * subtrees (a mount mark delivers events for the whole mount; the kernel has no
 * subtree filter in the notification class, so we filter in userspace). */
int ps_fan_path_under_csv(const char *path, const char *csv) {
    if (!csv || !csv[0] || !path || !path[0]) return 0;
    char buf[4096]; snprintf(buf, sizeof buf, "%s", csv);
    for (char *p = strtok(buf, ","); p; p = strtok(NULL, ",")) {
        size_t plen = strlen(p);
        while (plen > 1 && p[plen - 1] == '/') plen--;   /* ignore trailing '/' */
        if (plen == 0) continue;
        if (strncmp(path, p, plen) != 0) continue;
        /* match must end on a component boundary, except when the root itself is
         * a separator (p == "/"), which contains every absolute path. */
        if (p[plen - 1] == '/' || path[plen] == '/' || path[plen] == '\0')
            return 1;
    }
    return 0;
}

/* Mark the FILESYSTEM containing each comma-separated root for write-close events,
 * so writes anywhere beneath each root are caught across mount namespaces
 * (FAN_MARK_FILESYSTEM — see the rationale on the watch_paths marks; a bare inode
 * or mount mark would miss host writes from the agent's private namespace). Used
 * for the provenance transient/sensitive sets so write triggers fire at stock
 * config. The event loop filters these back down to the configured roots. */
static void ps_fan_mark_write_roots(int fan, const char *roots) {
    if (!roots || !roots[0]) return;
    char buf[4096]; snprintf(buf, sizeof buf, "%s", roots);
    for (char *p = strtok(buf, ","); p; p = strtok(NULL, ",")) {
        struct stat st;
        unsigned int flags = FAN_MARK_ADD;   /* file -> inode (precise, low-volume) */
        if (stat(p, &st) == 0 && S_ISDIR(st.st_mode)) flags |= FAN_MARK_FILESYSTEM;
        if (fanotify_mark(fan, flags, FAN_CLOSE_WRITE, AT_FDCWD, p) < 0)
            ps_warn("fan: mark write-root '%s' failed: %s", p, strerror(errno));
    }
}

int ps_fan_monitor_run(const struct ps_fan_cfg *cfg,
                       void (*emit)(const char *, size_t, void *), void *ctx) {
    int fan = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, O_RDONLY | O_CLOEXEC);
    if (fan < 0) { ps_warn("fan: fanotify_init failed: %s (CAP_SYS_ADMIN required)", strerror(errno)); return -1; }
    /* Mark each watch path. A bare inode mark on a DIRECTORY only fires for the
     * directory itself (never files within), and a FAN_MARK_MOUNT mark is scoped
     * to a single vfsmount in the CALLER's mount namespace — useless here because
     * systemd sandboxing (PrivateTmp/ProtectSystem/ProtectHome) runs packetsonded
     * in a private mount namespace, so a mount mark would see only the agent's OWN
     * activity, not the host processes we exist to watch. So:
     *  - a FILE entry  -> FAN_MARK_ADD on the inode: precise + LOW VOLUME, and the
     *    inode (superblock object) is shared across mount-namespace clones, so the
     *    sandboxed agent still sees host-wide accesses to that file. This is the
     *    preferred form for sensitive-file detection (e.g. /etc/passwd reads).
     *  - a DIR entry   -> FAN_MARK_FILESYSTEM on the superblock: also namespace-
     *    independent, but delivers events for the WHOLE filesystem (the loop below
     *    filters to watch_paths). High volume on a busy fs (e.g. /etc on '/') — the
     *    rate limit + the non-blocking activity emit keep it from wedging, but
     *    prefer listing specific files where you can. */
    char paths[4096]; snprintf(paths, sizeof paths, "%s", cfg->watch_paths ? cfg->watch_paths : "");
    int n_marks = 0;
    for (char *p = strtok(paths, ","); p; p = strtok(NULL, ",")) {
        struct stat st;
        unsigned int flags = FAN_MARK_ADD;
        const char *kind = "inode";
        if (stat(p, &st) == 0 && S_ISDIR(st.st_mode)) { flags |= FAN_MARK_FILESYSTEM; kind = "filesystem"; }
        if (fanotify_mark(fan, flags,
                          FAN_OPEN | FAN_ACCESS | FAN_OPEN_EXEC | FAN_CLOSE_WRITE, AT_FDCWD, p) < 0)
            ps_warn("fan: mark %s for watch_path '%s' failed: %s", kind, p, strerror(errno));
        else n_marks++;
    }
    /* Filesystem-wide exec mark: catch ANY execve on the root fs regardless of dir
     * (the unifying post-exploitation signal), across mount namespaces. */
    if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_OPEN_EXEC, AT_FDCWD, "/") < 0)
        ps_warn("fan: filesystem-wide exec mark on '/' failed: %s", strerror(errno));
    /* Provenance: also watch the transient + sensitive roots for writes, so the
     * write_executable / write_sensitive_path triggers fire at stock config
     * (otherwise they'd depend on those roots being in watch_paths). */
    if (cfg->prov.enabled) {
        ps_fan_mark_write_roots(fan, cfg->prov.transient_paths);
        ps_fan_mark_write_roots(fan, cfg->prov.sensitive_paths);
    }
    ps_info("fan: monitoring started (watch_paths=%s, filesystems marked=%d, max_events_ps=%d)",
            cfg->watch_paths ? cfg->watch_paths : "(none)", n_marks, cfg->max_events_ps);
    int max_depth = cfg->max_depth > 0 ? cfg->max_depth : 16;
    int max_eps = cfg->max_events_ps > 0 ? cfg->max_events_ps : 0;
    time_t rl_window = 0; int rl_count = 0, rl_dropped = 0;
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
            int is_read = 1;
            const char *event = ps_fan_event_for_mask(m->mask, &is_read);
            /* Mount marks deliver the whole mount; keep only execs (global
             * post-exploitation signal), paths under a configured watch_path,
             * or paths under a provenance root (for write classification).
             * Filter BEFORE the expensive enrich in ps_fan_build_record. */
            if (strcmp(event, "exec") != 0
                && !ps_fan_path_under_csv(path, cfg->watch_paths)
                && !(cfg->prov.enabled && (ps_fan_path_under_csv(path, cfg->prov.transient_paths)
                                        || ps_fan_path_under_csv(path, cfg->prov.sensitive_paths))))
                continue;
            /* Per-second rate limit (max_events_ps): drop overflow before enrich
             * so a busy mount can't flood the sink or starve the CPU. */
            if (max_eps) {
                time_t now = time(NULL);
                if (now != rl_window) {
                    if (rl_dropped > 0)
                        ps_warn("fan: rate limit hit, dropped %d events in prior second (max_events_ps=%d)", rl_dropped, max_eps);
                    rl_window = now; rl_count = 0; rl_dropped = 0;
                }
                if (rl_count >= max_eps) { rl_dropped++; continue; }
                rl_count++;
            }
            char json[PS_ACT_ITEM_SERIALIZE_MAX];
            int n = ps_fan_build_record("", (int)m->pid, path, event, is_read,
                                        cfg->suppress, max_depth, &cfg->prov, json, sizeof json);
            if (n > 0 && emit) emit(json, (size_t)n, ctx);
            else if (n < 0) ps_warn("fan: activity record overflow, dropped (pid=%d path=%s)", (int)m->pid, path);
        }
    }
    return 0;
}
#else  /* non-Linux: fanotify is Linux-only; the collection runtime is a no-op */
int ps_fan_monitor_run(const struct ps_fan_cfg *cfg,
                       void (*emit)(const char *, size_t, void *), void *ctx) {
    (void)cfg; (void)emit; (void)ctx;
    return -1;
}
#endif
