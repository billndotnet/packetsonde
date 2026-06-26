#ifndef PS_FAN_MONITOR_H
#define PS_FAN_MONITOR_H
#include <stddef.h>
#include "provenance.h"

/* Build one activity-record JSON for a file event. Applies the suppression gate
 * first (reads only): if suppressed, returns 0 and writes nothing. Otherwise
 * enriches the pid (+ ancestry), snapshots sockets (leaf+ancestors), serializes.
 * `event` is "open"|"access"|"exec"; is_read 1 for read opens. `suppress` is the
 * coarse list. proc_root "" -> "/proc". Returns JSON length, 0 if suppressed, -1 error. */
int ps_fan_build_record(const char *proc_root, int pid, const char *path,
                        const char *event, int is_read, const char *suppress,
                        int max_depth, const struct ps_prov_cfg *prov,
                        char *out, size_t cap);

/* Runtime entry (Task 11 wires fanotify to this). Returns 0; never returns until
 * stop flag set. `emit` is called with each record JSON. */
struct ps_fan_cfg { const char *watch_paths; const char *suppress; int max_depth; int max_events_ps;
                    struct ps_prov_cfg prov; };
int ps_fan_monitor_run(const struct ps_fan_cfg *cfg,
                       void (*emit)(const char *json, size_t len, void *ctx), void *ctx);

/* Map a fanotify event mask to the activity-record event string and read-ness.
 * Precedence: exec > write > access > open. *is_read is 0 for exec/write
 * (never suppressed), 1 for access/open. */
const char *ps_fan_event_for_mask(unsigned long long mask, int *is_read);

/* True if `path` equals, or is nested under, any comma-separated root in `csv`.
 * Boundary-aware ("/etc" matches "/etc/passwd", never "/etcfoo"). Used to filter
 * mount-wide fanotify events down to the configured watch_paths/provenance roots. */
int ps_fan_path_under_csv(const char *path, const char *csv);
#endif /* PS_FAN_MONITOR_H */
