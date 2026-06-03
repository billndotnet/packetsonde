#ifndef PS_PROC_ENRICH_H
#define PS_PROC_ENRICH_H
#include "activity_record.h"

/* Fill a->proc (leaf pid) and a->anc[] (ancestors to session/service root,
 * stopping before PID 1, skipping kernel threads, depth-capped at max_depth).
 * proc_root: "" or NULL -> "/proc". Returns 0, or -1 if the leaf is unreadable. */
int ps_proc_enrich(const char *proc_root, int pid, struct ps_activity *a, int max_depth);
#endif /* PS_PROC_ENRICH_H */
