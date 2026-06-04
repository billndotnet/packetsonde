#ifndef PS_BASELINE_MONITOR_H
#define PS_BASELINE_MONITOR_H
#include <stddef.h>
void *ps_baseline_seen_new(void);
void  ps_baseline_seen_free(void *seen);
/* Parse a record, load the exe's baseline+denials from state_dir, decide, and
 * emit a finding (kind candidate|anomaly) for NOVEL/ANOMALY; novel also appends
 * a candidate. Dedup per exe|path via seen. Returns findings emitted (0/1). */
int ps_baseline_process_record(const char *record_json, const char *state_dir, void *seen,
                               void (*emit)(void *, const char *, size_t), void *emit_ctx);
extern const struct ps_module ps_baseline_monitor_module;
#endif
