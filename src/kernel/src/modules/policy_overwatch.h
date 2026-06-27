#ifndef PS_POLICY_OVERWATCH_H
#define PS_POLICY_OVERWATCH_H
#include <stddef.h>
#include <stdint.h>
#include "policy_eval.h"
#include "systemd_policy.h"

enum ps_op ps_overwatch_op_for_event(const char *event);

/* opaque first-seen dedup set */
void *ps_overwatch_seen_new(void);
void  ps_overwatch_seen_free(void *seen);

/* Parse one activity-record JSON, resolve unit, look up policy via `loader`,
 * evaluate, dedup, and call emit(emit_ctx, finding_json, len) per NEW violation.
 * now_sec feeds the policy cache. Returns the number of findings emitted. */
int ps_overwatch_process_record(const char *record_json, ps_unit_policy_loader loader,
                                void *seen, void (*emit)(void *, const char *, size_t),
                                void *emit_ctx, uint64_t now_sec);

#include "unit_envelope.h"
/* Learn-mode: parse a record, resolve its unit, find-or-create its envelope in
 * envs[0..*n_envs) (growing up to max_envs), and accumulate the access. Returns
 * the envelope index updated, or -1 if the record has no unit / no capacity. */
int ps_overwatch_learn_record(const char *record_json, struct ps_unit_envelope *envs,
                              int *n_envs, int max_envs);
#endif
