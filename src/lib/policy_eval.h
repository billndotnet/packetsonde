#ifndef PS_POLICY_EVAL_H
#define PS_POLICY_EVAL_H
#include "systemd_policy.h"
enum ps_op { PS_OP_READ=0, PS_OP_WRITE, PS_OP_EXEC };
struct ps_eval_result { int violation; const char *directive; int heuristic; };
/* Evaluate one access against a unit policy. Returns 1 if a violation (out set),
 * 0 if allowed. Conservative: only clear violations. */
int ps_policy_eval(const struct ps_unit_policy *p, const char *path,
                   enum ps_op op, struct ps_eval_result *out);
#endif
