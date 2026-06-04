#ifndef PS_BASELINE_DECIDE_H
#define PS_BASELINE_DECIDE_H
#include "baseline_set.h"
enum ps_bl_verdict { PS_BL_COVERED=0, PS_BL_NOVEL, PS_BL_ANOMALY };
/* baseline (approved) wins over denials; else denied -> ANOMALY; else NOVEL. */
enum ps_bl_verdict ps_baseline_decide(const struct ps_baseline_set *baseline,
                                      const struct ps_baseline_set *denials, const char *path);
/* Same verdict semantics as ps_baseline_decide, but for a network raddr. */
enum ps_bl_verdict ps_baseline_decide_dest(const struct ps_baseline_set *baseline,
                                           const struct ps_baseline_set *denials, const char *raddr);
#endif
