#include "baseline_decide.h"
enum ps_bl_verdict ps_baseline_decide(const struct ps_baseline_set *baseline,
                                      const struct ps_baseline_set *denials, const char *path) {
    if (ps_blset_covered(baseline, path)) return PS_BL_COVERED;
    if (ps_blset_covered(denials, path))  return PS_BL_ANOMALY;
    return PS_BL_NOVEL;
}
