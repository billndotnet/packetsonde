#include "baseline_decide.h"
#include "dest_match.h"
enum ps_bl_verdict ps_baseline_decide(const struct ps_baseline_set *baseline,
                                      const struct ps_baseline_set *denials, const char *path) {
    if (ps_blset_covered(baseline, path)) return PS_BL_COVERED;
    if (ps_blset_covered(denials, path))  return PS_BL_ANOMALY;
    return PS_BL_NOVEL;
}
enum ps_bl_verdict ps_baseline_decide_dest(const struct ps_baseline_set *baseline,
                                           const struct ps_baseline_set *denials, const char *raddr) {
    if (ps_destset_covered(baseline, raddr)) return PS_BL_COVERED;
    if (ps_destset_covered(denials, raddr))  return PS_BL_ANOMALY;
    return PS_BL_NOVEL;
}
