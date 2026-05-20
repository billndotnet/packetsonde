#include "fail_on.h"
#include "finding.h"

#include <string.h>

int ps_fail_on_parse(const char *expr, struct ps_fail_on *F) {
    if (!F) return -1;
    F->active = 0;
    F->min_severity = PS_SEV_INFO;
    if (!expr || !*expr) return 0;
    if (strncmp(expr, "severity>=", 10) != 0) return -1;
    const char *L = expr + 10;
    if      (!strcmp(L, "info"))     F->min_severity = PS_SEV_INFO;
    else if (!strcmp(L, "low"))      F->min_severity = PS_SEV_LOW;
    else if (!strcmp(L, "medium"))   F->min_severity = PS_SEV_MEDIUM;
    else if (!strcmp(L, "high"))     F->min_severity = PS_SEV_HIGH;
    else if (!strcmp(L, "critical")) F->min_severity = PS_SEV_CRITICAL;
    else return -1;
    F->active = 1;
    return 0;
}

int ps_fail_on_eval(const struct ps_fail_on *F, const struct ps_fail_counts *c) {
    if (!F->active) return 0;
    switch (F->min_severity) {
        case PS_SEV_INFO:     return (c->n_info + c->n_low + c->n_medium + c->n_high + c->n_critical) > 0;
        case PS_SEV_LOW:      return (c->n_low + c->n_medium + c->n_high + c->n_critical) > 0;
        case PS_SEV_MEDIUM:   return (c->n_medium + c->n_high + c->n_critical) > 0;
        case PS_SEV_HIGH:     return (c->n_high + c->n_critical) > 0;
        case PS_SEV_CRITICAL: return c->n_critical > 0;
    }
    return 0;
}

void ps_output_snapshot(const struct ps_output *o, struct ps_fail_counts *c) {
    c->n_info     = o->n_info;
    c->n_low      = o->n_low;
    c->n_medium   = o->n_medium;
    c->n_high     = o->n_high;
    c->n_critical = o->n_critical;
}
