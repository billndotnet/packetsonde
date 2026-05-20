#ifndef PS_FAIL_ON_H
#define PS_FAIL_ON_H

#include "../output/output.h"

struct ps_fail_counts {
    unsigned n_info;
    unsigned n_low;
    unsigned n_medium;
    unsigned n_high;
    unsigned n_critical;
};

struct ps_fail_on {
    int active;
    int min_severity;
};

int ps_fail_on_parse(const char *expr, struct ps_fail_on *F);
int ps_fail_on_eval(const struct ps_fail_on *F, const struct ps_fail_counts *c);
void ps_output_snapshot(const struct ps_output *o, struct ps_fail_counts *c);

#endif
