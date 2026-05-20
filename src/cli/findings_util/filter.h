#ifndef PS_FINDING_FILTER_H
#define PS_FINDING_FILTER_H

#include "reader.h"

enum ps_filter_op {
    PS_FOP_EQ,
    PS_FOP_GE,
    PS_FOP_PREFIX
};

enum ps_filter_field {
    PS_FF_KIND,
    PS_FF_SOURCE,
    PS_FF_SEVERITY,
    PS_FF_TARGET
};

struct ps_finding_filter {
    enum ps_filter_field field;
    enum ps_filter_op    op;
    char                 value_s[128];
    enum ps_severity     value_sev;
};

int  ps_filter_parse  (const char *expr, struct ps_finding_filter *out);
int  ps_filter_eval   (const struct ps_finding_filter *F,
                       const struct ps_finding_lite *f);
void ps_filter_destroy(struct ps_finding_filter *F);

#endif
