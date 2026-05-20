#include "filter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_field(const char *s, size_t n, enum ps_filter_field *f) {
    if (n == 4 && !strncmp(s, "kind",     4)) { *f = PS_FF_KIND;     return 0; }
    if (n == 6 && !strncmp(s, "source",   6)) { *f = PS_FF_SOURCE;   return 0; }
    if (n == 8 && !strncmp(s, "severity", 8)) { *f = PS_FF_SEVERITY; return 0; }
    if (n == 6 && !strncmp(s, "target",   6)) { *f = PS_FF_TARGET;   return 0; }
    return -1;
}

static int sev_from(const char *s) {
    if (!strcmp(s, "info"))     return PS_SEV_INFO;
    if (!strcmp(s, "low"))      return PS_SEV_LOW;
    if (!strcmp(s, "medium"))   return PS_SEV_MEDIUM;
    if (!strcmp(s, "high"))     return PS_SEV_HIGH;
    if (!strcmp(s, "critical")) return PS_SEV_CRITICAL;
    return -1;
}

int ps_filter_parse(const char *expr, struct ps_finding_filter *F) {
    if (!expr || !F) return -1;
    memset(F, 0, sizeof(*F));

    const char *eq = strchr(expr, '=');
    const char *ge = strstr(expr, ">=");
    const char *pr = strchr(expr, '~');

    const char *split;
    enum ps_filter_op op;
    size_t op_len;
    if (ge && (!eq || ge < eq) && (!pr || ge < pr)) {
        split = ge; op = PS_FOP_GE; op_len = 2;
    } else if (pr && (!eq || pr < eq)) {
        split = pr; op = PS_FOP_PREFIX; op_len = 1;
    } else if (eq) {
        split = eq; op = PS_FOP_EQ; op_len = 1;
    } else {
        return -1;
    }

    size_t key_len = (size_t)(split - expr);
    if (parse_field(expr, key_len, &F->field) != 0) return -1;
    F->op = op;
    const char *val = split + op_len;
    size_t vlen = strlen(val);
    if (vlen == 0 || vlen >= sizeof(F->value_s)) return -1;
    memcpy(F->value_s, val, vlen + 1);

    if (F->field == PS_FF_SEVERITY) {
        int s = sev_from(F->value_s);
        if (s < 0) return -1;
        F->value_sev = (enum ps_severity)s;
        if (F->op == PS_FOP_PREFIX) return -1;
    }
    return 0;
}

int ps_filter_eval(const struct ps_finding_filter *F, const struct ps_finding_lite *f) {
    const char *field;
    switch (F->field) {
        case PS_FF_KIND:     field = f->kind;     break;
        case PS_FF_SOURCE:   field = f->source;   break;
        case PS_FF_TARGET:   field = f->target;   break;
        case PS_FF_SEVERITY:
            if (F->op == PS_FOP_EQ) return f->severity == F->value_sev;
            if (F->op == PS_FOP_GE) return f->severity >= F->value_sev;
            return 0;
    }
    if (F->op == PS_FOP_EQ)     return strcmp(field, F->value_s) == 0;
    if (F->op == PS_FOP_PREFIX) return strncmp(field, F->value_s, strlen(F->value_s)) == 0;
    return 0;
}

void ps_filter_destroy(struct ps_finding_filter *F) {
    (void)F;
}
