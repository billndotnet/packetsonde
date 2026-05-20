#include "../util/fail_on.h"
#include "../output/output.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void counts(struct ps_fail_counts *c, unsigned info, unsigned low,
                   unsigned med, unsigned high, unsigned crit) {
    memset(c, 0, sizeof(*c));
    c->n_info = info; c->n_low = low; c->n_medium = med;
    c->n_high = high; c->n_critical = crit;
}

int main(void) {
    struct ps_fail_on F;
    struct ps_fail_counts C;

    assert(ps_fail_on_parse("severity>=high", &F) == 0);
    counts(&C, 5, 5, 5, 0, 0); assert(ps_fail_on_eval(&F, &C) == 0);
    counts(&C, 0, 0, 0, 1, 0); assert(ps_fail_on_eval(&F, &C) == 1);
    counts(&C, 0, 0, 0, 0, 9); assert(ps_fail_on_eval(&F, &C) == 1);

    assert(ps_fail_on_parse("severity>=critical", &F) == 0);
    counts(&C, 0, 0, 0, 99, 0); assert(ps_fail_on_eval(&F, &C) == 0);
    counts(&C, 0, 0, 0, 0,  1); assert(ps_fail_on_eval(&F, &C) == 1);

    assert(ps_fail_on_parse(NULL, &F) == 0);
    counts(&C, 0, 0, 0, 99, 99); assert(ps_fail_on_eval(&F, &C) == 0);

    printf("test_fail_on: OK\n");
    return 0;
}
