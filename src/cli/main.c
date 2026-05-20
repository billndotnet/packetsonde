#include "args.h"
#include "verbs.h"
#include "util/fail_on.h"
#include "runstate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    struct ps_args opts;
    int prc = ps_args_parse(argc, argv, &opts);
    if (prc < 0) {
        ps_args_usage(argv[0]);
        return 2;
    }
    if (prc > 0) {
        return 0;
    }

    const char *verb_name = opts.verb_argv[0];
    const struct ps_verb *v = ps_verbs_find(verb_name);
    if (!v) {
        fprintf(stderr, "%s: unknown verb '%s'\n", argv[0], verb_name);
        ps_args_usage(argv[0]);
        return 2;
    }

    int rc = v->run(opts.verb_argc, opts.verb_argv, &opts);

    if (rc == 0 && opts.fail_on) {
        struct ps_fail_on F;
        if (ps_fail_on_parse(opts.fail_on, &F) != 0) {
            fprintf(stderr, "%s: bad --fail-on expression '%s'\n", argv[0], opts.fail_on);
            return 2;
        }
        if (ps_fail_on_eval(&F, &g_last_run_counts)) return 3;
    }
    return rc;
}
