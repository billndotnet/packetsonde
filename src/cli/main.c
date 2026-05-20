#include "args.h"
#include "verbs.h"

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
        /* --help printed already */
        return 0;
    }

    const char *verb_name = opts.verb_argv[0];
    const struct ps_verb *v = ps_verbs_find(verb_name);
    if (!v) {
        fprintf(stderr, "%s: unknown verb '%s'\n", argv[0], verb_name);
        ps_args_usage(argv[0]);
        return 2;
    }

    /* Verb sees its own argv starting at the verb name. */
    return v->run(opts.verb_argc, opts.verb_argv, &opts);
}
