#ifndef PS_VERBS_H
#define PS_VERBS_H

#include "args.h"

struct ps_verb {
    const char *name;
    int (*run)(int argc, char **argv, const struct ps_args *opts);
    const char *summary;
};

const struct ps_verb *ps_verbs_find(const char *name);

int ps_verb_help_run(int argc, char **argv, const struct ps_args *opts);

#endif
