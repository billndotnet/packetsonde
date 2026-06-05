#ifndef PS_VERBS_H
#define PS_VERBS_H

#include "args.h"

#include <stdio.h>

struct ps_verb {
    const char *name;
    int (*run)(int argc, char **argv, const struct ps_args *opts);
    const char *summary;
};

const struct ps_verb *ps_verbs_find(const char *name);

/* Walk the verb registry, printing "  <name>  <summary>" for each. Used
 * by both `packetsonde help` and the top-level usage error path so they
 * stay in sync with whatever's actually registered. */
void ps_verbs_print_list(FILE *fp);

int ps_verb_help_run(int argc, char **argv, const struct ps_args *opts);
int ps_verb_inspect_run(int argc, char **argv, const struct ps_args *opts);

#endif
