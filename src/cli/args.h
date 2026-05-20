#ifndef PS_ARGS_H
#define PS_ARGS_H

#include <stdbool.h>

enum ps_fmt {
    PS_FMT_AUTO = 0,   /* text on tty, jsonl otherwise */
    PS_FMT_TEXT,
    PS_FMT_JSON,
    PS_FMT_JSONL,
    PS_FMT_QUIET
};

struct ps_args {
    enum ps_fmt fmt;
    const char *via;          /* --via name, or NULL */
    const char *config_path;  /* --config path, or NULL */
    const char *socket_path;  /* --socket path (override), or NULL */
    bool no_color;
    bool auto_append;
    int concurrency;          /* --concurrency, 0 = default */
    int rate_pps;             /* --rate, 0 = default */

    int    verb_argc;
    char **verb_argv;         /* points into the original argv */
};

int ps_args_parse(int argc, char **argv, struct ps_args *out);

/* Prints usage to stderr. */
void ps_args_usage(const char *prog);

#endif
