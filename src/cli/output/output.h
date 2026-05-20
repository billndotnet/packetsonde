#ifndef PS_OUTPUT_H
#define PS_OUTPUT_H

#include "finding.h"
#include <pthread.h>
#include <stdio.h>

enum {
    PS_FMT_OUT_AUTO  = 0,
    PS_FMT_TEXT      = 1,
    PS_FMT_JSON      = 2,
    PS_FMT_JSONL     = 3,
    PS_FMT_QUIET     = 4
};

struct ps_output_opts {
    int  fmt_force;
    int  color;
    int  assume_tty;
    int  target_fd;
    const char *auto_append_path;
};

struct ps_output {
    int             fmt;
    int             color;
    int             stdout_fd;
    int             append_fd;
    pthread_mutex_t lock;
};

int  ps_output_init (struct ps_output *o, const struct ps_output_opts *opts);
void ps_output_emit (struct ps_output *o, const struct ps_finding *f);
void ps_output_close(struct ps_output *o);

#endif
