#ifndef PS_OUTPUT_H
#define PS_OUTPUT_H

#include "finding.h"
#include <pthread.h>
#include <stdio.h>

enum ps_out_fmt {
    PS_OFMT_AUTO  = 0,
    PS_OFMT_TEXT  = 1,
    PS_OFMT_JSON  = 2,
    PS_OFMT_JSONL = 3,
    PS_OFMT_QUIET = 4
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
    unsigned int    n_info;
    unsigned int    n_low;
    unsigned int    n_medium;
    unsigned int    n_high;
    unsigned int    n_critical;
};

int  ps_output_init   (struct ps_output *o, const struct ps_output_opts *opts);
void ps_output_emit   (struct ps_output *o, const struct ps_finding *f);
/*
 * Emit a pre-rendered JSONL finding line. Used by the --via forwarder,
 * where the agent already produced a finding in v:1 JSON form and we
 * splice via_agent in by string surgery rather than round-tripping
 * through ps_finding.
 *
 * Behaves like ps_output_emit in that it:
 *   - holds o->lock,
 *   - bumps the severity counter that --fail-on consults,
 *   - writes to the same stdout_fd / append_fd as locally-rendered findings.
 *
 * Does not render TEXT/QUIET (the parsed finding isn't available); in
 * those formats the caller still sees JSONL. That's a known limitation
 * of --via for human-targeted formats.
 *
 * `line` must include the trailing newline. `severity` is matched against
 * the PS_SEV_* enum; pass -1 if unknown and no counter will move.
 */
void ps_output_emit_raw_jsonl(struct ps_output *o, int severity,
                              const char *line, size_t len);
void ps_output_summary(const struct ps_output *o, const char *run_id, long duration_ms);
void ps_output_close  (struct ps_output *o);

#endif
