#ifndef PS_CLI_PROBE_VIA_H
#define PS_CLI_PROBE_VIA_H

#include "../args.h"
#include "output/output.h"

/* Run a probe on a remote agent (resolved via opts->via against the
 * registry). Streams results back, re-emitting each one locally with a
 * via_agent field populated. Returns the same exit code semantics as
 * a local probe run. */
int ps_probe_via_run(int argc, char **argv,
                     const struct ps_args *opts,
                     struct ps_output *out);

#endif
