#ifndef PS_CLI_AUDIT_VIA_H
#define PS_CLI_AUDIT_VIA_H

#include "../args.h"
#include "output/output.h"

/* Run an audit on a remote agent (resolved via opts->via against the
 * registry). Streams findings back, re-emits each one locally with a
 * via_agent field populated. Returns the same exit code semantics as
 * a local audit run. */
int ps_audit_via_run(int argc, char **argv,
                     const struct ps_args *opts,
                     struct ps_output *out);

#endif
