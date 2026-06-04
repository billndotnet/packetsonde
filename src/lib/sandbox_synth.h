#ifndef PS_SANDBOX_SYNTH_H
#define PS_SANDBOX_SYNTH_H
#include <stddef.h>
#include "unit_envelope.h"
/* Synthesize an annotated systemd [Service] sandboxing stanza from an envelope.
 * write paths are rolled up to a directory rule when >= rollup_threshold distinct
 * files share a parent dir (else emitted exact). Returns bytes written, or -1. */
int ps_sandbox_synth(const struct ps_unit_envelope *e, int rollup_threshold,
                     char *out, size_t cap);
#endif
