#ifndef PS_INGEST_VIA_H
#define PS_INGEST_VIA_H
#include "reporter.h"   /* struct ps_report_result */

/* Forward a pre-built envelope array (the "[…]" from ps_reporter_build_envelopes)
 * to relay_agent over the agent_proto ingest frame; fills *out from the ack.
 * Returns 0 on a completed exchange, -1 on transport failure. */
int ps_ingest_via(const char *relay_agent, const char *envelopes_array,
                  struct ps_report_result *out);
#endif
