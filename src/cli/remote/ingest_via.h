#ifndef PS_INGEST_VIA_H
#define PS_INGEST_VIA_H
#include <stddef.h>
#include "agent_proto.h"
#include "reporter.h"   /* struct ps_report_result */

/* Forward a pre-built envelope array (the "[…]" from ps_reporter_build_envelopes)
 * to relay_agent over the agent_proto ingest frame; fills *out from the ack.
 * Returns 0 on a completed exchange, -1 on failure. Every failure, including a
 * batch too large for one frame and a refusal from the relay, is reported on
 * stderr, as is any detail the relay attaches to its ack. */
int ps_ingest_via(const char *relay_agent, const char *envelopes_array,
                  struct ps_report_result *out);

/* Wrap the envelope array in an ingest frame. The frame may be at most
 * PS_AGENT_FRAME_MAX bytes, the protocol limit the relay reads up to. Returns 0
 * with a heap *frame (caller frees) and its length, or -1 with *len set to the
 * size the frame would have needed (0 if allocation failed). */
int ps_ingest_build_frame(const char *envelopes_array, char **frame, size_t *len);

/* Send one ingest frame on an open session and wait for the relay's answer,
 * skipping its hello. Returns 0 on an ack (*out's accepted / rejected filled; `why` holds the ack's
 * detail, possibly empty), or -1 with the reason in `why`: the relay's error
 * message, or a note that it closed without answering. */
int ps_ingest_exchange(const struct ps_ap_io *io, const char *frame, size_t len,
                       struct ps_report_result *out, char *why, size_t why_cap);
#endif
