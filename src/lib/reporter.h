#ifndef PS_REPORTER_H
#define PS_REPORTER_H
#include <stddef.h>
#include "central_config.h"
#include "finding.h"

/* total    items passed in
 * skipped  items whose envelope could not be built (logged, never sent)
 * unsent   buildable items not delivered: transport failure, non-2xx answer,
 *          or an unusable signing key
 * accepted sum of the server's "accepted" counts; rejected = total - accepted
 * posts    HTTP requests attempted; http_status the last status received.
 * Items delivered with a 2xx = total - skipped - unsent. */
struct ps_report_result {
    int accepted; int rejected; int total; int http_status;
    int skipped; int unsent; int posts;
    /* Of `unsent`, the items that failed for a reason worth retrying: the
     * signing key could not be loaded, a POST failed in transport, or central
     * answered 5xx, 408 or 429. Items of a POST answered with any other
     * non-2xx (e.g. 400, 413) are unsent but NOT retryable (poison). */
    int retryable;
    /* Items from the front that need no retry: delivered with a 2xx (whatever
     * central's per-envelope verdict, so accepted items are never re-sent and
     * rejected ones are final), refused for good (poison), or skipped as
     * unbuildable. A retryable failure stops the call, so the items still
     * to retry are always the tail [handled, total). */
    int handled;
};

/* 1 when an HTTP status is worth retrying later: 5xx, 408, 429. */
int ps_report_status_retryable(int status);

/* Per-call counters from building an envelope array. */
struct ps_envelope_stats {
    size_t consumed;  /* items examined, from the front: emitted + skipped */
    size_t emitted;   /* envelopes written to the array */
    size_t skipped;   /* items whose envelope could not be built */
};

/* Sign + POST raw event-JSON strings to central as {envelopes:[…]}, in as many
 * POSTs as the envelopes need; items that cannot be enveloped are skipped.
 * base_url NULL -> cc->url. Returns 0 when every POST completed an HTTP exchange
 * (inspect out, including its status), -1 on transport/local error (out is
 * still filled). Targets /api/v1/packetsonde/events. */
int ps_report_events(const struct ps_central_config *cc, const char *base_url,
                     const char **event_jsons, size_t n, struct ps_report_result *out);

/* Same as ps_report_events but targets /api/v1/packetsonde/observations — the
 * hash-chained, signature-preserving passive-observation store. */
int ps_report_observations(const struct ps_central_config *cc, const char *base_url,
                           const char **event_jsons, size_t n, struct ps_report_result *out);

/* Serialize findings to event JSON, then ps_report_events. */
int ps_report_findings(const struct ps_central_config *cc, const char *base_url,
                       const struct ps_finding *findings, size_t n,
                       struct ps_report_result *out);

/* Build the signed envelope array "[<env>,…]" (no outer key) for the events.
 * Items whose envelope cannot be built are skipped (and logged). Returns bytes
 * written, or -1 when the signing key cannot be loaded. Shared by the direct
 * POST and the relay path. Items that do not fit `cap` are left out with a
 * warning; use the _ex form to learn how many were consumed and continue. */
int ps_reporter_build_envelopes(const struct ps_central_config *cc,
                                const char **event_jsons, size_t n,
                                char *out, size_t cap);

/* As above; st (may be NULL) reports how many items were consumed from the
 * front, emitted and skipped. Items [st->consumed, n) did not fit: build them
 * into the next array. The array is always closed and NUL-terminated. */
int ps_reporter_build_envelopes_ex(const struct ps_central_config *cc,
                                   const char **event_jsons, size_t n,
                                   char *out, size_t cap,
                                   struct ps_envelope_stats *st);

/* Exposed for unit tests. */
int ps_reporter_build_payload(char *buf, size_t cap, const char *agent_id,
                              const char *ts, const char *event_json);
int ps_reporter_extract_ts(const char *event_json, char *out, size_t cap);
#endif
