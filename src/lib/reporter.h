#ifndef PS_REPORTER_H
#define PS_REPORTER_H
#include <stddef.h>
#include "central_config.h"
#include "finding.h"

struct ps_report_result { int accepted; int rejected; int total; int http_status; };

/* Sign + POST raw event-JSON strings to central as one {envelopes:[…]} batch.
 * base_url NULL -> cc->url. Returns 0 on a completed HTTP exchange (inspect out),
 * -1 on transport/local error. */
int ps_report_events(const struct ps_central_config *cc, const char *base_url,
                     const char **event_jsons, size_t n, struct ps_report_result *out);

/* Serialize findings to event JSON, then ps_report_events. */
int ps_report_findings(const struct ps_central_config *cc, const char *base_url,
                       const struct ps_finding *findings, size_t n,
                       struct ps_report_result *out);

/* Exposed for unit tests. */
int ps_reporter_build_payload(char *buf, size_t cap, const char *agent_id,
                              const char *ts, const char *event_json);
int ps_reporter_extract_ts(const char *event_json, char *out, size_t cap);
#endif
