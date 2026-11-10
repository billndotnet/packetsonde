#ifndef PS_CENTRAL_CHECKIN_H
#define PS_CENTRAL_CHECKIN_H

/* One checkin POST to central (reads PS_CENTRAL_* env). Returns 0 on HTTP 200,
 * -1 on transport/non-200 or when no central url is configured. */
int ps_central_checkin_once(long uptime_seconds);

/* Start a detached background thread that checks in every checkin_seconds.
 * Returns 0 if started, -1 if central is not configured. */
int ps_central_checkin_start(void);

/* Stop the checkin loop (if running) and run one last shipping cycle with
 * force: the queue, then every pending dedupe summary (obs_ship.h). Bounded
 * by the reporter's HTTP timeout; safe to call when central is not
 * configured (nothing is shipped then). */
void ps_central_checkin_stop(void);

/* Test seam: ship through `fn` instead of the reporter (NULL restores). */
#include "obs_ship.h"
void ps_central_checkin_set_ship_fn(ps_obs_ship_fn fn, void *user);

#endif
