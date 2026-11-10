#ifndef PS_CENTRAL_CHECKIN_H
#define PS_CENTRAL_CHECKIN_H

/* One checkin POST to central (reads PS_CENTRAL_* env). Returns 0 on HTTP 200,
 * -1 on transport/non-200 or when no central url is configured. */
int ps_central_checkin_once(long uptime_seconds);

/* Start a detached background thread that checks in every checkin_seconds.
 * Returns 0 if started, -1 if central is not configured. */
int ps_central_checkin_start(void);

/* Stop the checkin loop (if running), flush every pending dedupe summary
 * into the observation queue and ship the queue once more. Bounded by the
 * reporter's HTTP timeout; safe to call when central is not configured. */
void ps_central_checkin_stop(void);

#endif
