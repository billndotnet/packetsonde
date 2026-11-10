#ifndef PS_OBS_SHIP_H
#define PS_OBS_SHIP_H

/* One shipping cycle for passive observations, independent of transport so
 * it can be tested without central.
 *
 *  1. Ship the observation queue (first sightings and other raw events) in
 *     batches of PS_OBS_SHIP_BATCH, at most PS_OBS_SHIP_MAX_BATCHES batches.
 *     A batch is PEEKED, shipped, and only the items `ship` reports handled
 *     are popped: what central did not take stays at the head of the queue,
 *     in order, for the next cycle. The queue stays bounded: while central is
 *     down, new pushes drop the OLDEST items (ps_obs_queue_dropped counts
 *     them), so a long outage keeps the most recent 256.
 *  2. Ship the dedupe summaries (staged ones, then ended windows; every open
 *     window with `force`) straight from ps_obs_dedupe_flush in batches of
 *     PS_OBS_SHIP_BATCH. Summaries never pass through the 256-slot
 *     drop-oldest queue, so a burst of summaries cannot push anything out.
 *     The part of a summary batch that was not handled is re-staged at the
 *     front of the dedupe staging list (ps_obs_dedupe_restage) as a frozen
 *     byte copy, in order.
 *
 * `ship` returns 0 when all n items were handled, and non-zero when the
 * items from *done on must be retried; *done (0 on entry) is the number of
 * leading items that were handled before the failure. "Handled" means
 * delivered with a 2xx (central's per-envelope verdict in that answer is
 * final: accepted items are never re-sent, rejected ones are not retried) or
 * refused for good (a 4xx other than 408/429 is poison and dropped). Retried:
 * transport failure, 5xx, 408, 429. Non-zero stops the cycle at once, so at
 * most one failed POST is made per cycle and the checkin interval is the
 * retry interval. Retried items are re-sent as the same bytes, hence the same
 * deterministic envelope signatures, and central dedups on the signature, so
 * a retry is safe even for anything central stored before failing. */

#include <stdint.h>
#include "obs_queue.h"

#define PS_OBS_SHIP_BATCH        50   /* items per ship call */
#define PS_OBS_SHIP_MAX_BATCHES  16   /* raw queue: up to 800 items per cycle */

typedef int (*ps_obs_ship_fn)(const char **items, int n, void *user, int *done);

struct ps_obs_ship_counts {
    int raw;         /* queue items handed to ship */
    int summaries;   /* dedupe summaries handed to ship */
    int stopped;     /* 1 when ship asked to stop */
    int restaged;    /* summaries put back after a failed ship */
    int kept;        /* queue items left in the queue after a failed ship */
};

/* Returns 0, or -1 when ship stopped the cycle. Serialised internally. */
int ps_obs_ship_cycle(int64_t now_ms, int force, ps_obs_ship_fn ship, void *user,
                      struct ps_obs_ship_counts *out);

#endif /* PS_OBS_SHIP_H */
