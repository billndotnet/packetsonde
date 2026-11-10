#ifndef PS_OBS_SHIP_H
#define PS_OBS_SHIP_H

/* One shipping cycle for passive observations, independent of transport so
 * it can be tested without central.
 *
 *  1. Drain the observation queue (first sightings and other raw events) in
 *     batches of PS_OBS_SHIP_BATCH, at most PS_OBS_SHIP_MAX_BATCHES batches.
 *  2. Ship the dedupe summaries (staged ones, then ended windows; every open
 *     window with `force`) straight from ps_obs_dedupe_flush in batches of
 *     PS_OBS_SHIP_BATCH. Summaries never pass through the 256-slot
 *     drop-oldest queue, so a burst of summaries cannot push anything out.
 *
 * `ship` returns 0 when the batch was handed to central (individual items
 * may still be rejected), and otherwise stops the cycle at once, so further
 * queued items and every summary not yet flushed wait for the next cycle:
 *   -2  NOTHING of the batch was delivered (central unreachable on the
 *       first POST, or every POST refused): a summary batch is re-staged in
 *       dedupe (ps_obs_dedupe_restage) and shipped again next cycle;
 *   -1  delivery unknown or partial: not re-sent, so central never counts a
 *       summary twice; like a queued raw item it is lost.
 * Raw queue items in a failed batch are not retried (as before). */

#include <stdint.h>
#include "obs_queue.h"

#define PS_OBS_SHIP_BATCH        50   /* items per ship call */
#define PS_OBS_SHIP_MAX_BATCHES  16   /* raw queue: up to 800 items per cycle */

typedef int (*ps_obs_ship_fn)(const char **items, int n, void *user);

struct ps_obs_ship_counts {
    int raw;         /* queue items handed to ship */
    int summaries;   /* dedupe summaries handed to ship */
    int stopped;     /* 1 when ship asked to stop */
    int restaged;    /* summaries put back after a -2 */
};

/* Returns 0, or -1 when ship stopped the cycle. Serialised internally. */
int ps_obs_ship_cycle(int64_t now_ms, int force, ps_obs_ship_fn ship, void *user,
                      struct ps_obs_ship_counts *out);

#endif /* PS_OBS_SHIP_H */
