#include "obs_ship.h"
#include "obs_dedupe.h"

#include <pthread.h>
#include <string.h>

/* one failed batch must always fit back into the staging list */
_Static_assert(PS_DEDUPE_RESTAGE_MAX >= PS_OBS_SHIP_BATCH, "restage room");

static pthread_mutex_t g_cycle_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_items[PS_OBS_SHIP_BATCH][PS_OBS_ITEM_MAX];   /* under g_cycle_lock */

/* Calls ship; returns the number of leading items handled (0..n) and sets
 * *stop when the cycle must stop. */
static int ship_batch(ps_obs_ship_fn ship, void *user, const char **jsons, int n,
                      int *stop) {
    int done = 0;
    *stop = 0;
    if (ship(jsons, n, user, &done) == 0) return n;
    *stop = 1;
    return done < 0 ? 0 : done > n ? n : done;
}

int ps_obs_ship_cycle(int64_t now_ms, int force, ps_obs_ship_fn ship, void *user,
                      struct ps_obs_ship_counts *out) {
    struct ps_obs_ship_counts c = { 0, 0, 0, 0, 0 };
    const char *jsons[PS_OBS_SHIP_BATCH];
    int rc = 0;
    if (!ship) return -1;
    pthread_mutex_lock(&g_cycle_lock);

    for (int b = 0; b < PS_OBS_SHIP_MAX_BATCHES; b++) {
        uint64_t first = 0;
        int n = ps_obs_queue_peek(g_items, PS_OBS_SHIP_BATCH, &first);
        if (n <= 0) break;
        for (int i = 0; i < n; i++) jsons[i] = g_items[i];
        c.raw += n;
        int stop;
        int done = ship_batch(ship, user, jsons, n, &stop);
        /* only what central handled leaves the queue; the rest stays at
         * the head, in order (unless drop-oldest has pushed it out) */
        ps_obs_queue_pop(first, done);
        if (stop) { c.kept = n - done; rc = -1; goto done; }
    }
    for (;;) {
        int n = ps_obs_dedupe_flush(now_ms, force, g_items, PS_OBS_SHIP_BATCH);
        if (n <= 0) break;
        for (int i = 0; i < n; i++) jsons[i] = g_items[i];
        c.summaries += n;
        int stop;
        int done = ship_batch(ship, user, jsons, n, &stop);
        if (stop) {
            /* not (fully) delivered: the rest of the batch, byte for byte,
             * goes back to the front of the staging list */
            if (done < n) c.restaged = ps_obs_dedupe_restage(jsons + done, n - done);
            rc = -1;
            goto done;
        }
    }
done:
    c.stopped = rc != 0;
    pthread_mutex_unlock(&g_cycle_lock);
    if (out) *out = c;
    return rc;
}
