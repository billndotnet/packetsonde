#include "obs_ship.h"
#include "obs_dedupe.h"

#include <pthread.h>
#include <string.h>

static pthread_mutex_t g_cycle_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_items[PS_OBS_SHIP_BATCH][PS_OBS_ITEM_MAX];   /* under g_cycle_lock */

int ps_obs_ship_cycle(int64_t now_ms, int force, ps_obs_ship_fn ship, void *user,
                      struct ps_obs_ship_counts *out) {
    struct ps_obs_ship_counts c = { 0, 0, 0, 0 };
    const char *jsons[PS_OBS_SHIP_BATCH];
    int rc = 0;
    if (!ship) return -1;
    pthread_mutex_lock(&g_cycle_lock);

    for (int b = 0; b < PS_OBS_SHIP_MAX_BATCHES; b++) {
        int n = ps_obs_queue_drain(g_items, PS_OBS_SHIP_BATCH);
        if (n <= 0) break;
        for (int i = 0; i < n; i++) jsons[i] = g_items[i];
        c.raw += n;
        if (ship(jsons, n, user) != 0) { rc = -1; goto done; }
    }
    for (;;) {
        int n = ps_obs_dedupe_flush(now_ms, force, g_items, PS_OBS_SHIP_BATCH);
        if (n <= 0) break;
        for (int i = 0; i < n; i++) jsons[i] = g_items[i];
        c.summaries += n;
        int r = ship(jsons, n, user);
        if (r != 0) {
            if (r == -2) c.restaged = ps_obs_dedupe_restage(jsons, n);
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
