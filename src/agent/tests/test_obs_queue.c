#include "obs_queue.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    /* --- ps_obs_build_event (pure) --- */
    char ev[PS_OBS_ITEM_MAX];
    const char *obs = "{\"mac\":\"aa:bb:cc:dd:ee:ff\"}";
    size_t n = ps_obs_build_event(ev, sizeof(ev), "discovery.neighbor",
                                  "2026-05-23T08:00:00Z", obs, strlen(obs));
    assert(n > 0);
    assert(strcmp(ev,
        "{\"kind\":\"discovery.neighbor\",\"ts\":\"2026-05-23T08:00:00Z\","
        "\"observation\":{\"mac\":\"aa:bb:cc:dd:ee:ff\"}}") == 0);

    /* overflow returns 0 */
    assert(ps_obs_build_event(ev, 10, "k", "t", obs, strlen(obs)) == 0);

    /* --- queue push/drain --- */
    ps_obs_queue_init();
    assert(ps_obs_queue_count() == 0);
    ps_obs_queue_push("A", 1);
    ps_obs_queue_push("BB", 2);
    assert(ps_obs_queue_count() == 2);

    char items[8][PS_OBS_ITEM_MAX];
    int got = ps_obs_queue_drain(items, 8);
    assert(got == 2);
    assert(strcmp(items[0], "A") == 0);
    assert(strcmp(items[1], "BB") == 0);
    assert(ps_obs_queue_count() == 0);

    /* drop-oldest on overflow: push CAP+2, oldest two dropped */
    ps_obs_queue_init();
    char tmp[16];
    for (int i = 0; i < PS_OBS_QUEUE_CAP + 2; i++) {
        snprintf(tmp, sizeof(tmp), "%d", i);
        ps_obs_queue_push(tmp, strlen(tmp));
    }
    assert(ps_obs_queue_count() == PS_OBS_QUEUE_CAP);
    got = ps_obs_queue_drain(items, 8);   /* first 8 of the retained window */
    assert(got == 8);
    assert(strcmp(items[0], "2") == 0);   /* "0" and "1" were dropped */

    printf("test_obs_queue: OK\n");
    return 0;
}
