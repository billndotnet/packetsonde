#include "obs_queue.h"
#include <assert.h>
#include <stdint.h>
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

    assert(ps_obs_queue_dropped() == 2);

    /* --- peek / pop: nothing leaves the queue until it is popped --- */
    ps_obs_queue_init();
    assert(ps_obs_queue_dropped() == 0);
    for (int i = 0; i < 5; i++) {
        snprintf(tmp, sizeof(tmp), "%d", i);
        ps_obs_queue_push(tmp, strlen(tmp));
    }
    uint64_t first = 99;
    got = ps_obs_queue_peek(items, 3, &first);
    assert(got == 3 && first == 0);
    assert(strcmp(items[0], "0") == 0 && strcmp(items[2], "2") == 0);
    assert(ps_obs_queue_count() == 5);
    got = ps_obs_queue_peek(items, 8, &first);           /* same head again */
    assert(got == 5 && first == 0 && strcmp(items[0], "0") == 0);
    assert(ps_obs_queue_pop(first, 2) == 2);             /* "0","1" delivered */
    assert(ps_obs_queue_count() == 3);
    got = ps_obs_queue_peek(items, 8, &first);
    assert(got == 3 && first == 2 && strcmp(items[0], "2") == 0);
    assert(ps_obs_queue_pop(first, 0) == 0);             /* nothing delivered */
    assert(ps_obs_queue_count() == 3);

    /* drop-oldest between peek and pop: only the peeked items that are still
     * queued are removed, never one pushed after the peek */
    ps_obs_queue_init();
    for (int i = 0; i < PS_OBS_QUEUE_CAP; i++) {
        snprintf(tmp, sizeof(tmp), "%d", i);
        ps_obs_queue_push(tmp, strlen(tmp));
    }
    got = ps_obs_queue_peek(items, 8, &first);
    assert(got == 8 && first == 0);
    for (int i = PS_OBS_QUEUE_CAP; i < PS_OBS_QUEUE_CAP + 3; i++) {   /* drops 0,1,2 */
        snprintf(tmp, sizeof(tmp), "%d", i);
        ps_obs_queue_push(tmp, strlen(tmp));
    }
    assert(ps_obs_queue_dropped() == 3);
    assert(ps_obs_queue_pop(first, 8) == 5);             /* 3..7 */
    assert(ps_obs_queue_count() == PS_OBS_QUEUE_CAP - 5);
    got = ps_obs_queue_peek(items, 1, &first);
    assert(got == 1 && first == 8 && strcmp(items[0], "8") == 0);
    /* every peeked item already dropped: pop removes nothing */
    ps_obs_queue_init();
    for (int i = 0; i < PS_OBS_QUEUE_CAP; i++) ps_obs_queue_push("x", 1);
    got = ps_obs_queue_peek(items, 2, &first);
    for (int i = 0; i < 2; i++) ps_obs_queue_push("y", 1);
    assert(ps_obs_queue_pop(first, 2) == 0);
    assert(ps_obs_queue_count() == PS_OBS_QUEUE_CAP);

    printf("test_obs_queue: OK\n");
    return 0;
}
