#include "activity_ring.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    ps_act_ring_init();
    assert(ps_act_ring_count() == 0);
    ps_act_ring_push("{\"v\":1,\"n\":1}", 12);
    ps_act_ring_push("{\"v\":1,\"n\":2}", 12);
    assert(ps_act_ring_count() == 2);

    char items[8][PS_ACT_ITEM_MAX];
    int n = ps_act_ring_drain(items, 8);
    assert(n == 2);
    assert(strstr(items[0], "\"n\":1"));
    assert(ps_act_ring_count() == 0);

    /* overflow drops oldest */
    for (int i = 0; i < PS_ACT_RING_CAP + 5; i++) ps_act_ring_push("{\"x\":1}", 7);
    assert(ps_act_ring_count() == PS_ACT_RING_CAP);
    printf("test_activity_ring: OK\n");
    return 0;
}
