#include "activity_ring.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    ps_act_ring_init();
    int a = ps_act_ring_register(); assert(a >= 0);
    int b = ps_act_ring_register(); assert(b >= 0 && b != a);
    assert(ps_act_ring_count(a) == 0);

    ps_act_ring_push("{\"n\":1}", 7);
    ps_act_ring_push("{\"n\":2}", 7);
    /* both consumers see both records */
    assert(ps_act_ring_count(a) == 2 && ps_act_ring_count(b) == 2);

    char items[8][PS_ACT_ITEM_MAX];
    int na = ps_act_ring_drain(a, items, 8);
    assert(na == 2 && strstr(items[0], "\"n\":1"));
    assert(ps_act_ring_count(a) == 0 && ps_act_ring_count(b) == 2);   /* draining a doesn't affect b */
    int nb = ps_act_ring_drain(b, items, 8);
    assert(nb == 2);

    /* overflow per consumer */
    for (int i = 0; i < PS_ACT_RING_CAP + 5; i++) ps_act_ring_push("{\"x\":1}", 7);
    assert(ps_act_ring_count(a) == PS_ACT_RING_CAP);
    printf("test_activity_ring: OK\n");
    return 0;
}
