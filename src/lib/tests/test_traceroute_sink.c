#include "traceroute_internal.h"
#include <stdio.h>
#include <string.h>

#define CHECK(c) do{ if(!(c)){ fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c); return 1; } }while(0)

/* Recording callback: stores each hop's ttl + whether it had an address. */
struct rec { int ttls[64]; int live[64]; int n; int stop_after; };
static int rec_cb(const struct ps_tr_hop *h, void *u) {
    struct rec *r = u;
    r->ttls[r->n] = h->ttl;
    r->live[r->n] = h->addr[0] ? 1 : 0;
    r->n++;
    return (r->stop_after && r->n >= r->stop_after) ? 1 : 0;
}

static struct ps_tr_hop live_hop(int ttl) {
    struct ps_tr_hop h; memset(&h, 0, sizeof(h));
    h.ttl = ttl; snprintf(h.addr, sizeof(h.addr), "10.0.0.%d", ttl);
    h.rtt_us = 1000; h.reached_dst = 0; return h;
}
static struct ps_tr_hop dead_hop(int ttl) {
    struct ps_tr_hop h; memset(&h, 0, sizeof(h));
    h.ttl = ttl; h.addr[0] = '\0'; return h;
}
static struct ps_tr_hop dst_hop(int ttl) {
    struct ps_tr_hop h = live_hop(ttl); h.reached_dst = 1; return h;
}

int main(void) {
    /* 1. Destination reached -> stop on that hop. */
    {
        struct rec r = {0}; struct ps_tr_sink s;
        ps_tr_sink_init(&s, rec_cb, &r, 5);
        CHECK(ps_tr_sink_emit(&s, &(struct ps_tr_hop){.ttl=1, .addr="a"}) == 0);
        struct ps_tr_hop d = dst_hop(2);
        CHECK(ps_tr_sink_emit(&s, &d) == 1);   /* reached -> stop */
        CHECK(r.n == 2);
    }
    /* 2. Gap of 5 dead hops AFTER a live hop -> stop on the 5th dead. */
    {
        struct rec r = {0}; struct ps_tr_sink s;
        ps_tr_sink_init(&s, rec_cb, &r, 5);
        struct ps_tr_hop l = live_hop(1);
        CHECK(ps_tr_sink_emit(&s, &l) == 0);
        int stopped = 0;
        for (int t = 2; t <= 6; t++) {
            struct ps_tr_hop d = dead_hop(t);
            if (ps_tr_sink_emit(&s, &d)) { stopped = 1; CHECK(t == 6); break; }
        }
        CHECK(stopped);
        CHECK(r.n == 6);   /* 1 live + 5 dead */
    }
    /* 3. Whole path dark (no live hop ever) -> never gap-stops. */
    {
        struct rec r = {0}; struct ps_tr_sink s;
        ps_tr_sink_init(&s, rec_cb, &r, 5);
        for (int t = 1; t <= 10; t++) {
            struct ps_tr_hop d = dead_hop(t);
            CHECK(ps_tr_sink_emit(&s, &d) == 0);   /* never stops */
        }
        CHECK(r.n == 10);
    }
    /* 4. A live hop resets the dead run (gap counts CONSECUTIVE only). */
    {
        struct rec r = {0}; struct ps_tr_sink s;
        ps_tr_sink_init(&s, rec_cb, &r, 3);
        struct ps_tr_hop l1 = live_hop(1); ps_tr_sink_emit(&s, &l1);
        struct ps_tr_hop d2 = dead_hop(2); ps_tr_sink_emit(&s, &d2);
        struct ps_tr_hop d3 = dead_hop(3); ps_tr_sink_emit(&s, &d3);
        struct ps_tr_hop l4 = live_hop(4);
        CHECK(ps_tr_sink_emit(&s, &l4) == 0);  /* reset */
        struct ps_tr_hop d5 = dead_hop(5); CHECK(ps_tr_sink_emit(&s, &d5) == 0);
        struct ps_tr_hop d6 = dead_hop(6); CHECK(ps_tr_sink_emit(&s, &d6) == 0);
        struct ps_tr_hop d7 = dead_hop(7); CHECK(ps_tr_sink_emit(&s, &d7) == 1); /* 3rd consec */
    }
    /* 5. Consumer stop (cb returns non-zero) is honored immediately. */
    {
        struct rec r = {0}; r.stop_after = 2; struct ps_tr_sink s;
        ps_tr_sink_init(&s, rec_cb, &r, 0);
        struct ps_tr_hop a = live_hop(1); CHECK(ps_tr_sink_emit(&s, &a) == 0);
        struct ps_tr_hop b = live_hop(2); CHECK(ps_tr_sink_emit(&s, &b) == 1);
    }
    printf("ok\n");
    return 0;
}
