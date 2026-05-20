#include "../workers/workers.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static atomic_int g_done = 0;

static void work_inc(void *ctx) {
    (void)ctx;
    atomic_fetch_add(&g_done, 1);
}

static void test_basic(void) {
    g_done = 0;
    struct ps_workers W;
    ps_workers_init(&W, 4, NULL);
    for (int i = 0; i < 100; i++) ps_workers_submit(&W, work_inc, NULL);
    ps_workers_finish(&W);
    assert(atomic_load(&g_done) == 100);
    ps_workers_destroy(&W);
}

static atomic_int g_cancelled = 0;
static void work_slow(void *ctx) {
    struct ps_workers *W = (struct ps_workers *)ctx;
    if (ps_workers_cancelled(W)) {
        atomic_fetch_add(&g_cancelled, 1);
        return;
    }
    struct timespec t = { 0, 1000000 };
    nanosleep(&t, NULL);
    atomic_fetch_add(&g_done, 1);
}

static void test_cancel_drains(void) {
    g_done = 0; g_cancelled = 0;
    struct ps_workers W;
    ps_workers_init(&W, 2, NULL);
    for (int i = 0; i < 200; i++) ps_workers_submit(&W, work_slow, &W);
    ps_workers_cancel(&W);
    ps_workers_finish(&W);
    int total = atomic_load(&g_done) + atomic_load(&g_cancelled);
    assert(total == 200);
    ps_workers_destroy(&W);
}

int main(void) {
    test_basic();
    test_cancel_drains();
    printf("test_workers: OK\n");
    return 0;
}
