#include "../workers/limiter.h"
#include <assert.h>
#include <stdio.h>
#include <time.h>

static long now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void test_rate_zero_means_unlimited(void) {
    struct ps_limiter L;
    ps_limiter_init(&L, 0);
    long t0 = now_ms();
    for (int i = 0; i < 1000; i++) ps_limiter_acquire(&L);
    long dt = now_ms() - t0;
    assert(dt < 100);
    ps_limiter_destroy(&L);
}

static void test_rate_limits(void) {
    struct ps_limiter L;
    ps_limiter_init(&L, 100);
    long t0 = now_ms();
    for (int i = 0; i < 150; i++) ps_limiter_acquire(&L);
    long dt = now_ms() - t0;
    assert(dt >= 300);
    assert(dt < 1500);
    ps_limiter_destroy(&L);
}

int main(void) {
    test_rate_zero_means_unlimited();
    test_rate_limits();
    printf("test_limiter: OK\n");
    return 0;
}
