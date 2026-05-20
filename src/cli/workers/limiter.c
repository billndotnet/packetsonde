#include "limiter.h"

#include <errno.h>
#include <string.h>
#include <time.h>

static long now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000000L + t.tv_nsec / 1000;
}

void ps_limiter_init(struct ps_limiter *L, int rate_pps) {
    memset(L, 0, sizeof(*L));
    L->rate_pps       = rate_pps;
    L->capacity       = rate_pps > 0 ? (double)rate_pps : 0;
    L->tokens         = L->capacity;
    L->last_refill_us = now_us();
    pthread_mutex_init(&L->lock, NULL);
}

void ps_limiter_destroy(struct ps_limiter *L) {
    pthread_mutex_destroy(&L->lock);
}

void ps_limiter_acquire(struct ps_limiter *L) {
    if (L->rate_pps <= 0) return;
    for (;;) {
        long sleep_us = 0;
        pthread_mutex_lock(&L->lock);
        long n = now_us();
        double dt = (n - L->last_refill_us) / 1.0e6;
        L->tokens += dt * L->rate_pps;
        if (L->tokens > L->capacity) L->tokens = L->capacity;
        L->last_refill_us = n;
        if (L->tokens >= 1.0) {
            L->tokens -= 1.0;
            pthread_mutex_unlock(&L->lock);
            return;
        }
        double need = 1.0 - L->tokens;
        sleep_us = (long)((need / L->rate_pps) * 1.0e6) + 250;
        pthread_mutex_unlock(&L->lock);
        struct timespec req = { sleep_us / 1000000, (sleep_us % 1000000) * 1000 };
        while (nanosleep(&req, &req) == -1 && errno == EINTR) {}
    }
}
