#ifndef PS_LIMITER_H
#define PS_LIMITER_H

#include <pthread.h>
#include <stdint.h>

struct ps_limiter {
    int             rate_pps;
    double          tokens;
    double          capacity;
    long            last_refill_us;
    pthread_mutex_t lock;
};

void ps_limiter_init   (struct ps_limiter *L, int rate_pps);
void ps_limiter_destroy(struct ps_limiter *L);
void ps_limiter_acquire(struct ps_limiter *L);

#endif
