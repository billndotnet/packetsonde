#ifndef PS_WORKERS_H
#define PS_WORKERS_H

#include "limiter.h"

#include <pthread.h>
#include <stdatomic.h>

typedef void (*ps_work_fn)(void *ctx);

#define PS_WORK_QUEUE_CAP 4096

struct ps_work_item {
    ps_work_fn  fn;
    void       *ctx;
};

struct ps_workers {
    int                 nthreads;
    pthread_t          *threads;

    struct ps_work_item queue[PS_WORK_QUEUE_CAP];
    int                 q_head;
    int                 q_tail;
    int                 q_count;
    int                 closed;

    pthread_mutex_t     lock;
    pthread_cond_t      not_empty;
    pthread_cond_t      not_full;

    struct ps_limiter  *limiter;
    atomic_int          cancel;
};

void ps_workers_init     (struct ps_workers *W, int nthreads, struct ps_limiter *limiter);
void ps_workers_submit   (struct ps_workers *W, ps_work_fn fn, void *ctx);
void ps_workers_finish   (struct ps_workers *W);
void ps_workers_cancel   (struct ps_workers *W);
int  ps_workers_cancelled(const struct ps_workers *W);
void ps_workers_destroy  (struct ps_workers *W);

#endif
