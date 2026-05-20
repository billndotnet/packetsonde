#include "workers.h"

#include <stdlib.h>
#include <string.h>

static void *worker_main(void *arg) {
    struct ps_workers *W = (struct ps_workers *)arg;
    for (;;) {
        struct ps_work_item it;

        pthread_mutex_lock(&W->lock);
        while (W->q_count == 0 && !W->closed) {
            pthread_cond_wait(&W->not_empty, &W->lock);
        }
        if (W->q_count == 0 && W->closed) {
            pthread_mutex_unlock(&W->lock);
            break;
        }
        it = W->queue[W->q_head];
        W->q_head = (W->q_head + 1) % PS_WORK_QUEUE_CAP;
        W->q_count--;
        pthread_cond_signal(&W->not_full);
        pthread_mutex_unlock(&W->lock);

        if (!atomic_load(&W->cancel) && W->limiter) {
            ps_limiter_acquire(W->limiter);
        }
        it.fn(it.ctx);
    }
    return NULL;
}

void ps_workers_init(struct ps_workers *W, int nthreads, struct ps_limiter *limiter) {
    memset(W, 0, sizeof(*W));
    if (nthreads <= 0) nthreads = 1;
    W->nthreads = nthreads;
    W->limiter  = limiter;
    atomic_init(&W->cancel, 0);
    pthread_mutex_init(&W->lock, NULL);
    pthread_cond_init(&W->not_empty, NULL);
    pthread_cond_init(&W->not_full,  NULL);
    W->threads = calloc(nthreads, sizeof(pthread_t));
    for (int i = 0; i < nthreads; i++) {
        pthread_create(&W->threads[i], NULL, worker_main, W);
    }
}

void ps_workers_submit(struct ps_workers *W, ps_work_fn fn, void *ctx) {
    pthread_mutex_lock(&W->lock);
    while (W->q_count == PS_WORK_QUEUE_CAP && !W->closed) {
        pthread_cond_wait(&W->not_full, &W->lock);
    }
    if (W->closed) { pthread_mutex_unlock(&W->lock); return; }
    W->queue[W->q_tail].fn  = fn;
    W->queue[W->q_tail].ctx = ctx;
    W->q_tail = (W->q_tail + 1) % PS_WORK_QUEUE_CAP;
    W->q_count++;
    pthread_cond_signal(&W->not_empty);
    pthread_mutex_unlock(&W->lock);
}

void ps_workers_finish(struct ps_workers *W) {
    pthread_mutex_lock(&W->lock);
    W->closed = 1;
    pthread_cond_broadcast(&W->not_empty);
    pthread_cond_broadcast(&W->not_full);
    pthread_mutex_unlock(&W->lock);
    for (int i = 0; i < W->nthreads; i++) {
        pthread_join(W->threads[i], NULL);
    }
}

void ps_workers_cancel(struct ps_workers *W) {
    atomic_store(&W->cancel, 1);
}

int ps_workers_cancelled(const struct ps_workers *W) {
    return atomic_load((atomic_int *)&W->cancel);
}

void ps_workers_destroy(struct ps_workers *W) {
    free(W->threads);
    pthread_mutex_destroy(&W->lock);
    pthread_cond_destroy(&W->not_empty);
    pthread_cond_destroy(&W->not_full);
}
