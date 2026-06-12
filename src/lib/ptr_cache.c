#include "ptr_cache.h"

#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PTR_MAX 256

/* macOS lacks pthread_condattr_setclock; its condvars wait on CLOCK_REALTIME.
   Use a monotonic condvar clock where supported (robust against wall-clock
   jumps), falling back to realtime on Apple. The deadline clock in
   ps_ptr_cache_wait() must match whatever the condvar actually uses. */
#if defined(__APPLE__)
#define PS_PTR_COND_CLOCK CLOCK_REALTIME
#else
#define PS_PTR_COND_CLOCK CLOCK_MONOTONIC
#endif

struct ptr_entry {
    char ip[64];
    char name[256];   /* "" == resolved-negative */
    int  state;       /* 0 empty, 1 pending, 2 resolved */
};

struct ps_ptr_cache {
    struct ptr_entry e[PTR_MAX];
    int              n;
    ps_ptr_resolver_fn resolver;
    pthread_mutex_t  mu;
    pthread_cond_t   cv;       /* signalled when any entry resolves */
    pthread_t        worker;
    int              shutdown;
    int              pending;  /* count of state==1 needing work */
};

/* IPv4-only, matching the traceroute core (resolve_v4 / sockaddr_in). */
static int real_resolver(const char *ip, char *name, size_t cap) {
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) return -1;
    char host[256];
    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                    host, sizeof(host), NULL, 0, NI_NAMEREQD) != 0) return -1;
    snprintf(name, cap, "%s", host);
    return 0;
}

/* Find entry index for ip, or -1. Caller holds mu. */
static int find(struct ps_ptr_cache *c, const char *ip) {
    for (int i = 0; i < c->n; i++)
        if (strcmp(c->e[i].ip, ip) == 0) return i;
    return -1;
}

static void *worker_main(void *arg) {
    struct ps_ptr_cache *c = arg;
    pthread_mutex_lock(&c->mu);
    for (;;) {
        while (!c->shutdown && c->pending == 0)
            pthread_cond_wait(&c->cv, &c->mu);
        if (c->shutdown) break;
        /* Find a pending entry, resolve it without holding the lock. */
        int idx = -1;
        for (int i = 0; i < c->n; i++) if (c->e[i].state == 1) { idx = i; break; }
        if (idx < 0) { if (c->pending > 0) c->pending--; continue; }  /* defensive: pending>0 implies a state==1 entry */
        char ip[64]; snprintf(ip, sizeof(ip), "%s", c->e[idx].ip);
        pthread_mutex_unlock(&c->mu);

        char name[256] = "";
        int rc = c->resolver(ip, name, sizeof(name));

        pthread_mutex_lock(&c->mu);
        snprintf(c->e[idx].name, sizeof(c->e[idx].name), "%s", rc == 0 ? name : "");
        c->e[idx].state = 2;
        if (c->pending > 0) c->pending--;
        pthread_cond_broadcast(&c->cv);
    }
    pthread_mutex_unlock(&c->mu);
    return NULL;
}

static struct ps_ptr_cache *new_with(ps_ptr_resolver_fn r) {
    struct ps_ptr_cache *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->resolver = r;
    pthread_mutex_init(&c->mu, NULL);
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
#if !defined(__APPLE__)
    pthread_condattr_setclock(&ca, PS_PTR_COND_CLOCK);
#endif
    pthread_cond_init(&c->cv, &ca);
    pthread_condattr_destroy(&ca);
    if (pthread_create(&c->worker, NULL, worker_main, c) != 0) {
        pthread_mutex_destroy(&c->mu); pthread_cond_destroy(&c->cv);
        free(c); return NULL;
    }
    return c;
}
struct ps_ptr_cache *ps_ptr_cache_new(void)    { return new_with(real_resolver); }
struct ps_ptr_cache *ps_ptr_cache_new_ex(ps_ptr_resolver_fn r) { return new_with(r); }

void ps_ptr_cache_free(struct ps_ptr_cache *c) {
    if (!c) return;
    pthread_mutex_lock(&c->mu);
    c->shutdown = 1;
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->mu);
    pthread_join(c->worker, NULL);
    pthread_mutex_destroy(&c->mu);
    pthread_cond_destroy(&c->cv);
    free(c);
}

/* Ensure an entry exists + is scheduled. Caller holds mu. Returns index or -1. */
static int ensure(struct ps_ptr_cache *c, const char *ip) {
    int i = find(c, ip);
    if (i >= 0) return i;
    if (c->n >= PTR_MAX) return -1;
    i = c->n++;
    snprintf(c->e[i].ip, sizeof(c->e[i].ip), "%s", ip);
    c->e[i].name[0] = '\0';
    c->e[i].state = 1;       /* pending */
    c->pending++;
    pthread_cond_broadcast(&c->cv);
    return i;
}

int ps_ptr_cache_lookup(struct ps_ptr_cache *c, const char *ip,
                        char *name, size_t cap) {
    pthread_mutex_lock(&c->mu);
    int i = find(c, ip);
    if (i >= 0 && c->e[i].state == 2) {
        snprintf(name, cap, "%s", c->e[i].name);
        pthread_mutex_unlock(&c->mu);
        return 1;
    }
    ensure(c, ip);
    pthread_mutex_unlock(&c->mu);
    return 0;
}

int ps_ptr_cache_wait(struct ps_ptr_cache *c, const char *ip,
                      int timeout_ms, char *name, size_t cap) {
    if (timeout_ms <= 0) return ps_ptr_cache_lookup(c, ip, name, cap);

    struct timespec deadline;
    clock_gettime(PS_PTR_COND_CLOCK, &deadline);
    deadline.tv_sec  += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000L; }

    pthread_mutex_lock(&c->mu);
    int i = ensure(c, ip);
    if (i < 0) { pthread_mutex_unlock(&c->mu); return 0; }
    while (c->e[i].state != 2) {
        if (pthread_cond_timedwait(&c->cv, &c->mu, &deadline) != 0 &&
            c->e[i].state != 2) {
            pthread_mutex_unlock(&c->mu);
            return 0;   /* timed out */
        }
    }
    snprintf(name, cap, "%s", c->e[i].name);
    pthread_mutex_unlock(&c->mu);
    return 1;
}
