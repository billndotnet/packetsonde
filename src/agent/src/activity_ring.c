#include "activity_ring.h"
#include <string.h>
#include <pthread.h>

struct subring {
    char buf[PS_ACT_RING_CAP][PS_ACT_ITEM_MAX];
    int  len[PS_ACT_RING_CAP];
    int  head, count;
};
static struct subring g_sub[PS_ACT_MAX_CONSUMERS];
static int g_n;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

void ps_act_ring_init(void) {
    pthread_mutex_lock(&g_mu);
    g_n = 0;
    memset(g_sub, 0, sizeof g_sub);
    pthread_mutex_unlock(&g_mu);
}

int ps_act_ring_register(void) {
    pthread_mutex_lock(&g_mu);
    int id = (g_n < PS_ACT_MAX_CONSUMERS) ? g_n++ : -1;
    pthread_mutex_unlock(&g_mu);
    return id;
}

static void sub_push(struct subring *s, const char *json, size_t len) {
    int tail = (s->head + s->count) % PS_ACT_RING_CAP;
    if (s->count == PS_ACT_RING_CAP) {        /* full: drop oldest */
        s->head = (s->head + 1) % PS_ACT_RING_CAP;
        tail = (s->head + s->count - 1) % PS_ACT_RING_CAP;
    } else {
        s->count++;
    }
    memcpy(s->buf[tail], json, len);
    s->buf[tail][len] = 0;
    s->len[tail] = (int)len;
}

void ps_act_ring_push(const char *json, size_t len) {
    if (!json || len == 0 || len >= PS_ACT_ITEM_MAX) return;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_n; i++) sub_push(&g_sub[i], json, len);
    pthread_mutex_unlock(&g_mu);
}

int ps_act_ring_drain(int consumer, char out_items[][PS_ACT_ITEM_MAX], int max) {
    if (consumer < 0 || consumer >= PS_ACT_MAX_CONSUMERS) return 0;
    pthread_mutex_lock(&g_mu);
    struct subring *s = &g_sub[consumer];
    int n = 0;
    while (n < max && s->count > 0) {
        memcpy(out_items[n], s->buf[s->head], (size_t)s->len[s->head] + 1);
        s->head = (s->head + 1) % PS_ACT_RING_CAP;
        s->count--; n++;
    }
    pthread_mutex_unlock(&g_mu);
    return n;
}

int ps_act_ring_count(int consumer) {
    if (consumer < 0 || consumer >= PS_ACT_MAX_CONSUMERS) return 0;
    pthread_mutex_lock(&g_mu);
    int c = g_sub[consumer].count;
    pthread_mutex_unlock(&g_mu);
    return c;
}
