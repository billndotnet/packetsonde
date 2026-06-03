#include "activity_ring.h"
#include <string.h>
#include <pthread.h>

static char        g_buf[PS_ACT_RING_CAP][PS_ACT_ITEM_MAX];
static int         g_len[PS_ACT_RING_CAP];
static int         g_head, g_count;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

void ps_act_ring_init(void) {
    pthread_mutex_lock(&g_mu);
    g_head = 0; g_count = 0;
    pthread_mutex_unlock(&g_mu);
}

void ps_act_ring_push(const char *json, size_t len) {
    if (!json || len == 0 || len >= PS_ACT_ITEM_MAX) return;
    pthread_mutex_lock(&g_mu);
    int tail = (g_head + g_count) % PS_ACT_RING_CAP;
    if (g_count == PS_ACT_RING_CAP) {       /* full: drop oldest */
        g_head = (g_head + 1) % PS_ACT_RING_CAP;
        tail = (g_head + g_count - 1) % PS_ACT_RING_CAP;
    } else {
        g_count++;
    }
    memcpy(g_buf[tail], json, len);
    g_buf[tail][len] = 0;
    g_len[tail] = (int)len;
    pthread_mutex_unlock(&g_mu);
}

int ps_act_ring_drain(char out_items[][PS_ACT_ITEM_MAX], int max) {
    pthread_mutex_lock(&g_mu);
    int n = 0;
    while (n < max && g_count > 0) {
        memcpy(out_items[n], g_buf[g_head], (size_t)g_len[g_head] + 1);
        g_head = (g_head + 1) % PS_ACT_RING_CAP;
        g_count--; n++;
    }
    pthread_mutex_unlock(&g_mu);
    return n;
}

int ps_act_ring_count(void) {
    pthread_mutex_lock(&g_mu);
    int c = g_count;
    pthread_mutex_unlock(&g_mu);
    return c;
}
