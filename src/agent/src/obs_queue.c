#include "obs_queue.h"

#include <string.h>
#include <stdio.h>
#include <pthread.h>

struct obs_item {
    char   data[PS_OBS_ITEM_MAX];
    size_t len;
};

static struct obs_item  g_ring[PS_OBS_QUEUE_CAP];
static int              g_head;   /* next pop */
static int              g_tail;   /* next push */
static int              g_count;
static pthread_mutex_t  g_lock = PTHREAD_MUTEX_INITIALIZER;

/* JSON-escape is NOT applied to `channel`/`ts_iso` — both are controlled,
 * simple tokens (channel names + ISO timestamps). `observation_json` is spliced
 * raw (it is already valid JSON produced by ps_json). */
size_t ps_obs_build_event(char *out, size_t cap,
                          const char *channel, const char *ts_iso,
                          const char *observation_json, size_t obs_len) {
    if (!out || !channel || !ts_iso || !observation_json) return 0;
    int n = snprintf(out, cap,
                     "{\"kind\":\"%s\",\"ts\":\"%s\",\"observation\":%.*s}",
                     channel, ts_iso, (int)obs_len, observation_json);
    if (n < 0 || (size_t)n >= cap) {
        if (cap > 0) out[0] = '\0';
        return 0;
    }
    return (size_t)n;
}

void ps_obs_queue_init(void) {
    pthread_mutex_lock(&g_lock);
    g_head = g_tail = g_count = 0;
    pthread_mutex_unlock(&g_lock);
}

void ps_obs_queue_push(const char *event_json, size_t len) {
    if (!event_json || len == 0 || len >= PS_OBS_ITEM_MAX) return;
    pthread_mutex_lock(&g_lock);
    if (g_count == PS_OBS_QUEUE_CAP) {
        g_head = (g_head + 1) % PS_OBS_QUEUE_CAP;  /* drop oldest */
        g_count--;
    }
    struct obs_item *it = &g_ring[g_tail];
    memcpy(it->data, event_json, len);
    it->data[len] = '\0';
    it->len = len;
    g_tail = (g_tail + 1) % PS_OBS_QUEUE_CAP;
    g_count++;
    pthread_mutex_unlock(&g_lock);
}

int ps_obs_queue_drain(char out_items[][PS_OBS_ITEM_MAX], int max) {
    int drained = 0;
    pthread_mutex_lock(&g_lock);
    while (drained < max && g_count > 0) {
        struct obs_item *it = &g_ring[g_head];
        memcpy(out_items[drained], it->data, it->len + 1); /* incl NUL */
        g_head = (g_head + 1) % PS_OBS_QUEUE_CAP;
        g_count--;
        drained++;
    }
    pthread_mutex_unlock(&g_lock);
    return drained;
}

int ps_obs_queue_count(void) {
    pthread_mutex_lock(&g_lock);
    int c = g_count;
    pthread_mutex_unlock(&g_lock);
    return c;
}
