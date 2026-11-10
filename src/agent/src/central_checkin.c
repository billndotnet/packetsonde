#include "central_checkin.h"
#include "central_config.h"   /* ps_central_config_from_env (lib) */
#include "http_client.h"      /* lib */
#include "json.h"             /* lib */
#include "log.h"
#include "build_config.h"     /* PS_VERSION */
#include "obs_queue.h"
#include "obs_dedupe.h"
#include "platform/platform.h"
#include "reporter.h"         /* ps_report_events, ps_report_result */
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Post one heartbeat using an already-resolved config.  Returns 0 on HTTP 200,
 * -1 on transport / non-200 error or when no url is present. */
static int ps_checkin_post_heartbeat(const struct ps_central_config *cc,
                                     long uptime_seconds) {
    if (!cc->url || !cc->url[0]) return -1;

    char host[256];
    const char *agent_id = (cc->agent_id && cc->agent_id[0]) ? cc->agent_id
                          : (gethostname(host, sizeof host) == 0 ? host : "unknown");

    char body[512]; struct ps_json j; ps_json_init(&j, body, sizeof body);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "agent_id", agent_id);
    ps_json_key_int(&j, "uptime_seconds", uptime_seconds);
    ps_json_key_string(&j, "config_version", "none");
    ps_json_key_string(&j, "agent_version", PS_VERSION);
    ps_json_key_string(&j, "key_rotation_status", "none");
    {
        const char *lm = getenv("PS_AGENT_LISTEN_MODE");
        ps_json_key_string(&j, "listen_mode", (lm && lm[0]) ? lm : "persistent");
    }
    ps_json_object_end(&j);
    if (ps_json_finish(&j) < 0) return -1;

    char url[640]; snprintf(url, sizeof url, "%s/api/v1/packetsonde/checkin", cc->url);
    struct ps_http_opts opts = { cc->verify, cc->ca_cert, 10 };
    int status = 0; char resp[1024];
    if (ps_http_request("POST", url, body, &opts, &status, resp, sizeof resp) != 0) return -1;
    return status == 200 ? 0 : -1;
}

int ps_central_checkin_once(long uptime_seconds) {
    struct ps_central_config cc = ps_central_config_from_env();
    return ps_checkin_post_heartbeat(&cc, uptime_seconds);
}

/* Drain queued observations and ship them to central in bounded batches.
 * PS_OBS_SHIP_BATCH bounds the items drained per call; the reporter splits a
 * batch across several POSTs when its envelopes outgrow one request, and skips
 * (and logs) any single item it cannot envelope instead of failing the batch.
 * The per-cycle batch cap bounds work. Best-effort: items that cannot be
 * delivered (central unreachable, non-2xx) are already dequeued and dropped;
 * Phase-1 reconciliation backstops gaps; we never block the daemon on central
 * availability. */
#define PS_OBS_SHIP_BATCH        50   /* items drained per reporter call */
#define PS_OBS_SHIP_MAX_BATCHES  16   /* up to 800 observations drained per cycle */
static pthread_mutex_t g_ship_lock = PTHREAD_MUTEX_INITIALIZER;

/* Move dedupe summaries into the queue: those whose window ended, or all of
 * them with `force`. A summary is never dropped here: the dedupe table keeps
 * any that do not fit one round for the next. */
static void ps_checkin_flush_dedupe(int force) {
    static char items[PS_OBS_SHIP_BATCH][PS_OBS_ITEM_MAX];
    int64_t now_ms = (int64_t)(ps_platform_wall_usec() / 1000);
    int n;
    do {
        n = ps_obs_dedupe_flush(now_ms, force, items, PS_OBS_SHIP_BATCH);
        for (int i = 0; i < n; i++) ps_obs_queue_push(items[i], strlen(items[i]));
    } while (n == PS_OBS_SHIP_BATCH);

    static struct ps_obs_dedupe_counters last;
    struct ps_obs_dedupe_counters c;
    ps_obs_dedupe_get_counters(&c);
    if (c.summaries != last.summaries || c.sent != last.sent)
        ps_info("dedupe: offered %llu, sent %llu, suppressed %llu, summaries %llu "
                "(%llu repeats), evicted %llu, closed %llu, truncated %llu, open %d",
                (unsigned long long)c.offered, (unsigned long long)c.sent,
                (unsigned long long)c.suppressed, (unsigned long long)c.summaries,
                (unsigned long long)c.summary_repeats, (unsigned long long)c.evicted,
                (unsigned long long)c.closed, (unsigned long long)c.truncated,
                ps_obs_dedupe_count());
    last = c;
}

static void ps_checkin_ship_observations(const struct ps_central_config *cc) {
    if (!cc->url || !cc->url[0]) return;

    static char items[PS_OBS_SHIP_BATCH][PS_OBS_ITEM_MAX];
    const char *jsons[PS_OBS_SHIP_BATCH];
    int shipped = 0, skipped = 0, failed = 0, accepted = 0, last_status = 0;

    for (int batch = 0; batch < PS_OBS_SHIP_MAX_BATCHES; batch++) {
        int n = ps_obs_queue_drain(items, PS_OBS_SHIP_BATCH);
        if (n <= 0) break;
        for (int i = 0; i < n; i++) jsons[i] = items[i];

        struct ps_report_result rr;
        memset(&rr, 0, sizeof(rr));
        int rc = ps_report_observations(cc, NULL, jsons, (size_t)n, &rr);
        skipped  += rr.skipped;
        failed   += rr.unsent;
        shipped  += n - rr.skipped - rr.unsent;
        accepted += rr.accepted;
        if (rr.http_status) last_status = rr.http_status;
        if (rc != 0) {
            /* Central is unreachable: stop draining this cycle so queued items
             * wait for the next one instead of being dropped too. */
            break;
        }
        if (rr.http_status >= 500 || rr.http_status == 429) {
            /* Central (or the proxy in front of it) answered "unavailable"/"slow down": the batch in flight is
             * lost, but do not drain the rest of the queue into the same wall. */
            break;
        }
    }
    if (skipped > 0 || failed > 0)
        ps_warn("central: observations shipped %d (accepted %d), skipped %d (could not be "
                "enveloped), failed %d (not delivered, last HTTP %d)",
                shipped, accepted, skipped, failed, last_status);
    else if (shipped > 0)
        ps_info("central: shipped %d observations (accepted %d)", shipped, accepted);
}

static volatile int g_stop = 0;
static pthread_t g_thread;
static int g_interval = 60;
static long g_start = 0;

static void *checkin_loop(void *arg) {
    (void)arg;
    while (!g_stop) {
        struct ps_central_config cc = ps_central_config_from_env();
        if (ps_checkin_post_heartbeat(&cc, time(NULL) - g_start) != 0)
            ps_warn("central: checkin failed");
        pthread_mutex_lock(&g_ship_lock);
        if (!g_stop) {
            ps_checkin_flush_dedupe(0);
            ps_checkin_ship_observations(&cc);
        }
        pthread_mutex_unlock(&g_ship_lock);
        for (int i = 0; i < g_interval && !g_stop; i++) sleep(1);
    }
    return NULL;
}

void ps_central_checkin_stop(void) {
    pthread_mutex_lock(&g_ship_lock);   /* waits for a shipment in flight */
    g_stop = 1;
    ps_checkin_flush_dedupe(1);
    struct ps_central_config cc = ps_central_config_from_env();
    ps_checkin_ship_observations(&cc);
    pthread_mutex_unlock(&g_ship_lock);
}

int ps_central_checkin_start(void) {
    struct ps_central_config cc = ps_central_config_from_env();
    if (!cc.url || !cc.url[0]) return -1;
    g_interval = cc.checkin_seconds > 0 ? cc.checkin_seconds : 60;
    g_start = time(NULL);
    if (pthread_create(&g_thread, NULL, checkin_loop, NULL) != 0) return -1;
    pthread_detach(g_thread);
    return 0;
}
