#include "central_checkin.h"
#include "central_config.h"   /* ps_central_config_from_env (lib) */
#include "http_client.h"      /* lib */
#include "json.h"             /* lib */
#include "log.h"
#include "build_config.h"     /* PS_VERSION */
#include "obs_queue.h"
#include "obs_dedupe.h"
#include "obs_ship.h"
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

/* Ship queued observations and dedupe summaries to central (obs_ship.h).
 * The reporter splits a batch across several POSTs when its envelopes
 * outgrow one request, and skips (and logs) any single item it cannot
 * envelope instead of failing the batch. Best-effort: a batch that cannot be
 * delivered (central unreachable, non-2xx) is dropped; Phase-1 reconciliation
 * backstops gaps; we never block the daemon on central availability. Dedupe
 * summaries are only flushed while central takes them, so they wait inside
 * dedupe instead of being dropped. */
static pthread_mutex_t g_ship_lock = PTHREAD_MUTEX_INITIALIZER;

struct ship_ctx {
    const struct ps_central_config *cc;
    int shipped, skipped, failed, accepted, last_status;
};

static int ship_to_central(const char **items, int n, void *user) {
    struct ship_ctx *x = user;
    if (!x->cc->url || !x->cc->url[0]) return -1;
    struct ps_report_result rr;
    memset(&rr, 0, sizeof(rr));
    int rc = ps_report_observations(x->cc, NULL, items, (size_t)n, &rr);
    x->skipped  += rr.skipped;
    x->failed   += rr.unsent;
    x->shipped  += n - rr.skipped - rr.unsent;
    x->accepted += rr.accepted;
    if (rr.http_status) x->last_status = rr.http_status;
    /* Central unreachable, or it (or the proxy in front of it) answered
     * "unavailable"/"slow down" for any POST of the batch: stop this cycle
     * instead of draining the rest into the same wall. A dedupe summary batch
     * is then re-staged WHOLE and re-sent byte-identical next cycle; central
     * dedups on the deterministic envelope sig (central-protocol-v1:
     * "redelivery is idempotent"), so retrying the parts it did store is
     * safe. A POST answered with any other non-2xx (400, 413, ...) is poison:
     * those items are counted as failed and not retried. */
    if (rc != 0 || rr.retryable > 0) return -1;
    return 0;
}

/* Test seam: replaces ship_to_central (NULL restores it). */
static ps_obs_ship_fn g_ship_fn_override;
static void *g_ship_user_override;
void ps_central_checkin_set_ship_fn(ps_obs_ship_fn fn, void *user) {
    g_ship_fn_override = fn;
    g_ship_user_override = user;
}

static void ps_checkin_ship_observations(const struct ps_central_config *cc, int force) {
    struct ship_ctx x;
    memset(&x, 0, sizeof x);
    x.cc = cc;
    int64_t now_ms = (int64_t)(ps_platform_wall_usec() / 1000);
    struct ps_obs_ship_counts sc;
    if (g_ship_fn_override)
        ps_obs_ship_cycle(now_ms, force, g_ship_fn_override, g_ship_user_override, &sc);
    else if (cc->url && cc->url[0])
        ps_obs_ship_cycle(now_ms, force, ship_to_central, &x, &sc);
    else
        return;

    if (x.skipped > 0 || x.failed > 0)
        ps_warn("central: observations shipped %d (accepted %d), skipped %d (could not be "
                "enveloped), failed %d (not delivered, last HTTP %d)",
                x.shipped, x.accepted, x.skipped, x.failed, x.last_status);
    else if (x.shipped > 0)
        ps_info("central: shipped %d observations (accepted %d)", x.shipped, x.accepted);

    static struct ps_obs_dedupe_counters last;
    struct ps_obs_dedupe_counters c;
    ps_obs_dedupe_get_counters(&c);
    if (c.summaries != last.summaries || c.sent != last.sent)
        ps_info("dedupe: offered %llu, sent %llu, suppressed %llu, summaries %llu "
                "(%llu repeats, %d this cycle), evicted %llu, closed %llu, truncated %llu, "
                "staging full %llu, open %d",
                (unsigned long long)c.offered, (unsigned long long)c.sent,
                (unsigned long long)c.suppressed, (unsigned long long)c.summaries,
                (unsigned long long)c.summary_repeats, sc.summaries,
                (unsigned long long)c.evicted, (unsigned long long)c.closed,
                (unsigned long long)c.truncated, (unsigned long long)c.stage_full,
                ps_obs_dedupe_count());
    last = c;
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
        if (!g_stop) ps_checkin_ship_observations(&cc, 0);
        pthread_mutex_unlock(&g_ship_lock);
        for (int i = 0; i < g_interval && !g_stop; i++) sleep(1);
    }
    return NULL;
}

void ps_central_checkin_stop(void) {
    pthread_mutex_lock(&g_ship_lock);   /* waits for a shipment in flight */
    g_stop = 1;
    struct ps_central_config cc = ps_central_config_from_env();
    ps_checkin_ship_observations(&cc, 1);   /* every open window */
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
