#include "central_checkin.h"
#include "central_config.h"   /* ps_central_config_from_env (lib) */
#include "http_client.h"      /* lib */
#include "json.h"             /* lib */
#include "log.h"
#include "build_config.h"     /* PS_VERSION */
#include "obs_queue.h"
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

/* Drain queued observations and ship them to central as one signed batch.
 * Caps each cycle at PS_OBS_QUEUE_CAP items. Best-effort: on failure the
 * items are already dequeued (dropped) — the next snapshot/Phase-1 pass
 * reconciles gaps; we never block the daemon on central availability. */
static void ps_checkin_ship_observations(const struct ps_central_config *cc) {
    if (!cc->url || !cc->url[0]) return;
    if (ps_obs_queue_count() == 0) return;

    static char items[PS_OBS_QUEUE_CAP][PS_OBS_ITEM_MAX];
    int n = ps_obs_queue_drain(items, PS_OBS_QUEUE_CAP);
    if (n <= 0) return;

    const char *jsons[PS_OBS_QUEUE_CAP];
    for (int i = 0; i < n; i++) jsons[i] = items[i];

    struct ps_report_result rr;
    memset(&rr, 0, sizeof(rr));
    int rc = ps_report_observations(cc, NULL, jsons, (size_t)n, &rr);
    if (rc != 0)
        ps_warn("central: observation ship failed rc=%d (dropped %d)", rc, n);
    else
        ps_info("central: shipped %d observations", n);
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
        ps_checkin_ship_observations(&cc);
        for (int i = 0; i < g_interval && !g_stop; i++) sleep(1);
    }
    return NULL;
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
