/*
 * kernelsonded — Linux host behavioral-detection daemon (the "brain").
 *
 * Forks the unprivileged-capable kernelsonde-priv worker (fanotify), drops to
 * an unprivileged user, builds the activity ring, registers the two detect
 * modules (policy_overwatch + baseline_monitor), wires the activity sink /
 * provenance / capture-control plumbing, serves the IPC control socket, and
 * checks in to central.
 *
 * This is modeled on packetsonded's (src/agent/src/main.c) DETECT path ONLY.
 * No network modules, discovery, --via/relay, flow, or pcap code lives here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "build_config.h"
#include "log.h"
#include "config.h"
#include "config_to_env.h"
#include "central_config.h"
#include "registration.h"
#include "central_checkin.h"
#include "json.h"
#include "ipc_server.h"
#include "module.h"
#include "obs_queue.h"
#include "activity_ring.h"
#include "iso8601.h"
#include "priv_client.h"
#include "priv_protocol.h"
#include "activity_record.h"
#include "capture_session.h"
#include "provenance.h"
#include "platform/platform.h"

/* ------------------------------------------------------------------ */
/* Globals                                                              */
/* ------------------------------------------------------------------ */

static volatile int g_running = 1;
static struct ps_priv_client     g_priv;
static struct ps_ipc_server      g_ipc;
static struct ps_module_registry g_registry;

/* ------------------------------------------------------------------ */
/* Module extern declarations (the two detect modules)                  */
/* ------------------------------------------------------------------ */

extern const ps_module_t ps_policy_overwatch_module;
extern const ps_module_t ps_baseline_monitor_module;

/* ------------------------------------------------------------------ */
/* Signal handler                                                       */
/* ------------------------------------------------------------------ */

static void on_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

/* ------------------------------------------------------------------ */
/* Module context callbacks                                             */
/* ------------------------------------------------------------------ */

/* Detect modules publish their findings (policy.sandbox.violation,
 * baseline.anomaly, baseline.candidate) through this callback. Broadcast to
 * any connected IPC clients and queue the finding for continuous shipping to
 * central. */
static int ctx_publish(ps_module_ctx_t *ctx,
                       const char *channel,
                       const char *json, uint32_t json_len)
{
    /* Module event counter */
    if (ctx) {
        for (int i = 0; i < g_registry.count; i++) {
            if (&g_registry.instances[i].ctx == ctx) {
                g_registry.instances[i].event_count++;
                break;
            }
        }
    }

    int rc = ps_ipc_server_broadcast(&g_ipc, channel, json, json_len);

    /* Queue detect findings for continuous shipping to central. */
    char ts_iso[24];
    if (ps_iso8601_utc(ps_platform_wall_usec(), ts_iso, sizeof(ts_iso)) > 0) {
        char event_json[PS_OBS_ITEM_MAX];
        size_t evlen = ps_obs_build_event(event_json, sizeof(event_json),
                                          channel, ts_iso, json, json_len);
        if (evlen > 0)
            ps_obs_queue_push(event_json, evlen);
    }

    return rc;
}

static void ctx_log(ps_module_ctx_t *ctx, int level, const char *fmt, ...)
{
    (void)ctx;
    va_list ap;
    va_start(ap, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    ps_log((enum ps_log_level)level, "%s", buf);
}

/* ------------------------------------------------------------------ */
/* IPC frame handler                                                    */
/* ------------------------------------------------------------------ */

static void on_ipc_frame(int client_fd, const char *channel,
                         const char *payload, uint32_t payload_len,
                         void *userdata)
{
    (void)userdata;
    (void)payload_len;

    if (strcmp(channel, "detect.capture.control") == 0) {
        /*
         * detect.capture.control — start/stop a detect capture session.
         * Payload: {"action":"start","session_id":"<id>"}
         *          {"action":"stop"}
         * Response channel: "response.capture"
         *   {"ok":true,"session_id":"<id>","action":"<a>"} on success
         *   {"ok":false,"error":"..."} on bad/missing fields
         */
        char action[16]      = {0};
        char session_id[128] = {0};
        const char *p;

        if ((p = strstr(payload, "\"action\"")) != NULL) {
            sscanf(p, "\"action\" : \"%15[^\"]\"", action);
            if (action[0] == '\0')
                sscanf(p, "\"action\":\"%15[^\"]\"", action);
        }
        if ((p = strstr(payload, "\"session_id\"")) != NULL) {
            sscanf(p, "\"session_id\" : \"%127[^\"]\"", session_id);
            if (session_id[0] == '\0')
                sscanf(p, "\"session_id\":\"%127[^\"]\"", session_id);
        }

        char resp[256];
        struct ps_json j;
        ps_json_init(&j, resp, sizeof(resp));

        if (strcmp(action, "start") == 0) {
            if (session_id[0] == '\0') {
                ps_warn("main: detect.capture.control start missing session_id");
                ps_json_object_begin(&j);
                ps_json_key_bool(&j,   "ok", false);
                ps_json_key_string(&j, "error", "missing session_id");
                ps_json_object_end(&j);
            } else {
                ps_capture_session_set(session_id);
                ps_info("main: detect capture session started '%s'", session_id);
                ps_json_object_begin(&j);
                ps_json_key_bool(&j,   "ok", true);
                ps_json_key_string(&j, "session_id", session_id);
                ps_json_key_string(&j, "action", "start");
                ps_json_object_end(&j);
            }
        } else if (strcmp(action, "stop") == 0) {
            ps_capture_session_clear();
            ps_info("main: detect capture session stopped");
            ps_json_object_begin(&j);
            ps_json_key_bool(&j,   "ok", true);
            ps_json_key_string(&j, "action", "stop");
            ps_json_object_end(&j);
        } else {
            ps_warn("main: detect.capture.control bad action '%s'", action);
            ps_json_object_begin(&j);
            ps_json_key_bool(&j,   "ok", false);
            ps_json_key_string(&j, "error", "unknown action");
            ps_json_object_end(&j);
        }

        int rlen = ps_json_finish(&j);
        if (rlen > 0)
            ps_ipc_server_send_to(&g_ipc, client_fd, "response.capture",
                                  resp, (uint32_t)rlen);

    } else {
        ps_debug("main: unknown IPC channel '%s'", channel);
    }
}

/* ------------------------------------------------------------------ */
/* Activity JSONL sink                                                  */
/* ------------------------------------------------------------------ */

/* Append a single activity record (JSON bytes + newline) to the sink
 * file, if PS_DETECT_ENABLED is set.  Silently skips on open failure
 * (e.g. directory not yet created) — never crashes, never spams logs. */
static void activity_sink_append(const char *json, size_t len)
{
    const char *enabled = getenv("PS_DETECT_ENABLED");
    if (!enabled || !enabled[0]) return;

    const char *path = getenv("PS_DETECT_SINK");
    if (!path || !path[0]) path = "/var/lib/kernelsonde/activity.jsonl";

    FILE *f = fopen(path, "a");
    if (!f) return;  /* dir missing or unwritable — skip silently */
    fwrite(json, 1, len, f);
    fputc('\n', f);
    fclose(f);

    /* Tee into the active detect capture session, if one is set. The helper
     * no-ops when there is no session; it supplies its own trailing newline. */
    ps_capture_session_append(json);
}

/* If an activity record carries a provenance trigger, build the
 * detect.file_provenance bundle and enqueue it for central shipping. `json`
 * must be NUL-terminated. Cheap strstr gate first — only provenance records
 * (rare) pay the parse cost. */
static void maybe_ship_provenance(const char *json)
{
    if (!strstr(json, "\"prov_trigger\"")) return;

    struct ps_activity a;
    if (ps_activity_from_json(json, &a) != 0 || a.prov_trigger[0] == '\0') return;

    static char hostbuf[256];
    if (hostbuf[0] == '\0' && gethostname(hostbuf, sizeof hostbuf) != 0)
        snprintf(hostbuf, sizeof hostbuf, "unknown");

    char bundle[PS_OBS_ITEM_MAX];
    int bn = ps_provenance_build_record(&a, a.prov_trigger, hostbuf, bundle, sizeof bundle);
    if (bn <= 0) return;

    char ts_iso[24];
    if (ps_iso8601_utc(ps_platform_wall_usec(), ts_iso, sizeof ts_iso) <= 0) return;

    char event_json[PS_OBS_ITEM_MAX];
    size_t evlen = ps_obs_build_event(event_json, sizeof event_json,
                                      "detect.file_provenance", ts_iso,
                                      bundle, (size_t)bn);
    if (evlen > 0) ps_obs_queue_push(event_json, evlen);
}

/* ------------------------------------------------------------------ */
/* Priv client message dispatcher                                       */
/* ------------------------------------------------------------------ */

/* kernelsonded only consumes async activity records from the priv worker. */
static void dispatch_priv_msg(const struct ps_priv_msg *hdr,
                              const uint8_t *payload)
{
    switch (hdr->opcode) {
        case PS_OP_ACTIVITY_DATA:
            if (hdr->payload_len > 0) {
                /* NUL-terminate for ring/sink/provenance (the record JSON is
                 * text; the frame does not guarantee a trailing NUL). */
                char rec[PS_MAX_MSG_PAYLOAD + 1];
                uint32_t rlen = hdr->payload_len;
                if (rlen > PS_MAX_MSG_PAYLOAD) rlen = PS_MAX_MSG_PAYLOAD;
                memcpy(rec, payload, rlen); rec[rlen] = '\0';
                ps_act_ring_push(rec, rlen);
                activity_sink_append(rec, rlen);
                maybe_ship_provenance(rec);
            }
            break;
        case PS_OP_ERROR:
            ps_warn("main: priv worker error status=%d handle=%d",
                    hdr->status, hdr->handle_id);
            break;
        default:
            ps_debug("main: unhandled priv opcode 0x%02x", hdr->opcode);
            break;
    }
}

/* ------------------------------------------------------------------ */
/* main()                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    ps_log_set_prefix("kernel");
    ps_log_set_level(PS_LOG_INFO);

    /* --- Argument parsing --- */
    const char *config_path = NULL;
    int daemonize = 0;
    int verbosity = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0) {
            daemonize = 1;
        } else if (strcmp(argv[i], "-vv") == 0 || strcmp(argv[i], "--debug") == 0) {
            verbosity = 2;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbosity = 1;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("kernelsonded %s\n", PS_VERSION);
            return EXIT_SUCCESS;
        } else if (strcmp(argv[i], "-h") == 0) {
            printf("kernelsonded %s\n", PS_VERSION);
            printf("Usage: %s [-c config] [-v] [-vv] [-d] [-h]\n", argv[0]);
            printf("  -c config       config file path\n");
            printf("  -v, --verbose   info-level logging (default)\n");
            printf("  -vv, --debug    debug-level logging\n");
            return EXIT_SUCCESS;
        }
    }

    (void)daemonize; /* not implemented yet */

    if (verbosity >= 2)
        ps_log_set_level(PS_LOG_DEBUG);

    ps_info("kernelsonded %s starting", PS_VERSION);

    /* --- Load config --- */
    struct ps_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    if (config_path) {
        if (ps_config_parse_file(&cfg, config_path) < 0) {
            ps_warn("main: config '%s' not found or empty, using defaults", config_path);
        } else {
            ps_info("main: loaded config from '%s'", config_path);
        }
    }
    /* Translate config keys to env vars so modules / shared code can read them
     * unchanged. Pre-existing env vars win over file values. */
    int env_set = ps_config_to_env(&cfg);
    if (env_set > 0)
        ps_info("main: applied %d config keys to environment", env_set);

    /* --- Central management: own identity under /etc/kernelsonded/keys --- */
    /* Default the keystore dir to kernelsonded's own identity unless an
     * operator pinned PS_KEY_DIR explicitly (env or [central] key_dir via
     * config_to_env). Both enroll (ps_register, reads cc.key_dir) and the
     * checkin loop (ps_central_checkin_start, reads env) pick this up. */
    setenv("PS_KEY_DIR", "/etc/kernelsonded/keys", 0);
    {
        struct ps_central_config cc = ps_central_config_from_env();
        if (cc.url && cc.url[0]) {
            enum ps_reg_result r = ps_register(&cc, "direct", 0);
            ps_info("central: enroll result=%d (0=ok 1=already 2=http 3=local)", (int)r);
            if (ps_central_checkin_start() == 0)
                ps_info("central: checkin loop started (%ds)", cc.checkin_seconds);
        }
    }

    /* --- Configure log level from config --- */
    const char *log_level_str = ps_config_get(&cfg, "kernel", "log_level");
    if (!log_level_str) log_level_str = ps_config_get(&cfg, "agent", "log_level");
    if (log_level_str) {
        if (strcmp(log_level_str, "debug") == 0)
            ps_log_set_level(PS_LOG_DEBUG);
        else if (strcmp(log_level_str, "warn") == 0)
            ps_log_set_level(PS_LOG_WARN);
        else if (strcmp(log_level_str, "error") == 0)
            ps_log_set_level(PS_LOG_ERROR);
        /* default is INFO */
    }

    /* --- Find priv worker binary --- */
    char exe_dir[4096];
    if (ps_platform_exe_dir(exe_dir, sizeof(exe_dir)) < 0) {
        ps_warn("main: could not determine exe dir, using '.'");
        snprintf(exe_dir, sizeof(exe_dir), ".");
    }

    char priv_path[4096 + 64];
    snprintf(priv_path, sizeof(priv_path), "%s/kernelsonde-priv", exe_dir);
    ps_info("main: priv worker path: %s", priv_path);

    /* --- Fork priv worker --- */
    int priv_fd = ps_platform_fork_priv_worker(priv_path);
    if (priv_fd < 0) {
        ps_error("main: failed to fork priv worker");
        return EXIT_FAILURE;
    }
    ps_info("main: priv worker forked (fd=%d)", priv_fd);

    /* --- Drop privileges ---
     *
     * `[kernel] user = "current"` (or env PS_KERNEL_USER=current) keeps the
     * existing UID -- useful for self-tests and developer runs. Production
     * deployments leave this unset to drop to the dedicated 'kernelsonded'
     * service user. */
    const char *run_as = ps_config_get(&cfg, "kernel", "user");
    if (!run_as) run_as = getenv("PS_KERNEL_USER");
    if (!run_as || !*run_as) run_as = "kernelsonded";
    if (strcmp(run_as, "current") == 0) {
        ps_info("main: keeping current uid (kernel.user=current)");
    } else if (ps_platform_drop_privs(run_as) < 0) {
        ps_warn("main: could not drop privileges to '%s' (continuing)", run_as);
    } else {
        ps_info("main: privileges dropped to '%s'", run_as);
    }

    /* --- Init priv client --- */
    ps_priv_client_init(&g_priv, priv_fd);

    /* --- Init IPC server ---
     * Socket path resolution order: [agent] socket config, then the
     * PS_AGENT_SOCKET env var, then a platform default. */
    const char *sock_path = ps_config_get(&cfg, "agent", "socket");
    if (!sock_path || !*sock_path) sock_path = getenv("PS_AGENT_SOCKET");
    if (!sock_path || !*sock_path) {
#if defined(__APPLE__)
        sock_path = "/tmp/kernelsonde-agent.sock";
#else
        sock_path = "/run/kernelsonde/agent.sock";
#endif
    }

    if (ps_ipc_server_init(&g_ipc, sock_path, on_ipc_frame, NULL) < 0) {
        ps_error("main: failed to init IPC server on '%s'", sock_path);
        return EXIT_FAILURE;
    }
    ps_info("main: IPC server listening on '%s'", sock_path);

    /* --- Init module registry + queues --- */
    ps_module_registry_init(&g_registry);
    ps_obs_queue_init();
    ps_act_ring_init();

    /* Register the two detect modules (each gated by config, default on). */
    if (ps_config_get_bool(&cfg, "modules", "policy_overwatch", 1))
        ps_module_registry_add(&g_registry, &ps_policy_overwatch_module);
    if (ps_config_get_bool(&cfg, "modules", "baseline_monitor", 1))
        ps_module_registry_add(&g_registry, &ps_baseline_monitor_module);

    /* Wire module context callbacks (detect modules only use log + publish). */
    for (int i = 0; i < g_registry.count; i++) {
        ps_module_ctx_t *ctx = &g_registry.instances[i].ctx;
        ctx->publish = ctx_publish;
        ctx->log     = ctx_log;
    }

    /* Init all modules */
    ps_module_registry_init_all(&g_registry);

    /* --- Signal handlers --- */
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    ps_info("main: entering event loop");

    /* --- Event loop --- */
    uint8_t priv_payload[PS_MAX_MSG_PAYLOAD];

    while (g_running) {
        /* Poll IPC clients (non-blocking) */
        ps_ipc_server_poll(&g_ipc, 0);

        /* Receive from priv worker */
        struct ps_priv_msg hdr;
        int n = ps_priv_client_recv(&g_priv, &hdr, priv_payload, sizeof(priv_payload));
        if (n < 0) {
            ps_error("main: priv worker disconnected");
            g_running = 0;
            break;
        }
        if (n > 0)
            dispatch_priv_msg(&hdr, priv_payload);

        /* Tick all modules — drains the activity ring, emits findings. */
        ps_module_registry_tick_all(&g_registry, ps_platform_now_usec());

        /* Brief sleep to prevent busy-wait */
        usleep(1000);
    }

    ps_info("main: shutting down");

    ps_module_registry_shutdown_all(&g_registry);
    ps_ipc_server_shutdown(&g_ipc);
    close(priv_fd);
    ps_config_free(&cfg);

    ps_info("main: done");
    return EXIT_SUCCESS;
}
