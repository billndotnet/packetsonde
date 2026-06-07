#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
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
#include "host_table.h"
#include "obs_queue.h"
#include "activity_ring.h"
#include "iso8601.h"
#include "priv_client.h"
#include "activity_record.h"
#include "capture_session.h"
#include "provenance.h"
#include "platform/platform.h"
#include "capture/capture_handle.h"
#include "capture/protocol_demux.h"
#include "iface_enum.h"
#ifdef HAVE_HIREDIS
#include "redis_bridge.h"
#endif

/* ------------------------------------------------------------------ */
/* Forward declarations from other modules                             */
/* ------------------------------------------------------------------ */

/* flow_tracker_mod.c — serialize active flows to JSON */
extern int ps_flow_tracker_snapshot_json(struct ps_module_registry *reg,
                                          char *buf, size_t bufsz);

/* ------------------------------------------------------------------ */
/* Globals                                                              */
/* ------------------------------------------------------------------ */

static volatile int g_running = 1;
static struct ps_priv_client  g_priv;
static struct ps_ipc_server   g_ipc;
static struct ps_module_registry g_registry;
static struct ps_host_table      g_hosts;
static struct ps_capture_handle  g_capture;
static struct ps_protocol_demux  g_demux;
#ifdef HAVE_HIREDIS
static struct ps_redis_bridge *g_redis_br = NULL;
#endif

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

static int ctx_open_pcap(ps_module_ctx_t *ctx,
                          const char *iface,
                          const char *bpf_filter,
                          uint32_t snaplen)
{
    (void)ctx;
    if (!iface || iface[0] == '\0') {
        ps_error("ctx_open_pcap: NULL or empty interface name");
        return -1;
    }
    return ps_priv_client_open_pcap(&g_priv, iface, bpf_filter, snaplen);
}

static int ctx_create_raw_socket(ps_module_ctx_t *ctx, uint8_t af, uint8_t proto)
{
    (void)ctx;
    return ps_priv_client_create_raw_socket(&g_priv, af, proto);
}

static int ctx_send_raw(ps_module_ctx_t *ctx, int handle, uint8_t ttl,
                         const struct sockaddr *dest,
                         const uint8_t *pkt, uint32_t len)
{
    (void)ctx;
    /* Determine socklen from address family */
    socklen_t dest_len = (dest->sa_family == AF_INET6)
                       ? sizeof(struct sockaddr_in6)
                       : sizeof(struct sockaddr_in);
    return ps_priv_client_send_raw(&g_priv, (uint16_t)handle, ttl,
                                    dest, dest_len, pkt, len);
}

static int ctx_publish(ps_module_ctx_t *ctx,
                        const char *channel,
                        const char *json, uint32_t json_len)
{
    /* --- Host table update --- */
    {
        const char *p;
        char ip[46]          = {0};
        char hostname[256]   = {0};
        char device_type[32] = {0};
        char source[32]      = {0};
        uint8_t mac_bytes[6];
        bool has_mac = false;

        if ((p = strstr(json, "\"ip\"")) != NULL) {
            sscanf(p, "\"ip\" : \"%45[^\"]\"", ip);
            if (ip[0] == '\0') sscanf(p, "\"ip\":\"%45[^\"]\"", ip);
        }
        if ((p = strstr(json, "\"hostname\"")) != NULL) {
            sscanf(p, "\"hostname\" : \"%255[^\"]\"", hostname);
            if (hostname[0] == '\0') sscanf(p, "\"hostname\":\"%255[^\"]\"", hostname);
        }
        /* device_type or proto as fallback */
        if ((p = strstr(json, "\"device_type\"")) != NULL) {
            sscanf(p, "\"device_type\" : \"%31[^\"]\"", device_type);
            if (device_type[0] == '\0') sscanf(p, "\"device_type\":\"%31[^\"]\"", device_type);
        }
        if (device_type[0] == '\0') {
            if ((p = strstr(json, "\"type\"")) != NULL) {
                sscanf(p, "\"type\" : \"%31[^\"]\"", device_type);
                if (device_type[0] == '\0') sscanf(p, "\"type\":\"%31[^\"]\"", device_type);
            }
        }
        /* MAC: expect "mac":"xx:xx:xx:xx:xx:xx" */
        if ((p = strstr(json, "\"mac\"")) != NULL) {
            char mac_str[18] = {0};
            sscanf(p, "\"mac\" : \"%17[^\"]\"", mac_str);
            if (mac_str[0] == '\0') sscanf(p, "\"mac\":\"%17[^\"]\"", mac_str);
            if (mac_str[0] != '\0') {
                unsigned int m[6] = {0};
                if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                           &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for (int i = 0; i < 6; i++) mac_bytes[i] = (uint8_t)m[i];
                    has_mac = true;
                }
            }
        }
        /* source: use channel name as source identifier */
        strncpy(source, channel, sizeof(source) - 1);

        if (ip[0] != '\0' || has_mac) {
            uint64_t now = ps_platform_wall_usec();
            ps_host_table_update(&g_hosts, ip[0] ? ip : NULL,
                                 has_mac ? mac_bytes : NULL,
                                 hostname[0] ? hostname : NULL,
                                 device_type[0] ? device_type : NULL,
                                 source, now);
        }
    }

    /* --- Module event counter --- */
    if (ctx) {
        for (int i = 0; i < g_registry.count; i++) {
            if (&g_registry.instances[i].ctx == ctx) {
                g_registry.instances[i].event_count++;
                break;
            }
        }
    }

    int rc = ps_ipc_server_broadcast(&g_ipc, channel, json, json_len);

    /* Phase-0: queue passive findings for continuous shipping to central.
     * Filter to passive discovery + interface-state channels; active-probe
     * results (probe.* / traceroute.*) are shipped via their own report path. */
    if (strncmp(channel, "discovery.", 10) == 0 ||
        strncmp(channel, "net.iface.", 10) == 0) {
        char ts_iso[24];
        if (ps_iso8601_utc(ps_platform_wall_usec(), ts_iso, sizeof(ts_iso)) > 0) {
            char event_json[PS_OBS_ITEM_MAX];
            size_t evlen = ps_obs_build_event(event_json, sizeof(event_json),
                                              channel, ts_iso, json, json_len);
            if (evlen > 0)
                ps_obs_queue_push(event_json, evlen);
        }
    }

#ifdef HAVE_HIREDIS
    if (g_redis_br) {
        ps_redis_bridge_publish(g_redis_br, channel, json, (int)json_len);
    }
#endif
    return rc;
}

static void ctx_log(ps_module_ctx_t *ctx, int level, const char *fmt, ...)
{
    (void)ctx;
    va_list ap;
    va_start(ap, fmt);
    /* Route through ps_log — use vsnprintf to format first */
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    ps_log((enum ps_log_level)level, "%s", buf);
}

static int ctx_close_pcap(ps_module_ctx_t *ctx, int handle)
{
    (void)ctx;
    return ps_priv_client_close_pcap(&g_priv, (uint16_t)handle);
}

static int ctx_capture_add(ps_module_ctx_t *ctx, const char *iface)
{
    (void)ctx;
    if (!iface || !iface[0]) return -1;

    if (ps_iface_excluded(iface, getenv("PS_CAPTURE_EXCLUDE"))) {
        ps_info("capture: not adding %s (excluded / loopback)", iface);
        return -1;
    }
    /* Already captured? Idempotent no-op. */
    for (int i = 0; i < g_capture.count; i++)
        if (strcmp(g_capture.iface_names[i], iface) == 0)
            return 0;

    return ps_capture_open(&g_capture, (ps_open_pcap_fn)ctx_open_pcap, NULL, iface);
}

static int ctx_capture_remove(ps_module_ctx_t *ctx, const char *iface)
{
    (void)ctx;
    if (!iface || !iface[0]) return -1;
    return ps_capture_close_iface(&g_capture, iface,
                                  (ps_close_pcap_fn)ctx_close_pcap, NULL);
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

    if (strcmp(channel, "traceroute.request") == 0) {
        struct ps_job job;
        memset(&job, 0, sizeof(job));

        /* Extract fields via strstr+sscanf — payload is a JSON string */
        const char *p;

        if ((p = strstr(payload, "\"job_id\"")) != NULL) {
            sscanf(p, "\"job_id\" : \"%63[^\"]\"", job.job_id);
            if (job.job_id[0] == '\0')
                sscanf(p, "\"job_id\":\"%63[^\"]\"", job.job_id);
        }

        if ((p = strstr(payload, "\"destination\"")) != NULL) {
            sscanf(p, "\"destination\" : \"%255[^\"]\"", job.destination);
            if (job.destination[0] == '\0')
                sscanf(p, "\"destination\":\"%255[^\"]\"", job.destination);
        }

        if ((p = strstr(payload, "\"method\"")) != NULL) {
            sscanf(p, "\"method\" : \"%15[^\"]\"", job.method);
            if (job.method[0] == '\0')
                sscanf(p, "\"method\":\"%15[^\"]\"", job.method);
        }

        /* Legacy compat: TracerouteAdapter sends "use_tcp":true instead of "method":"tcp" */
        if (job.method[0] == '\0' && (p = strstr(payload, "\"use_tcp\"")) != NULL) {
            if (strstr(p, "true"))
                snprintf(job.method, sizeof(job.method), "tcp");
        }

        if ((p = strstr(payload, "\"max_hops\"")) != NULL) {
            int v = 30;
            sscanf(p, "\"max_hops\" : %d", &v);
            if (v == 30) sscanf(p, "\"max_hops\":%d", &v);
            job.max_hops = v;
        } else {
            job.max_hops = 30;
        }

        if ((p = strstr(payload, "\"tcp_port\"")) != NULL) {
            sscanf(p, "\"tcp_port\" : %d", &job.tcp_port);
            if (!job.tcp_port) sscanf(p, "\"tcp_port\":%d", &job.tcp_port);
        }

        if ((p = strstr(payload, "\"af\"")) != NULL) {
            int v = 4;
            sscanf(p, "\"af\" : %d", &v);
            if (v == 4) sscanf(p, "\"af\":%d", &v);
            job.af = (uint8_t)v;
        } else {
            job.af = 4;
        }

        if (job.job_id[0] == '\0' || job.destination[0] == '\0') {
            ps_warn("main: traceroute.request missing job_id or destination");
            return;
        }

        ps_info("main: dispatching traceroute job '%s' to '%s' via '%s'",
                job.job_id, job.destination,
                job.method[0] ? job.method : "icmp");

        /* Dispatch only to traceroute modules (name contains "traceroute") */
        for (int i = 0; i < g_registry.count; i++) {
            struct ps_module_instance *inst = &g_registry.instances[i];
            if (!inst->enabled) continue;
            if (!inst->module->on_job) continue;
            if (!strstr(inst->module->name, "traceroute")) continue;
            inst->module->on_job(&inst->ctx, &job);
        }
    } else if (strcmp(channel, "probe.request") == 0) {
        /*
         * probe.request payload format:
         *   {"job_id":"...","address":"...","ports":[80,443],"proto":"tcp"}
         *
         * Dispatches one ps_job per port in the "ports" array.
         * "address" maps to job.destination.
         * "proto" maps to job.method ("tcp" → "tcp", "udp" → "udp").
         */
        const char *p;
        char job_id[64]   = {0};
        char address[256] = {0};
        char proto[16]    = {0};

        if ((p = strstr(payload, "\"job_id\"")) != NULL) {
            sscanf(p, "\"job_id\" : \"%63[^\"]\"", job_id);
            if (job_id[0] == '\0')
                sscanf(p, "\"job_id\":\"%63[^\"]\"", job_id);
        }

        if ((p = strstr(payload, "\"address\"")) != NULL) {
            sscanf(p, "\"address\" : \"%255[^\"]\"", address);
            if (address[0] == '\0')
                sscanf(p, "\"address\":\"%255[^\"]\"", address);
        }

        if ((p = strstr(payload, "\"proto\"")) != NULL) {
            sscanf(p, "\"proto\" : \"%15[^\"]\"", proto);
            if (proto[0] == '\0')
                sscanf(p, "\"proto\":\"%15[^\"]\"", proto);
        }
        if (proto[0] == '\0')
            strncpy(proto, "tcp", sizeof(proto) - 1);

        if (job_id[0] == '\0' || address[0] == '\0') {
            ps_warn("main: probe.request missing job_id or address");
            return;
        }

        /* Parse the "ports" array: extract integers between '[' and ']' */
        const char *ports_start = strstr(payload, "\"ports\"");
        if (!ports_start) {
            ps_warn("main: probe.request missing ports array");
            return;
        }
        ports_start = strchr(ports_start, '[');
        if (!ports_start) {
            ps_warn("main: probe.request malformed ports array");
            return;
        }
        const char *ports_end = strchr(ports_start, ']');
        if (!ports_end) {
            ps_warn("main: probe.request unterminated ports array");
            return;
        }

        int port_count = 0;
        const char *cur = ports_start + 1;
        while (cur < ports_end) {
            /* Skip whitespace and commas */
            while (cur < ports_end &&
                   (*cur == ' ' || *cur == '\t' || *cur == '\n' || *cur == ','))
                cur++;
            if (cur >= ports_end) break;

            int port = 0;
            int consumed = 0;
            if (sscanf(cur, "%d%n", &port, &consumed) == 1 &&
                port > 0 && port <= 65535) {
                struct ps_job job;
                memset(&job, 0, sizeof(job));
                strncpy(job.job_id,      job_id,  sizeof(job.job_id) - 1);
                strncpy(job.destination, address, sizeof(job.destination) - 1);
                strncpy(job.method,      proto,   sizeof(job.method) - 1);
                job.tcp_port = port;
                job.af       = 4;

                ps_info("main: dispatching probe job '%s' → %s:%d proto=%s",
                        job_id, address, port, proto);

                for (int i = 0; i < g_registry.count; i++) {
                    struct ps_module_instance *inst = &g_registry.instances[i];
                    if (!inst->enabled) continue;
                    if (inst->module->on_job) {
                        inst->module->on_job(&inst->ctx, &job);
                    }
                }
                port_count++;
                cur += consumed;
            } else {
                break;
            }
        }

        if (port_count == 0)
            ps_warn("main: probe.request contained no valid ports");
    } else if (strcmp(channel, "flow.control") == 0) {
        /*
         * flow.control payload format:
         *   {"action":"start","interface":"en0"}
         *   {"action":"stop","interface":"en0"}
         *   {"action":"stop_all"}
         *   {"action":"status"}
         *
         * Dispatched to the flow_tracker module via on_job with
         * method="flow_control", job_id=action, destination=interface.
         */
        const char *p;
        struct ps_job job;
        memset(&job, 0, sizeof(job));
        strncpy(job.method, "flow_control", sizeof(job.method) - 1);

        if ((p = strstr(payload, "\"action\"")) != NULL) {
            sscanf(p, "\"action\" : \"%63[^\"]\"", job.job_id);
            if (job.job_id[0] == '\0')
                sscanf(p, "\"action\":\"%63[^\"]\"", job.job_id);
        }

        if ((p = strstr(payload, "\"interface\"")) != NULL) {
            sscanf(p, "\"interface\" : \"%255[^\"]\"", job.destination);
            if (job.destination[0] == '\0')
                sscanf(p, "\"interface\":\"%255[^\"]\"", job.destination);
        }

        if (job.job_id[0] == '\0') {
            ps_warn("main: flow.control missing action");
        } else {
            ps_info("main: flow.control action='%s' interface='%s'",
                    job.job_id, job.destination);
            /* Dispatch to flow_tracker module */
            for (int i = 0; i < g_registry.count; i++) {
                struct ps_module_instance *inst = &g_registry.instances[i];
                if (!inst->enabled) continue;
                if (!inst->module->on_job) continue;
                if (strcmp(inst->module->name, "flow_tracker") != 0) continue;
                inst->module->on_job(&inst->ctx, &job);
                break;
            }
        }
    } else if (strcmp(channel, "discovery.control") == 0) {
        /*
         * discovery.control commands:
         *   {"action":"enable","module":"lldp"}
         *   {"action":"disable","module":"ssdp"}
         *   {"action":"list"}
         *   {"action":"enable_all"}
         *   {"action":"disable_all"}
         */
        char action[32] = {0};
        char module_name[64] = {0};

        const char *p;
        if ((p = strstr(payload, "\"action\"")) != NULL) {
            sscanf(p, "\"action\" : \"%31[^\"]\"", action);
            if (action[0] == '\0')
                sscanf(p, "\"action\":\"%31[^\"]\"", action);
        }
        if ((p = strstr(payload, "\"module\"")) != NULL) {
            sscanf(p, "\"module\" : \"%63[^\"]\"", module_name);
            if (module_name[0] == '\0')
                sscanf(p, "\"module\":\"%63[^\"]\"", module_name);
        }

        if (strcmp(action, "enable") == 0 && module_name[0] != '\0') {
            for (int i = 0; i < g_registry.count; i++) {
                if (strcmp(g_registry.instances[i].module->name, module_name) == 0) {
                    g_registry.instances[i].enabled = 1;
                    ps_info("discovery.control: enabled '%s'", module_name);
                    break;
                }
            }
        } else if (strcmp(action, "disable") == 0 && module_name[0] != '\0') {
            for (int i = 0; i < g_registry.count; i++) {
                if (strcmp(g_registry.instances[i].module->name, module_name) == 0) {
                    g_registry.instances[i].enabled = 0;
                    ps_info("discovery.control: disabled '%s'", module_name);
                    break;
                }
            }
        } else if (strcmp(action, "enable_all") == 0) {
            for (int i = 0; i < g_registry.count; i++) {
                if (g_registry.instances[i].module->flags & PS_MOD_PASSIVE) {
                    g_registry.instances[i].enabled = 1;
                }
            }
            ps_info("discovery.control: enabled all passive modules");
        } else if (strcmp(action, "disable_all") == 0) {
            for (int i = 0; i < g_registry.count; i++) {
                if (g_registry.instances[i].module->flags & PS_MOD_PASSIVE) {
                    g_registry.instances[i].enabled = 0;
                }
            }
            ps_info("discovery.control: disabled all passive modules");
        } else if (strcmp(action, "list") == 0) {
            char resp[2048];
            int off = 0;
            off += snprintf(resp + off, sizeof(resp) - off, "{\"modules\":[");
            int first = 1;
            for (int i = 0; i < g_registry.count; i++) {
                if (!(g_registry.instances[i].module->flags & PS_MOD_PASSIVE)) continue;
                if (!first) off += snprintf(resp + off, sizeof(resp) - off, ",");
                first = 0;
                off += snprintf(resp + off, sizeof(resp) - off,
                    "{\"name\":\"%s\",\"enabled\":%s}",
                    g_registry.instances[i].module->name,
                    g_registry.instances[i].enabled ? "true" : "false");
            }
            off += snprintf(resp + off, sizeof(resp) - off, "]}");
            ps_ipc_server_broadcast(&g_ipc, "discovery.modules", resp, (uint32_t)off);
        }
    } else if (strcmp(channel, "query.modules") == 0) {
        /*
         * query.modules — returns list of all registered modules with
         * name, enabled state, event_count, and type (passive/active).
         * Response channel: "response.modules"
         */
        char resp[4096];
        struct ps_json j;
        ps_json_init(&j, resp, sizeof(resp));
        ps_json_object_begin(&j);
        ps_json_key_int(&j, "module_count", g_registry.count);
        ps_json_array_begin(&j, "modules");
        for (int i = 0; i < g_registry.count; i++) {
            const struct ps_module_instance *inst = &g_registry.instances[i];
            /* Inline object in array */
            char tmp[256];
            struct ps_json tj;
            ps_json_init(&tj, tmp, sizeof(tmp));
            ps_json_object_begin(&tj);
            ps_json_key_string(&tj, "name",    inst->module->name);
            ps_json_key_bool(&tj,   "enabled", inst->enabled);
            ps_json_key_int(&tj,    "event_count", (int64_t)inst->event_count);
            const char *mtype = (inst->module->flags & PS_MOD_PASSIVE) ? "passive" : "active";
            ps_json_key_string(&tj, "type", mtype);
            ps_json_object_end(&tj);
            int tlen = ps_json_finish(&tj);
            if (tlen > 0) {
                if (j.needs_comma && j.len < j.cap - 1) j.buf[j.len++] = ',';
                size_t rem = j.cap - j.len;
                size_t cp  = (size_t)tlen < rem ? (size_t)tlen : rem - 1;
                if (cp > 0) { memcpy(j.buf + j.len, tmp, cp); j.len += cp; }
                if (j.len < j.cap) j.buf[j.len] = '\0';
                j.needs_comma = 1;
            }
        }
        ps_json_array_end(&j);
        ps_json_object_end(&j);
        int rlen = ps_json_finish(&j);
        if (rlen > 0)
            ps_ipc_server_send_to(&g_ipc, client_fd, "response.modules", resp, (uint32_t)rlen);

    } else if (strcmp(channel, "query.hosts") == 0) {
        /*
         * query.hosts — returns full host table as JSON.
         * Response channel: "response.hosts"
         */
        char *resp = malloc(PS_MAX_HOSTS * 512);
        if (resp) {
            int rlen = ps_host_table_to_json(&g_hosts, resp, PS_MAX_HOSTS * 512);
            if (rlen > 0)
                ps_ipc_server_send_to(&g_ipc, client_fd, "response.hosts", resp, (uint32_t)rlen);
            free(resp);
        } else {
            ps_warn("main: query.hosts malloc failed");
        }

    } else if (strcmp(channel, "query.host") == 0) {
        /*
         * query.host — looks up a single host by IP.
         * Payload: {"ip":"..."}
         * Response channel: "response.host"
         */
        char ip[46] = {0};
        const char *p;
        if ((p = strstr(payload, "\"ip\"")) != NULL) {
            sscanf(p, "\"ip\" : \"%45[^\"]\"", ip);
            if (ip[0] == '\0') sscanf(p, "\"ip\":\"%45[^\"]\"", ip);
        }
        if (ip[0] == '\0') {
            const char *err = "{\"error\":\"missing ip\"}";
            ps_ipc_server_send_to(&g_ipc, client_fd, "response.host",
                                  err, (uint32_t)strlen(err));
        } else {
            struct ps_host_entry *entry = ps_host_table_find_by_ip(&g_hosts, ip);
            if (!entry) {
                const char *err = "{\"error\":\"not found\"}";
                ps_ipc_server_send_to(&g_ipc, client_fd, "response.host",
                                      err, (uint32_t)strlen(err));
            } else {
                char resp[2048];
                int rlen = ps_host_entry_to_json(entry, resp, sizeof(resp));
                if (rlen > 0)
                    ps_ipc_server_send_to(&g_ipc, client_fd, "response.host",
                                          resp, (uint32_t)rlen);
            }
        }

    } else if (strcmp(channel, "query.stats") == 0) {
        /*
         * query.stats — aggregate stats: host count, module count,
         * client count, per-module event counts.
         * Response channel: "response.stats"
         */
        char resp[4096];
        struct ps_json j;
        ps_json_init(&j, resp, sizeof(resp));
        ps_json_object_begin(&j);
        ps_json_key_int(&j, "host_count",   g_hosts.count);
        ps_json_key_int(&j, "module_count", g_registry.count);
        ps_json_key_int(&j, "client_count", g_ipc.client_count);
        ps_json_array_begin(&j, "modules");
        for (int i = 0; i < g_registry.count; i++) {
            const struct ps_module_instance *inst = &g_registry.instances[i];
            char tmp[256];
            struct ps_json tj;
            ps_json_init(&tj, tmp, sizeof(tmp));
            ps_json_object_begin(&tj);
            ps_json_key_string(&tj, "name",        inst->module->name);
            ps_json_key_int(&tj,    "event_count", (int64_t)inst->event_count);
            ps_json_object_end(&tj);
            int tlen = ps_json_finish(&tj);
            if (tlen > 0) {
                if (j.needs_comma && j.len < j.cap - 1) j.buf[j.len++] = ',';
                size_t rem = j.cap - j.len;
                size_t cp  = (size_t)tlen < rem ? (size_t)tlen : rem - 1;
                if (cp > 0) { memcpy(j.buf + j.len, tmp, cp); j.len += cp; }
                if (j.len < j.cap) j.buf[j.len] = '\0';
                j.needs_comma = 1;
            }
        }
        ps_json_array_end(&j);
        ps_json_object_end(&j);
        int rlen = ps_json_finish(&j);
        if (rlen > 0)
            ps_ipc_server_send_to(&g_ipc, client_fd, "response.stats", resp, (uint32_t)rlen);

    } else if (strcmp(channel, "query.flows") == 0) {
        /*
         * query.flows — returns the top 500 active flows (by total bytes)
         * serialized as JSON.
         * Response channel: "response.flows"
         */
        size_t bufsz = 512 * 1024;  /* 512 KB — flows can be large */
        char *resp = malloc(bufsz);
        if (resp) {
            int len = ps_flow_tracker_snapshot_json(&g_registry, resp, bufsz);
            if (len > 0) {
                ps_ipc_server_send_to(&g_ipc, client_fd, "response.flows",
                                       resp, (uint32_t)len);
            } else {
                const char *err = "{\"error\":\"flow snapshot failed\"}";
                ps_ipc_server_send_to(&g_ipc, client_fd, "response.flows",
                                       err, (uint32_t)strlen(err));
            }
            free(resp);
        } else {
            ps_warn("main: query.flows malloc failed");
        }

    } else if (strcmp(channel, "detect.capture.control") == 0) {
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
    if (!path || !path[0]) path = "/var/lib/packetsonde/activity.jsonl";

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

static void dispatch_priv_msg(const struct ps_priv_msg *hdr,
                               const uint8_t *payload)
{
    uint64_t now = ps_platform_now_usec();

    switch (hdr->opcode) {
        case PS_OP_PACKET_DATA: {
            if (hdr->payload_len < 8) break;
            uint64_t ts_usec = 0;
            memcpy(&ts_usec, payload, 8);
            const uint8_t *pkt = payload + 8;
            uint32_t pkt_len   = hdr->payload_len - 8;
            ps_module_registry_dispatch_packet(&g_registry, pkt, pkt_len,
                                                ts_usec, (int)hdr->handle_id);
            break;
        }
        case PS_OP_RAW_RESPONSE: {
            ps_debug("main: RAW_RESPONSE handle=%d payload_len=%u",
                     hdr->handle_id, hdr->payload_len);
            ps_module_registry_dispatch_response(&g_registry,
                                                  payload, hdr->payload_len,
                                                  now, (int)hdr->handle_id);
            break;
        }
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
/* Module extern declarations                                           */
/* ------------------------------------------------------------------ */

/* Task 11 will provide this. Declare extern here so we can register it. */
extern const ps_module_t ps_icmp_traceroute_module;
extern const ps_module_t ps_tcp_traceroute_module;
extern const ps_module_t ps_udp_traceroute_module;
extern const ps_module_t dublin_traceroute_module;
extern const ps_module_t ps_tcp_probe_module;
extern const ps_module_t ps_udp_probe_module;
extern const ps_module_t ps_flow_tracker_module;
extern const ps_module_t ps_neighbor_listener_module;
extern const ps_module_t ps_dhcp_listener_module;
extern const ps_module_t ps_stp_listener_module;
extern const ps_module_t ps_mld_listener_module;
extern const ps_module_t ps_dns_listener_module;
extern const ps_module_t lldp_module;
extern const ps_module_t cdp_module;
extern const ps_module_t ssdp_module;
extern const ps_module_t netbios_module;
extern const ps_module_t ospf_module;
extern const ps_module_t vrrp_module;
extern const ps_module_t broadcast_module;
extern const ps_module_t ps_iface_monitor_module;
extern const ps_module_t ps_policy_overwatch_module;
extern const ps_module_t ps_baseline_monitor_module;
extern const ps_module_t ps_honeypot_listener_module;
extern const ps_module_t discovery_listener_module;
extern const ps_module_t network_listener_module;
#ifdef HAVE_OPENSSL
extern const ps_module_t ps_tls_probe_module;
#endif

/* ------------------------------------------------------------------ */
/* Redis bridge incoming message callback                               */
/* ------------------------------------------------------------------ */

#ifdef HAVE_HIREDIS
static void on_redis_message(const char *channel, const char *payload,
                              int payload_len, void *userdata)
{
    (void)userdata;
    /* Reuse the same IPC frame handler — Redis is just another source */
    on_ipc_frame(-1, channel, payload, (uint32_t)payload_len, NULL);
}
#endif

/* ------------------------------------------------------------------ */
/* main()                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    ps_log_set_prefix("agent");
    ps_log_set_level(PS_LOG_INFO);

    /* --- Argument parsing --- */
    const char *config_path = NULL;
    int daemonize = 0;

    int verbosity = 0;
    const char *listen_addr = NULL;  /* -l addr:port for TCP listener */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            listen_addr = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0) {
            daemonize = 1;
        } else if (strcmp(argv[i], "-vv") == 0 || strcmp(argv[i], "--debug") == 0) {
            verbosity = 2;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbosity = 1;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("packetsonde-agent %s\n", PS_VERSION);
            return EXIT_SUCCESS;
        } else if (strcmp(argv[i], "-h") == 0) {
            printf("packetsonde-agent %s\n", PS_VERSION);
            printf("Usage: %s [-c config] [-v] [-vv] [-d] [-l addr:port] [-h]\n", argv[0]);
            printf("  -l addr:port    TCP listener for remote clients\n");
            printf("  -v, --verbose   Show hop results and module activity\n");
            printf("  -vv, --debug    Show all packet send/recv and protocol details\n");
            return EXIT_SUCCESS;
        }
    }

    (void)daemonize; /* not implemented yet */

    if (verbosity >= 2)
        ps_log_set_level(PS_LOG_DEBUG);
    else if (verbosity >= 1)
        ps_log_set_level(PS_LOG_INFO);  /* already default, but explicit */

    ps_info("packetsonde-agent %s starting", PS_VERSION);

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
    /* Translate config keys to env vars so the modules can read them
     * unchanged. Pre-existing env vars win over file values, giving
     * operators a clean override path (-e in systemd, env: in launchd). */
    int env_set = ps_config_to_env(&cfg);
    if (env_set > 0) {
        ps_info("main: applied %d config keys to environment", env_set);
    }

    /* --- Central management: self-enroll on first boot + start checkin --- */
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
    const char *log_level_str = ps_config_get(&cfg, "agent", "log_level");
    if (log_level_str) {
        if (strcmp(log_level_str, "debug") == 0)
            ps_log_set_level(PS_LOG_DEBUG);
        else if (strcmp(log_level_str, "warn") == 0)
            ps_log_set_level(PS_LOG_WARN);
        else if (strcmp(log_level_str, "error") == 0)
            ps_log_set_level(PS_LOG_ERROR);
        /* default is INFO */
    }

    /* --- Optional Redis bridge --- */
#ifdef HAVE_HIREDIS
    {
        const char *redis_host = ps_config_get(&cfg, "agent", "redis_host");
        if (redis_host) {
            int redis_port = ps_config_get_int(&cfg, "agent", "redis_port", 6379);
            const char *prefix = ps_config_get(&cfg, "agent", "redis_prefix");
            if (!prefix) prefix = "packetsonde:";
            g_redis_br = ps_redis_bridge_create(redis_host, redis_port, prefix);
            if (g_redis_br) {
                ps_redis_bridge_subscribe(g_redis_br, "traceroute.request");
                ps_redis_bridge_subscribe(g_redis_br, "probe.request");
                ps_info("Redis bridge connected to %s:%d", redis_host, redis_port);
            } else {
                ps_warn("main: Redis bridge init failed — continuing without Redis");
            }
        }
    }
#endif

    /* --- Find priv worker binary --- */
    char exe_dir[4096];
    if (ps_platform_exe_dir(exe_dir, sizeof(exe_dir)) < 0) {
        ps_warn("main: could not determine exe dir, using '.'");
        snprintf(exe_dir, sizeof(exe_dir), ".");
    }

    char priv_path[4096 + 64];
    snprintf(priv_path, sizeof(priv_path), "%s/packetsonde-priv", exe_dir);
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
     * `[agent] user = "current"` (or env PS_AGENT_USER=current) keeps
     * the existing UID -- useful for self-tests and developer runs
     * where the agent needs to read files owned by the invoking user.
     * Production deployments leave this unset to drop to 'nobody'. */
    const char *run_as = ps_config_get(&cfg, "agent", "user");
    if (!run_as) run_as = getenv("PS_AGENT_USER");
    if (!run_as || !*run_as) run_as = "nobody";
    if (strcmp(run_as, "current") == 0) {
        ps_info("main: keeping current uid (agent.user=current)");
    } else if (ps_platform_drop_privs(run_as) < 0) {
        ps_warn("main: could not drop privileges to '%s' (continuing)", run_as);
    } else {
        ps_info("main: privileges dropped to '%s'", run_as);
    }

    /* --- Init priv client --- */
    ps_priv_client_init(&g_priv, priv_fd);

    /* --- Init IPC server --- */
    const char *sock_path = ps_config_get(&cfg, "agent", "socket");
    if (!sock_path) sock_path = "/run/packetsonde/agent.sock";

    if (ps_ipc_server_init(&g_ipc, sock_path, on_ipc_frame, NULL) < 0) {
        ps_error("main: failed to init IPC server on '%s'", sock_path);
        return EXIT_FAILURE;
    }
    ps_info("main: IPC server listening on '%s'", sock_path);

    /* --- Optional TCP listener for remote clients --- */
    if (!listen_addr) {
        /* Check config file */
        listen_addr = ps_config_get(&cfg, "network", "listen");
    }
    if (listen_addr && listen_addr[0] != '\0') {
        /* Parse addr:port */
        char tcp_addr[64] = "0.0.0.0";
        int tcp_port = 4701;
        const char *colon = strrchr(listen_addr, ':');
        if (colon && colon != listen_addr) {
            size_t alen = (size_t)(colon - listen_addr);
            if (alen < sizeof(tcp_addr)) {
                memcpy(tcp_addr, listen_addr, alen);
                tcp_addr[alen] = '\0';
            }
            tcp_port = atoi(colon + 1);
        } else if (colon == listen_addr) {
            /* :port only */
            tcp_port = atoi(colon + 1);
        } else {
            /* No colon — treat as port only or addr only */
            int maybe_port = atoi(listen_addr);
            if (maybe_port > 0 && maybe_port < 65536) {
                tcp_port = maybe_port;
            } else {
                strncpy(tcp_addr, listen_addr, sizeof(tcp_addr) - 1);
            }
        }
        if (tcp_port > 0) {
            ps_ipc_server_add_tcp(&g_ipc, tcp_addr, tcp_port);
        }
    }

    /* --- Init module registry and host table --- */
    ps_module_registry_init(&g_registry);
    ps_host_table_init(&g_hosts);
    ps_obs_queue_init();
    ps_act_ring_init();

    /* Register modules */
    if (ps_module_registry_add(&g_registry, &ps_icmp_traceroute_module) < 0) {
        ps_error("main: failed to register icmp_traceroute module");
        return EXIT_FAILURE;
    }
    if (ps_config_get_bool(&cfg, "modules", "tcp_traceroute", 1))
        ps_module_registry_add(&g_registry, &ps_tcp_traceroute_module);
    if (ps_config_get_bool(&cfg, "modules", "udp_traceroute", 1))
        ps_module_registry_add(&g_registry, &ps_udp_traceroute_module);
    if (ps_config_get_bool(&cfg, "modules", "dublin_traceroute", 1))
        ps_module_registry_add(&g_registry, &dublin_traceroute_module);
    if (ps_config_get_bool(&cfg, "modules", "tcp_probe", 1))
        ps_module_registry_add(&g_registry, &ps_tcp_probe_module);
    if (ps_config_get_bool(&cfg, "modules", "udp_probe", 1))
        ps_module_registry_add(&g_registry, &ps_udp_probe_module);
    if (ps_config_get_bool(&cfg, "modules", "flow_tracker", 1))
        ps_module_registry_add(&g_registry, &ps_flow_tracker_module);
    if (ps_config_get_bool(&cfg, "modules", "neighbor_listener", 1))
        ps_module_registry_add(&g_registry, &ps_neighbor_listener_module);
    if (ps_config_get_bool(&cfg, "modules", "dhcp_listener", 1))
        ps_module_registry_add(&g_registry, &ps_dhcp_listener_module);
    if (ps_config_get_bool(&cfg, "modules", "stp_listener", 1))
        ps_module_registry_add(&g_registry, &ps_stp_listener_module);
    if (ps_config_get_bool(&cfg, "modules", "mld_listener", 1))
        ps_module_registry_add(&g_registry, &ps_mld_listener_module);
    if (ps_config_get_bool(&cfg, "modules", "dns_listener", 1))
        ps_module_registry_add(&g_registry, &ps_dns_listener_module);
    if (ps_config_get_bool(&cfg, "modules", "lldp_listener", 1))
        ps_module_registry_add(&g_registry, &lldp_module);
    if (ps_config_get_bool(&cfg, "modules", "cdp_listener", 1))
        ps_module_registry_add(&g_registry, &cdp_module);
    if (ps_config_get_bool(&cfg, "modules", "ssdp_listener", 1))
        ps_module_registry_add(&g_registry, &ssdp_module);
    if (ps_config_get_bool(&cfg, "modules", "netbios_listener", 1))
        ps_module_registry_add(&g_registry, &netbios_module);
    if (ps_config_get_bool(&cfg, "modules", "ospf_listener", 1))
        ps_module_registry_add(&g_registry, &ospf_module);
    if (ps_config_get_bool(&cfg, "modules", "vrrp_listener", 1))
        ps_module_registry_add(&g_registry, &vrrp_module);
    if (ps_config_get_bool(&cfg, "modules", "broadcast_listener", 1))
        ps_module_registry_add(&g_registry, &broadcast_module);
    if (ps_config_get_bool(&cfg, "modules", "iface_monitor", 1))
        ps_module_registry_add(&g_registry, &ps_iface_monitor_module);
    if (ps_config_get_bool(&cfg, "modules", "policy_overwatch", 1))
        ps_module_registry_add(&g_registry, &ps_policy_overwatch_module);
    if (ps_config_get_bool(&cfg, "modules", "baseline_monitor", 1))
        ps_module_registry_add(&g_registry, &ps_baseline_monitor_module);
    if (ps_config_get_bool(&cfg, "modules", "honeypot_listener", 0))  /* off by default */
        ps_module_registry_add(&g_registry, &ps_honeypot_listener_module);
    /* Discovery + network listener: registered unconditionally. Each
     * module is its own opt-in gate (PS_DISCOVERY_ENABLED /
     * PS_AGENT_LISTEN_MODE) so it stays a no-op unless the operator
     * turns it on in packetsonded.toml. */
    ps_module_registry_add(&g_registry, &discovery_listener_module);
    ps_module_registry_add(&g_registry, &network_listener_module);
#ifdef HAVE_OPENSSL
    if (ps_config_get_bool(&cfg, "modules", "tls_probe", 1))
        ps_module_registry_add(&g_registry, &ps_tls_probe_module);
#endif

    /* Wire module context callbacks */
    for (int i = 0; i < g_registry.count; i++) {
        ps_module_ctx_t *ctx = &g_registry.instances[i].ctx;
        ctx->open_pcap         = ctx_open_pcap;
        ctx->create_raw_socket = ctx_create_raw_socket;
        ctx->send_raw          = ctx_send_raw;
        ctx->publish           = ctx_publish;
        ctx->log               = ctx_log;
        ctx->close_pcap        = ctx_close_pcap;
        ctx->capture_add       = ctx_capture_add;
        ctx->capture_remove    = ctx_capture_remove;
    }

    /* Shared capture handle — one pcap per interface for all passive modules */
    ps_capture_init(&g_capture);
    ps_demux_init(&g_demux);

    /* Capture targets: explicit [agent] interface (or $PS_CAPTURE_INTERFACE) pins a
     * single iface; otherwise capture every real interface (all minus lo minus
     * [capture] exclude). No interface names are hardcoded. */
    char cap_ifaces[PS_CAPTURE_MAX_INTERFACES][64];
    int  cap_n = 0;
    const char *pin = ps_config_get(&cfg, "agent", "interface");
    if (!pin || !pin[0]) pin = getenv("PS_CAPTURE_INTERFACE");
    if (pin && pin[0]) {
        snprintf(cap_ifaces[0], sizeof cap_ifaces[0], "%s", pin);
        cap_n = 1;
    } else {
        cap_n = ps_iface_enumerate(getenv("PS_CAPTURE_EXCLUDE"),
                                   cap_ifaces, PS_CAPTURE_MAX_INTERFACES);
    }

    if (cap_n <= 0) {
        ps_warn("main: no capture interfaces resolved — passive capture disabled");
    } else {
        for (int i = 0; i < cap_n; i++) {
            if (ps_capture_open(&g_capture, (ps_open_pcap_fn)ctx_open_pcap, NULL,
                                cap_ifaces[i]) != 0)
                ps_warn("main: capture open failed for %s — continuing", cap_ifaces[i]);
            else
                ps_info("main: shared capture on %s", cap_ifaces[i]);
        }
        ps_info("main: capture BPF filter: %s", ps_capture_get_bpf_filter());
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

#ifdef HAVE_HIREDIS
        /* Poll Redis for incoming messages (non-blocking) */
        if (g_redis_br) {
            ps_redis_bridge_poll(g_redis_br, on_redis_message, &g_registry);
        }
#endif

        /* Receive from priv worker */
        struct ps_priv_msg hdr;
        int n = ps_priv_client_recv(&g_priv, &hdr, priv_payload, sizeof(priv_payload));
        if (n < 0) {
            ps_error("main: priv worker disconnected");
            g_running = 0;
            break;
        }
        if (n > 0) {
            dispatch_priv_msg(&hdr, priv_payload);
        }

        /* Tick all modules */
        ps_module_registry_tick_all(&g_registry, ps_platform_now_usec());

        /* Brief sleep to prevent busy-wait */
        usleep(1000);
    }

    ps_info("main: shutting down");

    /* Clean shutdown */
    ps_module_registry_shutdown_all(&g_registry);
    ps_ipc_server_shutdown(&g_ipc);
#ifdef HAVE_HIREDIS
    if (g_redis_br) {
        ps_redis_bridge_destroy(g_redis_br);
        g_redis_br = NULL;
    }
#endif
    close(priv_fd);

    ps_config_free(&cfg);

    ps_info("main: done");
    return EXIT_SUCCESS;
}
