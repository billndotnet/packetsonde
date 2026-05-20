/*
 * flow_tracker_mod.c — Flow tracker module for PacketSonde Agent
 *
 * Command-driven pcap capture pipeline that feeds raw Ethernet frames into the
 * flow tracking engine and exports expired flows as NetFlow v9 UDP records
 * to a collector.
 *
 * Capture is NOT started automatically — the UI sends flow.control commands
 * to start/stop capture per-interface.
 *
 * IPC commands (via on_job with method="flow_control"):
 *   {"action":"start","interface":"en0"}  — start capture on interface
 *   {"action":"stop","interface":"en0"}   — stop capture on interface
 *   {"action":"stop_all"}                 — stop all captures
 *   {"action":"status"}                   — broadcast current capture state
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "packetsonde/module_api.h"
#include "flow_tracker.h"
#include "netflow_export.h"
#include "module.h"
#include "json.h"
#include "log.h"
#include "platform/platform.h"

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define FT_MOD_MAX_FLOWS          65536
#define FT_MOD_TRACK_LEVEL        PS_TRACK_IP_PROTO_PORT
#define FT_MOD_COLLECTOR_HOST_DEFAULT  "127.0.0.1"
#define FT_MOD_COLLECTOR_PORT_DEFAULT  2055
#define FT_MOD_SOURCE_ID_DEFAULT       0x5053
#define FT_MOD_NETFLOW_VERSION_DEFAULT 9
#define FT_MOD_SNAPLEN            160
#define FT_MOD_EXPIRE_INTERVAL_US (10ULL * 1000000ULL)

/* Operator config (env):
 *   PS_NETFLOW_COLLECTOR    "host:port"  (default 127.0.0.1:2055)
 *   PS_NETFLOW_VERSION      5 | 9 | 10   (default 9; 10 = IPFIX)
 *   PS_NETFLOW_SOURCE_ID    u32          (default 0x5053)
 */

#define FT_MOD_EXPIRE_BATCH       256
#define FT_MOD_MAX_INTERFACES     8

/* ------------------------------------------------------------------ */
/* Per-interface capture slot                                           */
/* ------------------------------------------------------------------ */

struct ft_capture_slot {
    int   pcap_handle;  /* -1 = inactive */
    char  interface[64];
};

/* ------------------------------------------------------------------ */
/* State                                                                */
/* ------------------------------------------------------------------ */

struct flow_mod_state {
    struct ps_flow_table  *table;
    struct ps_nf_exporter *exporter;
    uint64_t               last_expire_time;
    uint64_t               last_snapshot_time; /* for active flow export */

    struct ft_capture_slot slots[FT_MOD_MAX_INTERFACES];
    int                    active_count;
};

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static struct ft_capture_slot *find_slot_by_iface(struct flow_mod_state *st,
                                                   const char *iface)
{
    for (int i = 0; i < FT_MOD_MAX_INTERFACES; i++) {
        if (st->slots[i].pcap_handle >= 0 &&
            strcmp(st->slots[i].interface, iface) == 0) {
            return &st->slots[i];
        }
    }
    return NULL;
}

static struct ft_capture_slot *find_free_slot(struct flow_mod_state *st)
{
    for (int i = 0; i < FT_MOD_MAX_INTERFACES; i++) {
        if (st->slots[i].pcap_handle < 0) return &st->slots[i];
    }
    return NULL;
}

static void publish_status(ps_module_ctx_t *ctx, struct flow_mod_state *st)
{
    char buf[1024];
    int pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - pos, "{\"interfaces\":[");
    int first = 1;
    for (int i = 0; i < FT_MOD_MAX_INTERFACES; i++) {
        if (st->slots[i].pcap_handle < 0) continue;
        if (!first) pos += snprintf(buf + pos, sizeof(buf) - pos, ",");
        pos += snprintf(buf + pos, sizeof(buf) - pos,
                        "\"%s\"", st->slots[i].interface);
        first = 0;
    }
    pos += snprintf(buf + pos, sizeof(buf) - pos, "],\"active_count\":%d}",
                    st->active_count);
    ctx->publish(ctx, "flow.status", buf, (uint32_t)pos);
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int ft_mod_init(ps_module_ctx_t *ctx)
{
    struct flow_mod_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("flow_tracker: out of memory");
        return -1;
    }
    st->last_expire_time = 0;
    st->active_count     = 0;

    /* Mark all slots inactive */
    for (int i = 0; i < FT_MOD_MAX_INTERFACES; i++)
        st->slots[i].pcap_handle = -1;

    /* Create flow table */
    st->table = ps_flow_table_create(FT_MOD_MAX_FLOWS, FT_MOD_TRACK_LEVEL);
    if (!st->table) {
        ps_error("flow_tracker: failed to create flow table");
        free(st);
        return -1;
    }

    /* Resolve operator-configurable export target. */
    char host[256]; int port = FT_MOD_COLLECTOR_PORT_DEFAULT;
    snprintf(host, sizeof(host), "%s", FT_MOD_COLLECTOR_HOST_DEFAULT);
    const char *coll = getenv("PS_NETFLOW_COLLECTOR");
    if (coll && *coll) {
        const char *colon = strrchr(coll, ':');
        if (colon) {
            size_t hl = (size_t)(colon - coll);
            if (hl < sizeof(host)) {
                memcpy(host, coll, hl); host[hl] = '\0';
                port = atoi(colon + 1);
            }
        } else {
            snprintf(host, sizeof(host), "%s", coll);
        }
    }
    int version = FT_MOD_NETFLOW_VERSION_DEFAULT;
    const char *vstr = getenv("PS_NETFLOW_VERSION");
    if (vstr && *vstr) version = atoi(vstr);
    uint32_t source_id = FT_MOD_SOURCE_ID_DEFAULT;
    const char *sstr = getenv("PS_NETFLOW_SOURCE_ID");
    if (sstr && *sstr) source_id = (uint32_t)strtoul(sstr, NULL, 0);

    st->exporter = ps_nf_exporter_create(host, port, source_id, version);
    if (!st->exporter) {
        ps_error("flow_tracker: failed to create NetFlow exporter");
        ps_flow_table_destroy(st->table);
        free(st);
        return -1;
    }

    ctx->userdata = st;
    ps_info("flow_tracker: initialized (collector=%s:%d, version=%d, "
            "capture will start on flow.control command)",
            host, port, version);
    return 0;
}

static int ft_mod_on_job(ps_module_ctx_t *ctx, const struct ps_job *job)
{
    struct flow_mod_state *st = (struct flow_mod_state *)ctx->userdata;
    if (!st) return -1;

    /* We only handle method="flow_control" */
    if (strcmp(job->method, "flow_control") != 0) return 0;

    /* Parse action from job_id (reused as action field) and interface from destination */
    const char *action = job->job_id;
    const char *iface  = job->destination;

    if (strcmp(action, "start") == 0 && iface[0] != '\0') {
        /* Already capturing on this interface? */
        if (find_slot_by_iface(st, iface)) {
            ps_info("flow_tracker: already capturing on '%s'", iface);
            publish_status(ctx, st);
            return 0;
        }

        struct ft_capture_slot *slot = find_free_slot(st);
        if (!slot) {
            ps_warn("flow_tracker: no free capture slots (max %d)", FT_MOD_MAX_INTERFACES);
            return -1;
        }

        int handle = ctx->open_pcap(ctx, iface, "", FT_MOD_SNAPLEN);
        if (handle < 0) {
            ps_warn("flow_tracker: open_pcap on '%s' failed (handle=%d)", iface, handle);
            return -1;
        }

        slot->pcap_handle = handle;
        strncpy(slot->interface, iface, sizeof(slot->interface) - 1);
        slot->interface[sizeof(slot->interface) - 1] = '\0';
        st->active_count++;

        ps_info("flow_tracker: capture started on '%s' (handle=%d, %d active)",
                iface, handle, st->active_count);
        publish_status(ctx, st);
        return 0;
    }

    if (strcmp(action, "stop") == 0 && iface[0] != '\0') {
        struct ft_capture_slot *slot = find_slot_by_iface(st, iface);
        if (!slot) {
            ps_info("flow_tracker: not capturing on '%s', ignoring stop", iface);
            return 0;
        }

        /* Close pcap via priv worker — TODO: need close_pcap in module API.
         * For now, mark the slot inactive; the priv worker will clean up
         * when the agent shuts down. */
        slot->pcap_handle = -1;
        slot->interface[0] = '\0';
        st->active_count--;

        ps_info("flow_tracker: capture stopped on '%s' (%d active)",
                iface, st->active_count);
        publish_status(ctx, st);
        return 0;
    }

    if (strcmp(action, "stop_all") == 0) {
        for (int i = 0; i < FT_MOD_MAX_INTERFACES; i++) {
            if (st->slots[i].pcap_handle >= 0) {
                ps_info("flow_tracker: stopping capture on '%s'", st->slots[i].interface);
                st->slots[i].pcap_handle = -1;
                st->slots[i].interface[0] = '\0';
            }
        }
        st->active_count = 0;
        publish_status(ctx, st);
        return 0;
    }

    if (strcmp(action, "status") == 0) {
        publish_status(ctx, st);
        return 0;
    }

    ps_warn("flow_tracker: unknown flow_control action '%s'", action);
    return -1;
}

static void ft_mod_on_packet(ps_module_ctx_t *ctx,
                              const uint8_t *pkt, uint32_t len,
                              uint64_t ts_usec, int handle_id)
{
    struct flow_mod_state *st = (struct flow_mod_state *)ctx->userdata;
    if (!st || !st->table) return;

    /* Accept packets from any of our active capture handles */
    int matched = 0;
    for (int i = 0; i < FT_MOD_MAX_INTERFACES; i++) {
        if (st->slots[i].pcap_handle == handle_id) {
            matched = 1;
            break;
        }
    }
    if (!matched) return;

    static uint64_t ft_pkt_count = 0;
    int rc = ps_flow_table_process_packet(st->table, pkt, len, ts_usec);
    if (rc < 0) {
        ps_debug("flow_tracker: process_packet returned %d (len=%u)", rc, len);
    }
    ft_pkt_count++;
    if ((ft_pkt_count & 0xFF) == 1) {
        ps_info("flow_tracker: processed %llu packets (table=%d flows)",
                (unsigned long long)ft_pkt_count,
                ps_flow_table_count(st->table));
    }
}

static void ft_mod_tick(ps_module_ctx_t *ctx, uint64_t now_usec)
{
    struct flow_mod_state *st = (struct flow_mod_state *)ctx->userdata;
    if (!st || !st->table || !st->exporter) return;

    if (st->last_expire_time != 0 &&
        (now_usec - st->last_expire_time) < FT_MOD_EXPIRE_INTERVAL_US)
        return;

    st->last_expire_time = now_usec;

    /* 1. Export idle-expired flows (removed from table) */
    struct ps_flow expired[FT_MOD_EXPIRE_BATCH];
    int n = ps_flow_table_expire(st->table, now_usec,
                                  expired, FT_MOD_EXPIRE_BATCH);
    if (n > 0) {
        int sent = ps_nf_exporter_send(st->exporter, expired, n);
        if (sent < 0) {
            ps_warn("flow_tracker: NetFlow export failed for %d expired flows", n);
        } else {
            ps_info("flow_tracker: exported %d expired flows (%d UDP packets)", n, sent);
        }
    }

    /* 2. Snapshot active flows (non-destructive — keeps them in table).
     * This ensures the UI sees live traffic without waiting for idle expiry. */
    struct ps_flow active[FT_MOD_EXPIRE_BATCH];
    int na = ps_flow_table_snapshot(st->table, st->last_snapshot_time,
                                     active, FT_MOD_EXPIRE_BATCH);
    st->last_snapshot_time = now_usec;
    if (na > 0) {
        int sent = ps_nf_exporter_send(st->exporter, active, na);
        if (sent < 0) {
            ps_warn("flow_tracker: NetFlow export failed for %d active flows", na);
        } else {
            ps_info("flow_tracker: exported %d active flows (%d UDP packets)", na, sent);
        }
    }
}

static void ft_mod_shutdown(ps_module_ctx_t *ctx)
{
    struct flow_mod_state *st = (struct flow_mod_state *)ctx->userdata;
    if (!st) return;

    /* Flush remaining flows */
    if (st->table && st->exporter) {
        uint64_t flush_ts = UINT64_MAX;
        struct ps_flow expired[FT_MOD_EXPIRE_BATCH];
        int total = 0;
        int n;

        do {
            n = ps_flow_table_expire(st->table, flush_ts,
                                      expired, FT_MOD_EXPIRE_BATCH);
            if (n > 0) {
                int sent = ps_nf_exporter_send(st->exporter, expired, n);
                if (sent < 0)
                    ps_warn("flow_tracker: flush export failed for %d flows", n);
                total += n;
            }
        } while (n == FT_MOD_EXPIRE_BATCH);

        ps_info("flow_tracker: flushed %d flows on shutdown", total);
    }

    if (st->exporter) {
        ps_nf_exporter_destroy(st->exporter);
        st->exporter = NULL;
    }
    if (st->table) {
        ps_flow_table_destroy(st->table);
        st->table = NULL;
    }

    free(st);
    ctx->userdata = NULL;
    ps_info("flow_tracker: shutdown complete");
}

/* ------------------------------------------------------------------ */
/* Public snapshot export                                               */
/* ------------------------------------------------------------------ */

#define FT_SNAPSHOT_MAX 65536   /* max flows to snapshot at once */
#define FT_SNAPSHOT_CAP 500     /* max flows to serialize in one response */

/* Sort comparator: descending total bytes (octets[0]+octets[1]) */
static int flow_cmp_bytes_desc(const void *a, const void *b)
{
    const struct ps_flow *fa = (const struct ps_flow *)a;
    const struct ps_flow *fb = (const struct ps_flow *)b;
    uint64_t ba = fa->octets[0] + fa->octets[1];
    uint64_t bb = fb->octets[0] + fb->octets[1];
    if (bb > ba) return 1;
    if (bb < ba) return -1;
    return 0;
}

/*
 * Public: serialize current flow table to JSON for query.flows responses.
 * Caller provides buffer. Returns bytes written or 0 on error.
 *
 * Output format:
 *   {"flow_count":N,"flows":[
 *     {"src_ip":"...","dst_ip":"...","proto":6,
 *      "src_port":443,"dst_port":54321,
 *      "packets_fwd":100,"packets_rev":50,
 *      "bytes_fwd":15000,"bytes_rev":3000,
 *      "duration_sec":30},
 *     ...
 *   ]}
 */
int ps_flow_tracker_snapshot_json(struct ps_module_registry *reg,
                                   char *buf, size_t bufsz)
{
    if (!reg || !buf || bufsz < 64) return 0;

    /* Find the flow_tracker module instance */
    struct flow_mod_state *st = NULL;
    for (int i = 0; i < reg->count; i++) {
        if (strcmp(reg->instances[i].module->name, "flow_tracker") == 0) {
            st = (struct flow_mod_state *)reg->instances[i].ctx.userdata;
            break;
        }
    }
    if (!st || !st->table) {
        /* No flow table — return empty response */
        int n = snprintf(buf, bufsz, "{\"flow_count\":0,\"flows\":[]}");
        return (n > 0 && (size_t)n < bufsz) ? n : 0;
    }

    /* Snapshot all active flows */
    struct ps_flow *flows = malloc(FT_SNAPSHOT_MAX * sizeof(struct ps_flow));
    if (!flows) return 0;

    int total = ps_flow_table_snapshot(st->table, 0, flows, FT_SNAPSHOT_MAX);
    if (total < 0) total = 0;

    /* Sort by total bytes descending, cap at FT_SNAPSHOT_CAP */
    if (total > 1)
        qsort(flows, (size_t)total, sizeof(struct ps_flow), flow_cmp_bytes_desc);

    int emit = (total < FT_SNAPSHOT_CAP) ? total : FT_SNAPSHOT_CAP;

    /* Build JSON manually to avoid a ps_json dependency on large arrays */
    size_t pos = 0;
    int n;

    n = snprintf(buf + pos, bufsz - pos, "{\"flow_count\":%d,\"flows\":[", total);
    if (n < 0 || (size_t)n >= bufsz - pos) { free(flows); return 0; }
    pos += (size_t)n;

    for (int i = 0; i < emit && pos < bufsz - 2; i++) {
        const struct ps_flow *f = &flows[i];
        char src_str[INET6_ADDRSTRLEN] = "?";
        char dst_str[INET6_ADDRSTRLEN] = "?";

        int af = (f->key.af == AF_INET6) ? AF_INET6 : AF_INET;
        int addr_len = (af == AF_INET6) ? 16 : 4;
        (void)addr_len;
        inet_ntop(af, f->key.src_addr, src_str, sizeof(src_str));
        inet_ntop(af, f->key.dst_addr, dst_str, sizeof(dst_str));

        int64_t dur = 0;
        if (f->flow_last > f->flow_start)
            dur = (int64_t)((f->flow_last - f->flow_start) / 1000000ULL);

        if (i > 0) {
            if (pos < bufsz - 1) buf[pos++] = ',';
        }

        n = snprintf(buf + pos, bufsz - pos,
            "{\"src_ip\":\"%s\",\"dst_ip\":\"%s\","
            "\"proto\":%u,\"src_port\":%u,\"dst_port\":%u,"
            "\"packets_fwd\":%llu,\"packets_rev\":%llu,"
            "\"bytes_fwd\":%llu,\"bytes_rev\":%llu,"
            "\"duration_sec\":%lld}",
            src_str, dst_str,
            (unsigned)f->key.proto,
            (unsigned)f->key.src_port,
            (unsigned)f->key.dst_port,
            (unsigned long long)f->packets[0],
            (unsigned long long)f->packets[1],
            (unsigned long long)f->octets[0],
            (unsigned long long)f->octets[1],
            (long long)dur);

        if (n < 0 || (size_t)n >= bufsz - pos) break;
        pos += (size_t)n;
    }

    free(flows);

    /* Close the array + object */
    n = snprintf(buf + pos, bufsz - pos, "]}");
    if (n < 0 || (size_t)n >= bufsz - pos) return 0;
    pos += (size_t)n;

    return (int)pos;
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

const ps_module_t ps_flow_tracker_module = {
    .name        = "flow_tracker",
    .description = "Command-driven flow tracking with NetFlow v5/v9 export",
    .version     = "2.0",
    .flags       = PS_MOD_PASSIVE | PS_MOD_NEEDS_PCAP,

    .init        = ft_mod_init,
    .shutdown    = ft_mod_shutdown,
    .on_packet   = ft_mod_on_packet,
    .on_job      = ft_mod_on_job,
    .on_response = NULL,
    .tick        = ft_mod_tick,
};
