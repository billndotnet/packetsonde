/*
 * iface_monitor — passive, tick-driven interface change reporter.
 *
 * On each throttled tick it re-snapshots the host's interfaces (getifaddrs) and
 * diffs against the previous snapshot, publishing a finding per change:
 *   net.iface.added | net.iface.removed | net.iface.state_change | net.iface.addr_change
 *
 * Detection is poll-on-tick (no netlink / event loop). Interval is
 * PS_IFACE_MONITOR_INTERVAL seconds (default 5; 0 disables diffing).
 *
 * (Dynamic re-capture is wired in a later task; this revision only reports.)
 */
#include "packetsonde/module_api.h"
#include "iface_snapshot.h"
#include "json.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>

#define PS_IFACE_MONITOR_DEFAULT_INTERVAL_SEC 5

struct iface_monitor_state {
    struct ps_iface_snap prev[PS_IFACE_SNAP_MAX];
    int      nprev;
    uint64_t last_usec;
    uint64_t interval_usec; /* 0 = module inert */
};

/* Build + publish one finding. channel == the kind string. */
static void emit_finding(ps_module_ctx_t *ctx, const struct ps_iface_change *c)
{
    char buf[512];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    const char *kind;
    const char *severity = "info";

    ps_json_object_begin(&j);
    switch (c->kind) {
    case PS_IFC_ADDED:
        kind = "net.iface.added";
        ps_json_key_string(&j, "iface", c->name);
        ps_json_key_bool(&j, "up", c->new_up);
        ps_json_key_bool(&j, "running", c->new_running);
        break;
    case PS_IFC_REMOVED:
        kind = "net.iface.removed";
        ps_json_key_string(&j, "iface", c->name);
        break;
    case PS_IFC_STATE:
        kind = "net.iface.state_change";
        if (!c->new_up) severity = "warning";
        ps_json_key_string(&j, "iface", c->name);
        ps_json_key_bool(&j, "old_up", c->old_up);
        ps_json_key_bool(&j, "old_running", c->old_running);
        ps_json_key_bool(&j, "new_up", c->new_up);
        ps_json_key_bool(&j, "new_running", c->new_running);
        break;
    case PS_IFC_ADDR:
    default:
        kind = "net.iface.addr_change";
        ps_json_key_string(&j, "iface", c->name);
        break;
    }
    ps_json_key_string(&j, "source", "agent.iface_monitor");
    ps_json_key_string(&j, "severity", severity);
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0 && ctx->publish)
        ctx->publish(ctx, kind, buf, (uint32_t)j.len);
}

static int iface_monitor_init(ps_module_ctx_t *ctx)
{
    struct iface_monitor_state *st = calloc(1, sizeof(*st));
    if (!st) return -1;

    const char *iv = getenv("PS_IFACE_MONITOR_INTERVAL");
    int sec = iv ? atoi(iv) : PS_IFACE_MONITOR_DEFAULT_INTERVAL_SEC;
    if (sec < 0) sec = 0;
    st->interval_usec = (uint64_t)sec * 1000000ULL;

    int n = ps_iface_snapshot(st->prev, PS_IFACE_SNAP_MAX);
    st->nprev = (n > 0) ? n : 0;
    st->last_usec = 0;

    ctx->userdata = st;
    ps_info("iface_monitor: initialized — interval=%ds, baseline %d interfaces",
            sec, st->nprev);
    return 0;
}

static void iface_monitor_tick(ps_module_ctx_t *ctx, uint64_t now_usec)
{
    struct iface_monitor_state *st = (struct iface_monitor_state *)ctx->userdata;
    if (!st || st->interval_usec == 0) return;
    if (st->last_usec != 0 && (now_usec - st->last_usec) < st->interval_usec) return;

    struct ps_iface_snap cur[PS_IFACE_SNAP_MAX];
    int ncur = ps_iface_snapshot(cur, PS_IFACE_SNAP_MAX);
    if (ncur < 0) {
        /* getifaddrs failed this tick — keep prev, try again next tick. */
        st->last_usec = now_usec;
        return;
    }

    struct ps_iface_change changes[PS_IFACE_SNAP_MAX];
    int nchg = ps_iface_diff(st->prev, st->nprev, cur, ncur,
                             changes, PS_IFACE_SNAP_MAX);

    for (int i = 0; i < nchg; i++)
        emit_finding(ctx, &changes[i]);

    memcpy(st->prev, cur, sizeof(cur[0]) * (size_t)ncur);
    st->nprev = ncur;
    st->last_usec = now_usec;
}

static void iface_monitor_shutdown(ps_module_ctx_t *ctx)
{
    free(ctx->userdata);
    ctx->userdata = NULL;
    ps_info("iface_monitor: shutdown");
}

const ps_module_t ps_iface_monitor_module = {
    .name        = "iface_monitor",
    .description = "Reports interface state/enumeration changes (poll-on-tick)",
    .version     = "1.0",
    .flags       = PS_MOD_PASSIVE,
    .init        = iface_monitor_init,
    .shutdown    = iface_monitor_shutdown,
    .on_packet   = NULL,
    .on_job      = NULL,
    .on_response = NULL,
    .tick        = iface_monitor_tick,
};
