#include "baseline_monitor.h"
#include "baseline_store.h"
#include "baseline_decide.h"
#include "baseline_set.h"
#include "dest_match.h"
#include "json_extract.h"
#include "json.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define PS_BLSEEN_N 2048
struct bl_seen { char keys[PS_BLSEEN_N][384]; int head, count; };
void *ps_baseline_seen_new(void) { return calloc(1, sizeof(struct bl_seen)); }
void  ps_baseline_seen_free(void *s) { free(s); }
static int seen_add(struct bl_seen *s, const char *key) {
    for (int i = 0; i < s->count; i++) {
        int idx = (s->head - 1 - i + PS_BLSEEN_N) % PS_BLSEEN_N;
        if (!strcmp(s->keys[idx], key)) return 1;
    }
    snprintf(s->keys[s->head], sizeof s->keys[0], "%s", key);
    s->head = (s->head + 1) % PS_BLSEEN_N;
    if (s->count < PS_BLSEEN_N) s->count++;
    return 0;
}

static void emit_finding(void (*emit)(void *, const char *, size_t), void *ctx,
                         const char *kind, const char *exe, const char *path,
                         const char *event, const char *comm) {
    char buf[2048]; struct ps_json j; ps_json_init(&j, buf, sizeof buf);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "source", "agent.baseline_monitor");
    ps_json_key_string(&j, "severity", !strcmp(kind,"anomaly") ? "high" : "info");
    ps_json_key_string(&j, "confidence", !strcmp(kind,"anomaly") ? "firm" : "tentative");
    ps_json_key_string(&j, "kind", kind);
    ps_json_key_string(&j, "exe", exe);
    ps_json_key_string(&j, "entry", path);
    ps_json_key_string(&j, "event", event);
    ps_json_key_string(&j, "comm", comm);
    ps_json_object_end(&j);
    if (ps_json_finish(&j) > 0 && emit) emit(ctx, buf, (size_t)j.len);
}

/* emit a finding for a network dest of the given kind. */
static void emit_dest_finding(void (*emit)(void *, const char *, size_t), void *ctx,
                              const char *kind, const char *exe, const char *raddr, const char *comm) {
    char buf[2048]; struct ps_json j; ps_json_init(&j, buf, sizeof buf);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "source", "agent.baseline_monitor");
    ps_json_key_string(&j, "severity", !strcmp(kind,"anomaly") ? "high" : "info");
    ps_json_key_string(&j, "confidence", !strcmp(kind,"anomaly") ? "firm" : "tentative");
    ps_json_key_string(&j, "kind", kind);
    ps_json_key_string(&j, "signal", "dest");
    ps_json_key_string(&j, "exe", exe);
    ps_json_key_string(&j, "dest", raddr);
    ps_json_key_string(&j, "comm", comm);
    ps_json_object_end(&j);
    if (ps_json_finish(&j) > 0 && emit) emit(ctx, buf, (size_t)j.len);
}

/* the immediate parent comm = first "comm":"..." after "ancestry":[  (empty if none) */
static void extract_parent_comm(const char *rec, char *out, size_t cap) {
    out[0] = 0;
    const char *a = strstr(rec, "\"ancestry\":[");
    if (!a) return;
    const char *c = strstr(a, "\"comm\":\"");
    if (!c) return;
    c += 8;
    const char *e = strchr(c, '"');
    if (!e) return;
    size_t n = (size_t)(e - c); if (n >= cap) n = cap - 1;
    memcpy(out, c, n); out[n] = 0;
}

/* emit a finding for a spawn parent of the given kind. */
static void emit_spawn_finding(void (*emit)(void *, const char *, size_t), void *ctx,
                               const char *kind, const char *exe, const char *parent, const char *comm) {
    char buf[2048]; struct ps_json j; ps_json_init(&j, buf, sizeof buf);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "source", "agent.baseline_monitor");
    ps_json_key_string(&j, "severity", !strcmp(kind,"anomaly") ? "high" : "info");
    ps_json_key_string(&j, "confidence", !strcmp(kind,"anomaly") ? "firm" : "tentative");
    ps_json_key_string(&j, "kind", kind);
    ps_json_key_string(&j, "signal", "spawn");
    ps_json_key_string(&j, "exe", exe);
    ps_json_key_string(&j, "parent", parent);
    ps_json_key_string(&j, "comm", comm);
    ps_json_object_end(&j);
    if (ps_json_finish(&j) > 0 && emit) emit(ctx, buf, (size_t)j.len);
}

int ps_baseline_process_record(const char *rec, const char *state_dir, void *seenv,
                               void (*emit)(void *, const char *, size_t), void *ectx) {
    struct bl_seen *seen = seenv;
    char exe[256], path[512], event[16], comm[64]="";
    if (ps_json_extract_string(rec, "exe", exe, sizeof exe) < 0 || !exe[0]) return 0;
    if (ps_json_extract_string(rec, "path", path, sizeof path) < 0) return 0;
    if (ps_json_extract_string(rec, "event", event, sizeof event) < 0) return 0;
    ps_json_extract_string(rec, "comm", comm, sizeof comm);

    int n = 0;

    /* file-path signal */
    struct ps_baseline_set bl, den;
    ps_baseline_load(state_dir, exe, &bl, &den);
    enum ps_bl_verdict v = ps_baseline_decide(&bl, &den, path);
    if (v != PS_BL_COVERED) {
        char key[384]; snprintf(key, sizeof key, "%s|%s", exe, path);
        if (!seen_add(seen, key)) {
            if (v == PS_BL_ANOMALY) { emit_finding(emit, ectx, "anomaly", exe, path, event, comm); n++; }
            else { ps_baseline_append_candidate(state_dir, exe, path);
                   emit_finding(emit, ectx, "candidate", exe, path, event, comm); n++; }
        }
    }

    /* network-destination signal: every "raddr":"..." in the record's sockets[] */
    struct ps_baseline_set dbl, dden;
    ps_baseline_load_dests(state_dir, exe, &dbl, &dden);
    const char *sp = rec;
    while ((sp = strstr(sp, "\"raddr\":\"")) != NULL) {
        sp += 9;
        const char *se = strchr(sp, '"');
        if (!se) break;
        char raddr[64]; size_t rl = (size_t)(se - sp); if (rl >= sizeof raddr) rl = sizeof raddr - 1;
        memcpy(raddr, sp, rl); raddr[rl] = 0; sp = se + 1;
        if (!raddr[0]) continue;
        enum ps_bl_verdict dv = ps_baseline_decide_dest(&dbl, &dden, raddr);
        if (dv == PS_BL_COVERED) continue;
        char dkey[384]; snprintf(dkey, sizeof dkey, "%s|D|%s", exe, raddr);
        if (seen_add(seen, dkey)) continue;
        if (dv == PS_BL_ANOMALY) { emit_dest_finding(emit, ectx, "anomaly", exe, raddr, comm); n++; }
        else { ps_baseline_append_dest_candidate(state_dir, exe, raddr);
               emit_dest_finding(emit, ectx, "candidate", exe, raddr, comm); n++; }
    }

    /* process-spawn signal: the immediate parent comm */
    char parent[64]; extract_parent_comm(rec, parent, sizeof parent);
    if (parent[0]) {
        struct ps_baseline_set pbl, pden;
        ps_baseline_load_parents(state_dir, exe, &pbl, &pden);
        enum ps_bl_verdict pv = ps_baseline_decide(&pbl, &pden, parent);   /* covered == exact for comms */
        if (pv != PS_BL_COVERED) {
            char pkey[384]; snprintf(pkey, sizeof pkey, "%s|P|%s", exe, parent);
            if (!seen_add(seen, pkey)) {
                if (pv == PS_BL_ANOMALY) { emit_spawn_finding(emit, ectx, "anomaly", exe, parent, comm); n++; }
                else { ps_baseline_append_parent_candidate(state_dir, exe, parent);
                       emit_spawn_finding(emit, ectx, "candidate", exe, parent, comm); n++; }
            }
        }
    }
    return n;
}

/* --- module wiring --- */
#include "module.h"
#include "activity_ring.h"

struct bl_state { int on; int consumer; void *seen; char state_dir[256]; };

static int bl_init(ps_module_ctx_t *ctx) {
    const char *m = getenv("PS_DETECT_BASELINE_MODE");
    struct bl_state *st = calloc(1, sizeof *st);
    if (!st) return -1;
    st->on = (m && !strcmp(m, "on")) ? 1 : 0;
    st->consumer = st->on ? ps_act_ring_register() : -1;   /* own ring consumer (fan-out) */
    st->seen = ps_baseline_seen_new();
    const char *d = getenv("PS_DETECT_BASELINE_STATE_DIR");
    snprintf(st->state_dir, sizeof st->state_dir, "%s", (d && d[0]) ? d : "/var/lib/packetsonde/baseline");
    ctx->userdata = st;
    if (ctx->log) ctx->log(ctx, 1 /* PS_LOG_INFO */, "baseline_monitor: %s", st->on ? "on" : "off");
    return 0;
}
static void bl_shutdown(ps_module_ctx_t *ctx) {
    struct bl_state *st = ctx->userdata;
    if (st) { ps_baseline_seen_free(st->seen); free(st); }
}
struct bl_emit_ctx { ps_module_ctx_t *mctx; };
static void bl_publish(void *c, const char *json, size_t len) {
    struct bl_emit_ctx *e = c;
    const char *ch = strstr(json, "\"kind\":\"anomaly\"") ? "baseline.anomaly" : "baseline.candidate";
    if (e->mctx->publish) e->mctx->publish(e->mctx, ch, json, (uint32_t)len);
}
static void bl_tick(ps_module_ctx_t *ctx, uint64_t now_usec) {
    (void)now_usec;
    struct bl_state *st = ctx->userdata;
    if (!st || !st->on) return;
    static char items[64][PS_ACT_ITEM_MAX];
    int n = ps_act_ring_drain(st->consumer, items, 64);
    struct bl_emit_ctx ec = { ctx };
    for (int i = 0; i < n; i++)
        ps_baseline_process_record(items[i], st->state_dir, st->seen, bl_publish, &ec);
}
const ps_module_t ps_baseline_monitor_module = {
    .name = "baseline_monitor",
    .description = "Learned per-exe behavioral baseline (hybrid learn+enforce)",
    .version = "1.0", .flags = PS_MOD_PASSIVE,
    .init = bl_init, .shutdown = bl_shutdown,
    .on_packet = NULL, .on_job = NULL, .on_response = NULL, .tick = bl_tick,
};
