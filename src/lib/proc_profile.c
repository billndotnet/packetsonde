#include "proc_profile.h"
#include "baseline_decide.h"
#include "exe_slug.h"
#include <stdio.h>
#include <string.h>

void ps_pp_init(struct ps_pp_model *m, const struct ps_pp_subject *subj,
                const char *epoch) {
    memset(m, 0, sizeof(*m));
    m->subject = *subj;
    snprintf(m->epoch, sizeof m->epoch, "%s", epoch ? epoch : "");
    ps_blset_init(&m->bl_files, subj->exe);  ps_blset_init(&m->den_files, subj->exe);
    ps_blset_init(&m->bl_dests, subj->exe);  ps_blset_init(&m->den_dests, subj->exe);
}

static int load_set(const char *dir, const char *slug, const char *file,
                    const char *key, const char *exe, struct ps_baseline_set *s) {
    ps_blset_init(s, exe);
    char p[700]; snprintf(p, sizeof p, "%s/%s/%s", dir, slug, file);
    FILE *f = fopen(p, "r"); if (!f) return 0;
    static char j[1 << 16]; size_t n = fread(j, 1, sizeof j - 1, f); fclose(f); j[n] = 0;
    if (key) ps_blset_from_json_key(j, key, s); else ps_blset_from_json(j, s);
    return s->n;
}

int ps_pp_load_baseline(struct ps_pp_model *m, const char *exe, const char *dir) {
    if (!dir) dir = "/var/lib/packetsonde/baseline";
    char slug[256]; if (ps_exe_slug(exe, slug, sizeof slug) != 0) return 0;
    int any = 0;
    any += load_set(dir, slug, "baseline.json", NULL, exe, &m->bl_files);
    any += load_set(dir, slug, "denials.json", NULL, exe, &m->den_files);
    any += load_set(dir, slug, "dests.json", "dests", exe, &m->bl_dests);
    any += load_set(dir, slug, "dest-denials.json", "dests", exe, &m->den_dests);
    m->have_baseline = any > 0;
    return 0;
}

static struct ps_pp_entity *ent_get(struct ps_pp_model *m, const char *id,
                                    enum ps_pp_kind kind, const char *value) {
    int oldest = -1; int64_t oldest_ms = 0;
    for (int i = 0; i < m->nent; i++) {
        if (!m->ent[i].present) continue;
        if (strcmp(m->ent[i].id, id) == 0) return &m->ent[i];
        if (oldest < 0 || m->ent[i].last_ms < oldest_ms) { oldest = i; oldest_ms = m->ent[i].last_ms; }
    }
    int slot;
    if (m->nent < PS_PP_MAX_ENT) slot = m->nent++;
    else slot = oldest;
    struct ps_pp_entity *e = &m->ent[slot];
    memset(e, 0, sizeof(*e));
    snprintf(e->id, sizeof e->id, "%s", id);
    e->kind = kind; snprintf(e->value, sizeof e->value, "%s", value);
    e->present = 1; e->verdict = PS_PP_NA;
    return e;
}

static enum ps_pp_verdict file_verdict(struct ps_pp_model *m, const char *path) {
    if (!m->have_baseline) return PS_PP_NA;
    switch (ps_baseline_decide(&m->bl_files, &m->den_files, path)) {
        case PS_BL_COVERED: return PS_PP_COVERED;
        case PS_BL_ANOMALY: return PS_PP_ANOMALY;
        default:            return PS_PP_NOVEL;
    }
}
static enum ps_pp_verdict dest_verdict(struct ps_pp_model *m, const char *raddr) {
    if (!m->have_baseline) return PS_PP_NA;
    switch (ps_baseline_decide_dest(&m->bl_dests, &m->den_dests, raddr)) {
        case PS_BL_COVERED: return PS_PP_COVERED;
        case PS_BL_ANOMALY: return PS_PP_ANOMALY;
        default:            return PS_PP_NOVEL;
    }
}

static void touch(struct ps_pp_entity *e, const char *ts, int64_t now_ms) {
    if (e->count == 0) snprintf(e->first, sizeof e->first, "%s", ts);
    snprintf(e->last, sizeof e->last, "%s", ts);
    e->count++; e->last_ms = now_ms; e->dirty = 1;
}

void ps_pp_fold(struct ps_pp_model *m, const struct ps_activity *a, int64_t now_ms) {
    if (m->rates.mark_ms == 0) m->rates.mark_ms = now_ms;
    if (a->proc.exe[0]) {
        m->subject.uid = a->proc.uid;
        if (a->proc.cgroup[0]) snprintf(m->subject.cgroup, sizeof m->subject.cgroup, "%s", a->proc.cgroup);
        if (a->proc.mac_label[0]) snprintf(m->subject.mac_label, sizeof m->subject.mac_label, "%s", a->proc.mac_label);
        if (a->proc.mac_mode[0]) snprintf(m->subject.mac_mode, sizeof m->subject.mac_mode, "%s", a->proc.mac_mode);
        if (m->subject.mode == PS_PP_BY_PID) m->subject.pid = a->proc.pid;
        if (a->nanc > 0) {
            m->subject.nanc = a->nanc > PS_ACT_MAX_ANC ? PS_ACT_MAX_ANC : a->nanc;
            for (int i = 0; i < m->subject.nanc; i++) {
                m->subject.anc[i].pid = a->anc[i].pid;
                snprintf(m->subject.anc[i].comm, 64, "%s", a->anc[i].comm);
            }
        }
    }
    if (strcmp(a->event, "open") == 0)        m->rates.n_open++;
    else if (strcmp(a->event, "connect") == 0) m->rates.n_connect++;
    else if (strcmp(a->event, "exec") == 0)    m->rates.n_exec++;

    if (a->path[0]) {
        char id[544]; snprintf(id, sizeof id, "file:%s", a->path);
        struct ps_pp_entity *e = ent_get(m, id, PS_PP_FILE, a->path);
        e->verdict = file_verdict(m, a->path);
        touch(e, a->ts, now_ms);
    }
    for (int i = 0; i < a->nsock; i++) {
        if (!a->sock[i].raddr[0]) continue;
        char id[544]; snprintf(id, sizeof id, "dest:%s", a->sock[i].raddr);
        struct ps_pp_entity *e = ent_get(m, id, PS_PP_DEST, a->sock[i].raddr);
        snprintf(e->state, sizeof e->state, "%s", a->sock[i].state);
        e->verdict = dest_verdict(m, a->sock[i].raddr);
        touch(e, a->ts, now_ms);
    }
    if (strcmp(a->event, "exec") == 0 && a->path[0]) {
        char id[544]; snprintf(id, sizeof id, "proc:%s", a->path);
        struct ps_pp_entity *e = ent_get(m, id, PS_PP_PROC, a->path);
        e->verdict = PS_PP_NA;
        touch(e, a->ts, now_ms);
    }
}

void ps_pp_tick_rates(struct ps_pp_model *m, int64_t now_ms) {
    int64_t dt = now_ms - m->rates.mark_ms;
    if (dt <= 0) return;
    double secs = (double)dt / 1000.0;
    m->rates.open_s    = (double)(m->rates.n_open    - m->rates.open_mark)    / secs;
    m->rates.connect_s = (double)(m->rates.n_connect - m->rates.connect_mark) / secs;
    m->rates.exec_s    = (double)(m->rates.n_exec    - m->rates.exec_mark)    / secs;
    m->rates.open_mark = m->rates.n_open;
    m->rates.connect_mark = m->rates.n_connect;
    m->rates.exec_mark = m->rates.n_exec;
    m->rates.mark_ms = now_ms;
}
