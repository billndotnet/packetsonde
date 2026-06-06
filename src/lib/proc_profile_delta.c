#include "proc_profile_delta.h"
#include "json.h"
#include "json_extract.h"
#include <stdio.h>
#include <string.h>

static const char *verdict_str(enum ps_pp_verdict v) {
    return v==PS_PP_COVERED?"covered":v==PS_PP_NOVEL?"novel":v==PS_PP_ANOMALY?"anomaly":"na";
}
static enum ps_pp_verdict verdict_of(const char *s) {
    if(!strcmp(s,"covered"))return PS_PP_COVERED;
    if(!strcmp(s,"novel"))return PS_PP_NOVEL;
    if(!strcmp(s,"anomaly"))return PS_PP_ANOMALY;
    return PS_PP_NA;
}
static const char *kind_str(enum ps_pp_kind k){ return k==PS_PP_FILE?"file":k==PS_PP_DEST?"dest":"proc"; }
static enum ps_pp_kind kind_of(const char *s){ return !strcmp(s,"file")?PS_PP_FILE:!strcmp(s,"dest")?PS_PP_DEST:PS_PP_PROC; }

int ps_pp_keyframe_json(const struct ps_pp_model *m, const char *host,
                        char *out, size_t cap) {
    struct ps_json j; ps_json_init(&j, out, cap);
    ps_json_object_begin(&j);
    ps_json_key_int(&j, "v", 1);
    ps_json_key_string(&j, "type", "keyframe");
    ps_json_key_string(&j, "epoch", m->epoch);
    ps_json_key_int(&j, "seq", 0);
    ps_json_key_string(&j, "host", host ? host : "");
    ps_json_key_object_begin(&j, "subject");
    ps_json_key_string(&j, "mode", m->subject.mode == PS_PP_BY_PID ? "pid" : "exe");
    ps_json_key_int(&j, "pid", m->subject.pid);
    ps_json_key_string(&j, "exe", m->subject.exe);
    ps_json_key_int(&j, "uid", m->subject.uid);
    ps_json_key_string(&j, "cgroup", m->subject.cgroup);
    ps_json_key_string(&j, "mac_label", m->subject.mac_label);
    ps_json_object_end(&j);
    ps_json_key_object_begin(&j, "rates");
    ps_json_key_int(&j, "open_s", (long)m->rates.open_s);
    ps_json_key_int(&j, "connect_s", (long)m->rates.connect_s);
    ps_json_key_int(&j, "exec_s", (long)m->rates.exec_s);
    ps_json_object_end(&j);
    ps_json_array_begin(&j, "entities");
    for (int i = 0; i < m->nent; i++) {
        const struct ps_pp_entity *e = &m->ent[i];
        if (!e->present) continue;
        ps_json_object_begin(&j);
        ps_json_key_string(&j, "id", e->id);
        ps_json_key_string(&j, "kind", kind_str(e->kind));
        ps_json_key_string(&j, "value", e->value);
        if (e->state[0]) ps_json_key_string(&j, "state", e->state);
        ps_json_key_int(&j, "count", (long)e->count);
        ps_json_key_string(&j, "first", e->first);
        ps_json_key_string(&j, "last", e->last);
        ps_json_key_string(&j, "verdict", verdict_str(e->verdict));
        ps_json_object_end(&j);
    }
    ps_json_array_end(&j);
    ps_json_object_end(&j);
    return ps_json_finish(&j);
}

int ps_pp_delta_json(struct ps_pp_model *m, char *out, size_t cap) {
    int any = 0;
    for (int i = 0; i < m->nent; i++) if (m->ent[i].present && m->ent[i].dirty) { any = 1; break; }
    if (!any) return 0;
    m->seq++;
    struct ps_json j; ps_json_init(&j, out, cap);
    ps_json_object_begin(&j);
    ps_json_key_int(&j, "v", 1);
    ps_json_key_string(&j, "type", "delta");
    ps_json_key_string(&j, "epoch", m->epoch);
    ps_json_key_int(&j, "seq", (long)m->seq);
    ps_json_array_begin(&j, "ops");
    for (int i = 0; i < m->nent; i++) {
        struct ps_pp_entity *e = &m->ent[i];
        if (!e->present || !e->dirty) continue;
        ps_json_object_begin(&j);
        ps_json_key_string(&j, "op", "entity_set");
        ps_json_key_string(&j, "id", e->id);
        ps_json_key_string(&j, "kind", kind_str(e->kind));
        ps_json_key_string(&j, "value", e->value);
        if (e->state[0]) ps_json_key_string(&j, "state", e->state);
        ps_json_key_int(&j, "count", (long)e->count);
        ps_json_key_string(&j, "first", e->first);
        ps_json_key_string(&j, "last", e->last);
        ps_json_key_string(&j, "verdict", verdict_str(e->verdict));
        ps_json_object_end(&j);
        e->dirty = 0;
    }
    ps_json_array_end(&j);
    ps_json_object_end(&j);
    return ps_json_finish(&j);
}

static void upsert(struct ps_pp_model *m, const char *obj) {
    char id[544]; if (ps_json_extract_string(obj, "id", id, sizeof id) < 0) return;
    struct ps_pp_entity *e = NULL;
    for (int i = 0; i < m->nent; i++) if (m->ent[i].present && !strcmp(m->ent[i].id, id)) { e = &m->ent[i]; break; }
    if (!e) {
        if (m->nent >= PS_PP_MAX_ENT) return;
        e = &m->ent[m->nent++]; memset(e, 0, sizeof(*e));
        snprintf(e->id, sizeof e->id, "%s", id); e->present = 1;
    }
    char tmp[32]; long iv;
    if (ps_json_extract_string(obj, "kind", tmp, sizeof tmp) >= 0) e->kind = kind_of(tmp);
    ps_json_extract_string(obj, "value", e->value, sizeof e->value);
    e->state[0] = '\0'; ps_json_extract_string(obj, "state", e->state, sizeof e->state);
    if (ps_json_extract_int(obj, "count", &iv) == 0) e->count = (uint64_t)iv;
    ps_json_extract_string(obj, "first", e->first, sizeof e->first);
    ps_json_extract_string(obj, "last", e->last, sizeof e->last);
    if (ps_json_extract_string(obj, "verdict", tmp, sizeof tmp) >= 0) e->verdict = verdict_of(tmp);
}

static int next_obj(const char **p, char *buf, size_t cap) {
    const char *s = *p;
    while (*s && *s != '{') { if (*s == ']') { *p = s; return 0; } s++; }
    if (*s != '{') return 0;
    int depth = 0, instr = 0; const char *start = s;
    for (; *s; s++) {
        char ch = *s;
        if (instr) { if (ch=='\\'&&s[1]) s++; else if (ch=='"') instr=0; }
        else if (ch=='"') instr=1; else if (ch=='{') depth++;
        else if (ch=='}') { depth--; if (depth==0){ s++; break; } }
    }
    size_t len = (size_t)(s - start);
    if (len == 0 || len >= cap) return 0;
    memcpy(buf, start, len); buf[len] = '\0'; *p = s; return 1;
}

enum ps_pp_apply ps_pp_apply_json(struct ps_pp_model *m, const char *json) {
    char type[16]; if (ps_json_extract_string(json, "type", type, sizeof type) < 0) return PS_PP_APPLY_DESYNC;
    char epoch[24]; ps_json_extract_string(json, "epoch", epoch, sizeof epoch);
    long seq = 0; ps_json_extract_int(json, "seq", &seq);

    if (strcmp(type, "keyframe") == 0) {
        memset(m->ent, 0, sizeof(m->ent)); m->nent = 0;
        snprintf(m->epoch, sizeof m->epoch, "%s", epoch); m->seq = 0;
        ps_json_extract_string(json, "exe", m->subject.exe, sizeof m->subject.exe);
        const char *arr = strstr(json, "\"entities\"");
        if (arr) { const char *p = strchr(arr, '['); char obj[2048];
                   while (p && next_obj(&p, obj, sizeof obj)) upsert(m, obj); }
        return PS_PP_APPLY_OK;
    }
    if (strcmp(epoch, m->epoch) != 0) return PS_PP_APPLY_DESYNC;
    if ((uint64_t)seq != m->seq + 1) return PS_PP_APPLY_DESYNC;
    m->seq = (uint64_t)seq;
    const char *arr = strstr(json, "\"ops\"");
    if (arr) { const char *p = strchr(arr, '['); char obj[2048];
               while (p && next_obj(&p, obj, sizeof obj)) upsert(m, obj); }
    return PS_PP_APPLY_OK;
}
