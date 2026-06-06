#include "activity_record.h"
#include "json.h"
#include "json_extract.h"
#include <string.h>

int ps_activity_to_json(const struct ps_activity *a, char *out, size_t cap) {
    struct ps_json j; ps_json_init(&j, out, cap);
    ps_json_object_begin(&j);
    ps_json_key_int(&j, "v", 1);
    ps_json_key_string(&j, "ts", a->ts);
    ps_json_key_string(&j, "event", a->event);
    ps_json_key_string(&j, "path", a->path);
    ps_json_key_bool(&j, "partial", a->partial);

    ps_json_key_object_begin(&j, "process");
    ps_json_key_int(&j, "pid", a->proc.pid);
    ps_json_key_int(&j, "ppid", a->proc.ppid);
    ps_json_key_int(&j, "uid", a->proc.uid);
    ps_json_key_int(&j, "sid", a->proc.sid);
    ps_json_key_int(&j, "start_ticks", (int64_t)a->proc.start_time);
    ps_json_key_string(&j, "comm", a->proc.comm);
    ps_json_key_string(&j, "exe", a->proc.exe);
    ps_json_key_string(&j, "cmdline", a->proc.cmdline);
    ps_json_key_string(&j, "cgroup", a->proc.cgroup);
    ps_json_key_object_begin(&j, "mac");
    ps_json_key_string(&j, "label", a->proc.mac_label);
    ps_json_key_string(&j, "mode", a->proc.mac_mode);
    ps_json_object_end(&j);   /* mac */
    ps_json_object_end(&j);   /* process */

    ps_json_array_begin(&j, "ancestry");
    for (int i = 0; i < a->nanc; i++) {
        ps_json_object_begin(&j);
        ps_json_key_int(&j, "pid", a->anc[i].pid);
        ps_json_key_string(&j, "comm", a->anc[i].comm);
        ps_json_key_int(&j, "depth", a->anc[i].depth);
        ps_json_key_int(&j, "start_ticks", (int64_t)a->anc[i].start_time);
        ps_json_object_end(&j);
    }
    ps_json_array_end(&j);

    ps_json_array_begin(&j, "sockets");
    for (int i = 0; i < a->nsock; i++) {
        ps_json_object_begin(&j);
        ps_json_key_int(&j, "owner_pid", a->sock[i].owner_pid);
        ps_json_key_string(&j, "owner_comm", a->sock[i].owner_comm);
        ps_json_key_int(&j, "depth", a->sock[i].depth);
        ps_json_key_string(&j, "proto", a->sock[i].proto);
        ps_json_key_string(&j, "laddr", a->sock[i].laddr);
        ps_json_key_string(&j, "raddr", a->sock[i].raddr);
        ps_json_key_string(&j, "state", a->sock[i].state);
        ps_json_object_end(&j);
    }
    ps_json_array_end(&j);

    ps_json_object_end(&j);
    return ps_json_finish(&j);
}

/* Copy the next brace-balanced {...} object starting at or after *p into buf,
 * advancing *p past it. Returns 1 if an object was copied, 0 if none remains. */
static int next_json_object(const char **p, char *buf, size_t cap) {
    const char *s = *p;
    while (*s && *s != '{') { if (*s == ']') { *p = s; return 0; } s++; }
    if (*s != '{') return 0;
    int depth = 0; int instr = 0;
    const char *start = s;
    for (; *s; s++) {
        char ch = *s;
        if (instr) { if (ch == '\\' && s[1]) { s++; } else if (ch == '"') instr = 0; }
        else if (ch == '"') instr = 1;
        else if (ch == '{') depth++;
        else if (ch == '}') { depth--; if (depth == 0) { s++; break; } }
    }
    size_t len = (size_t)(s - start);
    if (len == 0 || len >= cap) return 0;
    memcpy(buf, start, len); buf[len] = '\0';
    *p = s;
    return 1;
}

int ps_activity_from_json(const char *json, struct ps_activity *out) {
    if (!json || json[0] != '{') return -1;
    memset(out, 0, sizeof(*out));
    long iv;
    if (ps_json_extract_string(json, "ts", out->ts, sizeof out->ts) < 0) return -1;
    ps_json_extract_string(json, "event", out->event, sizeof out->event);
    ps_json_extract_string(json, "path", out->path, sizeof out->path);
    if (ps_json_extract_int(json, "pid", &iv) == 0) out->proc.pid = (int)iv;
    if (ps_json_extract_int(json, "ppid", &iv) == 0) out->proc.ppid = (int)iv;
    if (ps_json_extract_int(json, "uid", &iv) == 0) out->proc.uid = (int)iv;
    if (ps_json_extract_int(json, "sid", &iv) == 0) out->proc.sid = (int)iv;
    if (ps_json_extract_int(json, "start_ticks", &iv) == 0) out->proc.start_time = (unsigned long long)iv;
    ps_json_extract_string(json, "comm", out->proc.comm, sizeof out->proc.comm);
    ps_json_extract_string(json, "exe", out->proc.exe, sizeof out->proc.exe);
    ps_json_extract_string(json, "cmdline", out->proc.cmdline, sizeof out->proc.cmdline);
    ps_json_extract_string(json, "cgroup", out->proc.cgroup, sizeof out->proc.cgroup);
    ps_json_extract_string(json, "label", out->proc.mac_label, sizeof out->proc.mac_label);
    ps_json_extract_string(json, "mode", out->proc.mac_mode, sizeof out->proc.mac_mode);

    const char *anc = strstr(json, "\"ancestry\"");
    if (anc) {
        const char *p = strchr(anc, '[');
        char obj[256];
        while (p && out->nanc < PS_ACT_MAX_ANC && next_json_object(&p, obj, sizeof obj)) {
            if (ps_json_extract_int(obj, "pid", &iv) == 0) out->anc[out->nanc].pid = (int)iv;
            if (ps_json_extract_int(obj, "depth", &iv) == 0) out->anc[out->nanc].depth = (int)iv;
            if (ps_json_extract_int(obj, "start_ticks", &iv) == 0) out->anc[out->nanc].start_time = (unsigned long long)iv;
            ps_json_extract_string(obj, "comm", out->anc[out->nanc].comm, sizeof out->anc[out->nanc].comm);
            out->nanc++;
        }
    }
    const char *sk = strstr(json, "\"sockets\"");
    if (sk) {
        const char *p = strchr(sk, '[');
        char obj[512];
        while (p && out->nsock < PS_ACT_MAX_SOCK && next_json_object(&p, obj, sizeof obj)) {
            struct ps_act_socket *s = &out->sock[out->nsock];
            if (ps_json_extract_int(obj, "owner_pid", &iv) == 0) s->owner_pid = (int)iv;
            if (ps_json_extract_int(obj, "depth", &iv) == 0) s->depth = (int)iv;
            ps_json_extract_string(obj, "owner_comm", s->owner_comm, sizeof s->owner_comm);
            ps_json_extract_string(obj, "proto", s->proto, sizeof s->proto);
            ps_json_extract_string(obj, "laddr", s->laddr, sizeof s->laddr);
            ps_json_extract_string(obj, "raddr", s->raddr, sizeof s->raddr);
            ps_json_extract_string(obj, "state", s->state, sizeof s->state);
            out->nsock++;
        }
    }
    return 0;
}
