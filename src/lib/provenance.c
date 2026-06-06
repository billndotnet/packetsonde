#include "provenance.h"
#include "json.h"
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

/* True if `path` is exactly, or a child of, one of the comma-separated prefixes
 * in `set`. Boundary-correct: "/tmp" matches "/tmp" and "/tmp/x" but NOT
 * "/tmpfoo". */
static int path_in_set(const char *path, const char *set) {
    if (!path || !set || !set[0]) return 0;
    const char *p = set;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        while (len > 0 && p[len - 1] == '/') len--;   /* tolerate trailing slash */
        if (len > 0 && strncmp(path, p, len) == 0 &&
            (path[len] == '\0' || path[len] == '/'))
            return 1;
        if (!comma) break;
        p = comma + 1;
    }
    return 0;
}

const char *ps_provenance_classify(const char *event, const char *path,
                                   unsigned int mode, const struct ps_prov_cfg *cfg) {
    if (!cfg || !cfg->enabled || !event || !path) return "";
    if (strcmp(event, "write") == 0) {
        if (path_in_set(path, cfg->sensitive_paths)) return "write_sensitive_path";
        if ((mode & (S_IXUSR | S_IXGRP | S_IXOTH)) &&
            path_in_set(path, cfg->transient_paths)) return "write_executable";
        return "";
    }
    if (strcmp(event, "exec") == 0) {
        if (path_in_set(path, cfg->transient_paths)) return "exec_from_transient";
        return "";
    }
    return "";
}

/* Copy raddr's IP (drop ":port") into out. Handles "1.2.3.4:443" and
 * "[2001:db8::1]:443" (brackets retained — acceptable for v1). */
static void raddr_ip(const char *raddr, char *out, size_t cap) {
    const char *colon = strrchr(raddr, ':');
    size_t len = colon ? (size_t)(colon - raddr) : strlen(raddr);
    if (len >= cap) len = cap - 1;
    memcpy(out, raddr, len); out[len] = '\0';
}

static const char *prov_severity(const char *trigger) {
    if (strcmp(trigger, "write_executable") == 0)    return "high";
    if (strcmp(trigger, "write_sensitive_path") == 0) return "high";
    return "medium";   /* exec_from_transient (backstop, noisier) */
}

int ps_provenance_build_record(const struct ps_activity *a, const char *trigger,
                               const char *host, char *out, size_t cap) {
    if (!a || !trigger || !out) return -1;

    /* session_src_ip: first ancestor-owned (depth>0) ESTABLISHED tcp socket.
     * Count them: exactly one -> firm; more than one -> tentative. */
    const char *sess_raddr = NULL; int sess_count = 0;
    for (int i = 0; i < a->nsock; i++) {
        const struct ps_act_socket *s = &a->sock[i];
        if (s->depth > 0 && strcmp(s->proto, "tcp") == 0 &&
            strcmp(s->state, "ESTABLISHED") == 0) {
            if (!sess_raddr) sess_raddr = s->raddr;
            sess_count++;
        }
    }

    struct ps_json j; ps_json_init(&j, out, cap);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "host", host ? host : "");
    ps_json_key_string(&j, "severity", prov_severity(trigger));
    ps_json_key_string(&j, "confidence", "firm");
    ps_json_key_object_begin(&j, "target");
    ps_json_key_string(&j, "path", a->path);
    ps_json_object_end(&j);
    ps_json_key_string(&j, "trigger", trigger);
    ps_json_key_string(&j, "event", a->event);

    ps_json_key_object_begin(&j, "writer");
    ps_json_key_int(&j, "pid", a->proc.pid);
    ps_json_key_int(&j, "start_ticks", (int64_t)a->proc.start_time);
    ps_json_key_int(&j, "uid", a->proc.uid);
    ps_json_key_string(&j, "exe", a->proc.exe);
    ps_json_key_string(&j, "cmdline", a->proc.cmdline);
    ps_json_key_string(&j, "cgroup", a->proc.cgroup);
    ps_json_key_string(&j, "mac_label", a->proc.mac_label);
    ps_json_object_end(&j);

    ps_json_array_begin(&j, "ancestry");
    for (int i = 0; i < a->nanc; i++) {
        ps_json_object_begin(&j);
        ps_json_key_int(&j, "pid", a->anc[i].pid);
        ps_json_key_string(&j, "comm", a->anc[i].comm);
        ps_json_key_int(&j, "start_ticks", (int64_t)a->anc[i].start_time);
        ps_json_object_end(&j);
    }
    ps_json_array_end(&j);

    /* cap shipped sockets at 8 — the bundle must fit PS_OBS_ITEM_MAX (4096). */
    ps_json_array_begin(&j, "sockets");
    int emitted = 0;
    for (int i = 0; i < a->nsock && emitted < 8; i++, emitted++) {
        ps_json_object_begin(&j);
        ps_json_key_string(&j, "proto", a->sock[i].proto);
        ps_json_key_string(&j, "laddr", a->sock[i].laddr);
        ps_json_key_string(&j, "raddr", a->sock[i].raddr);
        ps_json_key_string(&j, "state", a->sock[i].state);
        ps_json_key_int(&j, "owner_pid", a->sock[i].owner_pid);
        ps_json_object_end(&j);
    }
    ps_json_array_end(&j);

    if (sess_raddr) {
        char ip[64]; raddr_ip(sess_raddr, ip, sizeof ip);
        ps_json_key_string(&j, "session_src_ip", ip);
        ps_json_key_string(&j, "session_src_ip_confidence", sess_count == 1 ? "firm" : "tentative");
    }

    ps_json_object_end(&j);
    return ps_json_finish(&j);
}
