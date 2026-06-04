#include "baseline_set.h"
#include "json.h"
#include "json_extract.h"
#include <string.h>
#include <stdio.h>

void ps_blset_init(struct ps_baseline_set *s, const char *exe) {
    s->n = 0;
    snprintf(s->exe, sizeof s->exe, "%s", exe ? exe : "");
}

static int under(const char *path, const char *prefix) {
    size_t lp = strlen(prefix);
    if (lp == 0) return 0;
    if (strncmp(path, prefix, lp) != 0) return 0;
    return path[lp] == 0 || path[lp] == '/' || prefix[lp-1] == '/';
}

int ps_blset_add(struct ps_baseline_set *s, const char *path) {
    if (!path || !*path) return -1;
    for (int i = 0; i < s->n; i++) if (!strcmp(s->path[i], path)) return 0;
    if (s->n >= PS_BL_MAX) return -1;
    snprintf(s->path[s->n], PS_BL_PATHLEN, "%s", path);
    s->n++;
    return 1;
}

int ps_blset_covered(const struct ps_baseline_set *s, const char *path) {
    for (int i = 0; i < s->n; i++) if (under(path, s->path[i])) return 1;
    return 0;
}

int ps_blset_to_json(const struct ps_baseline_set *s, char *out, size_t cap) {
    struct ps_json j; ps_json_init(&j, out, cap);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "exe", s->exe);
    ps_json_array_begin(&j, "paths");
    for (int i = 0; i < s->n; i++) ps_json_array_string(&j, s->path[i]);
    ps_json_array_end(&j);
    ps_json_object_end(&j);
    return ps_json_finish(&j);
}

int ps_blset_from_json(const char *json, struct ps_baseline_set *s) {
    if (!json) return -1;
    s->n = 0; s->exe[0] = 0;
    ps_json_extract_string(json, "exe", s->exe, sizeof s->exe);
    const char *p = strstr(json, "\"paths\":[");
    if (!p) return 0;
    p += strlen("\"paths\":[");
    while (*p && *p != ']' && s->n < PS_BL_MAX) {
        const char *q = strchr(p, '"'); const char *close = strchr(p, ']');
        if (!q || (close && q > close)) break;
        q++; const char *e = strchr(q, '"'); if (!e) break;
        size_t len = (size_t)(e - q);
        if (len < PS_BL_PATHLEN) { memcpy(s->path[s->n], q, len); s->path[s->n][len] = 0; s->n++; }
        p = e + 1; const char *comma = strchr(p, ','); close = strchr(p, ']');
        if (!comma || (close && close < comma)) break;
        p = comma + 1;
    }
    return 0;
}

static void parent_dir(const char *path, char *out, size_t cap) {
    const char *slash = strrchr(path, '/');
    size_t len = (slash && slash != path) ? (size_t)(slash - path) : 1;
    if (len >= cap) len = cap - 1;
    memcpy(out, path, len); out[len] = 0;
    if (len == 1 && path[0] == '/') { out[0] = '/'; out[1] = 0; }
}

int ps_blset_rollup(struct ps_baseline_set *s, int threshold) {
    if (threshold < 1) threshold = 1;
    static char dirs[PS_BL_MAX][PS_BL_PATHLEN]; int dn = 0; static int dc[PS_BL_MAX];
    for (int i = 0; i < PS_BL_MAX; i++) dc[i] = 0;
    for (int i = 0; i < s->n; i++) {
        char d[PS_BL_PATHLEN]; parent_dir(s->path[i], d, sizeof d);
        int k = -1; for (int j = 0; j < dn; j++) if (!strcmp(dirs[j], d)) { k = j; break; }
        if (k < 0) { k = dn; snprintf(dirs[dn], PS_BL_PATHLEN, "%s", d); dn++; }
        dc[k]++;
    }
    struct ps_baseline_set out; ps_blset_init(&out, s->exe);
    for (int k = 0; k < dn; k++) if (dc[k] >= threshold) ps_blset_add(&out, dirs[k]);
    for (int i = 0; i < s->n; i++) {
        char d[PS_BL_PATHLEN]; parent_dir(s->path[i], d, sizeof d);
        int k = 0; for (int j = 0; j < dn; j++) if (!strcmp(dirs[j], d)) { k = j; break; }
        if (dc[k] < threshold) ps_blset_add(&out, s->path[i]);
    }
    *s = out;
    return 0;
}
