#include "unit_envelope.h"
#include "json.h"
#include "json_extract.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void ps_envelope_init(struct ps_unit_envelope *e, const char *unit) {
    memset(e, 0, sizeof *e);
    snprintf(e->unit, sizeof e->unit, "%s", unit ? unit : "");
}

static int under(const char *path, const char *prefix) {
    size_t lp = strlen(prefix);
    return strncmp(path, prefix, lp) == 0 && (path[lp] == 0 || path[lp] == '/');
}

static void set_add(char arr[][PS_ENV_PATHLEN], int *n, const char *path, int *trunc) {
    for (int i = 0; i < *n; i++) if (strcmp(arr[i], path) == 0) return;   /* dedup */
    if (*n >= PS_ENV_MAX_PATHS) { *trunc = 1; return; }
    snprintf(arr[*n], PS_ENV_PATHLEN, "%s", path);
    (*n)++;
}

void ps_envelope_add(struct ps_unit_envelope *e, const char *event, const char *path) {
    if (!event || !path || !*path) return;
    e->records++;
    if (!strcmp(event, "write"))      set_add(e->wr, &e->n_write, path, &e->truncated);
    else if (!strcmp(event, "exec"))  set_add(e->ex, &e->n_exec,  path, &e->truncated);
    else                              set_add(e->rd, &e->n_read,  path, &e->truncated); /* open|access */
    if (under(path, "/home") || under(path, "/root")) e->touched_home = 1;
    if (under(path, "/tmp") || under(path, "/var/tmp") || under(path, "/dev/shm")) e->used_tmp = 1;
}

static void arr_to_json(struct ps_json *j, const char *key, char a[][PS_ENV_PATHLEN], int n) {
    ps_json_array_begin(j, key);
    for (int i = 0; i < n; i++) ps_json_array_string(j, a[i]);
    ps_json_array_end(j);
}

int ps_envelope_to_json(const struct ps_unit_envelope *e, char *out, size_t cap) {
    struct ps_json j; ps_json_init(&j, out, cap);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "unit", e->unit);
    ps_json_key_int(&j, "records", e->records);
    ps_json_key_int(&j, "truncated", e->truncated);
    ps_json_key_int(&j, "touched_home", e->touched_home);
    ps_json_key_int(&j, "used_tmp", e->used_tmp);
    arr_to_json(&j, "reads",  (char(*)[PS_ENV_PATHLEN])e->rd, e->n_read);
    arr_to_json(&j, "writes", (char(*)[PS_ENV_PATHLEN])e->wr, e->n_write);
    arr_to_json(&j, "execs",  (char(*)[PS_ENV_PATHLEN])e->ex, e->n_exec);
    ps_json_object_end(&j);
    return ps_json_finish(&j);
}

/* Parse a JSON array of strings "key":[ "a","b" ] into arr; returns count. */
static int arr_from_json(const char *json, const char *key, char arr[][PS_ENV_PATHLEN]) {
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\":[", key);
    const char *p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    int n = 0;
    while (*p && *p != ']' && n < PS_ENV_MAX_PATHS) {
        const char *q = strchr(p, '"');
        const char *close = strchr(p, ']');
        if (!q || (close && q > close)) break;
        q++;
        const char *e = strchr(q, '"');
        if (!e) break;
        size_t len = (size_t)(e - q);
        if (len < PS_ENV_PATHLEN) { memcpy(arr[n], q, len); arr[n][len] = 0; n++; }
        p = e + 1;
        const char *comma = strchr(p, ',');
        close = strchr(p, ']');
        if (!comma || (close && close < comma)) break;
        p = comma + 1;
    }
    return n;
}

int ps_envelope_from_json(const char *json, struct ps_unit_envelope *e) {
    if (!json) return -1;
    memset(e, 0, sizeof *e);
    if (ps_json_extract_string(json, "unit", e->unit, sizeof e->unit) < 0) return -1;
    #define INTOF(k,field) do { const char *p = strstr(json, "\"" k "\":"); \
        if (p) e->field = (int)strtol(p + strlen("\"" k "\":"), NULL, 10); } while (0)
    INTOF("records", records); INTOF("truncated", truncated);
    INTOF("touched_home", touched_home); INTOF("used_tmp", used_tmp);
    #undef INTOF
    e->n_read  = arr_from_json(json, "reads",  e->rd);
    e->n_write = arr_from_json(json, "writes", e->wr);
    e->n_exec  = arr_from_json(json, "execs",  e->ex);
    return 0;
}
