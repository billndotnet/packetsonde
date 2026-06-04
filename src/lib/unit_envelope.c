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
