#include "provenance.h"
#include "json.h"
#include <string.h>
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

int ps_provenance_build_record(const struct ps_activity *a, const char *trigger,
                               const char *host, char *out, size_t cap) {
    (void)a; (void)trigger; (void)host; (void)out; (void)cap;
    return -1;   /* implemented in Task 5 */
}
