#include "cgroup_unit.h"
#include <string.h>

static int has_suffix(const char *s, const char *suf) {
    size_t ls = strlen(s), lf = strlen(suf);
    return ls >= lf && strcmp(s + ls - lf, suf) == 0;
}

int ps_cgroup_to_unit(const char *cgroup, char *out, size_t cap) {
    if (!cgroup || !*cgroup) return -1;
    const char *slash = strrchr(cgroup, '/');
    const char *seg = slash ? slash + 1 : cgroup;
    if (!*seg) return -1;
    if (has_suffix(seg, ".service") || has_suffix(seg, ".socket") ||
        has_suffix(seg, ".mount")   || has_suffix(seg, ".scope")) {
        size_t n = strlen(seg);
        if (n >= cap) return -1;
        memcpy(out, seg, n + 1);
        return 0;
    }
    return -1;
}
