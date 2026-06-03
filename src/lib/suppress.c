#include "suppress.h"
#include <string.h>

static int prefix_match(const char *prefix, size_t plen, const char *path) {
    return strncmp(path, prefix, plen) == 0;
}

int ps_suppress_match(const char *list, const char *comm, const char *path, int is_read) {
    if (!is_read || !list || !*list || !path) return 0;
    const char *p = list;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t elen = comma ? (size_t)(comma - p) : strlen(p);
        /* split optional "comm:" */
        const char *colon = memchr(p, ':', elen);
        if (colon) {
            size_t clen = (size_t)(colon - p);
            const char *pref = colon + 1;
            size_t plen = elen - clen - 1;
            if (comm && strlen(comm) == clen && strncmp(comm, p, clen) == 0 &&
                plen > 0 && prefix_match(pref, plen, path))
                return 1;
        } else {
            if (elen > 0 && prefix_match(p, elen, path))
                return 1;
        }
        if (!comma) break;
        p = comma + 1;
    }
    return 0;
}
