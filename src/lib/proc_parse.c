#include "proc_parse.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* stat is "pid (comm) state ppid ...". comm can contain spaces and ')',
 * so find the LAST ')' and parse fields after it. */
static const char *after_comm(const char *stat_buf) {
    const char *rp = strrchr(stat_buf, ')');
    return rp ? rp + 1 : NULL;
}

int ps_proc_parse_ppid(const char *stat_buf) {
    const char *p = after_comm(stat_buf);
    if (!p) return -1;
    /* fields after ')': " state ppid ..." */
    while (*p == ' ') p++;
    while (*p && *p != ' ') p++;       /* skip state */
    while (*p == ' ') p++;
    if (!*p) return -1;
    return atoi(p);
}

int ps_proc_parse_starttime(const char *stat_buf, unsigned long long *out) {
    const char *p = after_comm(stat_buf);
    if (!p) return -1;
    /* Tokens after ')' are fields 3.. ; starttime is field 22, i.e. the
     * 20th whitespace-separated token after the ')'. Skip 19, read the 20th. */
    for (int i = 0; i < 19; i++) {
        while (*p == ' ') p++;
        if (!*p) return -1;
        while (*p && *p != ' ') p++;   /* consume one token */
    }
    while (*p == ' ') p++;
    if (*p < '0' || *p > '9') return -1;
    *out = strtoull(p, NULL, 10);
    return 0;
}

int ps_proc_parse_comm(const char *stat_buf, char *out, size_t cap) {
    const char *lp = strchr(stat_buf, '(');
    const char *rp = strrchr(stat_buf, ')');
    if (!lp || !rp || rp <= lp) return -1;
    size_t n = (size_t)(rp - lp - 1);
    if (n >= cap) n = cap - 1;
    memcpy(out, lp + 1, n); out[n] = 0;
    return 0;
}

int ps_proc_parse_unit(const char *cgroup_buf, char *out, size_t cap) {
    /* Find the last ':' on the first line; the rest is the cgroup path. */
    const char *nl = strchr(cgroup_buf, '\n');
    size_t linelen = nl ? (size_t)(nl - cgroup_buf) : strlen(cgroup_buf);
    const char *line = cgroup_buf;
    const char *colon = NULL;
    for (size_t i = 0; i < linelen; i++) if (line[i] == ':') colon = line + i;
    if (!colon) return -1;
    const char *path = colon + 1;
    size_t plen = (size_t)(line + linelen - path);
    if (plen == 0 || plen >= cap) { if (plen >= cap) plen = cap - 1; else return -1; }
    memcpy(out, path, plen); out[plen] = 0;
    return 0;
}

int ps_proc_parse_mac(const char *attr_buf, char *label, size_t lcap,
                      char *mode, size_t mcap) {
    char tmp[256];
    size_t n = strcspn(attr_buf, "\n");
    if (n >= sizeof tmp) n = sizeof tmp - 1;
    memcpy(tmp, attr_buf, n); tmp[n] = 0;
    /* AppArmor: "<label> (<mode>)"; SELinux/none: "<context>" or "unconfined" */
    char *paren = strrchr(tmp, '(');
    if (paren && tmp[n ? n - 1 : 0] == ')') {
        char *end = strrchr(tmp, ')');
        *end = 0;
        snprintf(mode, mcap, "%s", paren + 1);
        /* trim trailing space before '(' from label */
        char *lp = paren;
        while (lp > tmp && (lp[-1] == ' ')) lp--;
        size_t llen = (size_t)(lp - tmp);
        if (llen >= lcap) llen = lcap - 1;
        memcpy(label, tmp, llen); label[llen] = 0;
    } else {
        snprintf(label, lcap, "%s", tmp);
        snprintf(mode, mcap, "%s", tmp);   /* "unconfined" -> mode "unconfined" */
    }
    return 0;
}
