#include "systemd_policy.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static void add_paths(const char *val, char arr[][PS_POL_PATHLEN], int *n) {
    /* space-separated list */
    const char *p = val;
    while (*p && *n < PS_POL_MAX_PATHS) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *e = p;
        while (*e && *e != ' ') e++;
        size_t len = (size_t)(e - p);
        if (len > 0 && len < PS_POL_PATHLEN) { memcpy(arr[*n], p, len); arr[*n][len] = 0; (*n)++; }
        p = e;
    }
}

int ps_unit_policy_derive(const char *txt, struct ps_unit_policy *out) {
    memset(out, 0, sizeof *out);
    if (!txt) return 0;
    const char *line = txt;
    while (*line) {
        const char *nl = strchr(line, '\n');
        size_t llen = nl ? (size_t)(nl - line) : strlen(line);
        const char *eq = memchr(line, '=', llen);
        if (eq) {
            size_t klen = (size_t)(eq - line);
            const char *val = eq + 1;
            size_t vlen = llen - klen - 1;
            char v[2048]; size_t vc = vlen < sizeof v - 1 ? vlen : sizeof v - 1;
            memcpy(v, val, vc); v[vc] = 0;
            #define KEYIS(k) (klen == strlen(k) && strncmp(line, k, klen) == 0)
            if (KEYIS("FragmentPath")) { out->known = (vc > 0); }
            else if (KEYIS("ProtectSystem")) {
                out->protect_system = !strcmp(v,"strict") ? PS_PROTSYS_STRICT :
                                      !strcmp(v,"full")   ? PS_PROTSYS_FULL :
                                      !strcmp(v,"yes")    ? PS_PROTSYS_YES : PS_PROTSYS_NO;
            } else if (KEYIS("ProtectHome")) {
                out->protect_home = !strcmp(v,"read-only") ? PS_PROTHOME_RO :
                                    (!strcmp(v,"yes") || !strcmp(v,"true") || !strcmp(v,"tmpfs")) ?
                                        PS_PROTHOME_INACCESSIBLE : PS_PROTHOME_NO;
            } else if (KEYIS("PrivateTmp"))             out->private_tmp = (!strcmp(v,"yes") || !strcmp(v,"true"));
            else if (KEYIS("MemoryDenyWriteExecute"))   out->mdwe = (!strcmp(v,"yes") || !strcmp(v,"true"));
            else if (KEYIS("ReadWritePaths"))           add_paths(v, out->rw, &out->n_rw);
            else if (KEYIS("ReadOnlyPaths"))            add_paths(v, out->ro, &out->n_ro);
            else if (KEYIS("InaccessiblePaths"))        add_paths(v, out->inacc, &out->n_inacc);
            #undef KEYIS
        }
        if (!nl) break;
        line = nl + 1;
    }
    return 0;
}
