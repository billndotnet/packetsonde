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

/* --- cache --- */
#define PS_POL_CACHE_N 128
struct pol_cache_ent { char unit[128]; uint64_t loaded_sec; struct ps_unit_policy pol; int used; };
static struct pol_cache_ent g_cache[PS_POL_CACHE_N];

int ps_unit_policy_get(const char *unit, uint64_t now_sec, uint64_t ttl_sec,
                       ps_unit_policy_loader loader, struct ps_unit_policy *out) {
    struct pol_cache_ent *slot = NULL, *lru = &g_cache[0];
    for (int i = 0; i < PS_POL_CACHE_N; i++) {
        if (g_cache[i].used && strcmp(g_cache[i].unit, unit) == 0) { slot = &g_cache[i]; break; }
        if (!g_cache[i].used) { if (!slot) slot = &g_cache[i]; }
        if (g_cache[i].loaded_sec < lru->loaded_sec) lru = &g_cache[i];
    }
    if (slot && slot->used && strcmp(slot->unit, unit) == 0 &&
        now_sec - slot->loaded_sec < ttl_sec) { *out = slot->pol; return 0; }
    if (!slot) slot = lru;                 /* evict LRU */

    char text[8192];
    if (loader(unit, text, sizeof text) != 0) text[0] = 0;
    struct ps_unit_policy pol; ps_unit_policy_derive(text, &pol);
    snprintf(slot->unit, sizeof slot->unit, "%s", unit);
    slot->loaded_sec = now_sec; slot->pol = pol; slot->used = 1;
    *out = pol;
    return 0;
}

/* Real loader: `systemctl show <unit> -p ...`. Unit is validated (systemd unit
 * charset) before being placed in the command to avoid shell injection. */
int ps_unit_policy_load_systemctl(const char *unit, char *out, size_t cap) {
    for (const char *c = unit; *c; c++) {
        if (!((*c>='A'&&*c<='Z')||(*c>='a'&&*c<='z')||(*c>='0'&&*c<='9')||
              *c=='.'||*c=='-'||*c=='_'||*c=='@'||*c==':'||*c=='\\')) { out[0]=0; return -1; }
    }
    char cmd[512];
    snprintf(cmd, sizeof cmd,
        "systemctl show '%s' -p FragmentPath -p ProtectSystem -p ProtectHome "
        "-p PrivateTmp -p MemoryDenyWriteExecute -p ReadWritePaths -p ReadOnlyPaths "
        "-p InaccessiblePaths 2>/dev/null", unit);
    FILE *f = popen(cmd, "r");
    if (!f) { out[0] = 0; return -1; }
    size_t n = fread(out, 1, cap - 1, f);
    pclose(f);
    out[n] = 0;
    return 0;
}
