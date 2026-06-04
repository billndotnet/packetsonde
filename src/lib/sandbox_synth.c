#include "sandbox_synth.h"
#include <string.h>
#include <stdio.h>

static void parent_dir(const char *path, char *out, size_t cap) {
    const char *slash = strrchr(path, '/');
    size_t len = (slash && slash != path) ? (size_t)(slash - path) : 1;
    if (len >= cap) len = cap - 1;
    memcpy(out, path, len); out[len] = 0;
    if (len == 1 && path[0] == '/') { out[0] = '/'; out[1] = 0; }
}

static int under(const char *path, const char *prefix) {
    size_t lp = strlen(prefix);
    return strncmp(path, prefix, lp) == 0 && (path[lp] == 0 || path[lp] == '/');
}

/* emit ReadWritePaths lines with threshold rollup. */
static size_t emit_rw(const struct ps_unit_envelope *e, int thr, char *out, size_t cap, size_t o) {
    char dirs[PS_ENV_MAX_PATHS][PS_ENV_PATHLEN]; int dn = 0;
    int dcount[PS_ENV_MAX_PATHS]; memset(dcount, 0, sizeof dcount);
    for (int i = 0; i < e->n_write; i++) {
        char d[PS_ENV_PATHLEN]; parent_dir(e->wr[i], d, sizeof d);
        int k = -1;
        for (int j = 0; j < dn; j++) if (!strcmp(dirs[j], d)) { k = j; break; }
        if (k < 0) { k = dn; snprintf(dirs[dn], PS_ENV_PATHLEN, "%s", d); dn++; }
        dcount[k]++;
    }
    /* rolled-up dirs first (>=thr), then exact files in non-rolled dirs */
    for (int k = 0; k < dn; k++) {
        if (dcount[k] >= thr)
            o += (size_t)snprintf(out + o, cap - o,
                 "ReadWritePaths=%s        # generalized: %d files\n", dirs[k], dcount[k]);
    }
    for (int i = 0; i < e->n_write; i++) {
        char d[PS_ENV_PATHLEN]; parent_dir(e->wr[i], d, sizeof d);
        int k = 0; for (int j = 0; j < dn; j++) if (!strcmp(dirs[j], d)) { k = j; break; }
        if (dcount[k] < thr)
            o += (size_t)snprintf(out + o, cap - o, "ReadWritePaths=%s        # exact\n", e->wr[i]);
    }
    return o;
}

int ps_sandbox_synth(const struct ps_unit_envelope *e, int rollup_threshold,
                     char *out, size_t cap) {
    if (rollup_threshold < 1) rollup_threshold = 1;
    /* exec_from_writable: any exec path under any write path */
    int exec_from_writable = 0;
    for (int i = 0; i < e->n_exec && !exec_from_writable; i++)
        for (int w = 0; w < e->n_write; w++)
            if (under(e->ex[i], e->wr[w])) { exec_from_writable = 1; break; }

    size_t o = 0;
    o += (size_t)snprintf(out + o, cap - o, "[Service]\n");
    o += (size_t)snprintf(out + o, cap - o, "ProtectSystem=strict\n");
    if (!e->touched_home)
        o += (size_t)snprintf(out + o, cap - o, "ProtectHome=true\n");
    if (e->used_tmp)
        o += (size_t)snprintf(out + o, cap - o, "PrivateTmp=yes\n");
    if (!exec_from_writable)
        o += (size_t)snprintf(out + o, cap - o,
             "MemoryDenyWriteExecute=yes        # no exec from writable observed; verify (W^X != execve block)\n");
    o = emit_rw(e, rollup_threshold, out, cap, o);
    o += (size_t)snprintf(out + o, cap - o,
         "# learned over %d records%s. Review before applying; ReadWritePaths are minimal — widen if flows were missed.\n",
         e->records, e->truncated ? " (write set TRUNCATED — coverage capped)" : "");
    return (int)o;
}
