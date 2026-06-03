#include "policy_eval.h"
#include <string.h>

/* path-prefix with boundary: "/a/b" matches "/a/b" and "/a/b/..." but not "/a/bc" */
static int under(const char *path, const char *prefix) {
    size_t lp = strlen(prefix);
    if (lp == 0) return 0;
    if (strncmp(path, prefix, lp) != 0) return 0;
    return path[lp] == 0 || path[lp] == '/' || prefix[lp-1] == '/';
}
static int under_any(const char *path, const char arr[][PS_POL_PATHLEN], int n) {
    for (int i = 0; i < n; i++) if (under(path, arr[i])) return 1;
    return 0;
}
static int protsys_protects(enum ps_protect_system ps, const char *path) {
    if (ps == PS_PROTSYS_STRICT) return 1;                 /* whole FS read-only */
    if (ps >= PS_PROTSYS_FULL  && under(path, "/etc")) return 1;
    if (ps >= PS_PROTSYS_YES && (under(path,"/usr")||under(path,"/boot")||under(path,"/efi"))) return 1;
    return 0;
}

static int hit(struct ps_eval_result *o, const char *dir, int heur) {
    o->violation = 1; o->directive = dir; o->heuristic = heur; return 1;
}

int ps_policy_eval(const struct ps_unit_policy *p, const char *path,
                   enum ps_op op, struct ps_eval_result *out) {
    out->violation = 0; out->directive = NULL; out->heuristic = 0;
    if (!p->known || !path || !*path) return 0;

    /* deny-all: InaccessiblePaths (any op) */
    if (under_any(path, p->inacc, p->n_inacc))
        return hit(out, "InaccessiblePaths", 0);
    /* ProtectHome=inaccessible: any op on home dirs */
    if (p->protect_home == PS_PROTHOME_INACCESSIBLE &&
        (under(path,"/home")||under(path,"/root")||under(path,"/run/user")))
        return hit(out, "ProtectHome", 0);

    int rw = under_any(path, p->rw, p->n_rw);

    if (op == PS_OP_WRITE) {
        if (rw) return 0;                                  /* ReadWritePaths exception wins */
        if (p->protect_home == PS_PROTHOME_RO &&
            (under(path,"/home")||under(path,"/root")||under(path,"/run/user")))
            return hit(out, "ProtectHome", 0);
        if (under_any(path, p->ro, p->n_ro))
            return hit(out, "ReadOnlyPaths", 0);
        if (protsys_protects(p->protect_system, path))
            return hit(out, "ProtectSystem", 0);
        return 0;
    }
    if (op == PS_OP_EXEC) {
        /* exec from a writable area on a hardened unit (heuristic) */
        if (rw && (p->mdwe || p->protect_system == PS_PROTSYS_STRICT))
            return hit(out, "exec_from_writable", 1);
        return 0;                                          /* exec-from-denied handled as READ by caller */
    }
    /* PS_OP_READ: only the deny-all checks above apply (reads of ProtectSystem ok) */
    return 0;
}
