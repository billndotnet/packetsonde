#include "audit_loader.h"

#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef __APPLE__
#define PS_DL_EXT ".dylib"
#else
#define PS_DL_EXT ".so"
#endif

static int push(struct ps_audit_loader *L, const struct ps_audit_module *m,
                void *h, const char *path) {
    /* Skip duplicates by name (first one loaded wins). */
    for (size_t i = 0; i < L->count; i++) {
        if (strcmp(L->items[i].module->name, m->name) == 0) {
            return 0;
        }
    }
    if (L->count == L->cap) {
        size_t nc = L->cap ? L->cap * 2 : 16;
        struct ps_audit_loaded *g = realloc(L->items, nc * sizeof(*g));
        if (!g) return -1;
        L->items = g; L->cap = nc;
    }
    L->items[L->count].module    = m;
    L->items[L->count].dl_handle = h;
    snprintf(L->items[L->count].source_path,
             sizeof(L->items[L->count].source_path), "%s", path);
    L->count++;
    return 0;
}

static int has_module_suffix(const char *name) {
    size_t n = strlen(name);
    size_t e = strlen(PS_DL_EXT);
    if (n <= e) return 0;
    return strcmp(name + n - e, PS_DL_EXT) == 0;
}

static int try_load_dir(struct ps_audit_loader *L, const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    int loaded = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        /* Convention: filenames look like audit-tls.dylib / audit-smb.so etc. */
        if (strncmp(e->d_name, "audit-", 6) != 0) continue;
        if (!has_module_suffix(e->d_name)) continue;

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);

        void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (!h) {
            /* dlopen failure is silent unless PS_AUDIT_DEBUG is set. */
            if (getenv("PS_AUDIT_DEBUG"))
                fprintf(stderr, "audit-loader: dlopen %s: %s\n", path, dlerror());
            continue;
        }
        const struct ps_audit_module *(*entry)(void) =
            (const struct ps_audit_module *(*)(void))dlsym(h, "ps_audit_module");
        if (!entry) {
            dlclose(h);
            continue;
        }
        const struct ps_audit_module *m = entry();
        if (!m || m->abi_version != PS_AUDIT_ABI_VERSION ||
            !m->name || !m->run) {
            dlclose(h);
            continue;
        }
        if (push(L, m, h, path) == 0) loaded++;
    }
    closedir(d);
    return loaded;
}

int ps_audit_loader_scan(struct ps_audit_loader *L) {
    memset(L, 0, sizeof(*L));

    const char *override = getenv("PS_AUDITS_DIR");
    if (override && *override) {
        return try_load_dir(L, override);
    }

    char buf[512];
    const char *cfg = getenv("XDG_CONFIG_HOME");
    if (cfg && *cfg) {
        snprintf(buf, sizeof(buf), "%s/packetsonde/audits", cfg);
        try_load_dir(L, buf);
    }
    const char *home = getenv("HOME");
    if (home && *home) {
        snprintf(buf, sizeof(buf), "%s/.config/packetsonde/audits", home);
        try_load_dir(L, buf);
    }

    /* Build-tree default: relative to the binary location. The CMake build
     * outputs audit plugins to <build>/src/cli/audit/. When running from the
     * build dir during dev, this catches them. */
    {
        const char *build_dir = getenv("PS_BUILD_DIR");
        if (build_dir && *build_dir) {
            snprintf(buf, sizeof(buf), "%s/src/cli/audit", build_dir);
            try_load_dir(L, buf);
        }
    }

    try_load_dir(L, "/usr/local/lib/packetsonde/audits");
    try_load_dir(L, "/usr/lib/packetsonde/audits");
    return (int)L->count;
}

const struct ps_audit_loaded *ps_audit_loader_find(const struct ps_audit_loader *L,
                                                    const char *name) {
    for (size_t i = 0; i < L->count; i++) {
        if (strcmp(L->items[i].module->name, name) == 0) return &L->items[i];
    }
    return NULL;
}

void ps_audit_loader_destroy(struct ps_audit_loader *L) {
    for (size_t i = 0; i < L->count; i++) {
        if (L->items[i].dl_handle) dlclose(L->items[i].dl_handle);
    }
    free(L->items);
    memset(L, 0, sizeof(*L));
}
