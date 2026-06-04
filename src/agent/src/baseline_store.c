#include "baseline_store.h"
#include "exe_slug.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

static int load_one(const char *state_dir, const char *slug, const char *file,
                    const char *exe, struct ps_baseline_set *out) {
    ps_blset_init(out, exe);
    char path[512]; snprintf(path, sizeof path, "%s/%s/%s", state_dir, slug, file);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    static char j[1 << 16]; size_t n = fread(j, 1, sizeof j - 1, f); fclose(f); j[n] = 0;
    ps_blset_from_json(j, out);
    return 0;
}

int ps_baseline_load(const char *state_dir, const char *exe,
                     struct ps_baseline_set *baseline, struct ps_baseline_set *denials) {
    char slug[256];
    if (ps_exe_slug(exe, slug, sizeof slug) != 0) {
        ps_blset_init(baseline, exe); ps_blset_init(denials, exe); return 0;
    }
    load_one(state_dir, slug, "baseline.json", exe, baseline);
    load_one(state_dir, slug, "denials.json",  exe, denials);
    return 0;
}

/* atomic write: write to <path>.tmp, then rename. */
static int atomic_write(const char *path, const char *buf, size_t len) {
    char tmp[600]; snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    fwrite(buf, 1, len, f);
    fclose(f);
    return rename(tmp, path);
}

int ps_baseline_append_candidate(const char *state_dir, const char *exe, const char *path) {
    char slug[256];
    if (ps_exe_slug(exe, slug, sizeof slug) != 0) return -1;
    char dir[512]; snprintf(dir, sizeof dir, "%s/%s", state_dir, slug);
    mkdir(state_dir, 0700); mkdir(dir, 0700);   /* best-effort */
    char cpath[600]; snprintf(cpath, sizeof cpath, "%s/candidates.json", dir);

    struct ps_baseline_set c; ps_blset_init(&c, exe);
    FILE *f = fopen(cpath, "r");
    if (f) { static char j[1<<16]; size_t n = fread(j,1,sizeof j-1,f); fclose(f); j[n]=0; ps_blset_from_json(j, &c); }
    if (ps_blset_add(&c, path) != 1) return 0;   /* dup or full -> nothing to write */
    static char out[1 << 16];
    int len = ps_blset_to_json(&c, out, sizeof out);
    if (len < 0) return -1;
    return atomic_write(cpath, out, (size_t)len);
}
