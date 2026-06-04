#include "baseline_store.h"
#include "baseline_set.h"
#include "exe_slug.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char dir[] = "/tmp/ps_bl_XXXXXX"; assert(mkdtemp(dir));
    const char *exe = "/usr/sbin/nginx";
    /* empty store -> empty sets, no error */
    struct ps_baseline_set bl, den;
    assert(ps_baseline_load(dir, exe, &bl, &den) == 0);
    assert(bl.n == 0 && den.n == 0);
    /* append two candidates (atomic) */
    assert(ps_baseline_append_candidate(dir, exe, "/var/www/a") == 0);
    assert(ps_baseline_append_candidate(dir, exe, "/var/www/a") == 0);   /* dedup */
    assert(ps_baseline_append_candidate(dir, exe, "/tmp/b") == 0);
    /* read candidates.json back via baseline_set */
    char slug[256]; ps_exe_slug(exe, slug, sizeof slug);
    char path[512]; snprintf(path, sizeof path, "%s/%s/candidates.json", dir, slug);
    FILE *f = fopen(path, "r"); assert(f);
    static char j[8192]; size_t n = fread(j, 1, sizeof j - 1, f); fclose(f); j[n] = 0;
    struct ps_baseline_set c; assert(ps_blset_from_json(j, &c) == 0);
    assert(c.n == 2);   /* a (deduped) + b */
    printf("test_baseline_store: OK\n");
    return 0;
}
