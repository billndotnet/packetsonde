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

    /* dest store: load empty, append two (dedup), read back under "dests" key */
    struct ps_baseline_set dbl, dden;
    assert(ps_baseline_load_dests(dir, exe, &dbl, &dden) == 0);
    assert(dbl.n == 0 && dden.n == 0);
    assert(ps_baseline_append_dest_candidate(dir, exe, "1.2.3.4:443") == 0);
    assert(ps_baseline_append_dest_candidate(dir, exe, "1.2.3.4:443") == 0);
    assert(ps_baseline_append_dest_candidate(dir, exe, "8.8.8.8:53") == 0);
    char dpath[600]; snprintf(dpath, sizeof dpath, "%s/%s/dest-candidates.json", dir, slug);
    FILE *df = fopen(dpath, "r"); assert(df);
    static char dj[8192]; size_t dn2 = fread(dj,1,sizeof dj-1,df); fclose(df); dj[dn2]=0;
    struct ps_baseline_set dc; assert(ps_blset_from_json_key(dj, "dests", &dc) == 0);
    assert(dc.n == 2);

    printf("test_baseline_store: OK\n");
    return 0;
}
