#include "baseline_set.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    struct ps_baseline_set s; ps_blset_init(&s, "/usr/sbin/nginx");
    assert(strcmp(s.exe, "/usr/sbin/nginx") == 0 && s.n == 0);
    assert(ps_blset_add(&s, "/var/www") == 1);
    assert(ps_blset_add(&s, "/var/www") == 0);             /* dup */
    assert(ps_blset_add(&s, "/etc/nginx/nginx.conf") == 1);

    /* dir-prefix coverage */
    assert(ps_blset_covered(&s, "/var/www") == 1);
    assert(ps_blset_covered(&s, "/var/www/html/index.html") == 1);
    assert(ps_blset_covered(&s, "/var/wwwX") == 0);        /* boundary */
    assert(ps_blset_covered(&s, "/etc/nginx/nginx.conf") == 1);
    assert(ps_blset_covered(&s, "/etc/shadow") == 0);

    /* serde round-trip */
    char buf[8192]; assert(ps_blset_to_json(&s, buf, sizeof buf) > 0);
    assert(strstr(buf, "\"exe\":\"/usr/sbin/nginx\"") && strstr(buf, "/var/www"));
    struct ps_baseline_set t; assert(ps_blset_from_json(buf, &t) == 0);
    assert(strcmp(t.exe, "/usr/sbin/nginx") == 0 && t.n == 2);
    assert(ps_blset_covered(&t, "/var/www/x") == 1);

    /* rollup: 3 files under one dir -> the dir */
    struct ps_baseline_set r; ps_blset_init(&r, "/x");
    ps_blset_add(&r, "/d/a"); ps_blset_add(&r, "/d/b"); ps_blset_add(&r, "/d/c");
    ps_blset_add(&r, "/e/only");
    ps_blset_rollup(&r, 3);
    assert(ps_blset_covered(&r, "/d/zzz") == 1);           /* /d rolled up */
    int has_e_only = 0; for (int i=0;i<r.n;i++) if(!strcmp(r.path[i],"/e/only")) has_e_only=1;
    assert(has_e_only);                                    /* /e/only stayed exact */
    printf("test_baseline_set: OK\n");
    return 0;
}
