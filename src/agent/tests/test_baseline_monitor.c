#include "baseline_monitor.h"
#include "baseline_store.h"
#include "baseline_set.h"
#include "exe_slug.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int g_emits = 0; static char g_last[4096];
static void emit(void *c, const char *json, size_t len) { (void)c;(void)len; g_emits++; snprintf(g_last,sizeof g_last,"%s",json); }
static const char *REC(const char *exe, const char *path) {
    static char b[2048];
    snprintf(b, sizeof b, "{\"event\":\"open\",\"path\":\"%s\",\"process\":{\"pid\":9,\"comm\":\"nginx\",\"uid\":33,\"exe\":\"%s\"}}", path, exe);
    return b;
}

int main(void) {
    char dir[] = "/tmp/ps_blm_XXXXXX"; assert(mkdtemp(dir));
    const char *exe = "/usr/sbin/nginx";
    /* seed a baseline (/var/www) + a denial (/etc/shadow) */
    char slug[256]; ps_exe_slug(exe, slug, sizeof slug);
    char sub[512]; snprintf(sub, sizeof sub, "%s/%s", dir, slug); mkdir(dir,0700); mkdir(sub,0700);
    struct ps_baseline_set bl; ps_blset_init(&bl, exe); ps_blset_add(&bl, "/var/www");
    struct ps_baseline_set dn; ps_blset_init(&dn, exe); ps_blset_add(&dn, "/etc/shadow");
    char j[4096], p[600];
    snprintf(p,sizeof p,"%s/baseline.json",sub); FILE *f=fopen(p,"w"); ps_blset_to_json(&bl,j,sizeof j); fputs(j,f); fclose(f);
    snprintf(p,sizeof p,"%s/denials.json",sub);  f=fopen(p,"w"); ps_blset_to_json(&dn,j,sizeof j); fputs(j,f); fclose(f);

    void *seen = ps_baseline_seen_new();
    /* covered -> silent */
    ps_baseline_process_record(REC(exe,"/var/www/index.html"), dir, seen, emit, NULL);
    assert(g_emits == 0);
    /* denied -> anomaly */
    ps_baseline_process_record(REC(exe,"/etc/shadow"), dir, seen, emit, NULL);
    assert(g_emits == 1 && strstr(g_last, "\"kind\":\"anomaly\""));
    /* novel -> candidate + appended; repeat deduped */
    ps_baseline_process_record(REC(exe,"/tmp/x"), dir, seen, emit, NULL);
    assert(g_emits == 2 && strstr(g_last, "\"kind\":\"candidate\""));
    ps_baseline_process_record(REC(exe,"/tmp/x"), dir, seen, emit, NULL);
    assert(g_emits == 2);                                  /* deduped */
    /* empty exe -> skipped */
    ps_baseline_process_record(REC("","/y"), dir, seen, emit, NULL);
    assert(g_emits == 2);
    ps_baseline_seen_free(seen);
    printf("test_baseline_monitor: OK\n");
    return 0;
}
