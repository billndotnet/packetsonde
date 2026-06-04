#include "../verbs.h"
#include "exe_slug.h"
#include "baseline_set.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int load(const char *dir, const char *slug, const char *file, const char *exe, struct ps_baseline_set *s) {
    ps_blset_init(s, exe);
    char p[600]; snprintf(p, sizeof p, "%s/%s/%s", dir, slug, file);
    FILE *f = fopen(p, "r"); if (!f) return 0;
    static char j[1<<16]; size_t n = fread(j,1,sizeof j-1,f); fclose(f); j[n]=0;
    ps_blset_from_json(j, s); return 0;
}
static int save(const char *dir, const char *slug, const char *file, const struct ps_baseline_set *s) {
    char d[600]; snprintf(d, sizeof d, "%s/%s", dir, slug); mkdir(dir,0700); mkdir(d,0700);
    char p[700], tmp[760]; snprintf(p,sizeof p,"%s/%s",d,file); snprintf(tmp,sizeof tmp,"%s.tmp",p);
    static char j[1<<16]; int len = ps_blset_to_json(s, j, sizeof j); if (len<0) return -1;
    FILE *f = fopen(tmp,"w"); if(!f) return -1; fwrite(j,1,len,f); fclose(f); return rename(tmp,p);
}
static void remove_entry(struct ps_baseline_set *s, const char *entry) {
    int o = 0; for (int i=0;i<s->n;i++) if (strcmp(s->path[i],entry)) { if(o!=i) memcpy(s->path[o],s->path[i],PS_BL_PATHLEN); o++; } s->n=o;
}

int ps_verb_baseline_run(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    const char *dir = "/var/lib/packetsonde/baseline";
    const char *exe = NULL, *sub = NULL, *entry = NULL;
    int threshold = 3;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--state-dir") && i+1 < argc) dir = argv[++i];
        else if (!strcmp(argv[i], "--threshold") && i+1 < argc) threshold = atoi(argv[++i]);
        else if (argv[i][0] == '-') continue;
        else if (!exe) exe = argv[i];
        else if (!sub) sub = argv[i];
        else if (!entry) entry = argv[i];
    }
    if (!exe || !sub) { fprintf(stderr, "usage: packetsonde baseline <exe> list|approve <e>|deny <e>|approve-all [--state-dir D] [--threshold N]\n"); return 2; }
    char slug[256]; if (ps_exe_slug(exe, slug, sizeof slug) != 0) { fprintf(stderr,"bad exe\n"); return 2; }

    struct ps_baseline_set bl, cand, den;
    load(dir, slug, "baseline.json", exe, &bl);
    load(dir, slug, "candidates.json", exe, &cand);
    load(dir, slug, "denials.json", exe, &den);

    if (!strcmp(sub, "list")) {
        printf("exe: %s\nbaseline (%d):\n", exe, bl.n);
        for (int i=0;i<bl.n;i++) printf("  %s\n", bl.path[i]);
        printf("candidates (%d):\n", cand.n);
        for (int i=0;i<cand.n;i++) printf("  %s\n", cand.path[i]);
        printf("denials (%d):\n", den.n);
        for (int i=0;i<den.n;i++) printf("  %s\n", den.path[i]);
        return 0;
    }
    if (!strcmp(sub, "approve-all")) {
        for (int i=0;i<cand.n;i++) ps_blset_add(&bl, cand.path[i]);
        ps_blset_rollup(&bl, threshold);
        cand.n = 0;
        save(dir, slug, "baseline.json", &bl); save(dir, slug, "candidates.json", &cand);
        printf("approved all; baseline now %d entries\n", bl.n); return 0;
    }
    if (!entry) { fprintf(stderr, "approve/deny need an <entry>\n"); return 2; }
    if (!strcmp(sub, "approve")) {
        ps_blset_add(&bl, entry); remove_entry(&cand, entry);
        save(dir, slug, "baseline.json", &bl); save(dir, slug, "candidates.json", &cand);
        printf("approved %s\n", entry); return 0;
    }
    if (!strcmp(sub, "deny")) {
        ps_blset_add(&den, entry); remove_entry(&cand, entry);
        save(dir, slug, "denials.json", &den); save(dir, slug, "candidates.json", &cand);
        printf("denied %s\n", entry); return 0;
    }
    fprintf(stderr, "unknown subcommand %s\n", sub); return 2;
}
