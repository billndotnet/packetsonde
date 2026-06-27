#include "../verbs.h"
#include "exe_slug.h"
#include "baseline_set.h"
#include "dest_match.h"
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
static int load_key(const char *dir, const char *slug, const char *file, const char *key, const char *exe, struct ps_baseline_set *s) {
    ps_blset_init(s, exe);
    char p[600]; snprintf(p, sizeof p, "%s/%s/%s", dir, slug, file);
    FILE *f = fopen(p, "r"); if (!f) return 0;
    static char j[1<<16]; size_t n = fread(j,1,sizeof j-1,f); fclose(f); j[n]=0;
    ps_blset_from_json_key(j, key, s); return 0;
}
static int save_key(const char *dir, const char *slug, const char *file, const char *key, const struct ps_baseline_set *s) {
    char d[600]; snprintf(d, sizeof d, "%s/%s", dir, slug); mkdir(dir,0700); mkdir(d,0700);
    char p[700], tmp[760]; snprintf(p,sizeof p,"%s/%s",d,file); snprintf(tmp,sizeof tmp,"%s.tmp",p);
    static char j[1<<16]; int len = ps_blset_to_json_key(s, key, j, sizeof j); if (len<0) return -1;
    FILE *f = fopen(tmp,"w"); if(!f) return -1; fwrite(j,1,len,f); fclose(f); return rename(tmp,p);
}

int ps_verb_baseline_run(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    const char *dir = "/var/lib/kernelsonde/baseline";
    const char *exe = NULL, *sub = NULL, *entry = NULL, *form = "exact";
    int threshold = 3;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--state-dir") && i+1 < argc) dir = argv[++i];
        else if (!strcmp(argv[i], "--threshold") && i+1 < argc) threshold = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--as") && i+1 < argc) form = argv[++i];
        else if (argv[i][0] == '-') continue;
        else if (!exe) exe = argv[i];
        else if (!sub) sub = argv[i];
        else if (!entry) entry = argv[i];
    }
    if (!exe || !sub) { fprintf(stderr, "usage: packetsonde baseline <exe> list|approve <e>|deny <e>|approve-all|approve-dest <r> [--as host|port|cidr/N]|deny-dest <r>|approve-parent <comm>|deny-parent <comm> [--state-dir D] [--threshold N]\n"); return 2; }
    char slug[256]; if (ps_exe_slug(exe, slug, sizeof slug) != 0) { fprintf(stderr,"bad exe\n"); return 2; }

    struct ps_baseline_set bl, cand, den;
    load(dir, slug, "baseline.json", exe, &bl);
    load(dir, slug, "candidates.json", exe, &cand);
    load(dir, slug, "denials.json", exe, &den);
    struct ps_baseline_set dbl, dcand, dden;
    load_key(dir, slug, "dests.json", "dests", exe, &dbl);
    load_key(dir, slug, "dest-candidates.json", "dests", exe, &dcand);
    load_key(dir, slug, "dest-denials.json", "dests", exe, &dden);
    struct ps_baseline_set pbl, pcand, pden;
    load_key(dir, slug, "parents.json", "parents", exe, &pbl);
    load_key(dir, slug, "parent-candidates.json", "parents", exe, &pcand);
    load_key(dir, slug, "parent-denials.json", "parents", exe, &pden);

    if (!strcmp(sub, "list")) {
        printf("exe: %s\nbaseline (%d):\n", exe, bl.n);
        for (int i=0;i<bl.n;i++) printf("  %s\n", bl.path[i]);
        printf("candidates (%d):\n", cand.n);
        for (int i=0;i<cand.n;i++) printf("  %s\n", cand.path[i]);
        printf("denials (%d):\n", den.n);
        for (int i=0;i<den.n;i++) printf("  %s\n", den.path[i]);
        printf("dests baseline (%d):\n", dbl.n);   for (int i=0;i<dbl.n;i++) printf("  %s\n", dbl.path[i]);
        printf("dest candidates (%d):\n", dcand.n); for (int i=0;i<dcand.n;i++) printf("  %s\n", dcand.path[i]);
        printf("dest denials (%d):\n", dden.n);     for (int i=0;i<dden.n;i++) printf("  %s\n", dden.path[i]);
        printf("parents baseline (%d):\n", pbl.n);   for (int i=0;i<pbl.n;i++) printf("  %s\n", pbl.path[i]);
        printf("parent candidates (%d):\n", pcand.n); for (int i=0;i<pcand.n;i++) printf("  %s\n", pcand.path[i]);
        printf("parent denials (%d):\n", pden.n);     for (int i=0;i<pden.n;i++) printf("  %s\n", pden.path[i]);
        return 0;
    }
    if (!strcmp(sub, "approve-all")) {
        for (int i=0;i<cand.n;i++) ps_blset_add(&bl, cand.path[i]);
        ps_blset_rollup(&bl, threshold);
        cand.n = 0;
        save(dir, slug, "baseline.json", &bl); save(dir, slug, "candidates.json", &cand);
        for (int i=0;i<dcand.n;i++) ps_blset_add(&dbl, dcand.path[i]);
        dcand.n = 0;
        save_key(dir, slug, "dests.json", "dests", &dbl); save_key(dir, slug, "dest-candidates.json", "dests", &dcand);
        for (int i=0;i<pcand.n;i++) ps_blset_add(&pbl, pcand.path[i]);
        pcand.n = 0;
        save_key(dir, slug, "parents.json", "parents", &pbl); save_key(dir, slug, "parent-candidates.json", "parents", &pcand);
        printf("approved all; baseline now %d paths, %d dests, %d parents\n", bl.n, dbl.n, pbl.n); return 0;
    }
    if (!strcmp(sub, "approve-dest")) {
        if (!entry) { fprintf(stderr, "approve-dest needs a <raddr>\n"); return 2; }
        char gen[64]; if (ps_dest_generalize(entry, form, gen, sizeof gen) != 0) { fprintf(stderr,"bad --as form\n"); return 2; }
        ps_blset_add(&dbl, gen); remove_entry(&dcand, entry);
        save_key(dir, slug, "dests.json", "dests", &dbl); save_key(dir, slug, "dest-candidates.json", "dests", &dcand);
        printf("approved dest %s (as %s)\n", entry, gen); return 0;
    }
    if (!strcmp(sub, "deny-dest")) {
        if (!entry) { fprintf(stderr, "deny-dest needs a <raddr>\n"); return 2; }
        ps_blset_add(&dden, entry); remove_entry(&dcand, entry);
        save_key(dir, slug, "dest-denials.json", "dests", &dden); save_key(dir, slug, "dest-candidates.json", "dests", &dcand);
        printf("denied dest %s\n", entry); return 0;
    }
    if (!strcmp(sub, "approve-parent")) {
        if (!entry) { fprintf(stderr, "approve-parent needs a <comm>\n"); return 2; }
        ps_blset_add(&pbl, entry); remove_entry(&pcand, entry);
        save_key(dir, slug, "parents.json", "parents", &pbl); save_key(dir, slug, "parent-candidates.json", "parents", &pcand);
        printf("approved parent %s\n", entry); return 0;
    }
    if (!strcmp(sub, "deny-parent")) {
        if (!entry) { fprintf(stderr, "deny-parent needs a <comm>\n"); return 2; }
        ps_blset_add(&pden, entry); remove_entry(&pcand, entry);
        save_key(dir, slug, "parent-denials.json", "parents", &pden); save_key(dir, slug, "parent-candidates.json", "parents", &pcand);
        printf("denied parent %s\n", entry); return 0;
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
