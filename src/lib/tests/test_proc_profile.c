#include "proc_profile.h"
#include <stdio.h>
#include <string.h>
#define CHECK(c) do{ if(!(c)){ fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c); return 1; } }while(0)

static struct ps_activity ev(const char *event, const char *path, const char *exe,
                             int pid, const char *raddr) {
    struct ps_activity a; memset(&a, 0, sizeof a);
    snprintf(a.ts, sizeof a.ts, "2026-06-05T19:00:00Z");
    snprintf(a.event, sizeof a.event, "%s", event);
    if (path) snprintf(a.path, sizeof a.path, "%s", path);
    a.proc.pid = pid; snprintf(a.proc.exe, sizeof a.proc.exe, "%s", exe);
    if (raddr) { a.nsock = 1; snprintf(a.sock[0].raddr, 64, "%s", raddr);
                 snprintf(a.sock[0].state, 16, "ESTAB"); snprintf(a.sock[0].proto,4,"tcp"); }
    return a;
}
static struct ps_pp_entity *find(struct ps_pp_model *m, const char *id) {
    for (int i = 0; i < m->nent; i++)
        if (m->ent[i].present && strcmp(m->ent[i].id, id) == 0) return &m->ent[i];
    return NULL;
}

int main(void) {
    struct ps_pp_subject s; memset(&s, 0, sizeof s);
    s.mode = PS_PP_BY_EXE; snprintf(s.exe, sizeof s.exe, "/usr/bin/suspect");
    struct ps_pp_model m; ps_pp_init(&m, &s, "01EPOCH");

    ps_blset_init(&m.bl_files, s.exe);   ps_blset_add(&m.bl_files, "/usr/lib/");
    ps_blset_init(&m.den_files, s.exe);  ps_blset_add(&m.den_files, "/etc/shadow");
    ps_blset_init(&m.bl_dests, s.exe);
    ps_blset_init(&m.den_dests, s.exe);  ps_blset_add(&m.den_dests, "10.0.0.9:443");
    m.have_baseline = 1;

    struct ps_activity a1 = ev("open", "/usr/lib/libc.so.6", s.exe, 4242, NULL);
    ps_pp_fold(&m, &a1, 1000);
    struct ps_activity a2 = ev("open", "/etc/shadow", s.exe, 4242, NULL);
    ps_pp_fold(&m, &a2, 1100);
    ps_pp_fold(&m, &a2, 1200);
    struct ps_activity a3 = ev("open", "/tmp/x", s.exe, 4242, NULL);
    ps_pp_fold(&m, &a3, 1300);
    struct ps_activity a4 = ev("connect", NULL, s.exe, 4242, "10.0.0.9:443");
    ps_pp_fold(&m, &a4, 1400);

    CHECK(strcmp(m.subject.exe, "/usr/bin/suspect") == 0);
    struct ps_pp_entity *libc = find(&m, "file:/usr/lib/libc.so.6");
    CHECK(libc && libc->count == 1 && libc->verdict == PS_PP_COVERED);
    struct ps_pp_entity *shadow = find(&m, "file:/etc/shadow");
    CHECK(shadow && shadow->count == 2 && shadow->verdict == PS_PP_ANOMALY);
    struct ps_pp_entity *tmp = find(&m, "file:/tmp/x");
    CHECK(tmp && tmp->verdict == PS_PP_NOVEL);
    struct ps_pp_entity *dest = find(&m, "dest:10.0.0.9:443");
    CHECK(dest && dest->kind == PS_PP_DEST && dest->verdict == PS_PP_ANOMALY);
    CHECK(strcmp(dest->state, "ESTAB") == 0);

    ps_pp_tick_rates(&m, 2000);
    CHECK(m.rates.open_s > 0.0);
    CHECK(m.rates.connect_s > 0.0);
    printf("ok\n");
    return 0;
}
