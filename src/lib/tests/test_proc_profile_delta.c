#include "proc_profile_delta.h"
#include <stdio.h>
#include <string.h>
#define CHECK(c) do{ if(!(c)){ fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c); return 1; } }while(0)

static struct ps_activity fopen_ev(const char *path, const char *exe, const char *ts) {
    struct ps_activity a; memset(&a,0,sizeof a);
    snprintf(a.ts,sizeof a.ts,"%s",ts); snprintf(a.event,sizeof a.event,"open");
    snprintf(a.path,sizeof a.path,"%s",path); snprintf(a.proc.exe,sizeof a.proc.exe,"%s",exe);
    a.proc.pid=4242; return a;
}
static struct ps_pp_entity *find(struct ps_pp_model *m, const char *id){
    for(int i=0;i<m->nent;i++) if(m->ent[i].present&&!strcmp(m->ent[i].id,id)) return &m->ent[i];
    return NULL;
}
int main(void){
    struct ps_pp_subject s; memset(&s,0,sizeof s); s.mode=PS_PP_BY_EXE;
    snprintf(s.exe,sizeof s.exe,"/usr/bin/x");

    struct ps_pp_model prod; ps_pp_init(&prod,&s,"01EPOCH"); prod.have_baseline=0;
    struct ps_activity a=fopen_ev("/a","/usr/bin/x","2026-06-05T19:00:00Z");
    ps_pp_fold(&prod,&a,1000);

    char kf[1<<16]; CHECK(ps_pp_keyframe_json(&prod,"ca1",kf,sizeof kf) > 0);

    struct ps_pp_model cons; ps_pp_init(&cons,&s,"");
    CHECK(ps_pp_apply_json(&cons,kf) == PS_PP_APPLY_OK);
    CHECK(strcmp(cons.epoch,"01EPOCH")==0);
    struct ps_pp_entity *ea=find(&cons,"file:/a"); CHECK(ea && ea->count==1);

    struct ps_activity b=fopen_ev("/a","/usr/bin/x","2026-06-05T19:00:05Z");
    ps_pp_fold(&prod,&b,2000);
    struct ps_activity c=fopen_ev("/b","/usr/bin/x","2026-06-05T19:00:06Z");
    ps_pp_fold(&prod,&c,2100);
    char d[1<<16]; int dn = ps_pp_delta_json(&prod,d,sizeof d); CHECK(dn>0);
    CHECK(ps_pp_apply_json(&cons,d) == PS_PP_APPLY_OK);
    CHECK(find(&cons,"file:/a")->count==2);
    CHECK(find(&cons,"file:/b")!=NULL);

    char gap[256];
    snprintf(gap,sizeof gap,"{\"v\":1,\"type\":\"delta\",\"epoch\":\"01EPOCH\",\"seq\":999,\"ops\":[]}");
    CHECK(ps_pp_apply_json(&cons,gap) == PS_PP_APPLY_DESYNC);

    CHECK(ps_pp_delta_json(&prod,d,sizeof d) == 0);
    printf("ok\n");
    return 0;
}
