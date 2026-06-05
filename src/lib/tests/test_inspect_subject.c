#include "subject.h"
#include <stdio.h>
#include <string.h>
#define CHECK(c) do{ if(!(c)){ fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c); return 1; } }while(0)

static struct ps_activity rec(const char *event, int pid, int ppid, const char *exe) {
    struct ps_activity a; memset(&a,0,sizeof a);
    snprintf(a.event,sizeof a.event,"%s",event);
    a.proc.pid=pid; a.proc.ppid=ppid; snprintf(a.proc.exe,sizeof a.proc.exe,"%s",exe);
    return a;
}
int main(void){
    struct ps_inspect_subject e; ps_subject_init_exe(&e,"/usr/bin/x");
    struct ps_activity m1=rec("open",10,1,"/usr/bin/x"); CHECK(ps_subject_match(&e,&m1)==1);
    struct ps_activity m2=rec("open",11,1,"/usr/bin/y"); CHECK(ps_subject_match(&e,&m2)==0);

    struct ps_inspect_subject p; ps_subject_init_pid(&p,100);
    struct ps_activity r1=rec("open",100,1,"/usr/bin/x"); CHECK(ps_subject_match(&p,&r1)==1);
    struct ps_activity r2=rec("exec",200,100,"/bin/sh");  CHECK(ps_subject_match(&p,&r2)==1);
    struct ps_activity r3=rec("open",200,100,"/bin/sh");  CHECK(ps_subject_match(&p,&r3)==1);
    struct ps_activity r4=rec("exec",300,200,"/bin/nc");  CHECK(ps_subject_match(&p,&r4)==1);
    struct ps_activity r5=rec("open",999,1,"/bin/other"); CHECK(ps_subject_match(&p,&r5)==0);
    printf("ok\n");
    return 0;
}
