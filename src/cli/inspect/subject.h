#ifndef PS_INSPECT_SUBJECT_H
#define PS_INSPECT_SUBJECT_H
#include "activity_record.h"
#define PS_SUBJ_MAX_PIDS 4096
struct ps_inspect_subject {
    int by_pid;
    int root_pid;
    char exe[256];
    int pids[PS_SUBJ_MAX_PIDS]; int npids;
};
void ps_subject_init_pid(struct ps_inspect_subject *s, int pid);
void ps_subject_init_exe(struct ps_inspect_subject *s, const char *exe);
/* Returns 1 if this record belongs to the subject; for pid mode it also grows
 * the subtree when a tracked pid spawns a child. */
int  ps_subject_match(struct ps_inspect_subject *s, const struct ps_activity *a);
#endif
