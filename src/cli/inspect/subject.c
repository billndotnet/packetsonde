#include "subject.h"
#include <string.h>
#include <stdio.h>

void ps_subject_init_pid(struct ps_inspect_subject *s, int pid) {
    memset(s, 0, sizeof(*s)); s->by_pid = 1; s->root_pid = pid;
    s->pids[s->npids++] = pid;
}
void ps_subject_init_exe(struct ps_inspect_subject *s, const char *exe) {
    memset(s, 0, sizeof(*s)); s->by_pid = 0;
    snprintf(s->exe, sizeof s->exe, "%s", exe);
}
static int tracked(struct ps_inspect_subject *s, int pid) {
    for (int i = 0; i < s->npids; i++) if (s->pids[i] == pid) return 1;
    return 0;
}
static void track(struct ps_inspect_subject *s, int pid) {
    if (tracked(s, pid) || s->npids >= PS_SUBJ_MAX_PIDS) return;
    s->pids[s->npids++] = pid;
}
int ps_subject_match(struct ps_inspect_subject *s, const struct ps_activity *a) {
    if (!s->by_pid) return strcmp(a->proc.exe, s->exe) == 0;
    if (tracked(s, a->proc.pid)) return 1;
    if (a->proc.ppid && tracked(s, a->proc.ppid)) { track(s, a->proc.pid); return 1; }
    return 0;
}
