#ifndef PS_PROC_PROFILE_H
#define PS_PROC_PROFILE_H
#include <stdint.h>
#include "activity_record.h"
#include "baseline_set.h"

#define PS_PP_MAX_ENT 512

enum ps_pp_kind    { PS_PP_FILE = 0, PS_PP_DEST, PS_PP_PROC };
enum ps_pp_verdict { PS_PP_COVERED = 0, PS_PP_NOVEL, PS_PP_ANOMALY, PS_PP_NA };

struct ps_pp_entity {
    char id[544];
    enum ps_pp_kind kind;
    char value[512];
    char state[16];
    uint64_t count;
    char first[24], last[24];
    enum ps_pp_verdict verdict;
    int  dirty;
    int  present;
    int64_t last_ms;
};

struct ps_pp_subject {
    enum { PS_PP_BY_PID = 0, PS_PP_BY_EXE } mode;
    int  pid;
    char exe[256];
    int  uid;
    char cgroup[256], mac_label[128], mac_mode[32];
    int  nanc; struct { int pid; char comm[64]; } anc[PS_ACT_MAX_ANC];
};

struct ps_pp_rates {
    double open_s, connect_s, exec_s;
    uint64_t n_open, n_connect, n_exec;
    uint64_t open_mark, connect_mark, exec_mark;
    int64_t  mark_ms;
};

struct ps_pp_model {
    struct ps_pp_subject subject;
    struct ps_pp_rates   rates;
    struct ps_pp_entity  ent[PS_PP_MAX_ENT];
    int    nent;
    char   epoch[24];
    uint64_t seq;
    struct ps_baseline_set bl_files, den_files, bl_dests, den_dests;
    int    have_baseline;
};

void ps_pp_init(struct ps_pp_model *m, const struct ps_pp_subject *subj,
                const char *epoch);
int  ps_pp_load_baseline(struct ps_pp_model *m, const char *exe, const char *dir);
void ps_pp_fold(struct ps_pp_model *m, const struct ps_activity *a, int64_t now_ms);
void ps_pp_tick_rates(struct ps_pp_model *m, int64_t now_ms);

#endif
