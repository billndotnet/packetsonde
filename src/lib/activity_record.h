#ifndef PS_ACTIVITY_RECORD_H
#define PS_ACTIVITY_RECORD_H
#include <stddef.h>
#include <stdint.h>

#define PS_ACT_MAX_ANC   16
#define PS_ACT_MAX_SOCK  32

struct ps_act_proc {
    int pid, ppid, uid, sid;
    char comm[64], exe[256], cmdline[512];
    char cgroup[256], mac_label[128], mac_mode[32];
};
struct ps_act_ancestor { int pid, depth; char comm[64]; };
struct ps_act_socket {
    int owner_pid, depth;
    char owner_comm[64], proto[4], laddr[64], raddr[64], state[16];
};
struct ps_activity {
    char ts[24], event[8], path[512];
    int partial;
    struct ps_act_proc proc;
    int nanc;  struct ps_act_ancestor anc[PS_ACT_MAX_ANC];
    int nsock; struct ps_act_socket  sock[PS_ACT_MAX_SOCK];
};

/* Serialize to JSON (schema = spec §5). Returns bytes written, or -1. */
int ps_activity_to_json(const struct ps_activity *a, char *out, size_t cap);

/* Parse a JSON line produced by ps_activity_to_json back into *out.
 * Returns 0 on success, -1 on malformed input. Best-effort: fields absent
 * from the JSON are left zeroed. */
int ps_activity_from_json(const char *json, struct ps_activity *out);
#endif /* PS_ACTIVITY_RECORD_H */
