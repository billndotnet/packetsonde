#include "activity_record.h"
#include "json.h"
#include <string.h>

int ps_activity_to_json(const struct ps_activity *a, char *out, size_t cap) {
    struct ps_json j; ps_json_init(&j, out, cap);
    ps_json_object_begin(&j);
    ps_json_key_int(&j, "v", 1);
    ps_json_key_string(&j, "ts", a->ts);
    ps_json_key_string(&j, "event", a->event);
    ps_json_key_string(&j, "path", a->path);
    ps_json_key_bool(&j, "partial", a->partial);

    ps_json_key_object_begin(&j, "process");
    ps_json_key_int(&j, "pid", a->proc.pid);
    ps_json_key_int(&j, "ppid", a->proc.ppid);
    ps_json_key_int(&j, "uid", a->proc.uid);
    ps_json_key_int(&j, "sid", a->proc.sid);
    ps_json_key_string(&j, "comm", a->proc.comm);
    ps_json_key_string(&j, "exe", a->proc.exe);
    ps_json_key_string(&j, "cmdline", a->proc.cmdline);
    ps_json_key_string(&j, "cgroup", a->proc.cgroup);
    ps_json_key_object_begin(&j, "mac");
    ps_json_key_string(&j, "label", a->proc.mac_label);
    ps_json_key_string(&j, "mode", a->proc.mac_mode);
    ps_json_object_end(&j);   /* mac */
    ps_json_object_end(&j);   /* process */

    ps_json_array_begin(&j, "ancestry");
    for (int i = 0; i < a->nanc; i++) {
        ps_json_object_begin(&j);
        ps_json_key_int(&j, "pid", a->anc[i].pid);
        ps_json_key_string(&j, "comm", a->anc[i].comm);
        ps_json_key_int(&j, "depth", a->anc[i].depth);
        ps_json_object_end(&j);
    }
    ps_json_array_end(&j);

    ps_json_array_begin(&j, "sockets");
    for (int i = 0; i < a->nsock; i++) {
        ps_json_object_begin(&j);
        ps_json_key_int(&j, "owner_pid", a->sock[i].owner_pid);
        ps_json_key_string(&j, "owner_comm", a->sock[i].owner_comm);
        ps_json_key_int(&j, "depth", a->sock[i].depth);
        ps_json_key_string(&j, "proto", a->sock[i].proto);
        ps_json_key_string(&j, "laddr", a->sock[i].laddr);
        ps_json_key_string(&j, "raddr", a->sock[i].raddr);
        ps_json_key_string(&j, "state", a->sock[i].state);
        ps_json_object_end(&j);
    }
    ps_json_array_end(&j);

    ps_json_object_end(&j);
    return ps_json_finish(&j);
}
