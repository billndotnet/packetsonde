#include "policy_overwatch.h"
#include "cgroup_unit.h"
#include "json_extract.h"
#include "json.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

enum ps_op ps_overwatch_op_for_event(const char *event) {
    if (!event) return PS_OP_READ;
    if (!strcmp(event, "write")) return PS_OP_WRITE;
    if (!strcmp(event, "exec"))  return PS_OP_EXEC;
    return PS_OP_READ;   /* open|access */
}

/* --- bounded first-seen dedup set of (unit|path|op|directive) keys --- */
#define PS_SEEN_N 1024
struct seen_set { char keys[PS_SEEN_N][320]; int head, count; };
void *ps_overwatch_seen_new(void) { return calloc(1, sizeof(struct seen_set)); }
void  ps_overwatch_seen_free(void *s) { free(s); }
static int seen_check_add(struct seen_set *s, const char *key) {
    for (int i = 0; i < s->count; i++) {
        int idx = (s->head - 1 - i + PS_SEEN_N) % PS_SEEN_N;
        if (strcmp(s->keys[idx], key) == 0) return 1;     /* already seen */
    }
    snprintf(s->keys[s->head], sizeof s->keys[0], "%s", key);
    s->head = (s->head + 1) % PS_SEEN_N;
    if (s->count < PS_SEEN_N) s->count++;
    return 0;
}

static void emit_finding(void (*emit)(void *, const char *, size_t), void *ctx,
                         const char *unit, const char *directive, const char *path,
                         const char *op, int heuristic, const char *comm,
                         const char *exe, const char *mac_mode) {
    char buf[2048]; struct ps_json j; ps_json_init(&j, buf, sizeof buf);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "source", "agent.policy_overwatch");
    ps_json_key_string(&j, "severity", heuristic ? "medium" : "high");
    ps_json_key_string(&j, "confidence", heuristic ? "tentative" : "firm");
    ps_json_key_string(&j, "unit", unit);
    ps_json_key_string(&j, "directive", directive);
    ps_json_key_string(&j, "path", path);
    ps_json_key_string(&j, "op", op);
    ps_json_key_string(&j, "comm", comm);
    ps_json_key_string(&j, "exe", exe);
    ps_json_key_string(&j, "mac_mode", mac_mode);
    ps_json_object_end(&j);
    if (ps_json_finish(&j) > 0 && emit) emit(ctx, buf, (size_t)j.len);
}

static int consider(struct seen_set *seen, void (*emit)(void *, const char *, size_t),
                    void *ectx, const struct ps_unit_policy *pol, const char *unit,
                    const char *path, enum ps_op op, const char *opname,
                    const char *comm, const char *exe, const char *mac_mode) {
    struct ps_eval_result r;
    if (!ps_policy_eval(pol, path, op, &r)) return 0;
    char key[320]; snprintf(key, sizeof key, "%s|%s|%s|%s", unit, path, opname, r.directive);
    if (seen_check_add(seen, key)) return 0;
    emit_finding(emit, ectx, unit, r.directive, path, opname, r.heuristic, comm, exe, mac_mode);
    return 1;
}

int ps_overwatch_process_record(const char *rec, ps_unit_policy_loader loader,
                                void *seenv, void (*emit)(void *, const char *, size_t),
                                void *ectx, uint64_t now_sec) {
    struct seen_set *seen = seenv;
    char event[16], path[512], cgroup[256], comm[64]="", exe[256]="", mac[32]="";
    if (ps_json_extract_string(rec, "event", event, sizeof event) < 0) return 0;
    if (ps_json_extract_string(rec, "path",  path,  sizeof path)  < 0) return 0;
    if (ps_json_extract_string(rec, "cgroup", cgroup, sizeof cgroup) < 0) return 0;
    char unit[128];
    if (ps_cgroup_to_unit(cgroup, unit, sizeof unit) != 0) return 0;   /* not a unit -> skip */
    ps_json_extract_string(rec, "comm", comm, sizeof comm);
    ps_json_extract_string(rec, "exe",  exe,  sizeof exe);
    ps_json_extract_string(rec, "mode", mac,  sizeof mac);            /* mac.mode (first "mode") */

    struct ps_unit_policy pol;
    ps_unit_policy_get(unit, now_sec, 300, loader, &pol);
    if (!pol.known) return 0;

    enum ps_op op = ps_overwatch_op_for_event(event);
    int n = 0;
    n += consider(seen, emit, ectx, &pol, unit, path, op, event, comm, exe, mac);
    if (op == PS_OP_EXEC)   /* exec also evaluated as a READ (exec-from-denied) */
        n += consider(seen, emit, ectx, &pol, unit, path, PS_OP_READ, "exec", comm, exe, mac);
    return n;
}
