# systemd Policy Overwatch — Phase A (core + overwatch) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A brain-side `policy_overwatch` module drains the SP1 activity ring and, for each observed access, flags when a process's *declared* systemd sandbox (`systemctl show`) should have blocked it — emitting a finding through the existing publish pipeline.

**Architecture:** Phase A first extends SP1 with a write-typed event (`FAN_CLOSE_WRITE` → `event:"write"`) so read-vs-write policy is decidable. Then a tick-driven module (like `iface_monitor`) drains the ring, resolves each record's systemd unit from its `cgroup`, looks up the unit's derived sandbox policy (cached), evaluates the access, dedups, and publishes. Pure units (`cgroup_unit`, `systemd_policy` derive, `policy_eval`, the record-processing core) are fixture-tested; the `systemctl` I/O + module wiring are integration.

**Tech Stack:** C11, CMake/CTest. Reuses SP1's `activity_ring` (`ps_act_ring_drain`), `src/lib/json_extract` (`ps_json_extract_string`), the module framework (`ps_module_t`/`ps_module_ctx_t`, `ctx->publish`), `ps_json` writer, `config_to_env`, `popen`.

**Spec:** `docs/specs/2026-06-03-systemd-policy-overwatch-design.md` (this is **Phase A** per §10; Phase B = learn mode, separate plan).

**Build:** `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON && make <target> && ctest -R '^<name>$' --output-on-failure`. Known pre-existing: `test_via_e2e` is a flaky env test (exclude with `-E test_via_e2e`); `test_probe_icmp` skips.

---

## Interfaces locked here

- **`src/agent/src/fan_monitor.h`:** `const char *ps_fan_event_for_mask(unsigned long long mask, int *is_read);` → returns `"exec"|"write"|"access"|"open"`, sets `*is_read` (0 for exec/write, 1 for access/open).
- **`src/lib/cgroup_unit.h`:** `int ps_cgroup_to_unit(const char *cgroup, char *out, size_t cap);` → 0 + unit name (e.g. `smbd.service`) if the last segment ends in a unit suffix, else -1.
- **`src/lib/systemd_policy.h`:** `struct ps_unit_policy` (below); `int ps_unit_policy_derive(const char *systemctl_show_text, struct ps_unit_policy *out);` (pure); `typedef int (*ps_unit_policy_loader)(const char *unit, char *out, size_t cap);` and `int ps_unit_policy_get(const char *unit, uint64_t now_sec, uint64_t ttl_sec, ps_unit_policy_loader loader, struct ps_unit_policy *out);` (cached).
- **`src/lib/policy_eval.h`:** `enum ps_op { PS_OP_READ, PS_OP_WRITE, PS_OP_EXEC };` `struct ps_eval_result { int violation; const char *directive; int heuristic; };` `int ps_policy_eval(const struct ps_unit_policy *p, const char *path, enum ps_op op, struct ps_eval_result *out);` → returns 1 on violation.
- **`src/agent/src/modules/policy_overwatch.h`:** `enum ps_op ps_overwatch_op_for_event(const char *event);` and the testable core `int ps_overwatch_process_record(const char *record_json, ps_unit_policy_loader loader, void *seen, void (*emit)(void *emit_ctx, const char *json, size_t len), void *emit_ctx, uint64_t now_sec);`

`struct ps_unit_policy` (systemd_policy.h):
```c
#define PS_POL_MAX_PATHS 64
#define PS_POL_PATHLEN  256
enum ps_protect_system { PS_PROTSYS_NO=0, PS_PROTSYS_YES, PS_PROTSYS_FULL, PS_PROTSYS_STRICT };
enum ps_protect_home   { PS_PROTHOME_NO=0, PS_PROTHOME_RO, PS_PROTHOME_INACCESSIBLE };
struct ps_unit_policy {
    int known;                 /* 0 => no policy / not a unit => skip */
    enum ps_protect_system protect_system;
    enum ps_protect_home   protect_home;
    int private_tmp;           /* bool */
    int mdwe;                  /* MemoryDenyWriteExecute bool */
    int n_rw;    char rw   [PS_POL_MAX_PATHS][PS_POL_PATHLEN];  /* ReadWritePaths */
    int n_ro;    char ro   [PS_POL_MAX_PATHS][PS_POL_PATHLEN];  /* ReadOnlyPaths */
    int n_inacc; char inacc[PS_POL_MAX_PATHS][PS_POL_PATHLEN];  /* InaccessiblePaths */
};
```

---

## Task 1: SP1 write-typed event (`FAN_CLOSE_WRITE`)

**Files:** Modify `src/agent/src/fan_monitor.c`, `src/agent/src/fan_monitor.h`; Test `src/agent/tests/test_fan_event.c`; Modify `src/agent/CMakeLists.txt`

> SP1 emits `open`/`access`/`exec` but can't tell a write open from a read open. Add a `write` event via `FAN_CLOSE_WRITE` and factor the mask→event mapping into a pure, testable helper.

- [ ] **Step 1: Write the failing test** (`src/agent/tests/test_fan_event.c`)

```c
#include "fan_monitor.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sys/fanotify.h>

int main(void) {
    int is_read = -1;
    assert(strcmp(ps_fan_event_for_mask(FAN_OPEN_EXEC, &is_read), "exec") == 0);
    assert(is_read == 0);
    assert(strcmp(ps_fan_event_for_mask(FAN_CLOSE_WRITE, &is_read), "write") == 0);
    assert(is_read == 0);                                  /* writes never suppressed */
    assert(strcmp(ps_fan_event_for_mask(FAN_ACCESS, &is_read), "access") == 0);
    assert(is_read == 1);
    assert(strcmp(ps_fan_event_for_mask(FAN_OPEN, &is_read), "open") == 0);
    assert(is_read == 1);
    /* precedence: exec > write > access > open when bits combine */
    assert(strcmp(ps_fan_event_for_mask(FAN_OPEN | FAN_CLOSE_WRITE, &is_read), "write") == 0);
    assert(strcmp(ps_fan_event_for_mask(FAN_OPEN_EXEC | FAN_OPEN, &is_read), "exec") == 0);
    printf("test_fan_event: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_fan_event 2>&1 | tail -4`
Expected: FAIL — `ps_fan_event_for_mask` undeclared.

- [ ] **Step 3: Declare the helper in `src/agent/src/fan_monitor.h`** (after the `ps_fan_build_record` declaration)

```c
/* Map a fanotify event mask to the activity-record event string and read-ness.
 * Precedence: exec > write > access > open. *is_read is 0 for exec/write
 * (never suppressed), 1 for access/open. */
const char *ps_fan_event_for_mask(unsigned long long mask, int *is_read);
```

- [ ] **Step 4: Implement the helper + add `FAN_CLOSE_WRITE` in `src/agent/src/fan_monitor.c`**

Add the function (near the top, after the includes — it needs `<sys/fanotify.h>`, already included by the runtime section):

```c
const char *ps_fan_event_for_mask(unsigned long long mask, int *is_read) {
    if (mask & FAN_OPEN_EXEC)   { if (is_read) *is_read = 0; return "exec"; }
    if (mask & FAN_CLOSE_WRITE) { if (is_read) *is_read = 0; return "write"; }
    if (mask & FAN_ACCESS)      { if (is_read) *is_read = 1; return "access"; }
    if (is_read) *is_read = 1;  return "open";
}
```

In `ps_fan_monitor_run`, add `FAN_CLOSE_WRITE` to the per-path mark and replace the inline event/is_read derivation with the helper:

```c
        fanotify_mark(fan, FAN_MARK_ADD,
                      FAN_OPEN | FAN_ACCESS | FAN_OPEN_EXEC | FAN_CLOSE_WRITE, AT_FDCWD, p);
```
and in the event loop, replace the existing `const char *event = ...; int is_read = ...;` two lines with:
```c
            int is_read = 1;
            const char *event = ps_fan_event_for_mask(m->mask, &is_read);
```

> Note: a write produces both an `open` (treated as read) and a `write` record — harmless; overwatch uses the `write` record for write-deny checks. The mount-wide `FAN_OPEN_EXEC` mark is unchanged.

- [ ] **Step 5: Wire the test into `src/agent/CMakeLists.txt`** (mirror the `test_fan_build` block; it needs `fan_monitor.c` + its deps, link `packetsonde_lib`)

```cmake
add_executable(test_fan_event tests/test_fan_event.c
    src/fan_monitor.c src/proc_enrich.c src/sock_snapshot.c)
target_link_libraries(test_fan_event PRIVATE packetsonde_lib)
add_test(NAME test_fan_event COMMAND test_fan_event)
```

- [ ] **Step 6: Run to verify it passes + no regressions**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_fan_event test_fan_build packetsonde-agent packetsonde-priv >/dev/null 2>&1 && ctest -R 'fan_event|fan_build' --output-on-failure`
Expected: PASS; both binaries still link.

- [ ] **Step 7: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/src/fan_monitor.c src/agent/src/fan_monitor.h src/agent/tests/test_fan_event.c src/agent/CMakeLists.txt
git commit -m "agent: add write-typed activity event (FAN_CLOSE_WRITE) + pure mask->event helper"
```

---

## Task 2: `cgroup` → unit (`src/lib/cgroup_unit`)

**Files:** Create `src/lib/cgroup_unit.h`, `src/lib/cgroup_unit.c`; Test `src/lib/tests/test_cgroup_unit.c`; Modify `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test** (`src/lib/tests/test_cgroup_unit.c`)

```c
#include "cgroup_unit.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char u[128];
    assert(ps_cgroup_to_unit("/system.slice/smbd.service", u, sizeof u) == 0);
    assert(strcmp(u, "smbd.service") == 0);
    /* nested slice */
    assert(ps_cgroup_to_unit("/system.slice/system-getty.slice/getty@tty1.service", u, sizeof u) == 0);
    assert(strcmp(u, "getty@tty1.service") == 0);
    /* .socket / .scope / .mount accepted */
    assert(ps_cgroup_to_unit("/system.slice/sshd.socket", u, sizeof u) == 0);
    assert(strcmp(u, "sshd.socket") == 0);
    /* a .slice tail is NOT a unit we evaluate -> -1 */
    assert(ps_cgroup_to_unit("/system.slice", u, sizeof u) == -1);
    /* user session / non-unit cgroup -> -1 */
    assert(ps_cgroup_to_unit("/user.slice/user-1000.slice/session-3.scope/init.scope", u, sizeof u) == 0); /* .scope is a unit */
    assert(ps_cgroup_to_unit("", u, sizeof u) == -1);
    printf("test_cgroup_unit: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_cgroup_unit 2>&1 | tail -4`
Expected: FAIL — `cgroup_unit.h` not found.

- [ ] **Step 3: Create `src/lib/cgroup_unit.h`**

```c
#ifndef PS_CGROUP_UNIT_H
#define PS_CGROUP_UNIT_H
#include <stddef.h>
/* Extract the systemd unit from a cgroup path: the last '/'-segment if it ends
 * in .service/.socket/.mount/.scope. Returns 0 + unit name, or -1 if the cgroup
 * yields no evaluable unit (a .slice tail, empty, or non-unit). */
int ps_cgroup_to_unit(const char *cgroup, char *out, size_t cap);
#endif
```

- [ ] **Step 4: Create `src/lib/cgroup_unit.c`**

```c
#include "cgroup_unit.h"
#include <string.h>

static int has_suffix(const char *s, const char *suf) {
    size_t ls = strlen(s), lf = strlen(suf);
    return ls >= lf && strcmp(s + ls - lf, suf) == 0;
}

int ps_cgroup_to_unit(const char *cgroup, char *out, size_t cap) {
    if (!cgroup || !*cgroup) return -1;
    const char *slash = strrchr(cgroup, '/');
    const char *seg = slash ? slash + 1 : cgroup;
    if (!*seg) return -1;
    if (has_suffix(seg, ".service") || has_suffix(seg, ".socket") ||
        has_suffix(seg, ".mount")   || has_suffix(seg, ".scope")) {
        size_t n = strlen(seg);
        if (n >= cap) return -1;
        memcpy(out, seg, n + 1);
        return 0;
    }
    return -1;
}
```

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `cgroup_unit.c` to `packetsonde_lib` sources; add the test:

```cmake
    add_executable(test_cgroup_unit tests/test_cgroup_unit.c)
    target_link_libraries(test_cgroup_unit PRIVATE packetsonde_lib)
    add_test(NAME test_cgroup_unit COMMAND test_cgroup_unit)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_cgroup_unit >/dev/null && ctest -R '^test_cgroup_unit$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/lib/cgroup_unit.h src/lib/cgroup_unit.c src/lib/tests/test_cgroup_unit.c src/lib/CMakeLists.txt
git commit -m "lib: add cgroup->systemd-unit extraction"
```

---

## Task 3: `systemd_policy` types + derivation (`src/lib/systemd_policy`)

**Files:** Create `src/lib/systemd_policy.h`, `src/lib/systemd_policy.c`; Test `src/lib/tests/test_systemd_policy.c`; Modify `src/lib/CMakeLists.txt`

> Pure: parse `systemctl show` `Key=Value` text into a `ps_unit_policy`. (Acquisition + cache come in Task 4.)

- [ ] **Step 1: Write the failing test** (`src/lib/tests/test_systemd_policy.c`)

```c
#include "systemd_policy.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static const char *SHOW =
    "FragmentPath=/usr/lib/systemd/system/app.service\n"
    "ProtectSystem=strict\n"
    "ProtectHome=true\n"
    "PrivateTmp=yes\n"
    "MemoryDenyWriteExecute=yes\n"
    "ReadWritePaths=/var/lib/app /var/log/app\n"
    "ReadOnlyPaths=\n"
    "InaccessiblePaths=/etc/ssl/private\n";

int main(void) {
    struct ps_unit_policy p;
    assert(ps_unit_policy_derive(SHOW, &p) == 0);
    assert(p.known == 1);
    assert(p.protect_system == PS_PROTSYS_STRICT);
    assert(p.protect_home == PS_PROTHOME_INACCESSIBLE);
    assert(p.private_tmp == 1);
    assert(p.mdwe == 1);
    assert(p.n_rw == 2);
    assert(strcmp(p.rw[0], "/var/lib/app") == 0 && strcmp(p.rw[1], "/var/log/app") == 0);
    assert(p.n_ro == 0);
    assert(p.n_inacc == 1 && strcmp(p.inacc[0], "/etc/ssl/private") == 0);

    /* unset/default -> known but permissive */
    struct ps_unit_policy d;
    assert(ps_unit_policy_derive("FragmentPath=/x.service\nProtectSystem=no\nProtectHome=no\n", &d) == 0);
    assert(d.known == 1 && d.protect_system == PS_PROTSYS_NO && d.protect_home == PS_PROTHOME_NO);

    /* no FragmentPath (unit not found) -> not known */
    struct ps_unit_policy n;
    assert(ps_unit_policy_derive("", &n) == 0 && n.known == 0);
    printf("test_systemd_policy: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_systemd_policy 2>&1 | tail -4`
Expected: FAIL — `systemd_policy.h` not found.

- [ ] **Step 3: Create `src/lib/systemd_policy.h`** — the struct from "Interfaces locked here" plus:

```c
#ifndef PS_SYSTEMD_POLICY_H
#define PS_SYSTEMD_POLICY_H
#include <stddef.h>
#include <stdint.h>

#define PS_POL_MAX_PATHS 64
#define PS_POL_PATHLEN  256
enum ps_protect_system { PS_PROTSYS_NO=0, PS_PROTSYS_YES, PS_PROTSYS_FULL, PS_PROTSYS_STRICT };
enum ps_protect_home   { PS_PROTHOME_NO=0, PS_PROTHOME_RO, PS_PROTHOME_INACCESSIBLE };
struct ps_unit_policy {
    int known;
    enum ps_protect_system protect_system;
    enum ps_protect_home   protect_home;
    int private_tmp;
    int mdwe;
    int n_rw;    char rw   [PS_POL_MAX_PATHS][PS_POL_PATHLEN];
    int n_ro;    char ro   [PS_POL_MAX_PATHS][PS_POL_PATHLEN];
    int n_inacc; char inacc[PS_POL_MAX_PATHS][PS_POL_PATHLEN];
};

/* Parse `systemctl show <unit>` Key=Value text into *out. known=0 if no
 * FragmentPath (unit not found). Returns 0 (always; malformed lines ignored). */
int ps_unit_policy_derive(const char *systemctl_show_text, struct ps_unit_policy *out);

typedef int (*ps_unit_policy_loader)(const char *unit, char *out, size_t cap);
/* Cached lookup: returns a derived policy for `unit`, loading via `loader` on a
 * cold/expired entry (ttl_sec). now_sec is the caller's clock. Returns 0. */
int ps_unit_policy_get(const char *unit, uint64_t now_sec, uint64_t ttl_sec,
                       ps_unit_policy_loader loader, struct ps_unit_policy *out);
#endif
```

- [ ] **Step 4: Create `src/lib/systemd_policy.c`** (derivation only; `ps_unit_policy_get` added in Task 4)

```c
#include "systemd_policy.h"
#include <string.h>
#include <stdlib.h>

static void add_paths(const char *val, char arr[][PS_POL_PATHLEN], int *n) {
    /* space-separated list */
    const char *p = val;
    while (*p && *n < PS_POL_MAX_PATHS) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *e = p;
        while (*e && *e != ' ') e++;
        size_t len = (size_t)(e - p);
        if (len > 0 && len < PS_POL_PATHLEN) { memcpy(arr[*n], p, len); arr[*n][len] = 0; (*n)++; }
        p = e;
    }
}

int ps_unit_policy_derive(const char *txt, struct ps_unit_policy *out) {
    memset(out, 0, sizeof *out);
    if (!txt) return 0;
    const char *line = txt;
    while (*line) {
        const char *nl = strchr(line, '\n');
        size_t llen = nl ? (size_t)(nl - line) : strlen(line);
        const char *eq = memchr(line, '=', llen);
        if (eq) {
            size_t klen = (size_t)(eq - line);
            const char *val = eq + 1;
            size_t vlen = llen - klen - 1;
            char v[2048]; size_t vc = vlen < sizeof v - 1 ? vlen : sizeof v - 1;
            memcpy(v, val, vc); v[vc] = 0;
            #define KEYIS(k) (klen == strlen(k) && strncmp(line, k, klen) == 0)
            if (KEYIS("FragmentPath")) { out->known = (vc > 0); }
            else if (KEYIS("ProtectSystem")) {
                out->protect_system = !strcmp(v,"strict") ? PS_PROTSYS_STRICT :
                                      !strcmp(v,"full")   ? PS_PROTSYS_FULL :
                                      !strcmp(v,"yes")    ? PS_PROTSYS_YES : PS_PROTSYS_NO;
            } else if (KEYIS("ProtectHome")) {
                out->protect_home = !strcmp(v,"read-only") ? PS_PROTHOME_RO :
                                    (!strcmp(v,"yes") || !strcmp(v,"tmpfs")) ? PS_PROTHOME_INACCESSIBLE :
                                    PS_PROTHOME_NO;
            } else if (KEYIS("PrivateTmp"))             out->private_tmp = !strcmp(v,"yes");
            else if (KEYIS("MemoryDenyWriteExecute"))   out->mdwe = !strcmp(v,"yes");
            else if (KEYIS("ReadWritePaths"))           add_paths(v, out->rw, &out->n_rw);
            else if (KEYIS("ReadOnlyPaths"))            add_paths(v, out->ro, &out->n_ro);
            else if (KEYIS("InaccessiblePaths"))        add_paths(v, out->inacc, &out->n_inacc);
            #undef KEYIS
        }
        if (!nl) break;
        line = nl + 1;
    }
    return 0;
}
```

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `systemd_policy.c` to `packetsonde_lib`; add the test block (`test_systemd_policy`, same shape as Task 2 Step 5).

- [ ] **Step 6: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_systemd_policy >/dev/null && ctest -R '^test_systemd_policy$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/lib/systemd_policy.h src/lib/systemd_policy.c src/lib/tests/test_systemd_policy.c src/lib/CMakeLists.txt
git commit -m "lib: add systemd unit-policy struct + systemctl-show derivation"
```

---

## Task 4: `systemd_policy` cache + acquisition (`ps_unit_policy_get` + loader)

**Files:** Modify `src/lib/systemd_policy.c`, `src/lib/systemd_policy.h`; Test `src/lib/tests/test_systemd_policy_cache.c`; Modify `src/lib/CMakeLists.txt`

> The cache is pure-logic (testable with a stub loader counting calls). The real `popen` loader is a thin wrapper, added here and used only by the module (Task 7), not unit-tested.

- [ ] **Step 1: Write the failing test** (`src/lib/tests/test_systemd_policy_cache.c`)

```c
#include "systemd_policy.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static int g_calls = 0;
static int stub_loader(const char *unit, char *out, size_t cap) {
    g_calls++;
    if (!strcmp(unit, "app.service"))
        snprintf(out, cap, "FragmentPath=/x.service\nProtectHome=true\n");
    else
        snprintf(out, cap, "");   /* unknown unit */
    return 0;
}

int main(void) {
    struct ps_unit_policy p;
    /* cold miss -> loads */
    assert(ps_unit_policy_get("app.service", 1000, 300, stub_loader, &p) == 0);
    assert(p.known == 1 && p.protect_home == PS_PROTHOME_INACCESSIBLE);
    assert(g_calls == 1);
    /* within TTL -> cached, no reload */
    assert(ps_unit_policy_get("app.service", 1100, 300, stub_loader, &p) == 0);
    assert(g_calls == 1);
    /* past TTL -> reload */
    assert(ps_unit_policy_get("app.service", 1400, 300, stub_loader, &p) == 0);
    assert(g_calls == 2);
    /* unknown unit cached too (known=0) */
    assert(ps_unit_policy_get("nope.service", 1400, 300, stub_loader, &p) == 0);
    assert(p.known == 0);
    assert(g_calls == 3);
    assert(ps_unit_policy_get("nope.service", 1450, 300, stub_loader, &p) == 0);
    assert(g_calls == 3);   /* negative result cached */
    printf("test_systemd_policy_cache: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_systemd_policy_cache 2>&1 | tail -4`
Expected: FAIL — `ps_unit_policy_get` undefined.

- [ ] **Step 3: Add `ps_unit_policy_get` + the popen loader to `systemd_policy.c`**

```c
/* --- cache --- */
#define PS_POL_CACHE_N 128
struct pol_cache_ent { char unit[128]; uint64_t loaded_sec; struct ps_unit_policy pol; int used; };
static struct pol_cache_ent g_cache[PS_POL_CACHE_N];

int ps_unit_policy_get(const char *unit, uint64_t now_sec, uint64_t ttl_sec,
                       ps_unit_policy_loader loader, struct ps_unit_policy *out) {
    struct pol_cache_ent *slot = NULL, *lru = &g_cache[0];
    for (int i = 0; i < PS_POL_CACHE_N; i++) {
        if (g_cache[i].used && strcmp(g_cache[i].unit, unit) == 0) { slot = &g_cache[i]; break; }
        if (!g_cache[i].used) { if (!slot) slot = &g_cache[i]; }
        if (g_cache[i].loaded_sec < lru->loaded_sec) lru = &g_cache[i];
    }
    if (slot && slot->used && strcmp(slot->unit, unit) == 0 &&
        now_sec - slot->loaded_sec < ttl_sec) { *out = slot->pol; return 0; }
    if (!slot) slot = lru;                 /* evict LRU */

    char text[8192];
    if (loader(unit, text, sizeof text) != 0) text[0] = 0;
    struct ps_unit_policy pol; ps_unit_policy_derive(text, &pol);
    snprintf(slot->unit, sizeof slot->unit, "%s", unit);
    slot->loaded_sec = now_sec; slot->pol = pol; slot->used = 1;
    *out = pol;
    return 0;
}

/* Real loader: `systemctl show <unit> -p ...`. Unit is validated (systemd unit
 * charset) before being placed in the command to avoid shell injection. */
int ps_unit_policy_load_systemctl(const char *unit, char *out, size_t cap) {
    for (const char *c = unit; *c; c++) {
        if (!((*c>='A'&&*c<='Z')||(*c>='a'&&*c<='z')||(*c>='0'&&*c<='9')||
              *c=='.'||*c=='-'||*c=='_'||*c=='@'||*c==':'||*c=='\\')) { out[0]=0; return -1; }
    }
    char cmd[512];
    snprintf(cmd, sizeof cmd,
        "systemctl show '%s' -p FragmentPath -p ProtectSystem -p ProtectHome "
        "-p PrivateTmp -p MemoryDenyWriteExecute -p ReadWritePaths -p ReadOnlyPaths "
        "-p InaccessiblePaths 2>/dev/null", unit);
    FILE *f = popen(cmd, "r");
    if (!f) { out[0] = 0; return -1; }
    size_t n = fread(out, 1, cap - 1, f);
    pclose(f);
    out[n] = 0;
    return 0;
}
```

Declare the real loader in `systemd_policy.h`:
```c
int ps_unit_policy_load_systemctl(const char *unit, char *out, size_t cap);
```
Add `#include <stdio.h>` to `systemd_policy.c` if not present.

- [ ] **Step 4: Wire the test into `src/lib/CMakeLists.txt`** — add `test_systemd_policy_cache` (same shape).

- [ ] **Step 5: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_systemd_policy_cache >/dev/null && ctest -R '^test_systemd_policy_cache$' --output-on-failure`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/lib/systemd_policy.c src/lib/systemd_policy.h src/lib/tests/test_systemd_policy_cache.c src/lib/CMakeLists.txt
git commit -m "lib: add per-unit policy cache (TTL/LRU) + systemctl-show popen loader"
```

---

## Task 5: `policy_eval` (`src/lib/policy_eval`)

**Files:** Create `src/lib/policy_eval.h`, `src/lib/policy_eval.c`; Test `src/lib/tests/test_policy_eval.c`; Modify `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test** (`src/lib/tests/test_policy_eval.c`)

```c
#include "policy_eval.h"
#include "systemd_policy.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static struct ps_unit_policy mk(void) {
    struct ps_unit_policy p; memset(&p, 0, sizeof p);
    p.known = 1; p.protect_system = PS_PROTSYS_STRICT; p.protect_home = PS_PROTHOME_INACCESSIBLE;
    p.mdwe = 1;
    p.n_rw = 1; snprintf(p.rw[0], PS_POL_PATHLEN, "/var/lib/app");
    p.n_inacc = 1; snprintf(p.inacc[0], PS_POL_PATHLEN, "/etc/ssl/private");
    return p;
}

int main(void) {
    struct ps_unit_policy p = mk();
    struct ps_eval_result r;

    /* write outside ReadWritePaths under ProtectSystem=strict -> violation */
    assert(ps_policy_eval(&p, "/etc/passwd", PS_OP_WRITE, &r) == 1);
    assert(strcmp(r.directive, "ProtectSystem") == 0 && r.heuristic == 0);
    /* write INSIDE ReadWritePaths -> allowed */
    assert(ps_policy_eval(&p, "/var/lib/app/db/0001.dat", PS_OP_WRITE, &r) == 0);
    /* prefix boundary: /var/lib/appX is NOT under /var/lib/app */
    assert(ps_policy_eval(&p, "/var/lib/appX/y", PS_OP_WRITE, &r) == 1);
    /* read of a normal protected path under ProtectSystem -> allowed (reads ok) */
    assert(ps_policy_eval(&p, "/etc/passwd", PS_OP_READ, &r) == 0);
    /* read under ProtectHome=inaccessible -> violation */
    assert(ps_policy_eval(&p, "/home/alice/.ssh/id_rsa", PS_OP_READ, &r) == 1);
    assert(strcmp(r.directive, "ProtectHome") == 0);
    /* any access under InaccessiblePaths -> violation */
    assert(ps_policy_eval(&p, "/etc/ssl/private/key.pem", PS_OP_READ, &r) == 1);
    assert(strcmp(r.directive, "InaccessiblePaths") == 0);
    /* exec from a ReadWritePath under mdwe -> heuristic violation */
    assert(ps_policy_eval(&p, "/var/lib/app/dropped.bin", PS_OP_EXEC, &r) == 1);
    assert(strcmp(r.directive, "exec_from_writable") == 0 && r.heuristic == 1);
    /* exec from a normal read-only path -> allowed */
    assert(ps_policy_eval(&p, "/usr/bin/python3", PS_OP_EXEC, &r) == 0);

    /* a permissive unit (no directives) -> never a violation */
    struct ps_unit_policy perm; memset(&perm, 0, sizeof perm); perm.known = 1;
    assert(ps_policy_eval(&perm, "/etc/passwd", PS_OP_WRITE, &r) == 0);
    printf("test_policy_eval: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_policy_eval 2>&1 | tail -4`
Expected: FAIL — `policy_eval.h` not found.

- [ ] **Step 3: Create `src/lib/policy_eval.h`**

```c
#ifndef PS_POLICY_EVAL_H
#define PS_POLICY_EVAL_H
#include "systemd_policy.h"
enum ps_op { PS_OP_READ=0, PS_OP_WRITE, PS_OP_EXEC };
struct ps_eval_result { int violation; const char *directive; int heuristic; };
/* Evaluate one access against a unit policy. Returns 1 if a violation (out set),
 * 0 if allowed. Conservative: only clear violations. */
int ps_policy_eval(const struct ps_unit_policy *p, const char *path,
                   enum ps_op op, struct ps_eval_result *out);
#endif
```

- [ ] **Step 4: Create `src/lib/policy_eval.c`**

```c
#include "policy_eval.h"
#include <string.h>

/* path-prefix with boundary: "/a/b" matches "/a/b" and "/a/b/..." but not "/a/bc" */
static int under(const char *path, const char *prefix) {
    size_t lp = strlen(prefix);
    if (lp == 0) return 0;
    if (strncmp(path, prefix, lp) != 0) return 0;
    return path[lp] == 0 || path[lp] == '/' || (lp > 0 && prefix[lp-1] == '/');
}
static int under_any(const char *path, char arr[][PS_POL_PATHLEN], int n) {
    for (int i = 0; i < n; i++) if (under(path, arr[i])) return 1;
    return 0;
}
static int protsys_protects(enum ps_protect_system ps, const char *path) {
    if (ps == PS_PROTSYS_STRICT) return 1;                 /* whole FS read-only */
    if (ps >= PS_PROTSYS_FULL  && under(path, "/etc")) return 1;
    if (ps >= PS_PROTSYS_YES && (under(path,"/usr")||under(path,"/boot")||under(path,"/efi"))) return 1;
    return 0;
}

static int hit(struct ps_eval_result *o, const char *dir, int heur) {
    o->violation = 1; o->directive = dir; o->heuristic = heur; return 1;
}

int ps_policy_eval(const struct ps_unit_policy *p, const char *path,
                   enum ps_op op, struct ps_eval_result *out) {
    out->violation = 0; out->directive = NULL; out->heuristic = 0;
    if (!p->known || !path || !*path) return 0;

    /* deny-all: InaccessiblePaths (any op) */
    if (under_any(path, (char(*)[PS_POL_PATHLEN])p->inacc, p->n_inacc))
        return hit(out, "InaccessiblePaths", 0);
    /* ProtectHome=inaccessible: any op on home dirs */
    if (p->protect_home == PS_PROTHOME_INACCESSIBLE &&
        (under(path,"/home")||under(path,"/root")||under(path,"/run/user")))
        return hit(out, "ProtectHome", 0);

    int rw = under_any(path, (char(*)[PS_POL_PATHLEN])p->rw, p->n_rw);

    if (op == PS_OP_WRITE) {
        if (rw) return 0;                                  /* ReadWritePaths exception wins */
        if (p->protect_home == PS_PROTHOME_RO &&
            (under(path,"/home")||under(path,"/root")||under(path,"/run/user")))
            return hit(out, "ProtectHome", 0);
        if (under_any(path, (char(*)[PS_POL_PATHLEN])p->ro, p->n_ro))
            return hit(out, "ReadOnlyPaths", 0);
        if (protsys_protects(p->protect_system, path))
            return hit(out, "ProtectSystem", 0);
        return 0;
    }
    if (op == PS_OP_EXEC) {
        /* exec from a writable area on a hardened unit (heuristic) */
        if (rw && (p->mdwe || p->protect_system == PS_PROTSYS_STRICT))
            return hit(out, "exec_from_writable", 1);
        return 0;                                          /* exec-from-denied handled as READ below */
    }
    /* PS_OP_READ: only the deny-all checks above apply (reads of ProtectSystem ok) */
    return 0;
}
```

> Note: an `exec` record is processed by the caller (Task 6) as **both** an EXEC eval (this heuristic) **and** a READ eval (so exec-from-`InaccessiblePaths`/`ProtectHome` is caught by the deny-all read path).

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `policy_eval.c` to `packetsonde_lib`; add `test_policy_eval`.

- [ ] **Step 6: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_policy_eval >/dev/null && ctest -R '^test_policy_eval$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/lib/policy_eval.h src/lib/policy_eval.c src/lib/tests/test_policy_eval.c src/lib/CMakeLists.txt
git commit -m "lib: add policy_eval (observed access vs derived unit sandbox)"
```

---

## Task 6: Overwatch record-processing core (`src/agent/src/modules/policy_overwatch` core)

**Files:** Create `src/agent/src/modules/policy_overwatch.h`, `src/agent/src/modules/policy_overwatch.c` (core only); Test `src/agent/tests/test_overwatch_core.c`; Modify `src/agent/CMakeLists.txt`

> Testable core: parse a record JSON, resolve unit, look up policy (injected loader), evaluate (read + exec for exec events), dedup, emit (injected). The module tick (Task 7) wires the ring + real loader + publish to this.

- [ ] **Step 1: Write the failing test** (`src/agent/tests/test_overwatch_core.c`)

```c
#include "policy_overwatch.h"
#include "systemd_policy.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static int loader(const char *unit, char *out, size_t cap) {
    if (!strcmp(unit, "app.service"))
        snprintf(out, cap, "FragmentPath=/x.service\nProtectHome=true\nProtectSystem=strict\nReadWritePaths=/var/lib/app\n");
    else out[0] = 0;
    return 0;
}
static int g_emits = 0; static char g_last[4096];
static void emit(void *c, const char *json, size_t len) { (void)c;(void)len; g_emits++; snprintf(g_last,sizeof g_last,"%s",json); }

static const char *REC(const char *event, const char *path) {
    static char b[2048];
    snprintf(b, sizeof b,
      "{\"v\":1,\"event\":\"%s\",\"path\":\"%s\",\"process\":{\"pid\":9,\"comm\":\"app\",\"exe\":\"/usr/bin/app\","
      "\"cgroup\":\"/system.slice/app.service\",\"mac\":{\"label\":\"unconfined\",\"mode\":\"unconfined\"}}}", event, path);
    return b;
}

int main(void) {
    void *seen = ps_overwatch_seen_new();
    g_emits = 0;
    /* op mapping */
    assert(ps_overwatch_op_for_event("write") == PS_OP_WRITE);
    assert(ps_overwatch_op_for_event("exec")  == PS_OP_EXEC);
    assert(ps_overwatch_op_for_event("access")== PS_OP_READ);
    assert(ps_overwatch_op_for_event("open")  == PS_OP_READ);

    /* write to /home under ProtectHome=true -> 1 finding */
    ps_overwatch_process_record(REC("write","/home/x/secret"), loader, seen, emit, NULL, 100);
    assert(g_emits == 1);
    assert(strstr(g_last, "\"directive\":\"ProtectHome\""));
    assert(strstr(g_last, "\"unit\":\"app.service\""));
    /* same (unit,path,op,directive) again -> deduped, no new finding */
    ps_overwatch_process_record(REC("write","/home/x/secret"), loader, seen, emit, NULL, 101);
    assert(g_emits == 1);
    /* write inside ReadWritePaths -> allowed, no finding */
    ps_overwatch_process_record(REC("write","/var/lib/app/db"), loader, seen, emit, NULL, 102);
    assert(g_emits == 1);
    /* record with no unit (user slice) -> skipped */
    const char *nounit = "{\"event\":\"write\",\"path\":\"/home/x\",\"process\":{\"cgroup\":\"/user.slice\"}}";
    ps_overwatch_process_record(nounit, loader, seen, emit, NULL, 103);
    assert(g_emits == 1);
    ps_overwatch_seen_free(seen);
    printf("test_overwatch_core: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_overwatch_core 2>&1 | tail -4`
Expected: FAIL — `policy_overwatch.h` not found.

- [ ] **Step 3: Create `src/agent/src/modules/policy_overwatch.h`**

```c
#ifndef PS_POLICY_OVERWATCH_H
#define PS_POLICY_OVERWATCH_H
#include <stddef.h>
#include <stdint.h>
#include "policy_eval.h"
#include "systemd_policy.h"

enum ps_op ps_overwatch_op_for_event(const char *event);

/* opaque first-seen dedup set */
void *ps_overwatch_seen_new(void);
void  ps_overwatch_seen_free(void *seen);

/* Parse one activity-record JSON, resolve unit, look up policy via `loader`,
 * evaluate, dedup, and call emit(emit_ctx, finding_json, len) per NEW violation.
 * now_sec feeds the policy cache. Returns the number of findings emitted. */
int ps_overwatch_process_record(const char *record_json, ps_unit_policy_loader loader,
                                void *seen, void (*emit)(void *, const char *, size_t),
                                void *emit_ctx, uint64_t now_sec);

extern const struct ps_module ps_policy_overwatch_module;   /* defined in Task 7 */
#endif
```

- [ ] **Step 4: Create `src/agent/src/modules/policy_overwatch.c`** (core; the module struct + tick come in Task 7)

```c
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
```

- [ ] **Step 5: Wire the test into `src/agent/CMakeLists.txt`**

```cmake
add_executable(test_overwatch_core tests/test_overwatch_core.c src/modules/policy_overwatch.c)
target_link_libraries(test_overwatch_core PRIVATE packetsonde_lib)
add_test(NAME test_overwatch_core COMMAND test_overwatch_core)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_overwatch_core >/dev/null && ctest -R '^test_overwatch_core$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/src/modules/policy_overwatch.h src/agent/src/modules/policy_overwatch.c src/agent/tests/test_overwatch_core.c src/agent/CMakeLists.txt
git commit -m "agent: overwatch record-processing core (parse -> unit -> eval -> dedup -> emit)"
```

---

## Task 7: Module wiring + config + registration

**Files:** Modify `src/agent/src/modules/policy_overwatch.c` (add module struct + tick); `src/agent/src/config_to_env.c`; `src/agent/src/main.c`; `src/agent/CMakeLists.txt`; `packaging/packetsonded.toml`

> No unit test (drains the global ring + shells out + publishes). Verified by build + the full suite + the live script (Task 8).

- [ ] **Step 1: Add the module struct + tick to `policy_overwatch.c`**

```c
#include "module.h"
#include "activity_ring.h"

struct overwatch_state { int mode; void *seen; };   /* mode: 0 off, 1 overwatch */

static int overwatch_init(ps_module_ctx_t *ctx) {
    const char *m = getenv("PS_DETECT_POLICY_MODE");
    int mode = (m && strcmp(m, "overwatch") == 0) ? 1 : 0;
    struct overwatch_state *st = calloc(1, sizeof *st);
    if (!st) return -1;
    st->mode = mode; st->seen = ps_overwatch_seen_new();
    ctx->userdata = st;
    if (ctx->log) ctx->log(ctx, 6, "policy_overwatch: mode=%s", mode ? "overwatch" : "off");
    return 0;
}
static void overwatch_shutdown(ps_module_ctx_t *ctx) {
    struct overwatch_state *st = ctx->userdata;
    if (st) { ps_overwatch_seen_free(st->seen); free(st); }
}

struct emit_ctx { ps_module_ctx_t *mctx; };
static void publish_emit(void *c, const char *json, size_t len) {
    struct emit_ctx *e = c;
    if (e->mctx->publish) e->mctx->publish(e->mctx, "policy.sandbox.violation", json, (uint32_t)len);
}

static void overwatch_tick(ps_module_ctx_t *ctx, uint64_t now_usec) {
    struct overwatch_state *st = ctx->userdata;
    if (!st || st->mode != 1) return;
    static char items[64][PS_ACT_ITEM_MAX];
    int n = ps_act_ring_drain(items, 64);
    struct emit_ctx ec = { ctx };
    uint64_t now_sec = now_usec / 1000000ULL;
    for (int i = 0; i < n; i++)
        ps_overwatch_process_record(items[i], ps_unit_policy_load_systemctl,
                                    st->seen, publish_emit, &ec, now_sec);
}

const struct ps_module ps_policy_overwatch_module = {
    .name = "policy_overwatch",
    .init = overwatch_init,
    .shutdown = overwatch_shutdown,
    .tick = overwatch_tick,
};
```

> Check the exact field names/order of `struct ps_module` in `packetsonde/module_api.h` and match them (e.g. `.name/.init/.shutdown/.tick`); leave unused callbacks unset. The tick runs every registry tick — the ring (cap 256) buffers between ticks.

- [ ] **Step 2: Add `[detect] policy_mode` + `policy_cache_ttl` mappings in `config_to_env.c`** (with the other `detect` rows)

```c
    { "detect", "policy_mode",      "PS_DETECT_POLICY_MODE" },
    { "detect", "policy_cache_ttl", "PS_DETECT_POLICY_CACHE_TTL" },
```

- [ ] **Step 3: Register the module in `main.c`** (mirror the `iface_monitor` registration at ~line 1037)

Add the extern near the other module externs:
```c
extern const ps_module_t ps_policy_overwatch_module;
```
And register it (gated on the modules config like iface_monitor):
```c
    if (ps_config_get_bool(&cfg, "modules", "policy_overwatch", 1))
        ps_module_registry_add(&g_registry, &ps_policy_overwatch_module);
```

- [ ] **Step 4: Add the module source to `src/agent/CMakeLists.txt`** — add `src/modules/policy_overwatch.c` to the agent source list (`AGENT_CORE_SOURCES` or wherever `modules/iface_monitor.c` is listed).

- [ ] **Step 5: Document `[detect]` keys in `packaging/packetsonded.toml`** (append to the `[detect]` block)

```toml
policy_mode      = "off"     # off | overwatch  (learn mode lands in Phase B)
policy_cache_ttl = "300"     # overwatch: per-unit systemctl-show cache seconds
```

- [ ] **Step 6: Build + full regression**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make packetsonde-agent packetsonde-priv >/dev/null 2>&1 && echo LINK_OK && ctest -E 'test_via_e2e' 2>&1 | tail -4`
Expected: `LINK_OK`; suite 100% (test_probe_icmp skipped pre-existing).

- [ ] **Step 7: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/src/modules/policy_overwatch.c src/agent/src/config_to_env.c src/agent/src/main.c src/agent/CMakeLists.txt packaging/packetsonded.toml
git commit -m "agent: register policy_overwatch module + [detect] policy_mode/cache config"
```

---

## Task 8: Live overwatch test (assisted)

**Files:** Create `scripts/test-policy-overwatch.sh`

> Needs root + systemd (fanotify + a real unit). Created + syntax-checked here; the operator runs it.

- [ ] **Step 1: Create the script**

```bash
#!/bin/bash
# Assisted live test for systemd policy overwatch. Requires root + systemd.
# Verifies an enforcement-gap finding: a unit declares ProtectHome=true but its
# process reads /home, and overwatch flags it.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "must run as root (fanotify + systemctl)"; exit 1; }
SINK=/tmp/ps-act-$$.jsonl

echo "Setup:"
echo "  1. Pick or create a test unit with: [Service] ProtectHome=true ReadWritePaths=/var/lib/testapp"
echo "     (do NOT restart it after editing if you want to observe the *gap*; or use a unit whose"
echo "      ProtectHome is declared but the running process predates the setting)."
echo "  2. Run the agent with [detect] enabled=1, watch_paths includes /home, policy_mode=overwatch,"
echo "     activity sink -> $SINK."
echo "  3. As the unit's user/process, read a file under /home."
echo
echo "PASS: a published finding (channel policy.sandbox.violation) with"
echo "      unit=<unit>, directive=ProtectHome, path=/home/..., op=open|read, severity=high."
echo "      Check the agent's finding output / central ps_events."
echo
echo "Also exercise: write outside ReadWritePaths under ProtectSystem=strict -> directive=ProtectSystem."
echo "Cleanup: revert the unit edit; rm -f $SINK"
```

- [ ] **Step 2: Syntax-check + executable (do NOT run — needs root)**

Run: `cd /data/opt/repo/packetsonde && bash -n scripts/test-policy-overwatch.sh && echo SYNTAX_OK && chmod +x scripts/test-policy-overwatch.sh`
Expected: `SYNTAX_OK`.

- [ ] **Step 3: Commit**

```bash
cd /data/opt/repo/packetsonde
git add scripts/test-policy-overwatch.sh
git commit -m "Add assisted live test for systemd policy overwatch (enforcement-gap finding)"
```

---

## Self-Review

**Spec coverage (Phase A scope, spec §10):**
- §4.1 ring consumer (tick drain) → Task 7 ✓
- §4.2 record parse (json_extract) → Task 6 ✓
- §4.3 cgroup→unit + skip rule → Task 2, used in Task 6 ✓
- §4.4 systemd_policy acquire + derive + cache → Tasks 3, 4 ✓
- §5.1 policy_eval FS semantics (ProtectSystem/Home/ReadOnly/Inaccessible, RW exceptions, prefix boundary) → Task 5 ✓ (write op now real via Task 1)
- §5.2 exec hardening (exec-from-denied via READ pass + writable-exec heuristic) → Tasks 5, 6 ✓
- §5.3 dedup (first-seen per unit/path/op/directive) + findings via publish → Task 6 (core) + Task 7 (publish channel) ✓
- §7 config policy_mode/cache_ttl → Task 7 ✓ (learn keys deferred to Phase B)
- §9 conservatism (RW exception wins, prefix boundary, PrivateTmp excluded, known=0 skip) → Task 5 + Task 6 ✓
- **Write-signal prerequisite** (decided this session) → Task 1 ✓

**Placeholder scan:** no TBD/"add error handling"/"similar to Task N"; every code step is complete. Task 7's module-struct field caveat names the exact source to match.

**Type/name consistency:** `ps_fan_event_for_mask` (1); `ps_cgroup_to_unit` (2,6); `struct ps_unit_policy`/`ps_unit_policy_derive`/`ps_unit_policy_get`/`ps_unit_policy_load_systemctl` (3,4,6,7); `enum ps_op`/`ps_eval_result`/`ps_policy_eval` (5,6); `ps_overwatch_op_for_event`/`ps_overwatch_seen_new/_free`/`ps_overwatch_process_record`/`ps_policy_overwatch_module` (6,7); finding channel `policy.sandbox.violation` (7). `PS_DETECT_POLICY_MODE`/`_CACHE_TTL` (7). Directive strings `ProtectSystem`/`ProtectHome`/`ReadOnlyPaths`/`InaccessiblePaths`/`exec_from_writable` identical in Task 5 and the Task 6 test.

**Deferred to Phase B (not this plan):** learn mode, `unit_envelope`, `sandbox_synth`, `sandbox-suggest` verb, `learn_state_dir`/`rollup_threshold` config.
```
