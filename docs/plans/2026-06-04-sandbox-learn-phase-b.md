# systemd Policy Overwatch — Phase B (sandbox learning) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** In `policy_mode=learn` (dev/staging) the agent accumulates each systemd unit's observed-nominal access into an envelope and persists it; `packetsonde sandbox-suggest <unit>` synthesizes the minimal systemd sandboxing stanza that would permit that behavior (threshold path rollup + annotation).

**Architecture:** Reuses the merged SP2 Phase A `policy_overwatch` module (adds a learn branch to its tick) and the SP1 activity ring. Pure units in `src/lib` (`unit_envelope` accumulate + serialize/parse; `sandbox_synth`) are fixture-tested; the module's per-unit envelope collection + state-file flush and the `sandbox-suggest` verb are integration.

**Tech Stack:** C11, CMake/CTest. Reuses `ps_act_ring_drain`, `ps_json_extract_string`, `cgroup_unit`, `ps_json` writer, the module framework, `config_to_env`, the CLI verb-dispatch table.

**Spec:** `docs/specs/2026-06-03-systemd-policy-overwatch-design.md` §6, §10 (this is **Phase B**; Phase A — overwatch — is merged).

**Build:** `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON && make <target> && ctest -R '^<name>$' --output-on-failure`. Pre-existing: exclude `test_via_e2e` (flaky env); `test_probe_icmp` skips. The repo links plain `pthread` (NOT `Threads::Threads`).

---

## Interfaces locked here

- **`src/lib/unit_envelope.h`:**
  ```c
  #define PS_ENV_MAX_PATHS 256
  #define PS_ENV_PATHLEN   256
  struct ps_unit_envelope {
      char unit[128];
      int n_read;  char rd[PS_ENV_MAX_PATHS][PS_ENV_PATHLEN];
      int n_write; char wr[PS_ENV_MAX_PATHS][PS_ENV_PATHLEN];
      int n_exec;  char ex[PS_ENV_MAX_PATHS][PS_ENV_PATHLEN];
      int touched_home, used_tmp, records, truncated;
  };
  void ps_envelope_init(struct ps_unit_envelope *e, const char *unit);
  void ps_envelope_add(struct ps_unit_envelope *e, const char *event, const char *path);
  int  ps_envelope_to_json(const struct ps_unit_envelope *e, char *out, size_t cap);   /* bytes or -1 */
  int  ps_envelope_from_json(const char *json, struct ps_unit_envelope *e);            /* 0 or -1 */
  ```
- **`src/lib/sandbox_synth.h`:** `int ps_sandbox_synth(const struct ps_unit_envelope *e, int rollup_threshold, char *out, size_t cap);` → bytes written (the annotated `[Service]` stanza), or -1.
- **`src/agent/src/modules/policy_overwatch.h`** (added): `int ps_overwatch_learn_record(const char *record_json, struct ps_unit_envelope *envs, int *n_envs, int max_envs);` → returns the index of the envelope updated, or -1 if skipped.
- **Mode:** `overwatch_state.mode` gains value `2` = learn (1 = overwatch, 0 = off).
- **State file:** `<learn_state_dir>/<unit>.json` (one per unit), default dir `/var/lib/packetsonde/sandbox-learn`.
- **Verb:** `ps_verb_sandbox_suggest_run` registered as `sandbox-suggest`.

---

## Task 1: `unit_envelope` struct + accumulate (`src/lib/unit_envelope`)

**Files:** Create `src/lib/unit_envelope.h`, `src/lib/unit_envelope.c`; Test `src/lib/tests/test_unit_envelope.c`; Modify `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test** (`src/lib/tests/test_unit_envelope.c`)

```c
#include "unit_envelope.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    struct ps_unit_envelope e;
    ps_envelope_init(&e, "app.service");
    assert(strcmp(e.unit, "app.service") == 0);
    assert(e.n_read == 0 && e.records == 0);

    ps_envelope_add(&e, "write", "/var/lib/app/db/1.dat");
    ps_envelope_add(&e, "write", "/var/lib/app/db/1.dat");   /* dup -> deduped */
    ps_envelope_add(&e, "write", "/var/lib/app/db/2.dat");
    ps_envelope_add(&e, "open",  "/etc/app.conf");
    ps_envelope_add(&e, "access","/usr/share/app/x");
    ps_envelope_add(&e, "exec",  "/usr/bin/app");
    ps_envelope_add(&e, "open",  "/home/svc/.cache/y");      /* sets touched_home */
    ps_envelope_add(&e, "write", "/tmp/scratch");            /* sets used_tmp */

    assert(e.n_write == 3);                                  /* 2 db files + /tmp/scratch (dedup worked) */
    assert(e.n_read == 3);                                   /* etc.conf, usr/share, home cache */
    assert(e.n_exec == 1);
    assert(e.touched_home == 1);
    assert(e.used_tmp == 1);
    assert(e.records == 8);
    printf("test_unit_envelope: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_unit_envelope 2>&1 | tail -4`
Expected: FAIL — `unit_envelope.h` not found.

- [ ] **Step 3: Create `src/lib/unit_envelope.h`** (the struct + signatures from "Interfaces locked here", wrapped):

```c
#ifndef PS_UNIT_ENVELOPE_H
#define PS_UNIT_ENVELOPE_H
#include <stddef.h>

#define PS_ENV_MAX_PATHS 256
#define PS_ENV_PATHLEN   256
struct ps_unit_envelope {
    char unit[128];
    int n_read;  char rd[PS_ENV_MAX_PATHS][PS_ENV_PATHLEN];
    int n_write; char wr[PS_ENV_MAX_PATHS][PS_ENV_PATHLEN];
    int n_exec;  char ex[PS_ENV_MAX_PATHS][PS_ENV_PATHLEN];
    int touched_home, used_tmp, records, truncated;
};
void ps_envelope_init(struct ps_unit_envelope *e, const char *unit);
void ps_envelope_add(struct ps_unit_envelope *e, const char *event, const char *path);
int  ps_envelope_to_json(const struct ps_unit_envelope *e, char *out, size_t cap);
int  ps_envelope_from_json(const char *json, struct ps_unit_envelope *e);
#endif
```

- [ ] **Step 4: Create `src/lib/unit_envelope.c`** (this task: `init` + `add`; serialize/parse in Task 2)

```c
#include "unit_envelope.h"
#include <string.h>
#include <stdio.h>

void ps_envelope_init(struct ps_unit_envelope *e, const char *unit) {
    memset(e, 0, sizeof *e);
    snprintf(e->unit, sizeof e->unit, "%s", unit ? unit : "");
}

static int under(const char *path, const char *prefix) {
    size_t lp = strlen(prefix);
    return strncmp(path, prefix, lp) == 0 && (path[lp] == 0 || path[lp] == '/');
}

static void set_add(char arr[][PS_ENV_PATHLEN], int *n, const char *path, int *trunc) {
    for (int i = 0; i < *n; i++) if (strcmp(arr[i], path) == 0) return;   /* dedup */
    if (*n >= PS_ENV_MAX_PATHS) { *trunc = 1; return; }
    snprintf(arr[*n], PS_ENV_PATHLEN, "%s", path);
    (*n)++;
}

void ps_envelope_add(struct ps_unit_envelope *e, const char *event, const char *path) {
    if (!event || !path || !*path) return;
    e->records++;
    if (!strcmp(event, "write"))      set_add(e->wr, &e->n_write, path, &e->truncated);
    else if (!strcmp(event, "exec"))  set_add(e->ex, &e->n_exec,  path, &e->truncated);
    else                              set_add(e->rd, &e->n_read,  path, &e->truncated); /* open|access */
    if (under(path, "/home") || under(path, "/root")) e->touched_home = 1;
    if (under(path, "/tmp") || under(path, "/var/tmp") || under(path, "/dev/shm")) e->used_tmp = 1;
}
```

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `unit_envelope.c` to the `packetsonde_lib` STATIC source list; add the test block:

```cmake
    add_executable(test_unit_envelope tests/test_unit_envelope.c)
    target_link_libraries(test_unit_envelope PRIVATE packetsonde_lib)
    add_test(NAME test_unit_envelope COMMAND test_unit_envelope)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_unit_envelope >/dev/null && ctest -R '^test_unit_envelope$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/lib/unit_envelope.h src/lib/unit_envelope.c src/lib/tests/test_unit_envelope.c src/lib/CMakeLists.txt
git commit -m "lib: add unit envelope accumulator (per-unit read/write/exec sets + flags)"
```

---

## Task 2: envelope serialize + parse (`ps_envelope_to_json` / `_from_json`)

**Files:** Modify `src/lib/unit_envelope.c`; Test `src/lib/tests/test_unit_envelope_json.c`; Modify `src/lib/CMakeLists.txt`

> Round-trip via JSON so the agent writes the state file and the CLI reads it.

- [ ] **Step 1: Write the failing test** (`src/lib/tests/test_unit_envelope_json.c`)

```c
#include "unit_envelope.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    struct ps_unit_envelope a;
    ps_envelope_init(&a, "app.service");
    ps_envelope_add(&a, "write", "/var/lib/app/1");
    ps_envelope_add(&a, "write", "/var/lib/app/2");
    ps_envelope_add(&a, "open",  "/etc/app.conf");
    ps_envelope_add(&a, "exec",  "/usr/bin/app");
    ps_envelope_add(&a, "write", "/tmp/x");   /* used_tmp */

    char buf[16384];
    int n = ps_envelope_to_json(&a, buf, sizeof buf);
    assert(n > 0);
    assert(strstr(buf, "\"unit\":\"app.service\""));
    assert(strstr(buf, "\"used_tmp\":1"));
    assert(strstr(buf, "/var/lib/app/1"));

    struct ps_unit_envelope b;
    assert(ps_envelope_from_json(buf, &b) == 0);
    assert(strcmp(b.unit, "app.service") == 0);
    assert(b.n_write == 3 && b.n_read == 1 && b.n_exec == 1);
    assert(b.used_tmp == 1 && b.touched_home == 0);
    assert(strcmp(b.wr[0], "/var/lib/app/1") == 0);
    assert(strcmp(b.ex[0], "/usr/bin/app") == 0);
    printf("test_unit_envelope_json: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && make test_unit_envelope_json 2>&1 | tail -4`
Expected: FAIL — `test_unit_envelope_json` target unknown / link error (`ps_envelope_to_json` undefined).

- [ ] **Step 3: Add `ps_envelope_to_json` + `ps_envelope_from_json` to `unit_envelope.c`** (append; add `#include "json.h"` and `#include "json_extract.h"` at the top)

```c
static void arr_to_json(struct ps_json *j, const char *key, char a[][PS_ENV_PATHLEN], int n) {
    ps_json_array_begin(j, key);
    for (int i = 0; i < n; i++) ps_json_array_string(j, a[i]);
    ps_json_array_end(j);
}

int ps_envelope_to_json(const struct ps_unit_envelope *e, char *out, size_t cap) {
    struct ps_json j; ps_json_init(&j, out, cap);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "unit", e->unit);
    ps_json_key_int(&j, "records", e->records);
    ps_json_key_int(&j, "truncated", e->truncated);
    ps_json_key_int(&j, "touched_home", e->touched_home);
    ps_json_key_int(&j, "used_tmp", e->used_tmp);
    arr_to_json(&j, "reads",  (char(*)[PS_ENV_PATHLEN])e->rd, e->n_read);
    arr_to_json(&j, "writes", (char(*)[PS_ENV_PATHLEN])e->wr, e->n_write);
    arr_to_json(&j, "execs",  (char(*)[PS_ENV_PATHLEN])e->ex, e->n_exec);
    ps_json_object_end(&j);
    return ps_json_finish(&j);
}

/* Parse a JSON array of strings "key":[ "a","b" ] into arr; returns count. */
static int arr_from_json(const char *json, const char *key, char arr[][PS_ENV_PATHLEN]) {
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\":[", key);
    const char *p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    int n = 0;
    while (*p && *p != ']' && n < PS_ENV_MAX_PATHS) {
        const char *q = strchr(p, '"');
        if (!q || q > strchr(p, ']')) break;
        q++;
        const char *e = strchr(q, '"');
        if (!e) break;
        size_t len = (size_t)(e - q);
        if (len < PS_ENV_PATHLEN) { memcpy(arr[n], q, len); arr[n][len] = 0; n++; }
        p = e + 1;
        const char *comma = strchr(p, ',');
        const char *close = strchr(p, ']');
        if (!comma || (close && close < comma)) break;
        p = comma + 1;
    }
    return n;
}

int ps_envelope_from_json(const char *json, struct ps_unit_envelope *e) {
    if (!json) return -1;
    memset(e, 0, sizeof *e);
    if (ps_json_extract_string(json, "unit", e->unit, sizeof e->unit) < 0) return -1;
    char tmp[16];
    if (ps_json_extract_string(json, "touched_home", tmp, sizeof tmp) >= 0) {} /* ints below */
    /* ints: scan "key":N */
    #define INTOF(k,field) do { const char *p = strstr(json, "\"" k "\":"); \
        if (p) e->field = (int)strtol(p + strlen("\"" k "\":"), NULL, 10); } while (0)
    INTOF("records", records); INTOF("truncated", truncated);
    INTOF("touched_home", touched_home); INTOF("used_tmp", used_tmp);
    #undef INTOF
    e->n_read  = arr_from_json(json, "reads",  e->rd);
    e->n_write = arr_from_json(json, "writes", e->wr);
    e->n_exec  = arr_from_json(json, "execs",  e->ex);
    return 0;
}
```

Add `#include <stdlib.h>` for `strtol`.

- [ ] **Step 4: Wire the test into `src/lib/CMakeLists.txt`** (mirror Task 1's test block, name `test_unit_envelope_json`).

- [ ] **Step 5: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_unit_envelope_json >/dev/null && ctest -R '^test_unit_envelope_json$' --output-on-failure`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/lib/unit_envelope.c src/lib/tests/test_unit_envelope_json.c src/lib/CMakeLists.txt
git commit -m "lib: add unit-envelope JSON serialize/parse (state-file round-trip)"
```

---

## Task 3: `sandbox_synth` (`src/lib/sandbox_synth`)

**Files:** Create `src/lib/sandbox_synth.h`, `src/lib/sandbox_synth.c`; Test `src/lib/tests/test_sandbox_synth.c`; Modify `src/lib/CMakeLists.txt`

> The crux: envelope → annotated systemd stanza. Threshold rollup on write paths; directive choices from the flags.

- [ ] **Step 1: Write the failing test** (`src/lib/tests/test_sandbox_synth.c`)

```c
#include "sandbox_synth.h"
#include "unit_envelope.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    struct ps_unit_envelope e;
    ps_envelope_init(&e, "app.service");
    /* 3 files under /var/lib/app/db -> rolls up to the dir (threshold 3) */
    ps_envelope_add(&e, "write", "/var/lib/app/db/1.dat");
    ps_envelope_add(&e, "write", "/var/lib/app/db/2.dat");
    ps_envelope_add(&e, "write", "/var/lib/app/db/3.dat");
    /* 1 file under /run -> stays exact */
    ps_envelope_add(&e, "write", "/run/app.sock");
    ps_envelope_add(&e, "exec",  "/usr/bin/app");           /* exec from read-only -> MDWE ok */
    /* no /home access, no /tmp */

    char out[8192];
    int n = ps_sandbox_synth(&e, 3, out, sizeof out);
    assert(n > 0);
    assert(strstr(out, "[Service]"));
    assert(strstr(out, "ProtectSystem=strict"));
    assert(strstr(out, "ProtectHome=true"));               /* touched_home == 0 */
    assert(strstr(out, "MemoryDenyWriteExecute=yes"));      /* no exec from writable */
    assert(strstr(out, "ReadWritePaths=/var/lib/app/db"));  /* rolled up */
    assert(strstr(out, "generalized: 3 files"));
    assert(strstr(out, "ReadWritePaths=/run/app.sock"));    /* exact */
    assert(strstr(out, "# exact"));
    /* threshold boundary: with threshold 4, the 3-file dir stays exact */
    char out2[8192];
    ps_sandbox_synth(&e, 4, out2, sizeof out2);
    assert(strstr(out2, "ReadWritePaths=/var/lib/app/db/1.dat"));
    assert(!strstr(out2, "ReadWritePaths=/var/lib/app/db\n") && !strstr(out2, "ReadWritePaths=/var/lib/app/db "));

    /* a unit that touches /home + execs from a writable dir -> no ProtectHome/MDWE */
    struct ps_unit_envelope h;
    ps_envelope_init(&h, "web.service");
    ps_envelope_add(&h, "write", "/var/www/cache/a");
    ps_envelope_add(&h, "open",  "/home/www/data");         /* touched_home */
    ps_envelope_add(&h, "exec",  "/var/www/cache/a");       /* exec under a write path */
    char out3[8192];
    ps_sandbox_synth(&h, 3, out3, sizeof out3);
    assert(!strstr(out3, "ProtectHome=true"));
    assert(!strstr(out3, "MemoryDenyWriteExecute=yes"));
    printf("test_sandbox_synth: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_sandbox_synth 2>&1 | tail -4`
Expected: FAIL — `sandbox_synth.h` not found.

- [ ] **Step 3: Create `src/lib/sandbox_synth.h`**

```c
#ifndef PS_SANDBOX_SYNTH_H
#define PS_SANDBOX_SYNTH_H
#include <stddef.h>
#include "unit_envelope.h"
/* Synthesize an annotated systemd [Service] sandboxing stanza from an envelope.
 * write paths are rolled up to a directory rule when >= rollup_threshold distinct
 * files share a parent dir (else emitted exact). Returns bytes written, or -1. */
int ps_sandbox_synth(const struct ps_unit_envelope *e, int rollup_threshold,
                     char *out, size_t cap);
#endif
```

- [ ] **Step 4: Create `src/lib/sandbox_synth.c`**

```c
#include "sandbox_synth.h"
#include <string.h>
#include <stdio.h>

static void parent_dir(const char *path, char *out, size_t cap) {
    const char *slash = strrchr(path, '/');
    size_t len = (slash && slash != path) ? (size_t)(slash - path) : 1;
    if (len >= cap) len = cap - 1;
    memcpy(out, path, len); out[len] = 0;
    if (len == 1 && path[0] == '/') { out[0] = '/'; out[1] = 0; }
}

static int under(const char *path, const char *prefix) {
    size_t lp = strlen(prefix);
    return strncmp(path, prefix, lp) == 0 && (path[lp] == 0 || path[lp] == '/');
}

/* emit ReadWritePaths lines with threshold rollup. */
static int emit_rw(const struct ps_unit_envelope *e, int thr, char *out, size_t cap, size_t o) {
    char dirs[PS_ENV_MAX_PATHS][PS_ENV_PATHLEN]; int dn = 0;
    int counted[PS_ENV_MAX_PATHS]; memset(counted, 0, sizeof counted);
    /* count files per parent dir */
    int dcount[PS_ENV_MAX_PATHS]; memset(dcount, 0, sizeof dcount);
    for (int i = 0; i < e->n_write; i++) {
        char d[PS_ENV_PATHLEN]; parent_dir(e->wr[i], d, sizeof d);
        int k = -1;
        for (int j = 0; j < dn; j++) if (!strcmp(dirs[j], d)) { k = j; break; }
        if (k < 0) { k = dn; snprintf(dirs[dn], PS_ENV_PATHLEN, "%s", d); dn++; }
        dcount[k]++;
    }
    /* emit: rolled-up dirs first (>=thr), then exact files in non-rolled dirs */
    for (int k = 0; k < dn; k++) {
        if (dcount[k] >= thr)
            o += (size_t)snprintf(out + o, cap - o,
                 "ReadWritePaths=%s        # generalized: %d files\n", dirs[k], dcount[k]);
    }
    for (int i = 0; i < e->n_write; i++) {
        char d[PS_ENV_PATHLEN]; parent_dir(e->wr[i], d, sizeof d);
        int k = 0; for (int j = 0; j < dn; j++) if (!strcmp(dirs[j], d)) { k = j; break; }
        if (dcount[k] < thr)
            o += (size_t)snprintf(out + o, cap - o, "ReadWritePaths=%s        # exact\n", e->wr[i]);
    }
    (void)counted;
    return (int)o;
}

int ps_sandbox_synth(const struct ps_unit_envelope *e, int rollup_threshold,
                     char *out, size_t cap) {
    if (rollup_threshold < 1) rollup_threshold = 1;
    /* exec_from_writable: any exec path under any write path */
    int exec_from_writable = 0;
    for (int i = 0; i < e->n_exec && !exec_from_writable; i++)
        for (int w = 0; w < e->n_write; w++)
            if (under(e->ex[i], e->wr[w])) { exec_from_writable = 1; break; }

    size_t o = 0;
    o += (size_t)snprintf(out + o, cap - o, "[Service]\n");
    o += (size_t)snprintf(out + o, cap - o, "ProtectSystem=strict\n");
    if (!e->touched_home)
        o += (size_t)snprintf(out + o, cap - o, "ProtectHome=true\n");
    if (e->used_tmp)
        o += (size_t)snprintf(out + o, cap - o, "PrivateTmp=yes\n");
    if (!exec_from_writable)
        o += (size_t)snprintf(out + o, cap - o,
             "MemoryDenyWriteExecute=yes        # no exec from writable observed; verify (W^X != execve block)\n");
    o = (size_t)emit_rw(e, rollup_threshold, out, cap, o);
    o += (size_t)snprintf(out + o, cap - o,
         "# learned over %d records%s. Review before applying; ReadWritePaths are minimal — widen if flows were missed.\n",
         e->records, e->truncated ? " (write set TRUNCATED — coverage capped)" : "");
    return (int)o;
}
```

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `sandbox_synth.c` to `packetsonde_lib`; add `test_sandbox_synth`.

- [ ] **Step 6: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_sandbox_synth >/dev/null && ctest -R '^test_sandbox_synth$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/lib/sandbox_synth.h src/lib/sandbox_synth.c src/lib/tests/test_sandbox_synth.c src/lib/CMakeLists.txt
git commit -m "lib: add sandbox_synth (envelope -> annotated systemd stanza, threshold rollup)"
```

---

## Task 4: Learn mode in the `policy_overwatch` module

**Files:** Modify `src/agent/src/modules/policy_overwatch.h`, `src/agent/src/modules/policy_overwatch.c`; Test `src/agent/tests/test_overwatch_learn.c`; Modify `src/agent/CMakeLists.txt`

> Add the testable `ps_overwatch_learn_record` (parse → unit → find-or-add envelope) and wire the learn branch (mode 2) into init/tick with periodic state-file flush.

- [ ] **Step 1: Write the failing test** (`src/agent/tests/test_overwatch_learn.c`)

```c
#include "policy_overwatch.h"
#include "unit_envelope.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static const char *REC(const char *event, const char *path, const char *cg) {
    static char b[2048];
    snprintf(b, sizeof b,
      "{\"event\":\"%s\",\"path\":\"%s\",\"process\":{\"cgroup\":\"%s\"}}", event, path, cg);
    return b;
}

int main(void) {
    struct ps_unit_envelope envs[8]; int n = 0;
    /* two units accumulate independently */
    int i1 = ps_overwatch_learn_record(REC("write","/var/lib/app/1","/system.slice/app.service"), envs, &n, 8);
    assert(i1 == 0 && n == 1);
    ps_overwatch_learn_record(REC("write","/var/lib/app/2","/system.slice/app.service"), envs, &n, 8);
    int i2 = ps_overwatch_learn_record(REC("exec","/usr/sbin/db","/system.slice/db.service"), envs, &n, 8);
    assert(i2 == 1 && n == 2);
    assert(strcmp(envs[0].unit, "app.service") == 0 && envs[0].n_write == 2);
    assert(strcmp(envs[1].unit, "db.service") == 0 && envs[1].n_exec == 1);
    /* non-unit cgroup -> skipped */
    int sk = ps_overwatch_learn_record(REC("write","/x","/user.slice"), envs, &n, 8);
    assert(sk == -1 && n == 2);
    printf("test_overwatch_learn: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_overwatch_learn 2>&1 | tail -4`
Expected: FAIL — `ps_overwatch_learn_record` undeclared.

- [ ] **Step 3: Declare `ps_overwatch_learn_record` in `policy_overwatch.h`** (add `#include "unit_envelope.h"` and the decl before the `#endif`)

```c
#include "unit_envelope.h"
/* Learn-mode: parse a record, resolve its unit, find-or-create its envelope in
 * envs[0..*n_envs) (growing up to max_envs), and accumulate the access. Returns
 * the envelope index updated, or -1 if the record has no unit / no capacity. */
int ps_overwatch_learn_record(const char *record_json, struct ps_unit_envelope *envs,
                              int *n_envs, int max_envs);
```

- [ ] **Step 4: Implement `ps_overwatch_learn_record` in `policy_overwatch.c`** (add near the core, before the module wiring; it reuses `json_extract` + `cgroup_unit` already included)

```c
int ps_overwatch_learn_record(const char *rec, struct ps_unit_envelope *envs,
                              int *n_envs, int max_envs) {
    char event[16], path[512], cgroup[256];
    if (ps_json_extract_string(rec, "event", event, sizeof event) < 0) return -1;
    if (ps_json_extract_string(rec, "path",  path,  sizeof path)  < 0) return -1;
    if (ps_json_extract_string(rec, "cgroup", cgroup, sizeof cgroup) < 0) return -1;
    char unit[128];
    if (ps_cgroup_to_unit(cgroup, unit, sizeof unit) != 0) return -1;
    int idx = -1;
    for (int i = 0; i < *n_envs; i++) if (!strcmp(envs[i].unit, unit)) { idx = i; break; }
    if (idx < 0) {
        if (*n_envs >= max_envs) return -1;
        idx = (*n_envs)++;
        ps_envelope_init(&envs[idx], unit);
    }
    ps_envelope_add(&envs[idx], event, path);
    return idx;
}
```

- [ ] **Step 5: Wire learn into the module (mode 2 + flush)** — in `policy_overwatch.c`:

Extend `overwatch_state` and `overwatch_init` (mode parse + learn fields):
```c
#define PS_LEARN_MAX_UNITS 256
struct overwatch_state {
    int mode; void *seen;                       /* 1 overwatch, 2 learn, 0 off */
    struct ps_unit_envelope *envs; int n_envs;  /* learn */
    char state_dir[256]; uint64_t last_flush_us;
};
```
In `overwatch_init`, after the existing mode logic, set mode 2 for "learn" and allocate the envelope array:
```c
    if (m && strcmp(m, "learn") == 0) mode = 2;
    /* ... existing: mode 1 for "overwatch" ... */
    st->mode = mode; st->seen = ps_overwatch_seen_new();
    if (mode == 2) {
        st->envs = calloc(PS_LEARN_MAX_UNITS, sizeof *st->envs);
        const char *d = getenv("PS_DETECT_LEARN_STATE_DIR");
        snprintf(st->state_dir, sizeof st->state_dir, "%s",
                 (d && d[0]) ? d : "/var/lib/packetsonde/sandbox-learn");
    }
```
(Update the `overwatch_init` mode expression to: `m && !strcmp(m,"learn") ? 2 : (m && !strcmp(m,"overwatch") ? 1 : 0)`.)

Add a flush helper + extend the tick:
```c
static void learn_flush(struct overwatch_state *st) {
    for (int i = 0; i < st->n_envs; i++) {
        char buf[1 << 16];
        if (ps_envelope_to_json(&st->envs[i], buf, sizeof buf) <= 0) continue;
        char path[400];
        snprintf(path, sizeof path, "%s/%s.json", st->state_dir, st->envs[i].unit);
        FILE *f = fopen(path, "w");
        if (!f) continue;
        fwrite(buf, 1, strlen(buf), f);
        fclose(f);
    }
}
```
In `overwatch_tick`, replace the early `if (st->mode != 1) return;` so learn (mode 2) is handled:
```c
    if (!st || st->mode == 0) return;
    static char items[64][PS_ACT_ITEM_MAX];
    int n = ps_act_ring_drain(items, 64);
    if (st->mode == 1) {
        struct emit_ctx ec = { ctx };
        uint64_t now_sec = now_usec / 1000000ULL;
        for (int i = 0; i < n; i++)
            ps_overwatch_process_record(items[i], ps_unit_policy_load_systemctl,
                                        st->seen, publish_emit, &ec, now_sec);
        return;
    }
    /* mode 2: learn */
    for (int i = 0; i < n; i++)
        ps_overwatch_learn_record(items[i], st->envs, &st->n_envs, PS_LEARN_MAX_UNITS);
    if (now_usec - st->last_flush_us > 10000000ULL) {   /* flush ~every 10s */
        learn_flush(st);
        st->last_flush_us = now_usec;
    }
```
Add to `overwatch_shutdown`: `if (st->mode == 2) { learn_flush(st); free(st->envs); }` before freeing `st`. Ensure `mkdir(st->state_dir, 0700)` is attempted once in init (best-effort; ignore EEXIST) — add `#include <sys/stat.h>`.

- [ ] **Step 6: Wire the test into `src/agent/CMakeLists.txt`** (mirror `test_overwatch_core`: compile `src/modules/policy_overwatch.c src/activity_ring.c`, include dirs `include src src/modules`, link `packetsonde_lib pthread`), name `test_overwatch_learn`. Build the agent + run:

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_overwatch_learn packetsonde-agent >/dev/null 2>&1 && ctest -R '^test_overwatch_learn$' --output-on-failure`
Expected: PASS; agent links.

- [ ] **Step 7: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/src/modules/policy_overwatch.h src/agent/src/modules/policy_overwatch.c src/agent/tests/test_overwatch_learn.c src/agent/CMakeLists.txt
git commit -m "agent: learn mode — accumulate per-unit envelopes + flush state files"
```

---

## Task 5: `sandbox-suggest` verb

**Files:** Create `src/cli/verbs/sandbox_suggest.c`; Modify `src/cli/dispatch.c`, `src/cli/CMakeLists.txt`

- [ ] **Step 1: Create `src/cli/verbs/sandbox_suggest.c`**

```c
#include "../verbs.h"
#include "unit_envelope.h"
#include "sandbox_synth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

/* packetsonde sandbox-suggest <unit> [--state-dir D] [--threshold N] [--reset]
 * Reads <state-dir>/<unit>.json (learn-mode output), synthesizes a systemd
 * sandboxing stanza, prints it. --reset deletes the unit's envelope. */
int ps_verb_sandbox_suggest_run(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    const char *dir = "/var/lib/packetsonde/sandbox-learn";
    int threshold = 3, reset = 0;
    static struct option lo[] = {
        {"state-dir", required_argument, 0, 'd'},
        {"threshold", required_argument, 0, 't'},
        {"reset",     no_argument,       0, 'r'},
        {0,0,0,0}
    };
    optind = 1; int o;
    while ((o = getopt_long(argc, argv, "d:t:r", lo, NULL)) != -1) {
        if (o == 'd') dir = optarg;
        else if (o == 't') threshold = atoi(optarg);
        else if (o == 'r') reset = 1;
    }
    const char *unit = (optind < argc) ? argv[optind] : NULL;
    if (!unit) { fprintf(stderr, "usage: packetsonde sandbox-suggest <unit> [--state-dir D] [--threshold N] [--reset]\n"); return 2; }

    char path[512]; snprintf(path, sizeof path, "%s/%s.json", dir, unit);
    if (reset) { remove(path); printf("reset: %s\n", path); return 0; }

    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "sandbox-suggest: no envelope for %s at %s (run with [detect] policy_mode=learn)\n", unit, path); return 1; }
    static char json[1 << 16]; size_t n = fread(json, 1, sizeof json - 1, f); fclose(f); json[n] = 0;

    struct ps_unit_envelope e;
    if (ps_envelope_from_json(json, &e) != 0) { fprintf(stderr, "sandbox-suggest: malformed envelope %s\n", path); return 1; }
    static char out[1 << 16];
    if (ps_sandbox_synth(&e, threshold, out, sizeof out) <= 0) { fprintf(stderr, "sandbox-suggest: synth failed\n"); return 1; }
    fputs(out, stdout);
    return 0;
}
```

- [ ] **Step 2: Register in `src/cli/dispatch.c`** — add the prototype with the others and the VERBS[] row:
```c
int  ps_verb_sandbox_suggest_run(int argc, char **argv, const struct ps_args *opts);
```
```c
    { "sandbox-suggest", ps_verb_sandbox_suggest_run, "Suggest a systemd sandbox stanza from learned activity" },
```

- [ ] **Step 3: Add the source to `src/cli/CMakeLists.txt`** — `verbs/sandbox_suggest.c` in the CLI sources list.

- [ ] **Step 4: Build + smoke test (hand-made envelope)**

Run:
```bash
cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make packetsonde 2>&1 | tail -4
D=/tmp/sl-$$; mkdir -p "$D"
printf '{"unit":"app.service","records":4,"truncated":0,"touched_home":0,"used_tmp":0,"reads":["/etc/app.conf"],"writes":["/var/lib/app/db/1","/var/lib/app/db/2","/var/lib/app/db/3"],"execs":["/usr/bin/app"]}' > "$D/app.service.json"
./src/cli/packetsonde sandbox-suggest app.service --state-dir "$D"
echo "--- missing unit ---"; ./src/cli/packetsonde sandbox-suggest nope.service --state-dir "$D"; echo "exit=$?"
rm -rf "$D"
```
Expected: prints a `[Service]` stanza with `ProtectSystem=strict`, `ProtectHome=true`, `MemoryDenyWriteExecute=yes`, `ReadWritePaths=/var/lib/app/db   # generalized: 3 files`; missing unit prints a clean error + exit=1.

- [ ] **Step 5: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/cli/verbs/sandbox_suggest.c src/cli/dispatch.c src/cli/CMakeLists.txt
git commit -m "cli: add 'sandbox-suggest' verb (synthesize systemd stanza from learned envelope)"
```

---

## Task 6: `[detect]` learn config keys

**Files:** Modify `src/agent/src/config_to_env.c`; `packaging/packetsonded.toml`

- [ ] **Step 1: Add learn mappings to `config_to_env.c`** (with the other `detect` rows)

```c
    { "detect", "learn_state_dir",  "PS_DETECT_LEARN_STATE_DIR" },
    { "detect", "rollup_threshold", "PS_DETECT_ROLLUP_THRESHOLD" },
```

- [ ] **Step 2: Document in `packaging/packetsonded.toml`** (append to the `[detect]` block; note `policy_mode` now accepts `learn`)

```toml
# policy_mode also accepts "learn" (dev/staging): accumulate per-unit envelopes
# for `packetsonde sandbox-suggest <unit>` instead of flagging violations.
learn_state_dir  = "/var/lib/packetsonde/sandbox-learn"
rollup_threshold = "3"     # learn: distinct files/dir before rolling up to the dir rule
```

- [ ] **Step 3: Build to confirm config compiles + full regression**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make packetsonde-agent >/dev/null 2>&1 && echo OK && ctest -E 'test_via_e2e' 2>&1 | tail -3`
Expected: `OK`; suite 100%.

- [ ] **Step 4: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/src/config_to_env.c packaging/packetsonded.toml
git commit -m "config: add [detect] learn_state_dir + rollup_threshold (learn mode)"
```

---

## Task 7: Assisted live learn test

**Files:** Create `scripts/test-sandbox-learn.sh`

- [ ] **Step 1: Create the script**

```bash
#!/bin/bash
# Assisted live test for sandbox learning. Requires root + systemd.
# Runs a service under policy_mode=learn, then synthesizes its sandbox stanza.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "must run as root (fanotify)"; exit 1; }
echo "Steps:"
echo "  1. Run the agent with [detect] enabled=1, watch_paths covering the service's"
echo "     data dirs (e.g. /etc,/var,/run,/tmp), policy_mode=learn,"
echo "     learn_state_dir=/var/lib/packetsonde/sandbox-learn."
echo "  2. Exercise the target service through its NOMINAL flows for a while"
echo "     (start it, hit its endpoints, let it write its data/logs)."
echo "  3. Wait ~10s for a flush, then:"
echo "       ./build/src/cli/packetsonde sandbox-suggest <unit>.service"
echo
echo "PASS: a [Service] stanza whose ReadWritePaths cover exactly the dirs the"
echo "      service wrote, ProtectHome=true if it never touched /home, MDWE=yes if"
echo "      it never execed from a writable path. Sanity-check, then optionally apply"
echo "      it as a drop-in and switch to policy_mode=overwatch to verify enforcement."
echo "Cleanup: rm -f /var/lib/packetsonde/sandbox-learn/<unit>.service.json"
```

- [ ] **Step 2: Syntax-check + executable**

Run: `cd /data/opt/repo/packetsonde && bash -n scripts/test-sandbox-learn.sh && echo SYNTAX_OK && chmod +x scripts/test-sandbox-learn.sh`
Expected: `SYNTAX_OK`.

- [ ] **Step 3: Commit**

```bash
cd /data/opt/repo/packetsonde
git add scripts/test-sandbox-learn.sh
git commit -m "Add assisted live test for sandbox learning"
```

---

## Self-Review

**Spec coverage (Phase B, spec §6/§10):**
- §6.1 `unit_envelope` accumulate (reads/writes/execs + touched_home/used_tmp) → Task 1 ✓
- §6.2 persistence (state file per unit) → Task 4 (`learn_flush`) ✓; round-trip serde → Task 2 ✓
- §6.3 `sandbox_synth` rollup + annotation + directive synthesis → Task 3 ✓ (exec_from_writable computed from exec∩write at synth time — noted deviation from a stored flag; equivalent)
- §6.4 `sandbox-suggest` verb (`--state-dir`/`--threshold`/`--reset`) → Task 5 ✓
- §7 config `learn_state_dir`/`rollup_threshold`; `policy_mode=learn` → Tasks 6, 4 ✓
- §3 shared core / mode dispatch (learn = mode 2) → Task 4 ✓

**Placeholder scan:** no TBD/"add error handling"; every code step is complete. The synth annotation format and the threshold boundary are concretely tested (N-1 exact, N rolled up).

**Type/name consistency:** `struct ps_unit_envelope` fields `rd/wr/ex`, `n_read/n_write/n_exec`, `touched_home/used_tmp/records/truncated` (1,2,3,4); `ps_envelope_init/_add/_to_json/_from_json` (1,2,4,5); `ps_sandbox_synth` (3,5); `ps_overwatch_learn_record` (4); verb `ps_verb_sandbox_suggest_run` / `sandbox-suggest` (5); config `PS_DETECT_LEARN_STATE_DIR`/`PS_DETECT_ROLLUP_THRESHOLD` (6) + mode `learn`→2 (4). JSON keys `unit/records/truncated/touched_home/used_tmp/reads/writes/execs` identical in `to_json` (2) and `from_json` (2) and the Task 5 smoke fixture.

**Deferred (still, not this plan):** AppArmor/SELinux; network directives; auto-applied drop-ins / central-reported suggestions; SP3 statistical baseline.
```
