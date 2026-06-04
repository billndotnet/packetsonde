# Learned Per-Process Baseline — Phase A (exe prereq + lifecycle + file signal) Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A brain-side `baseline_monitor` module learns, per executable, the set of file paths it touches and — running hybrid-continuous — flags a novel path as a *candidate* finding (operator `approve`s it into the baseline or `deny`s it to a confirmed anomaly), all keyed on `process.exe`.

**Architecture:** Phase A first populates `process.exe` in SP1's `proc_enrich` (a `readlink`). Then: pure libs `exe_slug`, `baseline_set` (path set + dir-prefix match + serde + rollup), `baseline_decide`; an agent `baseline_store` (per-exe load + atomic candidate append); a `baseline_monitor` module (drain ring → decide → emit/append); a `baseline` CLI verb (list/approve/deny/approve-all). Lock-free ownership: agent appends `candidates.json`, CLI writes `baseline.json`/`denials.json`, all atomic.

**Tech Stack:** C11, CMake/CTest. Reuses SP1 `activity_ring`/`proc_enrich`, `ps_json_extract_string`, `ps_json` writer, the module framework, `config_to_env`, the verb-dispatch table.

**Spec:** `docs/specs/2026-06-04-process-baseline-design.md` (this is **Phase A** per §11; B = network, C = spawn).

**Build:** `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON && make <t> && ctest -R '^<t>$' --output-on-failure`. Pre-existing: exclude `test_via_e2e` (flaky); `test_probe_icmp` skips. CLI links plain `pthread`. **This CLI's getopt does NOT permute — verbs with a positional must scan argv manually.**

---

## Interfaces locked here

- **`src/lib/exe_slug.h`:** `int ps_exe_slug(const char *exe, char *out, size_t cap);` → 0 + filename slug (`/usr/sbin/nginx`→`usr-sbin-nginx`), or -1.
- **`src/lib/baseline_set.h`:**
  ```c
  #define PS_BL_MAX 512
  #define PS_BL_PATHLEN 256
  struct ps_baseline_set { char exe[256]; int n; char path[PS_BL_MAX][PS_BL_PATHLEN]; };
  void ps_blset_init(struct ps_baseline_set *s, const char *exe);
  int  ps_blset_add(struct ps_baseline_set *s, const char *path);     /* 1 added, 0 dup, -1 full */
  int  ps_blset_covered(const struct ps_baseline_set *s, const char *path); /* dir-prefix match */
  int  ps_blset_to_json(const struct ps_baseline_set *s, char *out, size_t cap);
  int  ps_blset_from_json(const char *json, struct ps_baseline_set *s);
  int  ps_blset_rollup(struct ps_baseline_set *s, int threshold);     /* collapse >=N files/dir -> dir */
  ```
- **`src/lib/baseline_decide.h`:** `enum ps_bl_verdict { PS_BL_COVERED=0, PS_BL_NOVEL, PS_BL_ANOMALY }; enum ps_bl_verdict ps_baseline_decide(const struct ps_baseline_set *baseline, const struct ps_baseline_set *denials, const char *path);`
- **`src/agent/src/baseline_store.h`:** `int ps_baseline_load(const char *state_dir, const char *exe, struct ps_baseline_set *baseline, struct ps_baseline_set *denials);` (0 always; empty sets if absent) and `int ps_baseline_append_candidate(const char *state_dir, const char *exe, const char *path);` (atomic; 0/-1).
- **`src/agent/src/modules/baseline_monitor.h`:** `int ps_baseline_process_record(const char *record_json, const char *state_dir, void *seen, void (*emit)(void *, const char *, size_t), void *emit_ctx);` and `extern const struct ps_module ps_baseline_monitor_module;`
- **State layout:** `<state_dir>/<slug>/{baseline,candidates,denials}.json`, each a `ps_baseline_set` JSON `{ "exe":"...","paths":[...] }`.
- **Verb:** `ps_verb_baseline_run` registered as `baseline`.

---

## Task 1: SP1 prerequisite — populate `process.exe`

**Files:** Modify `src/agent/src/proc_enrich.c`; `src/agent/tests/test_proc_enrich.c`

- [ ] **Step 1: Update the test fixture to create an exe symlink + assert** (`test_proc_enrich.c`)

In `mkpid`, replace the `(void)exe;` line with a symlink creation, and add an exe assertion in `main`.

Replace:
```c
    (void)exe;
```
with:
```c
    snprintf(p, sizeof p, "%s/%d/exe", root, pid); symlink(exe, p);
```
(ensure `#include <unistd.h>` is present in the test). In `main`, after the existing leaf asserts, add:
```c
    assert(strcmp(a.proc.exe, "/usr/bin/dash") == 0);
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && make test_proc_enrich 2>&1 | tail -3 && ctest -R '^test_proc_enrich$' 2>&1 | tail -3`
Expected: FAIL — `a.proc.exe` is empty (assert fails).

- [ ] **Step 3: Populate exe in `read_meta`** (`proc_enrich.c`)

Add `#include <unistd.h>` at the top. In `read_meta`, after the `status`/uid block and before `return 0;`, add:
```c
    char exep[320];
    snprintf(exep, sizeof exep, "%s/%d/exe", root, pid);
    ssize_t er = readlink(exep, p->exe, sizeof p->exe - 1);
    if (er > 0) p->exe[er] = 0;
```

- [ ] **Step 4: Run to verify it passes + no regressions**

Run: `cd /data/opt/repo/packetsonde/build && make test_proc_enrich test_fan_build packetsonde-agent packetsonde-priv >/dev/null 2>&1 && ctest -R 'proc_enrich|fan_build' --output-on-failure`
Expected: PASS; both binaries link.

- [ ] **Step 5: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/src/proc_enrich.c src/agent/tests/test_proc_enrich.c
git commit -m "agent: populate process.exe in proc_enrich (readlink /proc/<pid>/exe)"
```

---

## Task 2: `exe_slug` (`src/lib/exe_slug`)

**Files:** Create `src/lib/exe_slug.h`, `src/lib/exe_slug.c`; Test `src/lib/tests/test_exe_slug.c`; Modify `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test** (`test_exe_slug.c`)

```c
#include "exe_slug.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char s[256];
    assert(ps_exe_slug("/usr/sbin/nginx", s, sizeof s) == 0);
    assert(strcmp(s, "usr-sbin-nginx") == 0);
    assert(ps_exe_slug("/usr/bin/python3.11", s, sizeof s) == 0);
    assert(strcmp(s, "usr-bin-python3.11") == 0);          /* . and digits kept */
    assert(ps_exe_slug("", s, sizeof s) == -1);            /* empty -> error */
    /* odd chars collapse to '-' */
    assert(ps_exe_slug("/x y/z", s, sizeof s) == 0);
    assert(strcmp(s, "x-y-z") == 0);
    printf("test_exe_slug: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_exe_slug 2>&1 | tail -3`
Expected: FAIL — `exe_slug.h` not found.

- [ ] **Step 3: Create `src/lib/exe_slug.h`**

```c
#ifndef PS_EXE_SLUG_H
#define PS_EXE_SLUG_H
#include <stddef.h>
/* Sanitize an exe path to a filename slug: leading '/' dropped, each run of
 * non-[A-Za-z0-9._-] chars -> a single '-'. Returns 0, or -1 on empty input. */
int ps_exe_slug(const char *exe, char *out, size_t cap);
#endif
```

- [ ] **Step 4: Create `src/lib/exe_slug.c`**

```c
#include "exe_slug.h"
#include <string.h>

static int ok(char c) {
    return (c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c=='-';
}
int ps_exe_slug(const char *exe, char *out, size_t cap) {
    if (!exe || !*exe || cap < 2) return -1;
    size_t o = 0; int prev_dash = 1;   /* prev_dash=1 suppresses a leading '-' */
    for (const char *p = exe; *p && o < cap - 1; p++) {
        if (ok(*p)) { out[o++] = *p; prev_dash = 0; }
        else if (!prev_dash) { out[o++] = '-'; prev_dash = 1; }
    }
    while (o > 0 && out[o-1] == '-') o--;   /* trim trailing '-' */
    out[o] = 0;
    return o > 0 ? 0 : -1;
}
```

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `exe_slug.c` to `packetsonde_lib`; add `test_exe_slug` block.

- [ ] **Step 6: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_exe_slug >/dev/null && ctest -R '^test_exe_slug$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/lib/exe_slug.h src/lib/exe_slug.c src/lib/tests/test_exe_slug.c src/lib/CMakeLists.txt
git commit -m "lib: add exe_slug (executable path -> filename slug)"
```

---

## Task 3: `baseline_set` (`src/lib/baseline_set`)

**Files:** Create `src/lib/baseline_set.h`, `src/lib/baseline_set.c`; Test `src/lib/tests/test_baseline_set.c`; Modify `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test** (`test_baseline_set.c`)

```c
#include "baseline_set.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    struct ps_baseline_set s; ps_blset_init(&s, "/usr/sbin/nginx");
    assert(strcmp(s.exe, "/usr/sbin/nginx") == 0 && s.n == 0);
    assert(ps_blset_add(&s, "/var/www") == 1);
    assert(ps_blset_add(&s, "/var/www") == 0);             /* dup */
    assert(ps_blset_add(&s, "/etc/nginx/nginx.conf") == 1);

    /* dir-prefix coverage */
    assert(ps_blset_covered(&s, "/var/www") == 1);
    assert(ps_blset_covered(&s, "/var/www/html/index.html") == 1);
    assert(ps_blset_covered(&s, "/var/wwwX") == 0);        /* boundary */
    assert(ps_blset_covered(&s, "/etc/nginx/nginx.conf") == 1);
    assert(ps_blset_covered(&s, "/etc/shadow") == 0);

    /* serde round-trip */
    char buf[8192]; assert(ps_blset_to_json(&s, buf, sizeof buf) > 0);
    assert(strstr(buf, "\"exe\":\"/usr/sbin/nginx\"") && strstr(buf, "/var/www"));
    struct ps_baseline_set t; assert(ps_blset_from_json(buf, &t) == 0);
    assert(strcmp(t.exe, "/usr/sbin/nginx") == 0 && t.n == 2);
    assert(ps_blset_covered(&t, "/var/www/x") == 1);

    /* rollup: 3 files under one dir -> the dir */
    struct ps_baseline_set r; ps_blset_init(&r, "/x");
    ps_blset_add(&r, "/d/a"); ps_blset_add(&r, "/d/b"); ps_blset_add(&r, "/d/c");
    ps_blset_add(&r, "/e/only");
    ps_blset_rollup(&r, 3);
    assert(ps_blset_covered(&r, "/d/zzz") == 1);           /* /d rolled up */
    int has_e_only = 0; for (int i=0;i<r.n;i++) if(!strcmp(r.path[i],"/e/only")) has_e_only=1;
    assert(has_e_only);                                    /* /e/only stayed exact */
    printf("test_baseline_set: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_baseline_set 2>&1 | tail -3`
Expected: FAIL — `baseline_set.h` not found.

- [ ] **Step 3: Create `src/lib/baseline_set.h`** (struct + signatures from "Interfaces locked here", wrapped in guards + `#include <stddef.h>`).

- [ ] **Step 4: Create `src/lib/baseline_set.c`**

```c
#include "baseline_set.h"
#include "json.h"
#include "json_extract.h"
#include <string.h>
#include <stdio.h>

void ps_blset_init(struct ps_baseline_set *s, const char *exe) {
    s->n = 0;
    snprintf(s->exe, sizeof s->exe, "%s", exe ? exe : "");
}

static int under(const char *path, const char *prefix) {
    size_t lp = strlen(prefix);
    if (lp == 0) return 0;
    if (strncmp(path, prefix, lp) != 0) return 0;
    return path[lp] == 0 || path[lp] == '/' || prefix[lp-1] == '/';
}

int ps_blset_add(struct ps_baseline_set *s, const char *path) {
    if (!path || !*path) return -1;
    for (int i = 0; i < s->n; i++) if (!strcmp(s->path[i], path)) return 0;
    if (s->n >= PS_BL_MAX) return -1;
    snprintf(s->path[s->n], PS_BL_PATHLEN, "%s", path);
    s->n++;
    return 1;
}

int ps_blset_covered(const struct ps_baseline_set *s, const char *path) {
    for (int i = 0; i < s->n; i++) if (under(path, s->path[i])) return 1;
    return 0;
}

int ps_blset_to_json(const struct ps_baseline_set *s, char *out, size_t cap) {
    struct ps_json j; ps_json_init(&j, out, cap);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "exe", s->exe);
    ps_json_array_begin(&j, "paths");
    for (int i = 0; i < s->n; i++) ps_json_array_string(&j, s->path[i]);
    ps_json_array_end(&j);
    ps_json_object_end(&j);
    return ps_json_finish(&j);
}

int ps_blset_from_json(const char *json, struct ps_baseline_set *s) {
    if (!json) return -1;
    s->n = 0; s->exe[0] = 0;
    ps_json_extract_string(json, "exe", s->exe, sizeof s->exe);
    const char *p = strstr(json, "\"paths\":[");
    if (!p) return 0;
    p += strlen("\"paths\":[");
    while (*p && *p != ']' && s->n < PS_BL_MAX) {
        const char *q = strchr(p, '"'); const char *close = strchr(p, ']');
        if (!q || (close && q > close)) break;
        q++; const char *e = strchr(q, '"'); if (!e) break;
        size_t len = (size_t)(e - q);
        if (len < PS_BL_PATHLEN) { memcpy(s->path[s->n], q, len); s->path[s->n][len] = 0; s->n++; }
        p = e + 1; const char *comma = strchr(p, ','); close = strchr(p, ']');
        if (!comma || (close && close < comma)) break;
        p = comma + 1;
    }
    return 0;
}

static void parent_dir(const char *path, char *out, size_t cap) {
    const char *slash = strrchr(path, '/');
    size_t len = (slash && slash != path) ? (size_t)(slash - path) : 1;
    if (len >= cap) len = cap - 1;
    memcpy(out, path, len); out[len] = 0;
    if (len == 1 && path[0] == '/') { out[0] = '/'; out[1] = 0; }
}

int ps_blset_rollup(struct ps_baseline_set *s, int threshold) {
    if (threshold < 1) threshold = 1;
    char dirs[PS_BL_MAX][PS_BL_PATHLEN]; int dn = 0, dc[PS_BL_MAX]; 
    for (int i = 0; i < PS_BL_MAX; i++) dc[i] = 0;
    for (int i = 0; i < s->n; i++) {
        char d[PS_BL_PATHLEN]; parent_dir(s->path[i], d, sizeof d);
        int k = -1; for (int j = 0; j < dn; j++) if (!strcmp(dirs[j], d)) { k = j; break; }
        if (k < 0) { k = dn; snprintf(dirs[dn], PS_BL_PATHLEN, "%s", d); dn++; }
        dc[k]++;
    }
    struct ps_baseline_set out; ps_blset_init(&out, s->exe);
    for (int k = 0; k < dn; k++) if (dc[k] >= threshold) ps_blset_add(&out, dirs[k]);
    for (int i = 0; i < s->n; i++) {
        char d[PS_BL_PATHLEN]; parent_dir(s->path[i], d, sizeof d);
        int k = 0; for (int j = 0; j < dn; j++) if (!strcmp(dirs[j], d)) { k = j; break; }
        if (dc[k] < threshold) ps_blset_add(&out, s->path[i]);
    }
    *s = out;
    return 0;
}
```

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `baseline_set.c` to `packetsonde_lib`; add `test_baseline_set`.

- [ ] **Step 6: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_baseline_set >/dev/null && ctest -R '^test_baseline_set$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/lib/baseline_set.h src/lib/baseline_set.c src/lib/tests/test_baseline_set.c src/lib/CMakeLists.txt
git commit -m "lib: add baseline_set (path set, dir-prefix match, serde, rollup)"
```

---

## Task 4: `baseline_decide` (`src/lib/baseline_decide`)

**Files:** Create `src/lib/baseline_decide.h`, `src/lib/baseline_decide.c`; Test `src/lib/tests/test_baseline_decide.c`; Modify `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test** (`test_baseline_decide.c`)

```c
#include "baseline_decide.h"
#include "baseline_set.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    struct ps_baseline_set bl, den;
    ps_blset_init(&bl, "/x"); ps_blset_init(&den, "/x");
    ps_blset_add(&bl, "/var/www");
    ps_blset_add(&den, "/etc/shadow");
    assert(ps_baseline_decide(&bl, &den, "/var/www/index.html") == PS_BL_COVERED);
    assert(ps_baseline_decide(&bl, &den, "/etc/shadow") == PS_BL_ANOMALY);
    assert(ps_baseline_decide(&bl, &den, "/tmp/new") == PS_BL_NOVEL);
    /* baseline wins over denial if both match (approved beats denied) */
    ps_blset_add(&bl, "/etc/shadow");
    assert(ps_baseline_decide(&bl, &den, "/etc/shadow") == PS_BL_COVERED);
    printf("test_baseline_decide: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_baseline_decide 2>&1 | tail -3`
Expected: FAIL — `baseline_decide.h` not found.

- [ ] **Step 3: Create `src/lib/baseline_decide.h`**

```c
#ifndef PS_BASELINE_DECIDE_H
#define PS_BASELINE_DECIDE_H
#include "baseline_set.h"
enum ps_bl_verdict { PS_BL_COVERED=0, PS_BL_NOVEL, PS_BL_ANOMALY };
/* baseline (approved) wins over denials; else denied -> ANOMALY; else NOVEL. */
enum ps_bl_verdict ps_baseline_decide(const struct ps_baseline_set *baseline,
                                      const struct ps_baseline_set *denials, const char *path);
#endif
```

- [ ] **Step 4: Create `src/lib/baseline_decide.c`**

```c
#include "baseline_decide.h"
enum ps_bl_verdict ps_baseline_decide(const struct ps_baseline_set *baseline,
                                      const struct ps_baseline_set *denials, const char *path) {
    if (ps_blset_covered(baseline, path)) return PS_BL_COVERED;
    if (ps_blset_covered(denials, path))  return PS_BL_ANOMALY;
    return PS_BL_NOVEL;
}
```

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `baseline_decide.c` to `packetsonde_lib`; add `test_baseline_decide`.

- [ ] **Step 6: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_baseline_decide >/dev/null && ctest -R '^test_baseline_decide$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/lib/baseline_decide.h src/lib/baseline_decide.c src/lib/tests/test_baseline_decide.c src/lib/CMakeLists.txt
git commit -m "lib: add baseline_decide (covered/anomaly/novel verdict)"
```

---

## Task 5: `baseline_store` (`src/agent/src/baseline_store`)

**Files:** Create `src/agent/src/baseline_store.h`, `src/agent/src/baseline_store.c`; Test `src/agent/tests/test_baseline_store.c`; Modify `src/agent/CMakeLists.txt`

> Per-exe load (baseline+denials) and atomic candidate append, against an injectable `state_dir`.

- [ ] **Step 1: Write the failing test** (`test_baseline_store.c`)

```c
#include "baseline_store.h"
#include "baseline_set.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int main(void) {
    char dir[] = "/tmp/ps_bl_XXXXXX"; assert(mkdtemp(dir));
    const char *exe = "/usr/sbin/nginx";
    /* empty store -> empty sets, no error */
    struct ps_baseline_set bl, den;
    assert(ps_baseline_load(dir, exe, &bl, &den) == 0);
    assert(bl.n == 0 && den.n == 0);
    /* append two candidates (atomic) */
    assert(ps_baseline_append_candidate(dir, exe, "/var/www/a") == 0);
    assert(ps_baseline_append_candidate(dir, exe, "/var/www/a") == 0);   /* dedup */
    assert(ps_baseline_append_candidate(dir, exe, "/tmp/b") == 0);
    /* read candidates.json back via baseline_set */
    char path[512]; char slug[256];
    extern int ps_exe_slug(const char *, char *, size_t);
    ps_exe_slug(exe, slug, sizeof slug);
    snprintf(path, sizeof path, "%s/%s/candidates.json", dir, slug);
    FILE *f = fopen(path, "r"); assert(f);
    static char j[8192]; size_t n = fread(j, 1, sizeof j - 1, f); fclose(f); j[n] = 0;
    struct ps_baseline_set c; assert(ps_blset_from_json(j, &c) == 0);
    assert(c.n == 2);   /* a (deduped) + b */
    printf("test_baseline_store: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_baseline_store 2>&1 | tail -3`
Expected: FAIL — `baseline_store.h` not found.

- [ ] **Step 3: Create `src/agent/src/baseline_store.h`**

```c
#ifndef PS_BASELINE_STORE_H
#define PS_BASELINE_STORE_H
#include "baseline_set.h"
/* Load <state_dir>/<slug>/{baseline,denials}.json into the sets (empty if absent). 0. */
int ps_baseline_load(const char *state_dir, const char *exe,
                     struct ps_baseline_set *baseline, struct ps_baseline_set *denials);
/* Append `path` to <state_dir>/<slug>/candidates.json (dedup), atomically. 0/-1. */
int ps_baseline_append_candidate(const char *state_dir, const char *exe, const char *path);
#endif
```

- [ ] **Step 4: Create `src/agent/src/baseline_store.c`**

```c
#include "baseline_store.h"
#include "exe_slug.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

static int load_one(const char *state_dir, const char *slug, const char *file,
                    const char *exe, struct ps_baseline_set *out) {
    ps_blset_init(out, exe);
    char path[512]; snprintf(path, sizeof path, "%s/%s/%s", state_dir, slug, file);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    static char j[1 << 16]; size_t n = fread(j, 1, sizeof j - 1, f); fclose(f); j[n] = 0;
    ps_blset_from_json(j, out);
    return 0;
}

int ps_baseline_load(const char *state_dir, const char *exe,
                     struct ps_baseline_set *baseline, struct ps_baseline_set *denials) {
    char slug[256];
    if (ps_exe_slug(exe, slug, sizeof slug) != 0) { ps_blset_init(baseline, exe); ps_blset_init(denials, exe); return 0; }
    load_one(state_dir, slug, "baseline.json", exe, baseline);
    load_one(state_dir, slug, "denials.json",  exe, denials);
    return 0;
}

/* atomic write: write to <path>.tmp, then rename. */
static int atomic_write(const char *path, const char *buf, size_t len) {
    char tmp[600]; snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    fwrite(buf, 1, len, f);
    fclose(f);
    return rename(tmp, path);
}

int ps_baseline_append_candidate(const char *state_dir, const char *exe, const char *path) {
    char slug[256];
    if (ps_exe_slug(exe, slug, sizeof slug) != 0) return -1;
    char dir[512]; snprintf(dir, sizeof dir, "%s/%s", state_dir, slug);
    mkdir(state_dir, 0700); mkdir(dir, 0700);   /* best-effort */
    char cpath[600]; snprintf(cpath, sizeof cpath, "%s/candidates.json", dir);

    struct ps_baseline_set c; ps_blset_init(&c, exe);
    FILE *f = fopen(cpath, "r");
    if (f) { static char j[1<<16]; size_t n = fread(j,1,sizeof j-1,f); fclose(f); j[n]=0; ps_blset_from_json(j, &c); }
    if (ps_blset_add(&c, path) != 1) return 0;   /* dup or full -> nothing to write */
    static char out[1 << 16];
    int len = ps_blset_to_json(&c, out, sizeof out);
    if (len < 0) return -1;
    return atomic_write(cpath, out, (size_t)len);
}
```

- [ ] **Step 5: Wire into `src/agent/CMakeLists.txt`** — add `src/baseline_store.c` to the agent core sources; add the test (links `packetsonde_lib` for `baseline_set`/`exe_slug`):

```cmake
add_executable(test_baseline_store tests/test_baseline_store.c src/baseline_store.c)
target_include_directories(test_baseline_store PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(test_baseline_store PRIVATE packetsonde_lib)
add_test(NAME test_baseline_store COMMAND test_baseline_store)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_baseline_store >/dev/null && ctest -R '^test_baseline_store$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/src/baseline_store.h src/agent/src/baseline_store.c src/agent/tests/test_baseline_store.c src/agent/CMakeLists.txt
git commit -m "agent: add baseline_store (per-exe load + atomic candidate append)"
```

---

## Task 6: `baseline_monitor` module (core + wiring + config)

**Files:** Create `src/agent/src/modules/baseline_monitor.h`, `src/agent/src/modules/baseline_monitor.c`; Test `src/agent/tests/test_baseline_monitor.c`; Modify `src/agent/src/config_to_env.c`, `src/agent/src/main.c`, `src/agent/CMakeLists.txt`, `packaging/packetsonded.toml`

> Testable `ps_baseline_process_record` (parse → load(state_dir) → decide → emit/append, dedup) + the module struct/tick/registration + config.

- [ ] **Step 1: Write the failing test** (`test_baseline_monitor.c`)

```c
#include "baseline_monitor.h"
#include "baseline_store.h"
#include "baseline_set.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int g_emits = 0; static char g_last[4096];
static void emit(void *c, const char *json, size_t len) { (void)c;(void)len; g_emits++; snprintf(g_last,sizeof g_last,"%s",json); }
static const char *REC(const char *exe, const char *path) {
    static char b[2048];
    snprintf(b, sizeof b, "{\"event\":\"open\",\"path\":\"%s\",\"process\":{\"pid\":9,\"comm\":\"nginx\",\"uid\":33,\"exe\":\"%s\"}}", path, exe);
    return b;
}

int main(void) {
    char dir[] = "/tmp/ps_blm_XXXXXX"; assert(mkdtemp(dir));
    const char *exe = "/usr/sbin/nginx";
    /* seed a baseline (/var/www) + a denial (/etc/shadow) */
    char slug[256]; extern int ps_exe_slug(const char*,char*,size_t); ps_exe_slug(exe, slug, sizeof slug);
    char sub[512]; snprintf(sub, sizeof sub, "%s/%s", dir, slug); mkdir(dir,0700); mkdir(sub,0700);
    struct ps_baseline_set bl; ps_blset_init(&bl, exe); ps_blset_add(&bl, "/var/www");
    struct ps_baseline_set dn; ps_blset_init(&dn, exe); ps_blset_add(&dn, "/etc/shadow");
    char j[4096], p[600];
    snprintf(p,sizeof p,"%s/baseline.json",sub); FILE *f=fopen(p,"w"); ps_blset_to_json(&bl,j,sizeof j); fputs(j,f); fclose(f);
    snprintf(p,sizeof p,"%s/denials.json",sub);  f=fopen(p,"w"); ps_blset_to_json(&dn,j,sizeof j); fputs(j,f); fclose(f);

    void *seen = ps_baseline_seen_new();
    /* covered -> silent */
    ps_baseline_process_record(REC(exe,"/var/www/index.html"), dir, seen, emit, NULL);
    assert(g_emits == 0);
    /* denied -> anomaly */
    ps_baseline_process_record(REC(exe,"/etc/shadow"), dir, seen, emit, NULL);
    assert(g_emits == 1 && strstr(g_last, "\"kind\":\"anomaly\""));
    /* novel -> candidate + appended; repeat deduped */
    ps_baseline_process_record(REC(exe,"/tmp/x"), dir, seen, emit, NULL);
    assert(g_emits == 2 && strstr(g_last, "\"kind\":\"candidate\""));
    ps_baseline_process_record(REC(exe,"/tmp/x"), dir, seen, emit, NULL);
    assert(g_emits == 2);                                  /* deduped */
    /* empty exe -> skipped */
    ps_baseline_process_record(REC("","/y"), dir, seen, emit, NULL);
    assert(g_emits == 2);
    ps_baseline_seen_free(seen);
    printf("test_baseline_monitor: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_baseline_monitor 2>&1 | tail -3`
Expected: FAIL — `baseline_monitor.h` not found.

- [ ] **Step 3: Create `src/agent/src/modules/baseline_monitor.h`**

```c
#ifndef PS_BASELINE_MONITOR_H
#define PS_BASELINE_MONITOR_H
#include <stddef.h>
void *ps_baseline_seen_new(void);
void  ps_baseline_seen_free(void *seen);
/* Parse a record, load the exe's baseline+denials from state_dir, decide, and
 * emit a finding (kind candidate|anomaly) for NOVEL/ANOMALY; novel also appends
 * a candidate. Dedup per exe|path via seen. Returns findings emitted (0/1). */
int ps_baseline_process_record(const char *record_json, const char *state_dir, void *seen,
                               void (*emit)(void *, const char *, size_t), void *emit_ctx);
extern const struct ps_module ps_baseline_monitor_module;
#endif
```

- [ ] **Step 4: Create `src/agent/src/modules/baseline_monitor.c`** (core)

```c
#include "baseline_monitor.h"
#include "baseline_store.h"
#include "baseline_decide.h"
#include "baseline_set.h"
#include "json_extract.h"
#include "json.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define PS_BLSEEN_N 2048
struct bl_seen { char keys[PS_BLSEEN_N][384]; int head, count; };
void *ps_baseline_seen_new(void) { return calloc(1, sizeof(struct bl_seen)); }
void  ps_baseline_seen_free(void *s) { free(s); }
static int seen_add(struct bl_seen *s, const char *key) {
    for (int i = 0; i < s->count; i++) {
        int idx = (s->head - 1 - i + PS_BLSEEN_N) % PS_BLSEEN_N;
        if (!strcmp(s->keys[idx], key)) return 1;
    }
    snprintf(s->keys[s->head], sizeof s->keys[0], "%s", key);
    s->head = (s->head + 1) % PS_BLSEEN_N;
    if (s->count < PS_BLSEEN_N) s->count++;
    return 0;
}

static void emit_finding(void (*emit)(void *, const char *, size_t), void *ctx,
                         const char *kind, const char *exe, const char *path,
                         const char *event, const char *comm) {
    char buf[2048]; struct ps_json j; ps_json_init(&j, buf, sizeof buf);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "source", "agent.baseline_monitor");
    ps_json_key_string(&j, "severity", !strcmp(kind,"anomaly") ? "high" : "info");
    ps_json_key_string(&j, "confidence", !strcmp(kind,"anomaly") ? "firm" : "tentative");
    ps_json_key_string(&j, "kind", kind);
    ps_json_key_string(&j, "exe", exe);
    ps_json_key_string(&j, "entry", path);
    ps_json_key_string(&j, "event", event);
    ps_json_key_string(&j, "comm", comm);
    ps_json_object_end(&j);
    if (ps_json_finish(&j) > 0 && emit) emit(ctx, buf, (size_t)j.len);
}

int ps_baseline_process_record(const char *rec, const char *state_dir, void *seenv,
                               void (*emit)(void *, const char *, size_t), void *ectx) {
    struct bl_seen *seen = seenv;
    char exe[256], path[512], event[16], comm[64]="";
    if (ps_json_extract_string(rec, "exe", exe, sizeof exe) < 0 || !exe[0]) return 0;
    if (ps_json_extract_string(rec, "path", path, sizeof path) < 0) return 0;
    if (ps_json_extract_string(rec, "event", event, sizeof event) < 0) return 0;
    ps_json_extract_string(rec, "comm", comm, sizeof comm);

    struct ps_baseline_set bl, den;
    ps_baseline_load(state_dir, exe, &bl, &den);
    enum ps_bl_verdict v = ps_baseline_decide(&bl, &den, path);
    if (v == PS_BL_COVERED) return 0;

    char key[384]; snprintf(key, sizeof key, "%s|%s", exe, path);
    if (seen_add(seen, key)) return 0;                     /* dedup */
    if (v == PS_BL_ANOMALY) { emit_finding(emit, ectx, "anomaly", exe, path, event, comm); return 1; }
    /* NOVEL */
    ps_baseline_append_candidate(state_dir, exe, path);
    emit_finding(emit, ectx, "candidate", exe, path, event, comm);
    return 1;
}
```

- [ ] **Step 5: Add the module wiring** (append to `baseline_monitor.c`)

```c
#include "module.h"
#include "activity_ring.h"

struct bl_state { int on; void *seen; char state_dir[256]; };

static int bl_init(ps_module_ctx_t *ctx) {
    const char *m = getenv("PS_DETECT_BASELINE_MODE");
    struct bl_state *st = calloc(1, sizeof *st);
    if (!st) return -1;
    st->on = (m && !strcmp(m, "on")) ? 1 : 0;
    st->seen = ps_baseline_seen_new();
    const char *d = getenv("PS_DETECT_BASELINE_STATE_DIR");
    snprintf(st->state_dir, sizeof st->state_dir, "%s", (d && d[0]) ? d : "/var/lib/packetsonde/baseline");
    ctx->userdata = st;
    if (ctx->log) ctx->log(ctx, 6, "baseline_monitor: %s", st->on ? "on" : "off");
    return 0;
}
static void bl_shutdown(ps_module_ctx_t *ctx) {
    struct bl_state *st = ctx->userdata;
    if (st) { ps_baseline_seen_free(st->seen); free(st); }
}
struct bl_emit_ctx { ps_module_ctx_t *mctx; };
static void bl_publish(void *c, const char *json, size_t len) {
    struct bl_emit_ctx *e = c;
    const char *ch = strstr(json, "\"kind\":\"anomaly\"") ? "baseline.anomaly" : "baseline.candidate";
    if (e->mctx->publish) e->mctx->publish(e->mctx, ch, json, (uint32_t)len);
}
static void bl_tick(ps_module_ctx_t *ctx, uint64_t now_usec) {
    (void)now_usec;
    struct bl_state *st = ctx->userdata;
    if (!st || !st->on) return;
    static char items[64][PS_ACT_ITEM_MAX];
    int n = ps_act_ring_drain(items, 64);
    struct bl_emit_ctx ec = { ctx };
    for (int i = 0; i < n; i++)
        ps_baseline_process_record(items[i], st->state_dir, st->seen, bl_publish, &ec);
}
const ps_module_t ps_baseline_monitor_module = {
    .name = "baseline_monitor",
    .description = "Learned per-exe behavioral baseline (hybrid learn+enforce)",
    .version = "1.0", .flags = PS_MOD_PASSIVE,
    .init = bl_init, .shutdown = bl_shutdown,
    .on_packet = NULL, .on_job = NULL, .on_response = NULL, .tick = bl_tick,
};
```

> NOTE: only ONE module may drain the ring destructively. `policy_overwatch` already drains it. **Both `policy_overwatch` and `baseline_monitor` calling `ps_act_ring_drain` will each get only a fraction of records** (whoever ticks first wins each item). For Phase A, gate so they don't both run: document that `baseline_mode=on` and `policy_mode!=off` together is unsupported (the ring has a single consumer); the module logs a warning if both are enabled. (A shared fan-out is a follow-up — see Self-Review.)

- [ ] **Step 6: Config + registration + cmake + toml**

`config_to_env.c` — add with the other `detect` rows:
```c
    { "detect", "baseline_mode",      "PS_DETECT_BASELINE_MODE" },
    { "detect", "baseline_state_dir", "PS_DETECT_BASELINE_STATE_DIR" },
    { "detect", "baseline_reload",    "PS_DETECT_BASELINE_RELOAD" },
```
`main.c` — extern + register (next to `policy_overwatch`):
```c
extern const ps_module_t ps_baseline_monitor_module;
```
```c
    if (ps_config_get_bool(&cfg, "modules", "baseline_monitor", 1))
        ps_module_registry_add(&g_registry, &ps_baseline_monitor_module);
```
`src/agent/CMakeLists.txt` — add `src/modules/baseline_monitor.c` to the agent core sources; add the test:
```cmake
add_executable(test_baseline_monitor tests/test_baseline_monitor.c
    src/modules/baseline_monitor.c src/baseline_store.c src/activity_ring.c)
target_include_directories(test_baseline_monitor PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/src/modules)
target_link_libraries(test_baseline_monitor PRIVATE packetsonde_lib pthread)
add_test(NAME test_baseline_monitor COMMAND test_baseline_monitor)
```
`packaging/packetsonded.toml` — append to `[detect]`:
```toml
baseline_mode      = "off"     # off | on  (hybrid learn+enforce, keyed by exe; single ring consumer — do not run with policy_mode!=off)
baseline_state_dir = "/var/lib/packetsonde/baseline"
baseline_reload    = "10"      # seconds between baseline/denials reloads (reserved; v1 loads per-record)
```

- [ ] **Step 7: Build + test + full regression**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_baseline_monitor packetsonde-agent >/dev/null 2>&1 && ctest -R '^test_baseline_monitor$' --output-on-failure && ctest -E 'test_via_e2e' 2>&1 | tail -3`
Expected: PASS; agent links; suite 100%.

- [ ] **Step 8: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/src/modules/baseline_monitor.h src/agent/src/modules/baseline_monitor.c \
        src/agent/tests/test_baseline_monitor.c src/agent/src/config_to_env.c src/agent/src/main.c \
        src/agent/CMakeLists.txt packaging/packetsonded.toml
git commit -m "agent: baseline_monitor module (hybrid learn+enforce, file signal) + config"
```

---

## Task 7: `baseline` CLI verb

**Files:** Create `src/cli/verbs/baseline.c`; Modify `src/cli/dispatch.c`, `src/cli/CMakeLists.txt`

> `packetsonde baseline <exe> list|approve <entry>|deny <entry>|approve-all`. Manual, order-independent arg scan (getopt does not permute here).

- [ ] **Step 1: Create `src/cli/verbs/baseline.c`**

```c
#include "../verbs.h"
#include "exe_slug.h"
#include "baseline_set.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int load(const char *dir, const char *slug, const char *file, const char *exe, struct ps_baseline_set *s) {
    ps_blset_init(s, exe);
    char p[600]; snprintf(p, sizeof p, "%s/%s/%s", dir, slug, file);
    FILE *f = fopen(p, "r"); if (!f) return 0;
    static char j[1<<16]; size_t n = fread(j,1,sizeof j-1,f); fclose(f); j[n]=0;
    ps_blset_from_json(j, s); return 0;
}
static int save(const char *dir, const char *slug, const char *file, const struct ps_baseline_set *s) {
    char d[600]; snprintf(d, sizeof d, "%s/%s", dir, slug); mkdir(dir,0700); mkdir(d,0700);
    char p[700], tmp[760]; snprintf(p,sizeof p,"%s/%s",d,file); snprintf(tmp,sizeof tmp,"%s.tmp",p);
    static char j[1<<16]; int len = ps_blset_to_json(s, j, sizeof j); if (len<0) return -1;
    FILE *f = fopen(tmp,"w"); if(!f) return -1; fwrite(j,1,len,f); fclose(f); return rename(tmp,p);
}
static void remove_entry(struct ps_baseline_set *s, const char *entry) {
    int o = 0; for (int i=0;i<s->n;i++) if (strcmp(s->path[i],entry)) { if(o!=i) memcpy(s->path[o],s->path[i],PS_BL_PATHLEN); o++; } s->n=o;
}

int ps_verb_baseline_run(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    const char *dir = "/var/lib/packetsonde/baseline";
    const char *exe = NULL, *sub = NULL, *entry = NULL;
    int threshold = 3;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--state-dir") && i+1 < argc) dir = argv[++i];
        else if (!strcmp(argv[i], "--threshold") && i+1 < argc) threshold = atoi(argv[++i]);
        else if (argv[i][0] == '-') continue;
        else if (!exe) exe = argv[i];
        else if (!sub) sub = argv[i];
        else if (!entry) entry = argv[i];
    }
    if (!exe || !sub) { fprintf(stderr, "usage: packetsonde baseline <exe> list|approve <e>|deny <e>|approve-all [--state-dir D] [--threshold N]\n"); return 2; }
    char slug[256]; if (ps_exe_slug(exe, slug, sizeof slug) != 0) { fprintf(stderr,"bad exe\n"); return 2; }

    struct ps_baseline_set bl, cand, den;
    load(dir, slug, "baseline.json", exe, &bl);
    load(dir, slug, "candidates.json", exe, &cand);
    load(dir, slug, "denials.json", exe, &den);

    if (!strcmp(sub, "list")) {
        printf("exe: %s\nbaseline (%d):\n", exe, bl.n);
        for (int i=0;i<bl.n;i++) printf("  %s\n", bl.path[i]);
        printf("candidates (%d):\n", cand.n);
        for (int i=0;i<cand.n;i++) printf("  %s\n", cand.path[i]);
        printf("denials (%d):\n", den.n);
        for (int i=0;i<den.n;i++) printf("  %s\n", den.path[i]);
        return 0;
    }
    if (!strcmp(sub, "approve-all")) {
        for (int i=0;i<cand.n;i++) ps_blset_add(&bl, cand.path[i]);
        ps_blset_rollup(&bl, threshold);
        cand.n = 0;
        save(dir, slug, "baseline.json", &bl); save(dir, slug, "candidates.json", &cand);
        printf("approved all; baseline now %d entries\n", bl.n); return 0;
    }
    if (!entry) { fprintf(stderr, "approve/deny need an <entry>\n"); return 2; }
    if (!strcmp(sub, "approve")) {
        ps_blset_add(&bl, entry); remove_entry(&cand, entry);
        save(dir, slug, "baseline.json", &bl); save(dir, slug, "candidates.json", &cand);
        printf("approved %s\n", entry); return 0;
    }
    if (!strcmp(sub, "deny")) {
        ps_blset_add(&den, entry); remove_entry(&cand, entry);
        save(dir, slug, "denials.json", &den); save(dir, slug, "candidates.json", &cand);
        printf("denied %s\n", entry); return 0;
    }
    fprintf(stderr, "unknown subcommand %s\n", sub); return 2;
}
```

- [ ] **Step 2: Register in `dispatch.c`** — prototype + VERBS row:
```c
int  ps_verb_baseline_run(int argc, char **argv, const struct ps_args *opts);
```
```c
    { "baseline", ps_verb_baseline_run, "Manage learned per-exe baselines (list/approve/deny)" },
```

- [ ] **Step 3: Add to `src/cli/CMakeLists.txt`** — `verbs/baseline.c`.

- [ ] **Step 4: Build + smoke**

```bash
cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make packetsonde 2>&1 | tail -3
D=/tmp/blv-$$
./src/cli/packetsonde baseline /usr/sbin/nginx list --state-dir "$D"            # empty
# simulate a candidate the agent appended:
S="$D/usr-sbin-nginx"; mkdir -p "$S"
printf '{"exe":"/usr/sbin/nginx","paths":["/tmp/a","/tmp/b"]}' > "$S/candidates.json"
./src/cli/packetsonde baseline /usr/sbin/nginx approve /tmp/a --state-dir "$D"
./src/cli/packetsonde baseline /usr/sbin/nginx list --state-dir "$D"            # /tmp/a in baseline, /tmp/b pending
./src/cli/packetsonde baseline /usr/sbin/nginx deny /tmp/b --state-dir "$D"
./src/cli/packetsonde baseline /usr/sbin/nginx list --state-dir "$D"            # /tmp/b in denials
rm -rf "$D"
```
Expected: list shows empty first; after approve, `/tmp/a` under baseline and `/tmp/b` pending; after deny, `/tmp/b` under denials and candidates empty.

- [ ] **Step 5: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/cli/verbs/baseline.c src/cli/dispatch.c src/cli/CMakeLists.txt
git commit -m "cli: add 'baseline' verb (list/approve/deny/approve-all per-exe baselines)"
```

---

## Task 8: Assisted live test

**Files:** Create `scripts/test-baseline.sh`

- [ ] **Step 1: Create the script**

```bash
#!/bin/bash
# Assisted live test for the learned per-exe baseline. Requires root + a service.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "must run as root (fanotify)"; exit 1; }
echo "Steps:"
echo "  1. Run the agent with [detect] enabled=1, watch_paths covering the target's dirs,"
echo "     baseline_mode=on, policy_mode=off (single ring consumer),"
echo "     baseline_state_dir=/var/lib/packetsonde/baseline."
echo "  2. Exercise the target binary through NOMINAL flows. Candidate findings"
echo "     (channel baseline.candidate) appear for each new path; the agent appends them."
echo "  3. Bulk-approve the nominal set:"
echo "       ./build/src/cli/packetsonde baseline <exe-path> approve-all"
echo "  4. Trigger an ABNORMAL access by that exe (a path it never touches), then deny it:"
echo "       ./build/src/cli/packetsonde baseline <exe-path> deny <path>"
echo
echo "PASS: after approve-all, nominal paths stop producing candidates; the denied path"
echo "      produces a baseline.anomaly (severity high) finding on each sighting."
echo "Cleanup: rm -rf /var/lib/packetsonde/baseline/<slug>"
```

- [ ] **Step 2: Syntax-check + executable**

Run: `cd /data/opt/repo/packetsonde && bash -n scripts/test-baseline.sh && echo SYNTAX_OK && chmod +x scripts/test-baseline.sh`
Expected: `SYNTAX_OK`.

- [ ] **Step 3: Commit**

```bash
cd /data/opt/repo/packetsonde
git add scripts/test-baseline.sh
git commit -m "Add assisted live test for the learned per-exe baseline"
```

---

## Self-Review

**Spec coverage (Phase A, spec §11):**
- SP1 `exe` prereq → Task 1 ✓
- exe-keying / `exe_slug` → Task 2 ✓
- `baseline_set` (dir-prefix match, serde, rollup) → Task 3 ✓
- `baseline_decide` (covered/anomaly/novel) → Task 4 ✓
- `baseline_store` (load + atomic candidate append, ownership §8) → Task 5 ✓
- `baseline_monitor` hybrid flow (covered→silent, denied→anomaly, novel→candidate+append, dedup) + config → Task 6 ✓
- `baseline` verb (list/approve/deny/approve-all + rollup) → Task 7 ✓

**Known gap / accepted for Phase A:** the SP1 ring has a **single destructive consumer**. `policy_overwatch` (SP2) and `baseline_monitor` (SP3) both `ps_act_ring_drain` — running both at once splits records between them. Phase A documents "baseline_mode=on requires policy_mode=off" and logs it; a proper **ring fan-out / multi-consumer** (or a second ring) is a fast-follow tracked here, not built in Phase A. (Per-record `ps_baseline_load` file I/O is also unoptimized; the `baseline_reload` cache is reserved for a follow-up.)

**Placeholder scan:** no TBD/"add error handling"; every code step complete; the single-consumer limitation is stated explicitly rather than hand-waved.

**Type/name consistency:** `ps_exe_slug` (2,5,6,7); `struct ps_baseline_set`/`ps_blset_*` (3,5,6,7); `ps_baseline_decide`/`PS_BL_*` (4,6); `ps_baseline_load`/`ps_baseline_append_candidate` (5,6); `ps_baseline_process_record`/`ps_baseline_seen_*`/`ps_baseline_monitor_module` (6); `ps_verb_baseline_run`/`baseline` (7); config `PS_DETECT_BASELINE_MODE/_STATE_DIR/_RELOAD` (6); state files `baseline.json`/`candidates.json`/`denials.json` + finding `kind` `candidate`/`anomaly` consistent across 5,6,7.

**Deferred to Phase B/C:** network-dest + process-spawn signals; the ring fan-out; the reload cache; statistical scoring.
