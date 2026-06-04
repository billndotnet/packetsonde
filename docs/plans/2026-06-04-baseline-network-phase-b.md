# Learned Per-Process Baseline — Phase B (network destinations) Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the SP3 learned baseline to network destinations: per executable, learn the set of `raddr` (ip:port) it connects to and — hybrid-continuous — flag a novel destination as a candidate (operator `approve`s it into the baseline, optionally generalized to host/`:port`/CIDR, or `deny`s it to an anomaly).

**Architecture:** Reuses Phase A's exe-keyed store/lifecycle/verb. Destinations live in parallel state files (`dests.json`/`dest-candidates.json`/`dest-denials.json`) so the path files are untouched — `baseline_set` gains a keyed serde. A new pure `dest_match` handles exact `ip:port`, host, `:port`, and v4 `cidr/N` matching plus generalization. The `baseline_monitor` extracts every `raddr` from the record's `sockets[]` and runs a dest verdict alongside the file verdict; the `baseline` verb gains dest subcommands.

**Tech Stack:** C11, CMake/CTest. Reuses `baseline_set`/`baseline_store`/`baseline_decide`/`baseline_monitor`/`baseline` verb (Phase A, merged), `ps_json`/`json_extract`, the module + verb wiring.

**Spec:** `docs/specs/2026-06-04-process-baseline-design.md` §11 (Phase B); the dest-matching model (exact ip:port + generalize-on-approve) was settled during scoping.

**Build:** `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON && make <t> && ctest -R '^<t>$' --output-on-failure`. Exclude `test_via_e2e` (flaky). This CLI's getopt does NOT permute — verbs scan argv manually.

---

## Interfaces locked here

- **`src/lib/baseline_set.h`** (added): `int ps_blset_to_json_key(const struct ps_baseline_set *s, const char *key, char *out, size_t cap);` and `int ps_blset_from_json_key(const char *json, const char *key, struct ps_baseline_set *s);` (the existing `_to_json`/`_from_json` become wrappers passing `"paths"`).
- **`src/lib/dest_match.h`:**
  ```c
  /* Does a baseline dest entry match a live raddr "ip:port"?  Entry forms:
   *   "1.2.3.4:443" exact | "1.2.3.4" host(any port) | ":443" port(any host)
   *   "1.2.3.0/24" v4-CIDR(any port) | "1.2.3.0/24:443" v4-CIDR+port. Returns 1/0. */
  int ps_dest_match(const char *entry, const char *raddr);
  int ps_destset_covered(const struct ps_baseline_set *s, const char *raddr);
  /* Generalize a raddr per `form` ("exact"|"host"|"port"|"cidr/N") into out. 0/-1. */
  int ps_dest_generalize(const char *raddr, const char *form, char *out, size_t cap);
  ```
- **`src/agent/src/baseline_store.h`** (added): `int ps_baseline_load_dests(const char *state_dir, const char *exe, struct ps_baseline_set *baseline, struct ps_baseline_set *denials);` and `int ps_baseline_append_dest_candidate(const char *state_dir, const char *exe, const char *dest);`
- **`src/lib/baseline_decide.h`** (added): `enum ps_bl_verdict ps_baseline_decide_dest(const struct ps_baseline_set *baseline, const struct ps_baseline_set *denials, const char *raddr);`
- **Dest state files:** `<state_dir>/<slug>/{dests,dest-candidates,dest-denials}.json`, each a `ps_baseline_set` serialized with key `"dests"`.
- **Verb:** `baseline <exe> approve-dest <raddr> [--as host|port|cidr/N]`, `deny-dest <raddr>`; `list` shows dests; `approve-all` also approves dest candidates (exact).

---

## Task 1: `baseline_set` keyed serde

**Files:** Modify `src/lib/baseline_set.h`, `src/lib/baseline_set.c`; Test `src/lib/tests/test_baseline_set.c`

- [ ] **Step 1: Add a failing assertion to `test_baseline_set.c`** (in `main`, before the success print)

```c
    /* keyed serde: store/parse under a "dests" key */
    struct ps_baseline_set ds; ps_blset_init(&ds, "/usr/sbin/nginx");
    ps_blset_add(&ds, "1.2.3.4:443");
    char db[4096]; assert(ps_blset_to_json_key(&ds, "dests", db, sizeof db) > 0);
    assert(strstr(db, "\"dests\":[") && strstr(db, "1.2.3.4:443"));
    struct ps_baseline_set dt; assert(ps_blset_from_json_key(db, "dests", &dt) == 0);
    assert(dt.n == 1 && strcmp(dt.path[0], "1.2.3.4:443") == 0);
    /* the old "paths" wrappers still work */
    assert(ps_blset_from_json(db, &dt) == 0 && dt.n == 0);   /* no "paths" key in a dests doc */
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && make test_baseline_set 2>&1 | tail -4`
Expected: FAIL — `ps_blset_to_json_key` undefined.

- [ ] **Step 3: Add the keyed functions in `baseline_set.h`** (after `ps_blset_from_json`)

```c
int ps_blset_to_json_key(const struct ps_baseline_set *s, const char *key, char *out, size_t cap);
int ps_blset_from_json_key(const char *json, const char *key, struct ps_baseline_set *s);
```

- [ ] **Step 4: Refactor `baseline_set.c`** — make the existing `to_json`/`from_json` delegate to keyed versions.

Replace the existing `ps_blset_to_json` body with:
```c
int ps_blset_to_json_key(const struct ps_baseline_set *s, const char *key, char *out, size_t cap) {
    struct ps_json j; ps_json_init(&j, out, cap);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "exe", s->exe);
    ps_json_array_begin(&j, key);
    for (int i = 0; i < s->n; i++) ps_json_array_string(&j, s->path[i]);
    ps_json_array_end(&j);
    ps_json_object_end(&j);
    return ps_json_finish(&j);
}
int ps_blset_to_json(const struct ps_baseline_set *s, char *out, size_t cap) {
    return ps_blset_to_json_key(s, "paths", out, cap);
}
```
Replace the existing `ps_blset_from_json` body with (the array scan, parameterized by key):
```c
int ps_blset_from_json_key(const char *json, const char *key, struct ps_baseline_set *s) {
    if (!json) return -1;
    s->n = 0; s->exe[0] = 0;
    ps_json_extract_string(json, "exe", s->exe, sizeof s->exe);
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\":[", key);
    const char *p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
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
int ps_blset_from_json(const char *json, struct ps_baseline_set *s) {
    return ps_blset_from_json_key(json, "paths", s);
}
```
(`snprintf` needs `<stdio.h>` — already included.)

- [ ] **Step 5: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && make test_baseline_set >/dev/null && ctest -R '^test_baseline_set$' --output-on-failure`
Expected: PASS (existing + new assertions).

- [ ] **Step 6: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/lib/baseline_set.h src/lib/baseline_set.c src/lib/tests/test_baseline_set.c
git commit -m "lib: add keyed baseline_set serde (paths/dests share storage, distinct JSON key)"
```

---

## Task 2: `dest_match` (`src/lib/dest_match`)

**Files:** Create `src/lib/dest_match.h`, `src/lib/dest_match.c`; Test `src/lib/tests/test_dest_match.c`; Modify `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test** (`test_dest_match.c`)

```c
#include "dest_match.h"
#include "baseline_set.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    /* exact */
    assert(ps_dest_match("1.2.3.4:443", "1.2.3.4:443") == 1);
    assert(ps_dest_match("1.2.3.4:443", "1.2.3.4:80") == 0);
    /* host (any port) */
    assert(ps_dest_match("1.2.3.4", "1.2.3.4:443") == 1);
    assert(ps_dest_match("1.2.3.4", "1.2.3.5:443") == 0);
    /* port (any host) */
    assert(ps_dest_match(":443", "9.9.9.9:443") == 1);
    assert(ps_dest_match(":443", "9.9.9.9:80") == 0);
    /* v4 CIDR (any port) */
    assert(ps_dest_match("1.2.3.0/24", "1.2.3.200:443") == 1);
    assert(ps_dest_match("1.2.3.0/24", "1.2.4.1:443") == 0);
    /* CIDR + port */
    assert(ps_dest_match("10.0.0.0/8:22", "10.9.9.9:22") == 1);
    assert(ps_dest_match("10.0.0.0/8:22", "10.9.9.9:23") == 0);

    /* set coverage */
    struct ps_baseline_set s; ps_blset_init(&s, "/x");
    ps_blset_add(&s, "1.2.3.0/24"); ps_blset_add(&s, ":53");
    assert(ps_destset_covered(&s, "1.2.3.9:443") == 1);
    assert(ps_destset_covered(&s, "8.8.8.8:53") == 1);
    assert(ps_destset_covered(&s, "8.8.8.8:443") == 0);

    /* generalize */
    char o[64];
    assert(ps_dest_generalize("1.2.3.4:443", "host", o, sizeof o) == 0 && strcmp(o, "1.2.3.4") == 0);
    assert(ps_dest_generalize("1.2.3.4:443", "port", o, sizeof o) == 0 && strcmp(o, ":443") == 0);
    assert(ps_dest_generalize("1.2.3.4:443", "cidr/24", o, sizeof o) == 0 && strcmp(o, "1.2.3.0/24") == 0);
    assert(ps_dest_generalize("1.2.3.4:443", "exact", o, sizeof o) == 0 && strcmp(o, "1.2.3.4:443") == 0);
    printf("test_dest_match: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_dest_match 2>&1 | tail -4`
Expected: FAIL — `dest_match.h` not found.

- [ ] **Step 3: Create `src/lib/dest_match.h`** (the signatures from "Interfaces locked here", wrapped; `#include "baseline_set.h"` + `<stddef.h>`).

- [ ] **Step 4: Create `src/lib/dest_match.c`**

```c
#include "dest_match.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* split "ip:port" (v4) -> ip + port strings. For "[v6]:port" the ip keeps the
 * brackets; CIDR is not attempted on v6. Returns 0; port may be empty. */
static void split_raddr(const char *raddr, char *ip, size_t ipc, char *port, size_t pc) {
    const char *colon = strrchr(raddr, ':');
    if (colon) {
        size_t n = (size_t)(colon - raddr); if (n >= ipc) n = ipc - 1;
        memcpy(ip, raddr, n); ip[n] = 0;
        snprintf(port, pc, "%s", colon + 1);
    } else { snprintf(ip, ipc, "%s", raddr); port[0] = 0; }
}

static int v4_to_u32(const char *ip, unsigned *out) {
    unsigned a,b,c,d;
    if (sscanf(ip, "%u.%u.%u.%u", &a,&b,&c,&d) != 4) return -1;
    if (a>255||b>255||c>255||d>255) return -1;
    *out = (a<<24)|(b<<16)|(c<<8)|d; return 0;
}

int ps_dest_match(const char *entry, const char *raddr) {
    if (!entry || !raddr) return 0;
    char rip[64], rport[16]; split_raddr(raddr, rip, sizeof rip, rport, sizeof rport);

    /* does entry carry an explicit port?  split at the LAST ':' that's after any ']' or '/' */
    char e[128]; snprintf(e, sizeof e, "%s", entry);
    char *eport = NULL;
    char *slash = strchr(e, '/');
    char *ecolon = strrchr(e, ':');
    if (ecolon && (!slash || ecolon > slash)) { *ecolon = 0; eport = ecolon + 1; }
    /* now e is the host/cidr/"" part, eport is the port or NULL */
    if (eport && strcmp(eport, rport) != 0) return 0;      /* port specified and differs */

    if (e[0] == 0) return 1;                               /* ":port" form -> host wildcard, port matched */
    slash = strchr(e, '/');
    if (slash) {                                           /* v4 CIDR */
        *slash = 0; int bits = atoi(slash + 1);
        unsigned net, rip32;
        if (v4_to_u32(e, &net) != 0 || v4_to_u32(rip, &rip32) != 0) return 0;
        if (bits <= 0) return 1; if (bits > 32) bits = 32;
        unsigned mask = bits == 32 ? 0xFFFFFFFFu : ~((1u << (32 - bits)) - 1);
        return (net & mask) == (rip32 & mask);
    }
    return strcmp(e, rip) == 0;                            /* host (exact ip) */
}

int ps_destset_covered(const struct ps_baseline_set *s, const char *raddr) {
    for (int i = 0; i < s->n; i++) if (ps_dest_match(s->path[i], raddr)) return 1;
    return 0;
}

int ps_dest_generalize(const char *raddr, const char *form, char *out, size_t cap) {
    if (!raddr || !form) return -1;
    char ip[64], port[16]; split_raddr(raddr, ip, sizeof ip, port, sizeof port);
    if (!strcmp(form, "exact")) { snprintf(out, cap, "%s", raddr); return 0; }
    if (!strcmp(form, "host"))  { snprintf(out, cap, "%s", ip); return 0; }
    if (!strcmp(form, "port"))  { snprintf(out, cap, ":%s", port); return 0; }
    if (!strncmp(form, "cidr/", 5)) {
        int bits = atoi(form + 5); if (bits < 0) bits = 0; if (bits > 32) bits = 32;
        unsigned u; if (v4_to_u32(ip, &u) != 0) return -1;
        unsigned mask = bits == 0 ? 0 : (bits == 32 ? 0xFFFFFFFFu : ~((1u << (32 - bits)) - 1));
        unsigned net = u & mask;
        snprintf(out, cap, "%u.%u.%u.%u/%d", (net>>24)&255,(net>>16)&255,(net>>8)&255,net&255, bits);
        return 0;
    }
    return -1;
}
```

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `dest_match.c` to `packetsonde_lib`; add `test_dest_match` block.

- [ ] **Step 6: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_dest_match >/dev/null && ctest -R '^test_dest_match$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/lib/dest_match.h src/lib/dest_match.c src/lib/tests/test_dest_match.c src/lib/CMakeLists.txt
git commit -m "lib: add dest_match (ip:port/host/:port/v4-CIDR match + generalize)"
```

---

## Task 3: `baseline_store` dest ops

**Files:** Modify `src/agent/src/baseline_store.h`, `src/agent/src/baseline_store.c`; Test `src/agent/tests/test_baseline_store.c`

> Parallel dest files (`dests.json`/`dest-denials.json`/`dest-candidates.json`), key `"dests"`, reusing the atomic-write idiom.

- [ ] **Step 1: Add a failing assertion to `test_baseline_store.c`** (before the success print)

```c
    /* dest store: load empty, append two (dedup), read back under "dests" key */
    struct ps_baseline_set dbl, dden;
    assert(ps_baseline_load_dests(dir, exe, &dbl, &dden) == 0);
    assert(dbl.n == 0 && dden.n == 0);
    assert(ps_baseline_append_dest_candidate(dir, exe, "1.2.3.4:443") == 0);
    assert(ps_baseline_append_dest_candidate(dir, exe, "1.2.3.4:443") == 0);
    assert(ps_baseline_append_dest_candidate(dir, exe, "8.8.8.8:53") == 0);
    char dpath[600]; snprintf(dpath, sizeof dpath, "%s/%s/dest-candidates.json", dir, slug);
    FILE *df = fopen(dpath, "r"); assert(df);
    static char dj[8192]; size_t dn2 = fread(dj,1,sizeof dj-1,df); fclose(df); dj[dn2]=0;
    struct ps_baseline_set dc; assert(ps_blset_from_json_key(dj, "dests", &dc) == 0);
    assert(dc.n == 2);
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && make test_baseline_store 2>&1 | tail -4`
Expected: FAIL — `ps_baseline_load_dests` undefined.

- [ ] **Step 3: Declare in `baseline_store.h`**

```c
int ps_baseline_load_dests(const char *state_dir, const char *exe,
                           struct ps_baseline_set *baseline, struct ps_baseline_set *denials);
int ps_baseline_append_dest_candidate(const char *state_dir, const char *exe, const char *dest);
```

- [ ] **Step 4: Implement in `baseline_store.c`** (append; reuses `atomic_write` from Task-A code already in this file)

```c
static int load_one_key(const char *state_dir, const char *slug, const char *file,
                        const char *key, const char *exe, struct ps_baseline_set *out) {
    ps_blset_init(out, exe);
    char path[512]; snprintf(path, sizeof path, "%s/%s/%s", state_dir, slug, file);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    static char j[1 << 16]; size_t n = fread(j, 1, sizeof j - 1, f); fclose(f); j[n] = 0;
    ps_blset_from_json_key(j, key, out);
    return 0;
}

int ps_baseline_load_dests(const char *state_dir, const char *exe,
                           struct ps_baseline_set *baseline, struct ps_baseline_set *denials) {
    char slug[256];
    if (ps_exe_slug(exe, slug, sizeof slug) != 0) {
        ps_blset_init(baseline, exe); ps_blset_init(denials, exe); return 0;
    }
    load_one_key(state_dir, slug, "dests.json", "dests", exe, baseline);
    load_one_key(state_dir, slug, "dest-denials.json", "dests", exe, denials);
    return 0;
}

int ps_baseline_append_dest_candidate(const char *state_dir, const char *exe, const char *dest) {
    char slug[256];
    if (ps_exe_slug(exe, slug, sizeof slug) != 0) return -1;
    char dir[512]; snprintf(dir, sizeof dir, "%s/%s", state_dir, slug);
    mkdir(state_dir, 0700); mkdir(dir, 0700);
    char cpath[600]; snprintf(cpath, sizeof cpath, "%s/dest-candidates.json", dir);
    struct ps_baseline_set c; ps_blset_init(&c, exe);
    FILE *f = fopen(cpath, "r");
    if (f) { static char j[1<<16]; size_t n = fread(j,1,sizeof j-1,f); fclose(f); j[n]=0; ps_blset_from_json_key(j, "dests", &c); }
    if (ps_blset_add(&c, dest) != 1) return 0;
    static char out[1 << 16];
    int len = ps_blset_to_json_key(&c, "dests", out, sizeof out);
    if (len < 0) return -1;
    return atomic_write(cpath, out, (size_t)len);
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && make test_baseline_store >/dev/null && ctest -R '^test_baseline_store$' --output-on-failure`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/src/baseline_store.h src/agent/src/baseline_store.c src/agent/tests/test_baseline_store.c
git commit -m "agent: baseline_store dest ops (load dests + atomic dest-candidate append)"
```

---

## Task 4: `baseline_decide` dest verdict

**Files:** Modify `src/lib/baseline_decide.h`, `src/lib/baseline_decide.c`; Test `src/lib/tests/test_baseline_decide.c`

- [ ] **Step 1: Add a failing assertion to `test_baseline_decide.c`** (before the success print)

```c
    struct ps_baseline_set dbl, dden;
    ps_blset_init(&dbl, "/x"); ps_blset_init(&dden, "/x");
    ps_blset_add(&dbl, "1.2.3.0/24");      /* approved subnet */
    ps_blset_add(&dden, "6.6.6.6");        /* denied host */
    assert(ps_baseline_decide_dest(&dbl, &dden, "1.2.3.9:443") == PS_BL_COVERED);
    assert(ps_baseline_decide_dest(&dbl, &dden, "6.6.6.6:1337") == PS_BL_ANOMALY);
    assert(ps_baseline_decide_dest(&dbl, &dden, "9.9.9.9:443") == PS_BL_NOVEL);
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && make test_baseline_decide 2>&1 | tail -4`
Expected: FAIL — `ps_baseline_decide_dest` undefined.

- [ ] **Step 3: Declare in `baseline_decide.h`** (add `#include "dest_match.h"` and:)

```c
/* Same verdict semantics as ps_baseline_decide, but for a network raddr. */
enum ps_bl_verdict ps_baseline_decide_dest(const struct ps_baseline_set *baseline,
                                           const struct ps_baseline_set *denials, const char *raddr);
```

- [ ] **Step 4: Implement in `baseline_decide.c`** (add `#include "dest_match.h"`)

```c
enum ps_bl_verdict ps_baseline_decide_dest(const struct ps_baseline_set *baseline,
                                           const struct ps_baseline_set *denials, const char *raddr) {
    if (ps_destset_covered(baseline, raddr)) return PS_BL_COVERED;
    if (ps_destset_covered(denials, raddr))  return PS_BL_ANOMALY;
    return PS_BL_NOVEL;
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && make test_baseline_decide >/dev/null && ctest -R '^test_baseline_decide$' --output-on-failure`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/lib/baseline_decide.h src/lib/baseline_decide.c src/lib/tests/test_baseline_decide.c
git commit -m "lib: add baseline_decide_dest (network destination verdict)"
```

---

## Task 5: `baseline_monitor` — destination checks

**Files:** Modify `src/agent/src/modules/baseline_monitor.c`; Test `src/agent/tests/test_baseline_monitor.c`

> After the file verdict, extract every `raddr` from the record's `sockets[]` and run a dest verdict; emit candidate/anomaly with `kind` + a `dest` field; append novel dests.

- [ ] **Step 1: Add a failing test block to `test_baseline_monitor.c`** (a record with sockets; seed a dest baseline + denial)

```c
    /* --- dest signal --- */
    struct ps_baseline_set dbl; ps_blset_init(&dbl, exe); ps_blset_add(&dbl, "10.0.0.0/8");
    struct ps_baseline_set dden; ps_blset_init(&dden, exe); ps_blset_add(&dden, "6.6.6.6");
    snprintf(p,sizeof p,"%s/dests.json",sub);        f=fopen(p,"w"); ps_blset_to_json_key(&dbl,"dests",j,sizeof j); fputs(j,f); fclose(f);
    snprintf(p,sizeof p,"%s/dest-denials.json",sub); f=fopen(p,"w"); ps_blset_to_json_key(&dden,"dests",j,sizeof j); fputs(j,f); fclose(f);
    #define DREC(path,raddr) ({ static char b[2048]; snprintf(b,sizeof b, \
      "{\"event\":\"open\",\"path\":\"%s\",\"process\":{\"comm\":\"nginx\",\"exe\":\"%s\"}," \
      "\"sockets\":[{\"raddr\":\"%s\"}]}", path, exe, raddr); b; })
    int e0 = g_emits;
    /* covered path + covered dest -> silent */
    ps_baseline_process_record(DREC("/var/www/x","10.1.2.3:443"), dir, seen, emit, NULL);
    assert(g_emits == e0);
    /* covered path + denied dest -> anomaly */
    ps_baseline_process_record(DREC("/var/www/x","6.6.6.6:1337"), dir, seen, emit, NULL);
    assert(g_emits == e0 + 1 && strstr(g_last, "\"kind\":\"anomaly\"") && strstr(g_last, "6.6.6.6:1337"));
    /* covered path + novel dest -> candidate */
    ps_baseline_process_record(DREC("/var/www/x","9.9.9.9:53"), dir, seen, emit, NULL);
    assert(g_emits == e0 + 2 && strstr(g_last, "\"kind\":\"candidate\"") && strstr(g_last, "9.9.9.9:53"));
```

(Add `#include "baseline_set.h"` to the test if not present.)

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && make test_baseline_monitor 2>&1 | tail -4`
Expected: FAIL — dest findings not emitted (g_emits unchanged).

- [ ] **Step 3: Extend `ps_baseline_process_record` in `baseline_monitor.c`** — add the dest pass after the existing path logic. Add `#include "dest_match.h"` at the top.

Add a helper above `ps_baseline_process_record`:
```c
/* emit a finding for a network dest (entry) of the given kind. */
static void emit_dest_finding(void (*emit)(void *, const char *, size_t), void *ctx,
                              const char *kind, const char *exe, const char *raddr, const char *comm) {
    char buf[2048]; struct ps_json j; ps_json_init(&j, buf, sizeof buf);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "source", "agent.baseline_monitor");
    ps_json_key_string(&j, "severity", !strcmp(kind,"anomaly") ? "high" : "info");
    ps_json_key_string(&j, "confidence", !strcmp(kind,"anomaly") ? "firm" : "tentative");
    ps_json_key_string(&j, "kind", kind);
    ps_json_key_string(&j, "signal", "dest");
    ps_json_key_string(&j, "exe", exe);
    ps_json_key_string(&j, "dest", raddr);
    ps_json_key_string(&j, "comm", comm);
    ps_json_object_end(&j);
    if (ps_json_finish(&j) > 0 && emit) emit(ctx, buf, (size_t)j.len);
}
```

At the end of `ps_baseline_process_record` (after the file verdict block, before `return n;` — note the function currently `return`s inside the path block; refactor so the dest pass always runs). Restructure the tail of the function to:
```c
    /* ... existing file-verdict logic, but accumulate into `n` instead of early return ... */
    /* dest pass: scan every "raddr":"..." in the record */
    struct ps_baseline_set dbl, dden;
    ps_baseline_load_dests(state_dir, exe, &dbl, &dden);
    const char *sp = rec;
    while ((sp = strstr(sp, "\"raddr\":\"")) != NULL) {
        sp += 9;
        const char *se = strchr(sp, '"');
        if (!se) break;
        char raddr[64]; size_t rl = (size_t)(se - sp); if (rl >= sizeof raddr) rl = sizeof raddr - 1;
        memcpy(raddr, sp, rl); raddr[rl] = 0; sp = se + 1;
        if (!raddr[0]) continue;
        enum ps_bl_verdict dv = ps_baseline_decide_dest(&dbl, &dden, raddr);
        if (dv == PS_BL_COVERED) continue;
        char dkey[384]; snprintf(dkey, sizeof dkey, "%s|D|%s", exe, raddr);
        if (seen_add(seen, dkey)) continue;
        if (dv == PS_BL_ANOMALY) { emit_dest_finding(emit, ectx, "anomaly", exe, raddr, comm); n++; }
        else { ps_baseline_append_dest_candidate(state_dir, exe, raddr); emit_dest_finding(emit, ectx, "candidate", exe, raddr, comm); n++; }
    }
    return n;
```

> IMPORTANT refactor: the existing file logic does `if (v == PS_BL_COVERED) return 0;` and returns inside the ANOMALY/NOVEL branches. Change those to set a local `int n = 0;` and `n++` (no early `return`) so the dest pass always runs, except when `exe` is empty (still return 0 early at the top). The file `seen_add` key stays `"%s|%s"` (exe|path); the dest key uses `"%s|D|%s"` so a path and a dest with the same string don't collide.

- [ ] **Step 4: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && make test_baseline_monitor packetsonde-agent >/dev/null 2>&1 && ctest -R '^test_baseline_monitor$' --output-on-failure`
Expected: PASS (file + dest assertions); agent links.

- [ ] **Step 5: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/src/modules/baseline_monitor.c src/agent/tests/test_baseline_monitor.c
git commit -m "agent: baseline_monitor flags novel/denied network destinations (sockets raddr)"
```

---

## Task 6: `baseline` verb — destination subcommands

**Files:** Modify `src/cli/verbs/baseline.c`

> `list` shows dests; `approve-dest <raddr> [--as host|port|cidr/N]`, `deny-dest <raddr>`; `approve-all` also approves dest candidates (exact).

- [ ] **Step 1: Extend `baseline.c`** — load the dest files, add the subcommands. Add `#include "dest_match.h"`.

After the existing `load(...)` calls for path files, load the dest files:
```c
    struct ps_baseline_set dbl, dcand, dden;
    load_key(dir, slug, "dests.json", "dests", exe, &dbl);
    load_key(dir, slug, "dest-candidates.json", "dests", exe, &dcand);
    load_key(dir, slug, "dest-denials.json", "dests", exe, &dden);
```
Add `load_key`/`save_key` helpers (mirror the existing `load`/`save` but pass a key to the `_key` serde):
```c
static int load_key(const char *dir, const char *slug, const char *file, const char *key, const char *exe, struct ps_baseline_set *s) {
    ps_blset_init(s, exe);
    char p[600]; snprintf(p, sizeof p, "%s/%s/%s", dir, slug, file);
    FILE *f = fopen(p, "r"); if (!f) return 0;
    static char j[1<<16]; size_t n = fread(j,1,sizeof j-1,f); fclose(f); j[n]=0;
    ps_blset_from_json_key(j, key, s); return 0;
}
static int save_key(const char *dir, const char *slug, const char *file, const char *key, const struct ps_baseline_set *s) {
    char d[600]; snprintf(d, sizeof d, "%s/%s", dir, slug); mkdir(dir,0700); mkdir(d,0700);
    char p[700], tmp[760]; snprintf(p,sizeof p,"%s/%s",d,file); snprintf(tmp,sizeof tmp,"%s.tmp",p);
    static char j[1<<16]; int len = ps_blset_to_json_key(s, key, j, sizeof j); if (len<0) return -1;
    FILE *f = fopen(tmp,"w"); if(!f) return -1; fwrite(j,1,len,f); fclose(f); return rename(tmp,p);
}
```
Add a `--as <form>` option to the arg scan (`else if (!strcmp(argv[i],"--as") && i+1<argc) form = argv[++i];` with `const char *form = "exact";`).

Extend `list` to also print dests:
```c
        printf("dests baseline (%d):\n", dbl.n);   for (int i=0;i<dbl.n;i++) printf("  %s\n", dbl.path[i]);
        printf("dest candidates (%d):\n", dcand.n); for (int i=0;i<dcand.n;i++) printf("  %s\n", dcand.path[i]);
        printf("dest denials (%d):\n", dden.n);     for (int i=0;i<dden.n;i++) printf("  %s\n", dden.path[i]);
```
Extend `approve-all` to also approve dest candidates (exact, no rollup):
```c
        for (int i=0;i<dcand.n;i++) ps_blset_add(&dbl, dcand.path[i]);
        dcand.n = 0;
        save_key(dir, slug, "dests.json", "dests", &dbl); save_key(dir, slug, "dest-candidates.json", "dests", &dcand);
```
Add the new subcommands (before the final "unknown subcommand"):
```c
    if (!strcmp(sub, "approve-dest")) {
        if (!entry) { fprintf(stderr, "approve-dest needs a <raddr>\n"); return 2; }
        char gen[64]; if (ps_dest_generalize(entry, form, gen, sizeof gen) != 0) { fprintf(stderr,"bad --as form\n"); return 2; }
        ps_blset_add(&dbl, gen); remove_entry(&dcand, entry);
        save_key(dir, slug, "dests.json", "dests", &dbl); save_key(dir, slug, "dest-candidates.json", "dests", &dcand);
        printf("approved dest %s (as %s)\n", entry, gen); return 0;
    }
    if (!strcmp(sub, "deny-dest")) {
        if (!entry) { fprintf(stderr, "deny-dest needs a <raddr>\n"); return 2; }
        ps_blset_add(&dden, entry); remove_entry(&dcand, entry);
        save_key(dir, slug, "dest-denials.json", "dests", &dden); save_key(dir, slug, "dest-candidates.json", "dests", &dcand);
        printf("denied dest %s\n", entry); return 0;
    }
```

- [ ] **Step 2: Build + smoke**

```bash
cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make packetsonde 2>&1 | tail -3
D=/tmp/bld-$$; S="$D/usr-sbin-nginx"; mkdir -p "$S"
printf '{"exe":"/usr/sbin/nginx","dests":["1.2.3.4:443","8.8.8.8:53"]}' > "$S/dest-candidates.json"
./src/cli/packetsonde baseline /usr/sbin/nginx approve-dest 1.2.3.4:443 --as cidr/24 --state-dir "$D"
./src/cli/packetsonde baseline /usr/sbin/nginx deny-dest 8.8.8.8:53 --state-dir "$D"
echo "--- list ---"; ./src/cli/packetsonde baseline /usr/sbin/nginx list --state-dir "$D"
rm -rf "$D"
```
Expected: approve-dest stores `1.2.3.0/24` in dests baseline; deny-dest moves `8.8.8.8:53` to dest denials; list shows both, candidates empty.

- [ ] **Step 3: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/cli/verbs/baseline.c
git commit -m "cli: baseline verb gains dest subcommands (approve-dest --as / deny-dest)"
```

---

## Task 7: Live test note + full regression

**Files:** Modify `scripts/test-baseline.sh`

- [ ] **Step 1: Append a network section to `scripts/test-baseline.sh`** (before the final cleanup echo)

```bash
echo
echo "Network destinations (Phase B):"
echo "  - With baseline_mode=on, an exe connecting to a NEW raddr yields a baseline.candidate"
echo "    (signal=dest). Approve it (optionally generalized):"
echo "       ./build/src/cli/packetsonde baseline <exe-path> approve-dest <ip:port> --as cidr/24"
echo "  - A connection to a denied host yields a baseline.anomaly (signal=dest):"
echo "       ./build/src/cli/packetsonde baseline <exe-path> deny-dest <ip:port>"
```

- [ ] **Step 2: Syntax-check + full regression**

Run: `cd /data/opt/repo/packetsonde && bash -n scripts/test-baseline.sh && echo SYNTAX_OK && cd build && cmake .. -DBUILD_TESTING=ON >/dev/null && make packetsonde-agent packetsonde-priv packetsonde >/dev/null 2>&1 && echo LINK_OK && ctest -E 'test_via_e2e' 2>&1 | tail -3`
Expected: `SYNTAX_OK`, `LINK_OK`, suite 100%.

- [ ] **Step 3: Commit**

```bash
cd /data/opt/repo/packetsonde
git add scripts/test-baseline.sh
git commit -m "Add network-destination steps to the assisted baseline live test"
```

---

## Self-Review

**Spec coverage (Phase B, spec §11):**
- Network-dest signal from `sockets[].raddr` → Tasks 5 (extraction + verdict), 4 (decide) ✓
- exact ip:port + generalize-on-approve (host/`:port`/CIDR) → Task 2 (`dest_match`/`ps_dest_generalize`), Task 6 (`approve-dest --as`) ✓
- Reuse Phase A store/lifecycle/verb (hybrid candidate→approve/deny) → Tasks 3 (store), 6 (verb), 5 (monitor) ✓
- Parallel dest state files via keyed serde → Tasks 1, 3 ✓

**Known limitations (accepted):** v6 CIDR not matched (exact/host/`:port` only for v6 — noted in `dest_match`); the monitor attributes ALL `sockets[].raddr` (incl. ancestor sockets) to the leaf exe's dest baseline (same attribution SP1 chose; may add minor noise); per-record dest load is unoptimized (shares Phase A's reserved reload-cache follow-up).

**Placeholder scan:** no TBD/"add error handling"; every code step complete; the monitor refactor (early-return → accumulate `n`) is described concretely.

**Type/name consistency:** `ps_blset_to_json_key`/`ps_blset_from_json_key` (1,3,6); `ps_dest_match`/`ps_destset_covered`/`ps_dest_generalize` (2,4,6); `ps_baseline_load_dests`/`ps_baseline_append_dest_candidate` (3,5); `ps_baseline_decide_dest` (4,5); dest files `dests.json`/`dest-candidates.json`/`dest-denials.json` + JSON key `"dests"` + finding `signal:"dest"` consistent across 3,5,6.

**Deferred to Phase C:** process-spawn signal (expected child comm/exe from `ancestry[]`).
```
