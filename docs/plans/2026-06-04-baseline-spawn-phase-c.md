# Learned Per-Process Baseline — Phase C (process spawning) Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the SP3 learned baseline to process spawning: per executable, learn the set of immediate-parent `comm`s that normally launch it, and — hybrid-continuous — flag a process launched by a novel parent as a candidate (operator `approve-parent`s it, or `deny-parent`s it to an anomaly).

**Architecture:** Reuses Phase A/B's exe-keyed store/lifecycle/verb. The "parents" set is a third per-exe string set in parallel state files (`parents.json`/`parent-candidates.json`/`parent-denials.json`, key `"parents"`). Matching is **exact comm membership** — `ps_blset_covered` already does this for comms (comms contain no `/`, so its dir-prefix rule degenerates to exact), and the verdict reuses `ps_baseline_decide` directly. The monitor extracts the immediate parent `comm` (the first `"comm"` inside the record's `"ancestry":[…]`).

**Tech Stack:** C11, CMake/CTest. Reuses `baseline_set` (keyed serde, `covered`), `baseline_store` (load + atomic append), `baseline_decide`, `baseline_monitor`, the `baseline` verb — all merged.

**Spec:** `docs/specs/2026-06-04-process-baseline-design.md` §11 (Phase C); the spawn model (per-exe expected-parent-comms, exact match) was settled during scoping.

**Build:** `cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON && make <t> && ctest -R '^<t>$' --output-on-failure`. Exclude `test_via_e2e` (flaky). This CLI's getopt does NOT permute — the verb scans argv manually.

---

## Interfaces locked here

- **`src/agent/src/baseline_store.h`** (added): `int ps_baseline_load_parents(const char *state_dir, const char *exe, struct ps_baseline_set *baseline, struct ps_baseline_set *denials);` and `int ps_baseline_append_parent_candidate(const char *state_dir, const char *exe, const char *parent_comm);`
- **Parent state files:** `<state_dir>/<slug>/{parents,parent-candidates,parent-denials}.json`, each a `ps_baseline_set` serialized with key `"parents"`.
- **Verdict:** reuse `ps_baseline_decide(parent_baseline, parent_denials, parent_comm)` — `ps_blset_covered` is exact for comms.
- **Finding:** `signal:"spawn"`, field `parent` = the parent comm.
- **Verb:** `baseline <exe> approve-parent <comm>`, `deny-parent <comm>`; `list` shows parents; `approve-all` also approves parent candidates (exact, no rollup).

---

## Task 1: `baseline_store` parent ops

**Files:** Modify `src/agent/src/baseline_store.h`, `src/agent/src/baseline_store.c`; Test `src/agent/tests/test_baseline_store.c`

> Parallel parent files, key `"parents"`, reusing the existing `load_one_key` + `atomic_write` helpers (added for dests in Phase B).

- [ ] **Step 1: Add a failing assertion to `test_baseline_store.c`** (before the success print)

```c
    /* parent store: load empty, append two (dedup), read back under "parents" key */
    struct ps_baseline_set pbl, pden;
    assert(ps_baseline_load_parents(dir, exe, &pbl, &pden) == 0);
    assert(pbl.n == 0 && pden.n == 0);
    assert(ps_baseline_append_parent_candidate(dir, exe, "bash") == 0);
    assert(ps_baseline_append_parent_candidate(dir, exe, "bash") == 0);
    assert(ps_baseline_append_parent_candidate(dir, exe, "sshd") == 0);
    char ppath[600]; snprintf(ppath, sizeof ppath, "%s/%s/parent-candidates.json", dir, slug);
    FILE *pf = fopen(ppath, "r"); assert(pf);
    static char pj[8192]; size_t pn2 = fread(pj,1,sizeof pj-1,pf); fclose(pf); pj[pn2]=0;
    struct ps_baseline_set pc; assert(ps_blset_from_json_key(pj, "parents", &pc) == 0);
    assert(pc.n == 2);
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && make test_baseline_store 2>&1 | tail -4`
Expected: FAIL — `ps_baseline_load_parents` undefined.

- [ ] **Step 3: Declare in `baseline_store.h`** (after the dest decls)

```c
int ps_baseline_load_parents(const char *state_dir, const char *exe,
                             struct ps_baseline_set *baseline, struct ps_baseline_set *denials);
int ps_baseline_append_parent_candidate(const char *state_dir, const char *exe, const char *parent_comm);
```

- [ ] **Step 4: Implement in `baseline_store.c`** (append; reuses `load_one_key`/`atomic_write` from the dest section)

```c
int ps_baseline_load_parents(const char *state_dir, const char *exe,
                             struct ps_baseline_set *baseline, struct ps_baseline_set *denials) {
    char slug[256];
    if (ps_exe_slug(exe, slug, sizeof slug) != 0) {
        ps_blset_init(baseline, exe); ps_blset_init(denials, exe); return 0;
    }
    load_one_key(state_dir, slug, "parents.json", "parents", exe, baseline);
    load_one_key(state_dir, slug, "parent-denials.json", "parents", exe, denials);
    return 0;
}

int ps_baseline_append_parent_candidate(const char *state_dir, const char *exe, const char *parent_comm) {
    char slug[256];
    if (ps_exe_slug(exe, slug, sizeof slug) != 0) return -1;
    char dir[512]; snprintf(dir, sizeof dir, "%s/%s", state_dir, slug);
    mkdir(state_dir, 0700); mkdir(dir, 0700);
    char cpath[600]; snprintf(cpath, sizeof cpath, "%s/parent-candidates.json", dir);
    struct ps_baseline_set c; ps_blset_init(&c, exe);
    FILE *f = fopen(cpath, "r");
    if (f) { static char j[1<<16]; size_t n = fread(j,1,sizeof j-1,f); fclose(f); j[n]=0; ps_blset_from_json_key(j, "parents", &c); }
    if (ps_blset_add(&c, parent_comm) != 1) return 0;
    static char out[1 << 16];
    int len = ps_blset_to_json_key(&c, "parents", out, sizeof out);
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
git commit -m "agent: baseline_store parent ops (load parents + atomic parent-candidate append)"
```

---

## Task 2: `baseline_monitor` — process-spawn checks

**Files:** Modify `src/agent/src/modules/baseline_monitor.c`; Test `src/agent/tests/test_baseline_monitor.c`

> After the dest pass, extract the immediate-parent comm (first `"comm"` after `"ancestry":[`) and run a verdict against the exe's parent baseline; emit candidate/anomaly with `signal:"spawn"` and field `parent`; append novel parents.

- [ ] **Step 1: Add a failing test block to `test_baseline_monitor.c`** (before `ps_baseline_seen_free(seen);`)

```c
    /* --- spawn signal: seed a parent baseline ({bash}) + denial ({evilparent}) --- */
    {
        struct ps_baseline_set pbl; ps_blset_init(&pbl, exe); ps_blset_add(&pbl, "bash");
        struct ps_baseline_set pden; ps_blset_init(&pden, exe); ps_blset_add(&pden, "evilparent");
        snprintf(p,sizeof p,"%s/parents.json",sub);        f=fopen(p,"w"); ps_blset_to_json_key(&pbl,"parents",j,sizeof j); fputs(j,f); fclose(f);
        snprintf(p,sizeof p,"%s/parent-denials.json",sub); f=fopen(p,"w"); ps_blset_to_json_key(&pden,"parents",j,sizeof j); fputs(j,f); fclose(f);
        char b[2048]; int e0 = g_emits;
        const char *FMT = "{\"event\":\"open\",\"path\":\"/var/www/x\",\"process\":{\"comm\":\"sh\",\"exe\":\"%s\"},\"ancestry\":[{\"pid\":1,\"comm\":\"%s\",\"depth\":1}]}";
        /* covered path + covered parent -> silent */
        snprintf(b,sizeof b,FMT,exe,"bash"); ps_baseline_process_record(b, dir, seen, emit, NULL);
        assert(g_emits == e0);
        /* denied parent -> anomaly */
        snprintf(b,sizeof b,FMT,exe,"evilparent"); ps_baseline_process_record(b, dir, seen, emit, NULL);
        assert(g_emits == e0 + 1 && strstr(g_last, "\"signal\":\"spawn\"") && strstr(g_last, "\"kind\":\"anomaly\"") && strstr(g_last, "evilparent"));
        /* novel parent -> candidate */
        snprintf(b,sizeof b,FMT,exe,"nginx"); ps_baseline_process_record(b, dir, seen, emit, NULL);
        assert(g_emits == e0 + 2 && strstr(g_last, "\"kind\":\"candidate\"") && strstr(g_last, "nginx"));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /data/opt/repo/packetsonde/build && make test_baseline_monitor 2>&1 | tail -4`
Expected: FAIL — spawn findings not emitted.

- [ ] **Step 3: Add a parent-comm extractor + the spawn pass to `baseline_monitor.c`**

Add a helper above `ps_baseline_process_record` (next to `emit_dest_finding`):
```c
/* the immediate parent comm = first "comm":"..." after "ancestry":[  (empty if none) */
static void extract_parent_comm(const char *rec, char *out, size_t cap) {
    out[0] = 0;
    const char *a = strstr(rec, "\"ancestry\":[");
    if (!a) return;
    const char *c = strstr(a, "\"comm\":\"");
    if (!c) return;
    c += 8;
    const char *e = strchr(c, '"');
    if (!e) return;
    size_t n = (size_t)(e - c); if (n >= cap) n = cap - 1;
    memcpy(out, c, n); out[n] = 0;
}

/* emit a finding for a spawn parent of the given kind. */
static void emit_spawn_finding(void (*emit)(void *, const char *, size_t), void *ctx,
                               const char *kind, const char *exe, const char *parent, const char *comm) {
    char buf[2048]; struct ps_json j; ps_json_init(&j, buf, sizeof buf);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "source", "agent.baseline_monitor");
    ps_json_key_string(&j, "severity", !strcmp(kind,"anomaly") ? "high" : "info");
    ps_json_key_string(&j, "confidence", !strcmp(kind,"anomaly") ? "firm" : "tentative");
    ps_json_key_string(&j, "kind", kind);
    ps_json_key_string(&j, "signal", "spawn");
    ps_json_key_string(&j, "exe", exe);
    ps_json_key_string(&j, "parent", parent);
    ps_json_key_string(&j, "comm", comm);
    ps_json_object_end(&j);
    if (ps_json_finish(&j) > 0 && emit) emit(ctx, buf, (size_t)j.len);
}
```

In `ps_baseline_process_record`, after the dest-pass `while` loop and before `return n;`, add:
```c
    /* process-spawn signal: the immediate parent comm */
    char parent[64]; extract_parent_comm(rec, parent, sizeof parent);
    if (parent[0]) {
        struct ps_baseline_set pbl, pden;
        ps_baseline_load_parents(state_dir, exe, &pbl, &pden);
        enum ps_bl_verdict pv = ps_baseline_decide(&pbl, &pden, parent);   /* covered == exact for comms */
        if (pv != PS_BL_COVERED) {
            char pkey[384]; snprintf(pkey, sizeof pkey, "%s|P|%s", exe, parent);
            if (!seen_add(seen, pkey)) {
                if (pv == PS_BL_ANOMALY) { emit_spawn_finding(emit, ectx, "anomaly", exe, parent, comm); n++; }
                else { ps_baseline_append_parent_candidate(state_dir, exe, parent);
                       emit_spawn_finding(emit, ectx, "candidate", exe, parent, comm); n++; }
            }
        }
    }
    return n;
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd /data/opt/repo/packetsonde/build && make test_baseline_monitor packetsonde-agent >/dev/null 2>&1 && ctest -R '^test_baseline_monitor$' --output-on-failure`
Expected: PASS (file + dest + spawn assertions); agent links.

- [ ] **Step 5: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/src/modules/baseline_monitor.c src/agent/tests/test_baseline_monitor.c
git commit -m "agent: baseline_monitor flags novel/denied spawn parents (ancestry comm)"
```

---

## Task 3: `baseline` verb — parent subcommands

**Files:** Modify `src/cli/verbs/baseline.c`

- [ ] **Step 1: Extend `baseline.c`** — load the parent files, add the subcommands, extend list + approve-all.

After the dest-file loads, add the parent loads:
```c
    struct ps_baseline_set pbl, pcand, pden;
    load_key(dir, slug, "parents.json", "parents", exe, &pbl);
    load_key(dir, slug, "parent-candidates.json", "parents", exe, &pcand);
    load_key(dir, slug, "parent-denials.json", "parents", exe, &pden);
```
In the `list` block, after the dest prints, add:
```c
        printf("parents baseline (%d):\n", pbl.n);   for (int i=0;i<pbl.n;i++) printf("  %s\n", pbl.path[i]);
        printf("parent candidates (%d):\n", pcand.n); for (int i=0;i<pcand.n;i++) printf("  %s\n", pcand.path[i]);
        printf("parent denials (%d):\n", pden.n);     for (int i=0;i<pden.n;i++) printf("  %s\n", pden.path[i]);
```
In the `approve-all` block, after the dest approval, add:
```c
        for (int i=0;i<pcand.n;i++) ps_blset_add(&pbl, pcand.path[i]);
        pcand.n = 0;
        save_key(dir, slug, "parents.json", "parents", &pbl); save_key(dir, slug, "parent-candidates.json", "parents", &pcand);
```
Add the new subcommands (before the final "unknown subcommand"):
```c
    if (!strcmp(sub, "approve-parent")) {
        if (!entry) { fprintf(stderr, "approve-parent needs a <comm>\n"); return 2; }
        ps_blset_add(&pbl, entry); remove_entry(&pcand, entry);
        save_key(dir, slug, "parents.json", "parents", &pbl); save_key(dir, slug, "parent-candidates.json", "parents", &pcand);
        printf("approved parent %s\n", entry); return 0;
    }
    if (!strcmp(sub, "deny-parent")) {
        if (!entry) { fprintf(stderr, "deny-parent needs a <comm>\n"); return 2; }
        ps_blset_add(&pden, entry); remove_entry(&pcand, entry);
        save_key(dir, slug, "parent-denials.json", "parents", &pden); save_key(dir, slug, "parent-candidates.json", "parents", &pcand);
        printf("denied parent %s\n", entry); return 0;
    }
```
Update the usage string to mention `approve-parent <comm>` / `deny-parent <comm>`.

- [ ] **Step 2: Build + smoke**

```bash
cd /data/opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make packetsonde 2>&1 | tail -3
D=/tmp/blp-$$; S="$D/usr-bin-dash"; mkdir -p "$S"
printf '{"exe":"/usr/bin/dash","parents":["bash","nginx"]}' > "$S/parent-candidates.json"
./src/cli/packetsonde baseline /usr/bin/dash approve-parent bash --state-dir "$D"
./src/cli/packetsonde baseline /usr/bin/dash deny-parent nginx --state-dir "$D"
echo "--- list ---"; ./src/cli/packetsonde baseline /usr/bin/dash list --state-dir "$D" | grep -A4 'parents baseline'
rm -rf "$D"
```
Expected: `approve-parent bash` stores `bash` in parents baseline; `deny-parent nginx` moves `nginx` to parent denials; list shows both, parent candidates empty.

- [ ] **Step 3: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/cli/verbs/baseline.c
git commit -m "cli: baseline verb gains parent subcommands (approve-parent / deny-parent)"
```

---

## Task 4: Live test note + full regression

**Files:** Modify `scripts/test-baseline.sh`

- [ ] **Step 1: Append a spawn section to `scripts/test-baseline.sh`** (before the final cleanup echo)

```bash
echo
echo "Process spawning (Phase C):"
echo "  - With baseline_mode=on, an exe launched by a NEW parent comm yields a baseline.candidate"
echo "    (signal=spawn). Approve the expected launcher:"
echo "       ./build/src/cli/packetsonde baseline <exe-path> approve-parent <parent-comm>"
echo "  - An exe launched by a denied parent (e.g. a shell spawned by a web server) yields a"
echo "    baseline.anomaly (signal=spawn): ./build/src/cli/packetsonde baseline <exe> deny-parent <comm>"
```

- [ ] **Step 2: Syntax-check + full regression**

Run: `cd /data/opt/repo/packetsonde && bash -n scripts/test-baseline.sh && echo SYNTAX_OK && cd build && cmake .. -DBUILD_TESTING=ON >/dev/null && make packetsonde-agent packetsonde-priv packetsonde >/dev/null 2>&1 && echo LINK_OK && ctest -E 'test_via_e2e' 2>&1 | tail -3`
Expected: `SYNTAX_OK`, `LINK_OK`, suite 100%.

- [ ] **Step 3: Commit**

```bash
cd /data/opt/repo/packetsonde
git add scripts/test-baseline.sh
git commit -m "Add process-spawn steps to the assisted baseline live test"
```

---

## Self-Review

**Spec coverage (Phase C, spec §11):**
- Process-spawn signal (expected child/parent from `ancestry[]`) → Task 2 (extract immediate parent comm + verdict) ✓
- per-exe keying, exact comm match → reuses `ps_blset_covered` (exact for comms) via `ps_baseline_decide` (Task 2) ✓
- hybrid candidate→approve/deny, parallel state files → Tasks 1 (store), 3 (verb) ✓

**Known limitations (accepted):** only the **immediate** parent (`ancestry[0].comm`, depth 1) is checked, not the whole ancestry chain (the most direct spawner is the strongest signal; deeper-chain matching is a follow-up). `comm` is the kernel's 15-char name (truncation/collision possible — inherent to the signal). Per-record parent load shares Phase A's reserved reload-cache follow-up.

**Placeholder scan:** no TBD/"add error handling"; every code step complete; the monitor insertion point (after the dest loop, before `return n`) and the parent-comm extraction are concrete.

**Type/name consistency:** `ps_baseline_load_parents`/`ps_baseline_append_parent_candidate` (1,2); reuse of `ps_baseline_decide` for the comm verdict (2); `extract_parent_comm`/`emit_spawn_finding` (2); verb `approve-parent`/`deny-parent` + parent files `parents.json`/`parent-candidates.json`/`parent-denials.json` + key `"parents"` + finding `signal:"spawn"` consistent across 1,2,3.

**Completes the §4 triad:** file paths (A) + network destinations (B) + process spawning (C). After this, SP3 is feature-complete for v1; the fleet deploy ([[fleet-deploy-plan]]) is the next step.
```
