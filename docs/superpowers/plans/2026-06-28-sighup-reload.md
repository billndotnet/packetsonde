# SIGHUP Reload Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `packetsonded` honor SIGHUP as a live reload — re-scan authorized client keys and re-apply log level + max_clients without restarting or dropping live state.

**Architecture:** A SIGHUP handler sets a `g_reload` flag; the event loop calls `do_reload()`, which re-parses the config (re-applying log level) and invokes an optional new `reload(ctx)` module hook. `network_listener` implements the hook to re-scan its authorized-key dir (thread-safe via a new mutex) and re-read `max_clients`. The priv worker ignores SIGHUP; the systemd unit maps `systemctl reload` to it.

**Tech Stack:** C11, POSIX signals/pthreads, CMake/ctest, systemd.

## Global Constraints

- Scope is **`packetsonded` only**. `kernelsonded` is a separate follow-up (not this plan).
- This branch (`feat/sighup-reload`) is **stacked on `fix/network-listener-shutdown-hang`** (`c68ac8c`); `network_listener.c` already has the `shutdown()` fix — do not revert it.
- **Reloaded live:** authorized client keys (re-scan `PS_AGENT_AUTHORIZED_DIR`), log level (`[agent] log_level`), `max_clients` (`PS_AGENT_MAX_CLIENTS`, default 64).
- **Restart-required (logged, unchanged):** capture iface/exclude, listen addr/port/TLS, central URL/interval, all detect/priv settings. Never half-apply.
- **SIGHUP must NEVER set `g_running = 0`** — it cannot terminate the agent.
- Reload runs **synchronously on the main thread** between event-loop polls (no reentrancy).
- Authorized-key constant `MAX_AUTHORIZED` = 64; pubkey size `PS_KEYSTORE_PUBKEY_SIZE` = 32.
- Build with `-DCMAKE_BUILD_TYPE=Debug` for ctest (Release/NDEBUG segfaults 5 tests). Run on `ca1`. The shell aliases `grep` to `ugrep` — use `/bin/grep` in verification commands.
- No Claude/Co-Authored-By footers in commits; SSH git, never `gh`.

---

### Task 1: `network_listener` live authorized-key reload (+ driver wiring + e2e test)

**Files:**
- Modify: `src/agent/include/packetsonde/module_api.h` (add `reload` to the vtable)
- Modify: `src/agent/src/modules/network_listener.c` (mutex, scan refactor, `nl_reload`, vtable entry)
- Modify: `src/agent/tests/test_network_listener_driver.c` (SIGHUP → reload)
- Create: `src/cli/tests/test_via_reload.sh`
- Modify: `src/cli/CMakeLists.txt` (register the new test)

**Interfaces:**
- Produces: `void (*reload)(ps_module_ctx_t *ctx)` field on `struct ps_module` (after `tick`); `network_listener_module.reload = nl_reload`. `nl_reload` re-scans the authorized dir and re-reads `PS_AGENT_MAX_CLIENTS`, swapping into `nl_state` under `auth_lock`.

- [ ] **Step 1: Add the `reload` hook to the module vtable.** In `src/agent/include/packetsonde/module_api.h`, in `struct ps_module`, add after the `tick` member:

```c
    void (*tick)(ps_module_ctx_t *ctx, uint64_t now_usec);

    /* Optional: re-read hot config (e.g. authorized keys) on SIGHUP.
     * Called on the main thread between event-loop polls. NULL = no reload
     * support. Must be safe against the module's own worker threads. */
    void (*reload)(ps_module_ctx_t *ctx);
```
(Other modules use designated initializers, so the new field defaults to NULL for them — no other module file needs editing.)

- [ ] **Step 2: Add `auth_lock` to `nl_state`.** In `src/agent/src/modules/network_listener.c`, add to `struct nl_state` (after `char packetsonde_bin[256];`):

```c
    pthread_mutex_t    auth_lock;   /* guards authorized[]/authorized_n vs reload */
```

- [ ] **Step 3: Refactor key scanning into a reusable helper.** Replace `load_authorized(struct nl_state *st, const char *dir)` with a pure scanner that fills a caller array:

```c
/* Scan `dir` for *.pub files, writing up to `max` 32-byte pubkeys into
 * out[]. Returns the count. No shared state -- safe to call into a temp. */
static size_t scan_authorized(const char *dir,
                              uint8_t out[][PS_KEYSTORE_PUBKEY_SIZE], size_t max) {
    DIR *d = opendir(dir);
    if (!d) {
        ps_info("network_listener: authorized dir '%s' missing -- no clients can connect", dir);
        return 0;
    }
    size_t n = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && n < max) {
        size_t len = strlen(de->d_name);
        if (len < 5 || strcmp(de->d_name + len - 4, ".pub") != 0) continue;
        char p[1100]; snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        FILE *f = fopen(p, "rb");
        if (!f) continue;
        if (fread(out[n], 1, PS_KEYSTORE_PUBKEY_SIZE, f) == PS_KEYSTORE_PUBKEY_SIZE) n++;
        fclose(f);
    }
    closedir(d);
    return n;
}
```

- [ ] **Step 4: Update `nl_init` to use the helper + init the mutex.** Where `nl_init` currently calls `load_authorized(st, auth_dir);`, replace with:

```c
    pthread_mutex_init(&st->auth_lock, NULL);
    st->authorized_n = scan_authorized(auth_dir, st->authorized, MAX_AUTHORIZED);
    ps_info("network_listener: %zu authorized client pubkey(s) loaded from %s",
            st->authorized_n, auth_dir);
```
(This runs before the accept thread starts, so no lock needed here.)

- [ ] **Step 5: Lock `is_authorized` and destroy the mutex in shutdown.** Wrap the scan loop in `is_authorized()` with the lock:

```c
static int is_authorized(struct nl_state *st, SSL *ssl) {
    char fpr[PS_KEYSTORE_FPR_HEX_SIZE];
    if (ps_at_peer_fingerprint(ssl, fpr, sizeof(fpr)) != 0) return 0;
    int matched = 0;
    pthread_mutex_lock(&st->auth_lock);
    for (size_t i = 0; i < st->authorized_n; i++) {
        char expected[PS_KEYSTORE_FPR_HEX_SIZE];
        ps_keystore_fingerprint(st->authorized[i], expected);
        if (strcmp(fpr, expected) == 0) matched = 1;
    }
    pthread_mutex_unlock(&st->auth_lock);
    return matched;
}
```
In `nl_shutdown`, after `pthread_join(...)` and before `free(st)`, add `pthread_mutex_destroy(&st->auth_lock);`.

- [ ] **Step 6: Implement `nl_reload`.** Add above the `network_listener_module` definition:

```c
static void nl_reload(ps_module_ctx_t *ctx) {
    struct nl_state *st = ctx && ctx->userdata ? ctx->userdata : g_state;
    if (!st) return;

    /* Resolve the authorized dir the same way nl_init does. */
    char auth_dir[1100];
    const char *ad = getenv("PS_AGENT_AUTHORIZED_DIR");
    if (ad && *ad) {
        snprintf(auth_dir, sizeof(auth_dir), "%s", ad);
    } else {
        char kdir[1024]; kdir[0] = '\0';
        const char *kd = getenv("PS_KEY_DIR");
        if (kd && *kd) snprintf(kdir, sizeof(kdir), "%s", kd);
        else ps_keystore_default_dir(kdir, sizeof(kdir));
        snprintf(auth_dir, sizeof(auth_dir), "%s/authorized", kdir);
    }

    uint8_t tmp[MAX_AUTHORIZED][PS_KEYSTORE_PUBKEY_SIZE];
    size_t tmp_n = scan_authorized(auth_dir, tmp, MAX_AUTHORIZED);

    int new_max = st->max_clients;
    const char *mc = getenv("PS_AGENT_MAX_CLIENTS");
    if (mc && *mc) new_max = atoi(mc);

    pthread_mutex_lock(&st->auth_lock);
    memcpy(st->authorized, tmp, sizeof(tmp));
    st->authorized_n = tmp_n;
    st->max_clients  = new_max;
    pthread_mutex_unlock(&st->auth_lock);

    ps_info("network_listener: reloaded %zu authorized key(s) from %s, max_clients=%d",
            tmp_n, auth_dir, new_max);
}
```
Then add `.reload = nl_reload,` to the `network_listener_module` initializer (after `.tick = NULL,`).

- [ ] **Step 7: Wire SIGHUP → reload in the test driver.** In `src/agent/tests/test_network_listener_driver.c`, add a reload flag + handler and call `nl_reload` from the loop:

```c
static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_reload = 0;
static void on_term(int sig) { (void)sig; g_stop = 1; }
static void on_hup(int sig)  { (void)sig; g_reload = 1; }

int main(void) {
    signal(SIGTERM, on_term);
    signal(SIGINT,  on_term);
    signal(SIGHUP,  on_hup);
    ps_module_ctx_t ctx; memset(&ctx, 0, sizeof(ctx));
    if (nl_init(&ctx) != 0) {
        fprintf(stderr, "test_network_listener_driver: init failed\n");
        return 1;
    }
    while (!g_stop) {
        if (g_reload) { g_reload = 0; nl_reload(&ctx); }
        sleep(1);
    }
    nl_shutdown(&ctx);
    return 0;
}
```

- [ ] **Step 8: Write the e2e reload test.** Create `src/cli/tests/test_via_reload.sh` by copying `src/cli/tests/test_via_e2e.sh` and changing the flow to: (a) start the driver with an **empty** authorized dir, (b) run the `--via` ssh audit and assert it does NOT succeed (no `ssh.` finding — the client is unauthorized), (c) `cp "$KDIR/default.pub" "$ADIR/cli.pub"`, (d) `kill -HUP "$DRIVER_PID"`, (e) `sleep 1`, (f) re-run the same audit and assert it now succeeds (`ssh.` finding present). Keep e2e's `reap` cleanup (kill + escalate to `-9`). Concretely, the assertion pair:

```bash
# before authorizing: expect rejection (no findings)
OUT1=$(PS_AGENTS_TOML="$AGENTS_CFG" PS_KEY_DIR="$KDIR" \
    "$CLI" --jsonl --via testagent audit ssh "127.0.0.1:$SSH_PORT" 2>/dev/null || true)
echo "$OUT1" | grep -q '"kind":"ssh.' && { echo "FAIL: connected while unauthorized"; exit 1; }

cp "$KDIR/default.pub" "$ADIR/cli.pub"
kill -HUP "$DRIVER_PID"
sleep 1

# after SIGHUP: same client now authorized -> findings present
OUT2=$(PS_AGENTS_TOML="$AGENTS_CFG" PS_KEY_DIR="$KDIR" \
    "$CLI" --jsonl --via testagent audit ssh "127.0.0.1:$SSH_PORT" 2>/dev/null || true)
echo "$OUT2" | grep -q '"kind":"ssh.' || { echo "FAIL: still rejected after SIGHUP reload"; echo "$OUT2"; exit 1; }
echo "test_via_reload: OK"
```
Note: keep e2e's **single-accept** mock SSH helper unchanged. The first (unauthorized) attempt is rejected at the agent's mTLS peer check and never runs the audit subprocess, so it never connects to the mock — only the second (authorized) run reaches it, needing exactly one accept. Just make the driver's authorized dir start **empty** (don't pre-copy `cli.pub` the way e2e does).

- [ ] **Step 9: Register the test in CMake.** In `src/cli/CMakeLists.txt`, mirror the existing `test_via_e2e` block:

```cmake
    add_test(NAME test_via_reload
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_via_reload.sh)
    set_tests_properties(test_via_reload PROPERTIES TIMEOUT 60)
```
(Match the surrounding block's exact `set_tests_properties` form, e.g. any `ENVIRONMENT PS_BUILD_DIR=...` the neighbors use.)

- [ ] **Step 10: Build + run the new test + confirm no leak.**

```bash
cd /data/opt/repo/packetsonde
rm -rf build && cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug >/dev/null && cmake --build build -j"$(nproc)" 2>&1 | tail -5
b=$(pgrep -xc test_network_li)
ctest --test-dir build -R '^test_via_reload$' --output-on-failure 2>&1 | tail -15
sleep 1; echo "leaked drivers: $(( $(pgrep -xc test_network_li) - b ))"
```
Expected: `test_via_reload` Passed; leaked = 0.

- [ ] **Step 11: Commit.**

```bash
git add src/agent/include/packetsonde/module_api.h src/agent/src/modules/network_listener.c src/agent/tests/test_network_listener_driver.c src/cli/tests/test_via_reload.sh src/cli/CMakeLists.txt
git commit -m "feat(agent): network_listener live authorized-key reload (module reload hook)"
```

---

### Task 2: agent SIGHUP plumbing + `do_reload`

**Files:**
- Modify: `src/agent/src/module.h` + `src/agent/src/module.c` (add `ps_module_registry_reload_all`)
- Modify: `src/agent/src/main.c` (g_reload, on_sighup, config-path stash, `do_reload`, loop hook)

**Interfaces:**
- Consumes: the `reload` vtable hook from Task 1.
- Produces: `void ps_module_registry_reload_all(struct ps_module_registry *reg)`; SIGHUP-driven `do_reload()` in the agent.

- [ ] **Step 1: Add `ps_module_registry_reload_all`.** In `src/agent/src/module.h`, declare it next to `ps_module_registry_tick_all`:

```c
void ps_module_registry_reload_all(struct ps_module_registry *reg);
```
In `src/agent/src/module.c`, mirror `ps_module_registry_init_all`:

```c
void ps_module_registry_reload_all(struct ps_module_registry *reg)
{
    for (int i = 0; i < reg->count; i++) {
        struct ps_module_instance *inst = &reg->instances[i];
        if (!inst->enabled || !inst->module->reload) continue;
        inst->module->reload(&inst->ctx);
    }
}
```

- [ ] **Step 2: Stash the config path.** Near the top of `src/agent/src/main.c` (with the other file-scope statics, e.g. by `g_running`), add:

```c
static char g_config_path[4096];
static volatile sig_atomic_t g_reload = 0;
```
Where the config is loaded (`if (config_path) { ps_config_parse_file(...) ... }`, ~main.c:1110), record it: right after a successful parse add
`snprintf(g_config_path, sizeof(g_config_path), "%s", config_path);`
(Leave `g_config_path` empty when no `-c` was given; `do_reload` no-ops the config-reparse in that case but still reloads keys.)

- [ ] **Step 3: Add the SIGHUP handler + `do_reload`.** Add the handler next to `on_signal`:

```c
static void on_sighup(int sig) { (void)sig; g_reload = 1; }
```
Add `do_reload` (place it after `on_signal`, before `main`; it needs `g_registry` which is file-scope):

```c
static void do_reload(void)
{
    ps_info("reload: SIGHUP received");

    /* Re-parse config (if we have a path) and re-apply the hot settings. */
    if (g_config_path[0]) {
        struct ps_config cfg;
        memset(&cfg, 0, sizeof(cfg));
        if (ps_config_parse_file(&cfg, g_config_path) < 0) {
            ps_warn("reload: config '%s' unreadable -- keeping running config", g_config_path);
        } else {
            const char *lvl = ps_config_get(&cfg, "agent", "log_level");
            if (lvl) {
                if      (strcmp(lvl, "debug") == 0) ps_log_set_level(PS_LOG_DEBUG);
                else if (strcmp(lvl, "warn")  == 0) ps_log_set_level(PS_LOG_WARN);
                else if (strcmp(lvl, "error") == 0) ps_log_set_level(PS_LOG_ERROR);
                else                                ps_log_set_level(PS_LOG_INFO);
            }
            ps_config_free(&cfg);
        }
    }

    /* Module reload hooks (network_listener re-scans authorized keys). */
    ps_module_registry_reload_all(&g_registry);

    ps_info("reload: done (capture/listen/central/detect settings require a restart)");
}
```
(Use the project's real config free function — confirm it is `ps_config_free`; if the struct is freed differently, match that.)

- [ ] **Step 4: Install the handler + hook the loop.** Where SIGINT/SIGTERM are installed (~main.c:1406), add:

```c
    signal(SIGHUP, on_sighup);
```
At the very top of the `while (g_running) {` body, before `ps_ipc_server_poll`:

```c
        if (g_reload) { g_reload = 0; do_reload(); }
```

- [ ] **Step 5: Build, then verify a live SIGHUP doesn't kill the agent and logs the reload.**

```bash
cd /data/opt/repo/packetsonde
cmake --build build -j"$(nproc)" --target packetsonde-agent 2>&1 | tail -5
WORK=$(mktemp -d); printf '[agent]\nlog_level = "info"\n' > "$WORK/cfg.toml"
PS_AGENT_NO_UNIX=1 PS_KEY_DIR="$WORK" build/src/agent/packetsonded -c "$WORK/cfg.toml" >"$WORK/agent.log" 2>&1 &
A=$!; sleep 2
kill -HUP $A; sleep 1
kill -0 $A 2>/dev/null && echo "agent ALIVE after SIGHUP (correct)" || echo "agent DIED on SIGHUP (BUG)"
/bin/grep -q 'reload: done' "$WORK/agent.log" && echo "reload logged (correct)"
kill -TERM $A 2>/dev/null; sleep 1; kill -9 $A 2>/dev/null; rm -rf "$WORK"
```
Expected: `agent ALIVE after SIGHUP (correct)` and `reload logged (correct)`. (The agent forks the priv worker; `PS_AGENT_NO_UNIX=1` skips the IPC socket so no `/run` perms needed.)

- [ ] **Step 6: Full ctest (no regression).**

```bash
ctest --test-dir build 2>&1 | /bin/grep -E 'tests passed|failed out of'
```
Expected: 100% passed (count unchanged + the new `test_via_reload`).

- [ ] **Step 7: Commit.**

```bash
git add src/agent/src/module.h src/agent/src/module.c src/agent/src/main.c
git commit -m "feat(agent): SIGHUP triggers live config + key reload (do_reload)"
```

---

### Task 3: priv worker SIGHUP-ignore + systemd ExecReload

**Files:**
- Modify: `src/agent/src/priv_worker.c` (ignore SIGHUP)
- Modify: `packaging/packetsonded.service` (`ExecReload`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: a priv worker that survives a stray SIGHUP; a unit where `systemctl reload` triggers the agent reload.

- [ ] **Step 1: Ignore SIGHUP in the priv worker.** In `src/agent/src/priv_worker.c`, near the start of `main()` (the worker currently installs no handlers), add — after confirming `#include <signal.h>` is present (add it if not):

```c
    /* The agent never forwards SIGHUP to the worker, but ignore it so a
     * stray process-group HUP can't kill the worker out from under the
     * agent. The worker holds no reloadable state. */
    signal(SIGHUP, SIG_IGN);
```

- [ ] **Step 2: Add `ExecReload` to the unit.** In `packaging/packetsonded.service`, under `[Service]` after the `ExecStart=` line, add:

```ini
ExecReload=/bin/kill -HUP $MAINPID
```

- [ ] **Step 3: Verify.**

```bash
cd /data/opt/repo/packetsonde
cmake --build build -j"$(nproc)" --target packetsonde-priv 2>&1 | tail -3
/bin/grep -q 'SIGHUP, SIG_IGN' src/agent/src/priv_worker.c && echo "priv ignores SIGHUP"
/bin/grep -q 'ExecReload=/bin/kill -HUP' packaging/packetsonded.service && echo "ExecReload present"
```
Expected: builds; both echoes print.

- [ ] **Step 4: Commit.**

```bash
git add src/agent/src/priv_worker.c packaging/packetsonded.service
git commit -m "feat: priv worker ignores SIGHUP; packetsonded.service ExecReload maps to reload"
```

---

## Notes for the implementer

- Branch `feat/sighup-reload` (stacked on the shutdown-hang fix). All tasks build + ctest on `ca1`, Debug only.
- The exact `ps_config` free / `ps_config_get` symbol names are in `src/lib`/`src/agent` config code — confirm against the headers before using (the plan uses `ps_config_parse_file`, `ps_config_get`, `ps_config_free`, matching main.c's existing usage).
- Don't touch `nl_shutdown`'s `shutdown()`+`close()` (the stacked fix).
- No Claude/Co-Authored-By footers; SSH git, never `gh`.
