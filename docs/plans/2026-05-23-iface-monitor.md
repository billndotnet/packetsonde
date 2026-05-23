# Interface Monitor (state + enumeration changes) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a poll-on-tick `iface_monitor` module to the packetsonde C agent that detects and reports interface state/enumeration changes and dynamically adjusts passive capture (add a recovered/added iface, drop a removed/down one) without a restart.

**Architecture:** Two layers landed in order. **Layer 1 (detect + report):** a pure, testable `ps_iface_diff` over `getifaddrs` snapshots, driven by a new tick-only module that publishes `net.iface.*` findings via `ctx->publish`. **Layer 2 (re-capture):** a `ps_capture_close_iface` teardown on the shared capture handle, three new module-ctx hooks (`close_pcap`/`capture_add`/`capture_remove`) that `main` wires to operate on `g_capture`, and the monitor calling them on each detected transition. No interface names are ever hardcoded.

**Tech Stack:** C (C11), CMake + CTest, `getifaddrs(3)`, the existing `ps_json` builder (`src/lib/json.h`), the shared `ps_capture_handle`, and the privileged pcap worker via `ps_priv_client_*`.

**Reference spec:** `docs/specs/2026-05-23-iface-monitor-design.md`

---

## File Structure

**New files:**
- `src/agent/src/iface_snapshot.h` — snapshot/change types + `ps_iface_snapshot` + pure `ps_iface_diff`.
- `src/agent/src/iface_snapshot.c` — `getifaddrs` snapshot (no logging — keeps the unit test link-free) + the pure diff.
- `src/agent/src/modules/iface_monitor.c` — the tick-only module: baseline snapshot, throttled re-snapshot+diff, publish findings, (Layer 2) re-capture calls.
- `src/agent/tests/test_iface_snapshot.c` — unit test for `ps_iface_diff`.
- `src/agent/tests/test_capture_close.c` — unit test for `ps_capture_close_iface`.

**Modified files:**
- `src/agent/CMakeLists.txt` — add the two new `.c` sources to `AGENT_CORE_SOURCES`; add the two test targets.
- `src/agent/src/main.c` — extern + register the module; (Layer 2) `ctx_close_pcap`/`ctx_capture_add`/`ctx_capture_remove` impls + wire them into every module ctx.
- `src/agent/src/config_to_env.c` — map `[iface_monitor] interval` → `PS_IFACE_MONITOR_INTERVAL`.
- `src/agent/tests/test_config_to_env.c` — assert the new mapping.
- `src/agent/src/capture/capture_handle.h` — `ps_close_pcap_fn` typedef + `ps_capture_close_iface` decl.
- `src/agent/src/capture/capture_handle.c` — `ps_capture_close_iface` impl.
- `src/agent/include/packetsonde/module_api.h` — three new ctx hook members.

---

## Build & test commands (used throughout)

Configure once, then rebuild incrementally:

```bash
cd /data/opt/repo/packetsonde
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Run a single test target after building it:

```bash
ctest --test-dir build --output-on-failure -R test_iface_snapshot
```

---

## Task 1: `iface_snapshot` — snapshot types + pure `ps_iface_diff`

**Files:**
- Create: `src/agent/src/iface_snapshot.h`
- Create: `src/agent/src/iface_snapshot.c`
- Test: `src/agent/tests/test_iface_snapshot.c`
- Modify: `src/agent/CMakeLists.txt`

- [ ] **Step 1: Create the header**

Create `src/agent/src/iface_snapshot.h`:

```c
#ifndef PS_IFACE_SNAPSHOT_H
#define PS_IFACE_SNAPSHOT_H

#include <stdint.h>

/* Upper bound on interfaces tracked per snapshot. Larger than the 8-iface
 * capture cap because the monitor observes ALL interfaces (incl. down/virtual),
 * not just the ones being captured. */
#define PS_IFACE_SNAP_MAX 32

struct ps_iface_snap {
    char     name[64];
    int      up;        /* IFF_UP   */
    int      running;   /* IFF_RUNNING (carrier) */
    uint32_t addr_hash; /* order-independent hash of the iface's addresses */
};

enum ps_iface_change_kind {
    PS_IFC_ADDED,   /* in cur, not in prev */
    PS_IFC_REMOVED, /* in prev, not in cur */
    PS_IFC_STATE,   /* up/running differ */
    PS_IFC_ADDR     /* addr_hash differs (up/running unchanged) */
};

struct ps_iface_change {
    enum ps_iface_change_kind kind;
    char name[64];
    int  old_up, old_running, new_up, new_running; /* meaningful for STATE/ADDED */
};

/* Snapshot the host's interfaces via getifaddrs into out[], one entry per unique
 * name, up to `max`. Returns the count, or -1 on getifaddrs failure. */
int ps_iface_snapshot(struct ps_iface_snap out[], int max);

/* Pure: diff prev vs cur (matched by name). Fills changes[] up to `max`,
 * returns the number of changes written. */
int ps_iface_diff(const struct ps_iface_snap *prev, int nprev,
                  const struct ps_iface_snap *cur, int ncur,
                  struct ps_iface_change *changes, int max);

#endif /* PS_IFACE_SNAPSHOT_H */
```

- [ ] **Step 2: Write the failing unit test**

Create `src/agent/tests/test_iface_snapshot.c`:

```c
#include "iface_snapshot.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static struct ps_iface_snap mk(const char *name, int up, int running, uint32_t h) {
    struct ps_iface_snap s;
    memset(&s, 0, sizeof(s));
    strncpy(s.name, name, sizeof(s.name) - 1);
    s.up = up; s.running = running; s.addr_hash = h;
    return s;
}

static const struct ps_iface_change *find(const struct ps_iface_change *c, int n,
                                          const char *name,
                                          enum ps_iface_change_kind kind) {
    for (int i = 0; i < n; i++)
        if (c[i].kind == kind && strcmp(c[i].name, name) == 0) return &c[i];
    return NULL;
}

int main(void) {
    struct ps_iface_change ch[16];

    /* No change: identical sets -> 0 */
    {
        struct ps_iface_snap a[] = { mk("eth0",1,1,111), mk("eth1",1,1,222) };
        struct ps_iface_snap b[] = { mk("eth0",1,1,111), mk("eth1",1,1,222) };
        assert(ps_iface_diff(a,2,b,2,ch,16) == 0);
    }

    /* Ordering of inputs must not matter */
    {
        struct ps_iface_snap a[] = { mk("eth0",1,1,111), mk("eth1",1,1,222) };
        struct ps_iface_snap b[] = { mk("eth1",1,1,222), mk("eth0",1,1,111) };
        assert(ps_iface_diff(a,2,b,2,ch,16) == 0);
    }

    /* ADDED */
    {
        struct ps_iface_snap a[] = { mk("eth0",1,1,111) };
        struct ps_iface_snap b[] = { mk("eth0",1,1,111), mk("eth1",1,0,222) };
        int n = ps_iface_diff(a,1,b,2,ch,16);
        assert(n == 1);
        const struct ps_iface_change *c = find(ch,n,"eth1",PS_IFC_ADDED);
        assert(c && c->new_up == 1 && c->new_running == 0);
    }

    /* REMOVED */
    {
        struct ps_iface_snap a[] = { mk("eth0",1,1,111), mk("eth1",1,1,222) };
        struct ps_iface_snap b[] = { mk("eth0",1,1,111) };
        int n = ps_iface_diff(a,2,b,1,ch,16);
        assert(n == 1);
        assert(find(ch,n,"eth1",PS_IFC_REMOVED) != NULL);
    }

    /* STATE up->down */
    {
        struct ps_iface_snap a[] = { mk("eth1",1,1,222) };
        struct ps_iface_snap b[] = { mk("eth1",0,0,222) };
        int n = ps_iface_diff(a,1,b,1,ch,16);
        assert(n == 1);
        const struct ps_iface_change *c = find(ch,n,"eth1",PS_IFC_STATE);
        assert(c && c->old_up == 1 && c->new_up == 0);
    }

    /* STATE down->up */
    {
        struct ps_iface_snap a[] = { mk("eth1",0,0,222) };
        struct ps_iface_snap b[] = { mk("eth1",1,1,222) };
        int n = ps_iface_diff(a,1,b,1,ch,16);
        assert(n == 1);
        const struct ps_iface_change *c = find(ch,n,"eth1",PS_IFC_STATE);
        assert(c && c->old_up == 0 && c->new_up == 1);
    }

    /* ADDR change only (up/running same) */
    {
        struct ps_iface_snap a[] = { mk("eth0",1,1,111) };
        struct ps_iface_snap b[] = { mk("eth0",1,1,999) };
        int n = ps_iface_diff(a,1,b,1,ch,16);
        assert(n == 1);
        assert(find(ch,n,"eth0",PS_IFC_ADDR) != NULL);
    }

    /* STATE takes priority over ADDR when both differ (one change per iface) */
    {
        struct ps_iface_snap a[] = { mk("eth0",1,1,111) };
        struct ps_iface_snap b[] = { mk("eth0",0,0,999) };
        int n = ps_iface_diff(a,1,b,1,ch,16);
        assert(n == 1);
        assert(find(ch,n,"eth0",PS_IFC_STATE) != NULL);
    }

    printf("test_iface_snapshot: OK\n");
    return 0;
}
```

- [ ] **Step 3: Register the source + test in CMake**

In `src/agent/CMakeLists.txt`, add `src/iface_snapshot.c` to the `AGENT_CORE_SOURCES` list — put it right after the existing `src/iface_enum.c` line:

```cmake
    src/iface_enum.c
    src/iface_snapshot.c
```

Then add a test target next to the existing `test_iface_enum` block (the block at `add_executable(test_iface_enum ...)`):

```cmake
add_executable(test_iface_snapshot tests/test_iface_snapshot.c src/iface_snapshot.c)
target_include_directories(test_iface_snapshot PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
add_test(NAME test_iface_snapshot COMMAND test_iface_snapshot)
```

- [ ] **Step 4: Run the test to verify it fails (no implementation yet)**

```bash
cd /data/opt/repo/packetsonde
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --target test_iface_snapshot -j
```

Expected: **build/link failure** — `undefined reference to 'ps_iface_diff'` (and `ps_iface_snapshot`).

- [ ] **Step 5: Implement `iface_snapshot.c`**

Create `src/agent/src/iface_snapshot.c`:

```c
#include "iface_snapshot.h"

#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>

/* FNV-1a over a byte range. */
static uint32_t fnv1a(const unsigned char *p, unsigned long n, uint32_t h) {
    while (n--) { h ^= *p++; h *= 16777619u; }
    return h;
}

/* Find an interface by name in arr[0..n); return index or -1. */
static int find_by_name(const struct ps_iface_snap *arr, int n, const char *name) {
    for (int i = 0; i < n; i++)
        if (strcmp(arr[i].name, name) == 0) return i;
    return -1;
}

int ps_iface_snapshot(struct ps_iface_snap out[], int max) {
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0) return -1;

    int count = 0;
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name) continue;

        int idx = find_by_name(out, count, ifa->ifa_name);
        if (idx < 0) {
            if (count >= max) continue; /* table full; skip extras */
            idx = count++;
            memset(&out[idx], 0, sizeof(out[idx]));
            strncpy(out[idx].name, ifa->ifa_name, sizeof(out[idx].name) - 1);
            out[idx].up      = (ifa->ifa_flags & IFF_UP)      ? 1 : 0;
            out[idx].running = (ifa->ifa_flags & IFF_RUNNING) ? 1 : 0;
        }

        /* Fold each address into an order-independent hash: hash this address
         * on its own, then XOR it in (XOR is commutative so getifaddrs ordering
         * never produces a false ADDR change). */
        if (ifa->ifa_addr) {
            const unsigned char *sa = (const unsigned char *)ifa->ifa_addr;
            /* sa_family is the first field across platforms we target; hash the
             * family plus a fixed window of the sockaddr payload. */
            uint32_t one = fnv1a(sa, sizeof(struct sockaddr), 2166136261u);
            out[idx].addr_hash ^= one;
        }
    }

    freeifaddrs(ifaddr);
    return count;
}

int ps_iface_diff(const struct ps_iface_snap *prev, int nprev,
                  const struct ps_iface_snap *cur, int ncur,
                  struct ps_iface_change *changes, int max) {
    int n = 0;

    /* Walk cur: ADDED / STATE / ADDR. */
    for (int i = 0; i < ncur && n < max; i++) {
        int p = find_by_name(prev, nprev, cur[i].name);
        if (p < 0) {
            struct ps_iface_change *c = &changes[n++];
            memset(c, 0, sizeof(*c));
            c->kind = PS_IFC_ADDED;
            strncpy(c->name, cur[i].name, sizeof(c->name) - 1);
            c->new_up = cur[i].up; c->new_running = cur[i].running;
            continue;
        }
        if (prev[p].up != cur[i].up || prev[p].running != cur[i].running) {
            struct ps_iface_change *c = &changes[n++];
            memset(c, 0, sizeof(*c));
            c->kind = PS_IFC_STATE;
            strncpy(c->name, cur[i].name, sizeof(c->name) - 1);
            c->old_up = prev[p].up; c->old_running = prev[p].running;
            c->new_up = cur[i].up;  c->new_running = cur[i].running;
            continue;
        }
        if (prev[p].addr_hash != cur[i].addr_hash) {
            struct ps_iface_change *c = &changes[n++];
            memset(c, 0, sizeof(*c));
            c->kind = PS_IFC_ADDR;
            strncpy(c->name, cur[i].name, sizeof(c->name) - 1);
        }
    }

    /* Walk prev: REMOVED. */
    for (int i = 0; i < nprev && n < max; i++) {
        if (find_by_name(cur, ncur, prev[i].name) < 0) {
            struct ps_iface_change *c = &changes[n++];
            memset(c, 0, sizeof(*c));
            c->kind = PS_IFC_REMOVED;
            strncpy(c->name, prev[i].name, sizeof(c->name) - 1);
            c->old_up = prev[i].up; c->old_running = prev[i].running;
        }
    }

    return n;
}
```

- [ ] **Step 6: Run the test to verify it passes**

```bash
cd /data/opt/repo/packetsonde
cmake --build build --target test_iface_snapshot -j
ctest --test-dir build --output-on-failure -R test_iface_snapshot
```

Expected: `test_iface_snapshot: OK` and `100% tests passed, 0 tests failed out of 1`.

- [ ] **Step 7: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/src/iface_snapshot.h src/agent/src/iface_snapshot.c \
        src/agent/tests/test_iface_snapshot.c src/agent/CMakeLists.txt
git commit -m "agent: add iface_snapshot (getifaddrs snapshot + pure diff)"
```

---

## Task 2: `iface_monitor` module — report-only (publish findings on tick)

This task lands the detect+report layer fully: the module enumerates on init, re-enumerates on a throttled tick, diffs, and publishes a `net.iface.*` finding per change. No capture manipulation yet (Layer 2).

**Files:**
- Create: `src/agent/src/modules/iface_monitor.c`
- Modify: `src/agent/CMakeLists.txt` (add the module source)
- Modify: `src/agent/src/main.c` (extern + register)

- [ ] **Step 1: Create the module (report-only)**

Create `src/agent/src/modules/iface_monitor.c`:

```c
/*
 * iface_monitor — passive, tick-driven interface change reporter.
 *
 * On each throttled tick it re-snapshots the host's interfaces (getifaddrs) and
 * diffs against the previous snapshot, publishing a finding per change:
 *   net.iface.added | net.iface.removed | net.iface.state_change | net.iface.addr_change
 *
 * Detection is poll-on-tick (no netlink / event loop). Interval is
 * PS_IFACE_MONITOR_INTERVAL seconds (default 5; 0 disables diffing).
 *
 * (Dynamic re-capture is wired in a later task; this revision only reports.)
 */
#include "packetsonde/module_api.h"
#include "iface_snapshot.h"
#include "json.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>

#define PS_IFACE_MONITOR_DEFAULT_INTERVAL_SEC 5

struct iface_monitor_state {
    struct ps_iface_snap prev[PS_IFACE_SNAP_MAX];
    int      nprev;
    uint64_t last_usec;
    uint64_t interval_usec; /* 0 = module inert */
};

/* Build + publish one finding. channel == the kind string. */
static void emit_finding(ps_module_ctx_t *ctx, const struct ps_iface_change *c) {
    char buf[512];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    const char *kind;
    const char *severity = "info";

    ps_json_object_begin(&j);
    switch (c->kind) {
    case PS_IFC_ADDED:
        kind = "net.iface.added";
        ps_json_key_string(&j, "iface", c->name);
        ps_json_key_bool(&j, "up", c->new_up);
        ps_json_key_bool(&j, "running", c->new_running);
        break;
    case PS_IFC_REMOVED:
        kind = "net.iface.removed";
        ps_json_key_string(&j, "iface", c->name);
        break;
    case PS_IFC_STATE:
        kind = "net.iface.state_change";
        if (!c->new_up) severity = "warning";
        ps_json_key_string(&j, "iface", c->name);
        ps_json_key_bool(&j, "old_up", c->old_up);
        ps_json_key_bool(&j, "old_running", c->old_running);
        ps_json_key_bool(&j, "new_up", c->new_up);
        ps_json_key_bool(&j, "new_running", c->new_running);
        break;
    case PS_IFC_ADDR:
    default:
        kind = "net.iface.addr_change";
        ps_json_key_string(&j, "iface", c->name);
        break;
    }
    ps_json_key_string(&j, "source", "agent.iface_monitor");
    ps_json_key_string(&j, "severity", severity);
    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0 && ctx->publish)
        ctx->publish(ctx, kind, buf, (uint32_t)j.len);
}

static int iface_monitor_init(ps_module_ctx_t *ctx) {
    struct iface_monitor_state *st = calloc(1, sizeof(*st));
    if (!st) return -1;

    const char *iv = getenv("PS_IFACE_MONITOR_INTERVAL");
    int sec = iv ? atoi(iv) : PS_IFACE_MONITOR_DEFAULT_INTERVAL_SEC;
    if (!iv) sec = PS_IFACE_MONITOR_DEFAULT_INTERVAL_SEC;
    if (sec < 0) sec = 0;
    st->interval_usec = (uint64_t)sec * 1000000ULL;

    int n = ps_iface_snapshot(st->prev, PS_IFACE_SNAP_MAX);
    st->nprev = (n > 0) ? n : 0;
    st->last_usec = 0;

    ctx->userdata = st;
    ps_info("iface_monitor: initialized — interval=%ds, baseline %d interfaces",
            sec, st->nprev);
    return 0;
}

static void iface_monitor_tick(ps_module_ctx_t *ctx, uint64_t now_usec) {
    struct iface_monitor_state *st = (struct iface_monitor_state *)ctx->userdata;
    if (!st || st->interval_usec == 0) return;
    if (st->last_usec != 0 && (now_usec - st->last_usec) < st->interval_usec) return;

    struct ps_iface_snap cur[PS_IFACE_SNAP_MAX];
    int ncur = ps_iface_snapshot(cur, PS_IFACE_SNAP_MAX);
    if (ncur < 0) {
        /* getifaddrs failed this tick — keep prev, try again next tick. */
        st->last_usec = now_usec;
        return;
    }

    struct ps_iface_change changes[PS_IFACE_SNAP_MAX];
    int nchg = ps_iface_diff(st->prev, st->nprev, cur, ncur,
                             changes, PS_IFACE_SNAP_MAX);

    for (int i = 0; i < nchg; i++)
        emit_finding(ctx, &changes[i]);

    memcpy(st->prev, cur, sizeof(cur[0]) * ncur);
    st->nprev = ncur;
    st->last_usec = now_usec;
}

static void iface_monitor_shutdown(ps_module_ctx_t *ctx) {
    free(ctx->userdata);
    ctx->userdata = NULL;
    ps_info("iface_monitor: shutdown");
}

const ps_module_t ps_iface_monitor_module = {
    .name        = "iface_monitor",
    .description = "Reports interface state/enumeration changes (poll-on-tick)",
    .version     = "1.0",
    .flags       = PS_MOD_PASSIVE,
    .init        = iface_monitor_init,
    .shutdown    = iface_monitor_shutdown,
    .on_packet   = NULL,
    .on_job      = NULL,
    .on_response = NULL,
    .tick        = iface_monitor_tick,
};
```

> Note: `ps_info`, `PS_MOD_PASSIVE`, `ps_json_*`, and `ps_iface_*` are all already available via the includes above (`log.h`, `module_api.h`, `json.h`, `iface_snapshot.h`). Mirror the include style of `src/agent/src/modules/broadcast_listener.c` if the compiler reports a missing symbol for `PS_MOD_PASSIVE`.

- [ ] **Step 2: Add the module to `AGENT_CORE_SOURCES`**

In `src/agent/CMakeLists.txt`, add to the module list in `AGENT_CORE_SOURCES`, right after `src/modules/broadcast_listener.c`:

```cmake
    src/modules/broadcast_listener.c
    src/modules/iface_monitor.c
```

- [ ] **Step 3: Declare + register the module in `main.c`**

In `src/agent/src/main.c`, add the extern declaration alongside the other module externs (near the `extern const ps_module_t broadcast_module;` group, around line 686-690):

```c
extern const ps_module_t ps_iface_monitor_module;
```

Then register it into `g_registry` right after the `broadcast_module` registration (around line 955):

```c
        ps_module_registry_add(&g_registry, &broadcast_module);
        ps_module_registry_add(&g_registry, &ps_iface_monitor_module);
```

- [ ] **Step 4: Build the agent**

```bash
cd /data/opt/repo/packetsonde
cmake --build build --target packetsonde-agent -j
```

Expected: clean build, no warnings about `ps_iface_monitor_module` or unused symbols. The module is now registered and will tick.

- [ ] **Step 5: Run the full test suite (regression check)**

```bash
ctest --test-dir build --output-on-failure
```

Expected: all tests pass (the new module has no unit test of its own — its diff logic is covered by `test_iface_snapshot`; behavior is verified live in Task 7).

- [ ] **Step 6: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/src/modules/iface_monitor.c src/agent/CMakeLists.txt src/agent/src/main.c
git commit -m "agent: add iface_monitor module (reports net.iface.* changes on tick)"
```

---

## Task 3: Config mapping — `[iface_monitor] interval` → `PS_IFACE_MONITOR_INTERVAL`

**Files:**
- Modify: `src/agent/src/config_to_env.c`
- Test: `src/agent/tests/test_config_to_env.c`

- [ ] **Step 1: Add the failing test assertion**

Open `src/agent/tests/test_config_to_env.c` and find where existing mappings are asserted (e.g. the `PS_CAPTURE_EXCLUDE` / `PS_DISCOVERY_*` assertions). Add a config entry for `[iface_monitor] interval` to the test's input config and assert the env var is set. Mirror the existing assertion style in that file; the new assertion is:

```c
    /* iface_monitor interval maps to PS_IFACE_MONITOR_INTERVAL */
    assert(getenv("PS_IFACE_MONITOR_INTERVAL") != NULL);
    assert(strcmp(getenv("PS_IFACE_MONITOR_INTERVAL"), "5") == 0);
```

And add the corresponding entry to the in-test config fixture (mirror however the file adds `capture`/`exclude` — typically a `cfg_add(&cfg, "section", "key", "value")` helper or a literal `ps_config_entry`):

```c
    /* section="iface_monitor", key="interval", value="5" */
```

> Read the top of `test_config_to_env.c` to see the exact fixture-building idiom (it constructs a `struct ps_config` and calls `ps_config_to_env`). Use that same idiom to inject `iface_monitor / interval / 5` before the `ps_config_to_env(&cfg)` call.

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /data/opt/repo/packetsonde
cmake --build build --target test_config_to_env -j
ctest --test-dir build --output-on-failure -R test_config_to_env
```

Expected: FAIL — `PS_IFACE_MONITOR_INTERVAL` is NULL (mapping not yet added).

- [ ] **Step 3: Add the mapping**

In `src/agent/src/config_to_env.c`, add to the `MAPPINGS[]` array. Place it next to the `capture` mapping:

```c
    /* capture -- passive pcap interface selection */
    { "capture", "exclude", "PS_CAPTURE_EXCLUDE" },

    /* iface_monitor -- interface change detection poll interval (seconds) */
    { "iface_monitor", "interval", "PS_IFACE_MONITOR_INTERVAL" },
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /data/opt/repo/packetsonde
cmake --build build --target test_config_to_env -j
ctest --test-dir build --output-on-failure -R test_config_to_env
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/src/config_to_env.c src/agent/tests/test_config_to_env.c
git commit -m "agent: map [iface_monitor] interval to PS_IFACE_MONITOR_INTERVAL"
```

---

## Task 4: `ps_capture_close_iface` — tear down one interface's capture

This begins Layer 2. Add the ability to close a single interface's pcap handle on the shared capture handle and compact the array.

**Files:**
- Modify: `src/agent/src/capture/capture_handle.h`
- Modify: `src/agent/src/capture/capture_handle.c`
- Test: `src/agent/tests/test_capture_close.c`
- Modify: `src/agent/CMakeLists.txt`

- [ ] **Step 1: Add the typedef + declaration to the header**

In `src/agent/src/capture/capture_handle.h`, after the existing `ps_open_pcap_fn` typedef, add:

```c
typedef int (*ps_close_pcap_fn)(void *ctx, int handle_id);
```

And after the `ps_capture_open` declaration, add:

```c
/* Close the pcap handle for `iface` if present: invokes close_fn(ctx, handle_id),
 * removes the slot (compacting the arrays), decrements count. Returns 0 if closed,
 * -1 if `iface` is not currently captured. */
int ps_capture_close_iface(struct ps_capture_handle *ch, const char *iface,
                           ps_close_pcap_fn close_fn, void *ctx);
```

- [ ] **Step 2: Write the failing unit test**

Create `src/agent/tests/test_capture_close.c`:

```c
#include "capture/capture_handle.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

/* Stub pcap open: hand back an incrementing fake handle id. */
static int g_next = 100;
static int fake_open(void *ctx, const char *iface,
                     const char *bpf, uint32_t snaplen) {
    (void)ctx; (void)iface; (void)bpf; (void)snaplen;
    return ++g_next;
}

/* Stub close: record the last handle we were asked to close. */
static int g_closed = -1;
static int fake_close(void *ctx, int handle_id) {
    (void)ctx;
    g_closed = handle_id;
    return 0;
}

int main(void) {
    struct ps_capture_handle ch;
    ps_capture_init(&ch);

    assert(ps_capture_open(&ch, (ps_open_pcap_fn)fake_open, NULL, "eth0") == 0);
    assert(ps_capture_open(&ch, (ps_open_pcap_fn)fake_open, NULL, "eth1") == 0);
    assert(ch.count == 2);
    int eth0_handle = ch.handle_ids[0];

    /* Close eth0: close_fn called with eth0's handle, slot removed, array compacted */
    int r = ps_capture_close_iface(&ch, "eth0", (ps_close_pcap_fn)fake_close, NULL);
    assert(r == 0);
    assert(g_closed == eth0_handle);
    assert(ch.count == 1);
    assert(strcmp(ch.iface_names[0], "eth1") == 0); /* eth1 shifted down */

    /* Close a missing iface: no-op, returns -1 */
    g_closed = -1;
    r = ps_capture_close_iface(&ch, "nope", (ps_close_pcap_fn)fake_close, NULL);
    assert(r == -1);
    assert(g_closed == -1);
    assert(ch.count == 1);

    printf("test_capture_close: OK\n");
    return 0;
}
```

- [ ] **Step 3: Register the test in CMake**

In `src/agent/CMakeLists.txt`, add next to the other capture/iface test targets. `capture_handle.c` uses `log.h` (which lives in `packetsonde_lib`), so compile the unit source and link the lib for the logging symbols:

```cmake
add_executable(test_capture_close tests/test_capture_close.c src/capture/capture_handle.c)
target_include_directories(test_capture_close PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_capture_close PRIVATE packetsonde_lib)
add_test(NAME test_capture_close COMMAND test_capture_close)
```

- [ ] **Step 4: Run the test to verify it fails**

```bash
cd /data/opt/repo/packetsonde
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --target test_capture_close -j
```

Expected: build/link failure — `undefined reference to 'ps_capture_close_iface'`.

- [ ] **Step 5: Implement `ps_capture_close_iface`**

In `src/agent/src/capture/capture_handle.c`, add after `ps_capture_open` (before `ps_capture_get_bpf_filter`):

```c
int ps_capture_close_iface(struct ps_capture_handle *ch, const char *iface,
                           ps_close_pcap_fn close_fn, void *ctx)
{
    for (int i = 0; i < ch->count; i++) {
        if (strcmp(ch->iface_names[i], iface) != 0) continue;

        int handle = ch->handle_ids[i];
        if (close_fn) close_fn(ctx, handle);

        /* Compact the arrays: shift everything after i down by one. */
        for (int k = i; k < ch->count - 1; k++) {
            ch->handle_ids[k] = ch->handle_ids[k + 1];
            strncpy(ch->iface_names[k], ch->iface_names[k + 1],
                    sizeof(ch->iface_names[k]) - 1);
            ch->iface_names[k][sizeof(ch->iface_names[k]) - 1] = '\0';
        }
        ch->count--;
        ps_info("capture_handle: closed handle=%d on %s", handle, iface);
        return 0;
    }
    return -1;
}
```

- [ ] **Step 6: Run the test to verify it passes**

```bash
cd /data/opt/repo/packetsonde
cmake --build build --target test_capture_close -j
ctest --test-dir build --output-on-failure -R test_capture_close
```

Expected: `test_capture_close: OK`, 1/1 passed.

- [ ] **Step 7: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/src/capture/capture_handle.h src/agent/src/capture/capture_handle.c \
        src/agent/tests/test_capture_close.c src/agent/CMakeLists.txt
git commit -m "agent: add ps_capture_close_iface (single-iface capture teardown)"
```

---

## Task 5: Module-ctx capture hooks — `close_pcap`, `capture_add`, `capture_remove`

Add the three hooks to the module ctx, implement them in `main` (operating on `g_capture`, honoring `[capture] exclude` and the 8-iface cap, using the priv worker), and wire them into every module's ctx.

**Files:**
- Modify: `src/agent/include/packetsonde/module_api.h`
- Modify: `src/agent/src/main.c`

- [ ] **Step 1: Add the hook members to the ctx struct**

In `src/agent/include/packetsonde/module_api.h`, inside `struct ps_module_ctx`, add three members immediately after the existing `log` member (the last member before the closing brace):

```c
    void (*log)(ps_module_ctx_t *ctx, int level, const char *fmt, ...);

    /* Capture lifecycle (wired by main to operate on the shared capture set). */
    int  (*close_pcap)(ps_module_ctx_t *ctx, int handle);
    int  (*capture_add)(ps_module_ctx_t *ctx, const char *iface);
    int  (*capture_remove)(ps_module_ctx_t *ctx, const char *iface);
```

- [ ] **Step 2: Implement the three callbacks in `main.c`**

In `src/agent/src/main.c`, add these static functions next to the existing `ctx_open_pcap` (which is around line 66). `ctx_open_pcap` already calls `ps_priv_client_open_pcap(&g_priv, ...)`; mirror it:

```c
static int ctx_close_pcap(ps_module_ctx_t *ctx, int handle)
{
    (void)ctx;
    return ps_priv_client_close_pcap(&g_priv, (uint16_t)handle);
}

static int ctx_capture_add(ps_module_ctx_t *ctx, const char *iface)
{
    (void)ctx;
    if (!iface || !iface[0]) return -1;

    if (ps_iface_excluded(iface, getenv("PS_CAPTURE_EXCLUDE"))) {
        ps_info("capture: not adding %s (excluded / loopback)", iface);
        return -1;
    }
    /* Already captured? Idempotent no-op. */
    for (int i = 0; i < g_capture.count; i++)
        if (strcmp(g_capture.iface_names[i], iface) == 0)
            return 0;

    return ps_capture_open(&g_capture, (ps_open_pcap_fn)ctx_open_pcap, NULL, iface);
}

static int ctx_capture_remove(ps_module_ctx_t *ctx, const char *iface)
{
    (void)ctx;
    if (!iface || !iface[0]) return -1;
    return ps_capture_close_iface(&g_capture, iface,
                                  (ps_close_pcap_fn)ctx_close_pcap, NULL);
}
```

> `ps_iface_excluded` comes from `iface_enum.h` (already included by `main.c` for the dynamic-capture work). `ps_capture_open`/`ps_capture_close_iface`/`g_capture` come from `capture/capture_handle.h` (already included). `ps_priv_client_close_pcap`/`g_priv` come from `priv_client.h` (already included). If the compiler reports any of these as undeclared, add the corresponding `#include` that `ctx_open_pcap` already relies on.

- [ ] **Step 3: Wire the hooks into every module ctx**

In `src/agent/src/main.c`, in the "Wire module context callbacks" loop (around line 970-978), add the three new assignments after `ctx->log`:

```c
        ctx->open_pcap         = ctx_open_pcap;
        ctx->create_raw_socket = ctx_create_raw_socket;
        ctx->send_raw          = ctx_send_raw;
        ctx->publish           = ctx_publish;
        ctx->log               = ctx_log;
        ctx->close_pcap        = ctx_close_pcap;
        ctx->capture_add       = ctx_capture_add;
        ctx->capture_remove    = ctx_capture_remove;
```

- [ ] **Step 4: Build the agent**

```bash
cd /data/opt/repo/packetsonde
cmake --build build --target packetsonde-agent -j
```

Expected: clean build. No `-Wunused-function` warnings for the three new statics (they're referenced in the wiring loop and the casts).

- [ ] **Step 5: Run the full test suite (regression check)**

```bash
ctest --test-dir build --output-on-failure
```

Expected: all tests pass. The ctx grew three members; any test that builds a ctx on the stack and zero-inits it (e.g. `test_neighbor_listener`'s stub ctx) is unaffected because the new hooks default to NULL and the report path guards `if (ctx->publish)` / Task 6 guards the capture calls.

- [ ] **Step 6: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/include/packetsonde/module_api.h src/agent/src/main.c
git commit -m "agent: add close_pcap/capture_add/capture_remove module-ctx hooks"
```

---

## Task 6: Wire dynamic re-capture into `iface_monitor`

Now that the ctx exposes `capture_add`/`capture_remove`, have the monitor act on each detected transition: an added or recovered (state→up) interface gets captured; a removed or downed (state→down) interface gets dropped.

**Files:**
- Modify: `src/agent/src/modules/iface_monitor.c`

- [ ] **Step 1: Add the re-capture switch to the tick loop**

In `src/agent/src/modules/iface_monitor.c`, in `iface_monitor_tick`, replace the existing publish loop:

```c
    for (int i = 0; i < nchg; i++)
        emit_finding(ctx, &changes[i]);
```

with a loop that publishes **and** re-captures (report stays independent of the capture outcome — the finding is always emitted first):

```c
    for (int i = 0; i < nchg; i++) {
        const struct ps_iface_change *c = &changes[i];
        emit_finding(ctx, c);

        switch (c->kind) {
        case PS_IFC_ADDED:
            if (ctx->capture_add) ctx->capture_add(ctx, c->name);
            break;
        case PS_IFC_STATE:
            if (c->new_up && !c->old_up) {
                if (ctx->capture_add) ctx->capture_add(ctx, c->name);
            } else if (!c->new_up && c->old_up) {
                if (ctx->capture_remove) ctx->capture_remove(ctx, c->name);
            }
            break;
        case PS_IFC_REMOVED:
            if (ctx->capture_remove) ctx->capture_remove(ctx, c->name);
            break;
        case PS_IFC_ADDR:
        default:
            break; /* address change alone doesn't change the capture set */
        }
    }
```

> The `if (ctx->capture_*)` guards keep the module safe under unit-test ctxs that leave the hooks NULL. In the running agent they're wired (Task 5), so a recovered interface auto-captures and a downed one is dropped. `capture_add` itself applies `[capture] exclude` and the 8-iface cap, so excluded/virtual interfaces are never auto-captured.

- [ ] **Step 2: Update the file header comment**

In `src/agent/src/modules/iface_monitor.c`, update the parenthetical at the end of the top comment block from:

```c
 * (Dynamic re-capture is wired in a later task; this revision only reports.)
```

to:

```c
 * On a change it also adjusts the shared capture set via ctx->capture_add /
 * ctx->capture_remove: added or recovered interfaces start being captured;
 * removed or downed interfaces stop. Re-capture honors [capture] exclude.
```

- [ ] **Step 3: Build the agent**

```bash
cd /data/opt/repo/packetsonde
cmake --build build --target packetsonde-agent -j
```

Expected: clean build.

- [ ] **Step 4: Run the full test suite (regression check)**

```bash
ctest --test-dir build --output-on-failure
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
cd /data/opt/repo/packetsonde
git add src/agent/src/modules/iface_monitor.c
git commit -m "agent: iface_monitor dynamically re-captures on iface add/recover/remove"
```

---

## Task 7: Full build, guard checks, and gated live verification

**Files:** none (verification + deploy).

- [ ] **Step 1: Clean build + full test suite**

```bash
cd /data/opt/repo/packetsonde
rm -rf build
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Expected: 100% of tests pass, including `test_iface_snapshot`, `test_capture_close`, `test_config_to_env`.

- [ ] **Step 2: Guard — no hardcoded interface names introduced**

```bash
cd /data/opt/repo/packetsonde
grep -rEn '"(en0|em0|eth0|ens18|ens19|enp[0-9]|eth1)"' src/agent/src/iface_snapshot.c \
     src/agent/src/modules/iface_monitor.c && echo "FOUND HARDCODED NAME (fail)" || echo "OK: no hardcoded iface names"
```

Expected: `OK: no hardcoded iface names`. (Test files may contain literal example names like `eth0`/`eth1` — that is expected and fine; this check targets the production sources only.)

- [ ] **Step 3: STOP — request approval before deploying to the fleet**

This step deploys to live lab nodes. **Do not proceed without explicit user go-ahead.** Present the diff summary and ask to deploy.

- [ ] **Step 4: Stage the rebuilt binary + apply the salt state (after approval)**

The binary staging + fleet apply lives in the private `rna-salt` repo. After approval, follow `docs/specs/2026-05-23-iface-monitor-design.md` §7:

```bash
# (in the rna-salt working tree — private repo)
scripts/stage-packetsonde-binaries.sh
sudo -n salt '*' state.apply packetsonde
```

- [ ] **Step 5: Live verification on a node with a spare interface**

On a fleet node (e.g. one with a second, normally-down interface), watch the agent log and toggle the interface. Use the live log tail and a transition:

```bash
# On the node, tail the agent log, then in another shell toggle a spare iface:
sudo ip link set <spare-iface> up
#   -> within one interval: a net.iface.state_change (new_up=true) finding is published
#      AND the journal shows "capture_handle: opened shared handle=... on <spare-iface>"
sudo ip link set <spare-iface> down
#   -> net.iface.state_change (new_up=false, severity=warning) finding
#      AND "capture_handle: closed handle=... on <spare-iface>"
```

Confirm in the central fleet view / events that `net.iface.state_change` events arrive, and the capture log lines appear. Verify an excluded iface (e.g. a `docker`/`veth` if `[capture] exclude` is set) does **not** trigger a capture open.

- [ ] **Step 6: Final commit (if any verification tweaks were needed)**

```bash
cd /data/opt/repo/packetsonde
git add -A
git commit -m "agent: iface_monitor live-verification adjustments" || echo "no changes to commit"
```

---

## Self-Review Notes

**Spec coverage (vs `2026-05-23-iface-monitor-design.md`):**
- §3.1 `iface_snapshot.{c,h}` + pure `ps_iface_diff` → Task 1. ✓ (types match the spec exactly: `ps_iface_snap`, `ps_iface_change_kind` with `PS_IFC_ADDED/REMOVED/STATE/ADDR`, `ps_iface_change`.)
- §3.2 `iface_monitor` module (init baseline, throttled tick, diff, publish, copy cur→prev) → Task 2 (report) + Task 6 (re-capture). ✓
- §3.3 capture lifecycle: `ps_capture_close_iface` → Task 4; ctx `close_pcap`/`capture_add`/`capture_remove` + `main` wiring → Task 5; monitor calls → Task 6. ✓
- §3.4 finding shape (`net.iface.{added,removed,state_change,addr_change}`, severity info except state→down = warning, source=`agent.iface_monitor`) → Task 2 `emit_finding`. ✓
- §3.5 config `[iface_monitor] interval` → `PS_IFACE_MONITOR_INTERVAL`; re-capture reads `PS_CAPTURE_EXCLUDE` → Task 3 + Task 5 `ctx_capture_add`. ✓
- §4 error handling: getifaddrs fail → skip tick keep prev (Task 2 tick); capture_add excluded/already/max → no-op (Task 5 + `ps_capture_open` cap); capture_remove not-present → -1 no-op (Task 4). ✓
- §5 testing: unit `test_iface_snapshot` (added/removed/state both directions/addr/no-change/ordering) → Task 1; build+register → Task 2; live → Task 7. ✓ (Added `test_capture_close` for the teardown — exceeds spec, justified: the compaction logic is error-prone and worth a pure test.)
- §6 ordering: report layer (Tasks 1-3) before re-capture layer (Tasks 4-6). ✓
- §7 deploy + "no hardcoded names" + generic/public → Task 7 Steps 2-5. ✓

**Type consistency:** `ps_iface_snap`, `ps_iface_change`, `ps_iface_change_kind`, `ps_iface_diff`, `ps_iface_snapshot`, `PS_IFACE_SNAP_MAX` used identically across Tasks 1/2/6. `ps_close_pcap_fn`, `ps_capture_close_iface` identical across Tasks 4/5. ctx hook names `close_pcap`/`capture_add`/`capture_remove` identical across Tasks 5/6. `PS_IFACE_MONITOR_INTERVAL` identical across Tasks 2/3. Module symbol `ps_iface_monitor_module` identical across Task 2 (definition) and `main.c` (extern + register).

**Placeholders:** none — every code step contains full code; the one read-the-file instruction (Task 3 Step 1, the test fixture idiom) is bounded by an explicit assertion and a concrete entry to add.
