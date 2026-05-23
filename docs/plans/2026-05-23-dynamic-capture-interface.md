# Dynamic Capture-Interface Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The agent captures on all of a node's real interfaces (minus `lo` + an operator exclude list) by dynamic enumeration — no hardcoded interface names anywhere.

**Architecture:** A new `iface_enum` helper enumerates interfaces via `getifaddrs` and applies a prefix-matched exclude list. `main.c` resolves the capture targets (explicit `[agent] interface` pin → else enumerate) and opens one shared-capture handle per interface (the `ps_capture_handle` already holds up to 8). The hardcoded `eth0`/`en0`/`em0` literals + `*_DEFAULT_IFACE` defines are deleted from `main.c` and the passive listeners (which share the pipeline and don't capture themselves).

**Tech Stack:** C11, getifaddrs(3), libpcap (existing), CMake/CTest.

**Spec:** `docs/specs/2026-05-23-dynamic-capture-interface-design.md`.

**Repo:** `/data/opt/repo/packetsonde` (public; branch `feat/dynamic-capture-iface`). **No lab-specific names in code or commits.** Build: `cd build && cmake .. -DBUILD_TESTING=ON && make <t> && ctest -R <t>`.

---

## Task 1: `iface_enum` helper (enumerate + exclude)

**Files:** Create `src/agent/src/iface_enum.h`, `src/agent/src/iface_enum.c`; Test `src/agent/tests/test_iface_enum.c`; Modify `src/agent/CMakeLists.txt`

- [ ] **Step 1: Write the failing test** (`src/agent/tests/test_iface_enum.c`)

```c
#include "iface_enum.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    /* lo always excluded, regardless of csv */
    assert(ps_iface_excluded("lo", NULL) == 1);
    assert(ps_iface_excluded("lo", "") == 1);
    assert(ps_iface_excluded("lo", "docker") == 1);
    /* empty/NULL csv excludes ONLY lo */
    assert(ps_iface_excluded("ens18", NULL) == 0);
    assert(ps_iface_excluded("ens18", "") == 0);
    /* prefix match: token "veth" excludes veth*, "docker" excludes docker0 */
    assert(ps_iface_excluded("veth1a2b", "veth") == 1);
    assert(ps_iface_excluded("docker0", "docker,veth") == 1);
    assert(ps_iface_excluded("br-abc", "docker,veth") == 0);
    assert(ps_iface_excluded("br-abc", "docker,veth,br-") == 1);
    /* non-matching real iface passes */
    assert(ps_iface_excluded("enp3s0", "docker,veth") == 0);

    /* enumerate returns >=1 (the test host has at least one non-lo iface) and never lo */
    char names[8][64];
    int n = ps_iface_enumerate(NULL, names, 8);
    assert(n >= 1);
    for (int i = 0; i < n; i++) assert(strcmp(names[i], "lo") != 0);
    printf("test_iface_enum: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_iface_enum 2>&1 | tail -4`
Expected: FAIL — `iface_enum.h` not found.

- [ ] **Step 3: Create `src/agent/src/iface_enum.h`**

```c
#ifndef PS_IFACE_ENUM_H
#define PS_IFACE_ENUM_H

/* Returns 1 if `name` should be excluded from capture: it is "lo" (always), or it
 * starts with any comma-separated token in `exclude_csv` (prefix match; NULL/empty
 * csv excludes only "lo"). */
int ps_iface_excluded(const char *name, const char *exclude_csv);

/* Enumerate the host's interfaces (getifaddrs), collect unique names that are not
 * excluded (ps_iface_excluded), into out[][64] up to `max`. Returns the count. */
int ps_iface_enumerate(const char *exclude_csv, char out[][64], int max);

#endif
```

- [ ] **Step 4: Create `src/agent/src/iface_enum.c`**

```c
#include "iface_enum.h"
#include <ifaddrs.h>
#include <string.h>
#include <stdio.h>

int ps_iface_excluded(const char *name, const char *exclude_csv) {
    if (!name || !name[0]) return 1;
    if (strcmp(name, "lo") == 0) return 1;
    if (!exclude_csv || !exclude_csv[0]) return 0;
    /* prefix-match name against each comma-separated token */
    const char *p = exclude_csv;
    while (*p) {
        while (*p == ',' || *p == ' ') p++;
        const char *start = p;
        while (*p && *p != ',') p++;
        size_t len = (size_t)(p - start);
        if (len > 0 && strncmp(name, start, len) == 0) return 1;
    }
    return 0;
}

int ps_iface_enumerate(const char *exclude_csv, char out[][64], int max) {
    struct ifaddrs *ifa, *cur;
    if (getifaddrs(&ifa) != 0) return 0;
    int n = 0;
    for (cur = ifa; cur && n < max; cur = cur->ifa_next) {
        const char *nm = cur->ifa_name;
        if (!nm || ps_iface_excluded(nm, exclude_csv)) continue;
        int dup = 0;
        for (int i = 0; i < n; i++) if (strcmp(out[i], nm) == 0) { dup = 1; break; }
        if (dup) continue;
        snprintf(out[n], 64, "%s", nm);
        n++;
    }
    freeifaddrs(ifa);
    return n;
}
```

- [ ] **Step 5: Wire into `src/agent/CMakeLists.txt`** — add `src/iface_enum.c` to the agent binary's sources (alongside the other `src/*.c`), and a test next to `test_config`:

```cmake
add_executable(test_iface_enum tests/test_iface_enum.c src/iface_enum.c)
add_test(NAME test_iface_enum COMMAND test_iface_enum)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_iface_enum >/dev/null && ctest -R '^test_iface_enum$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/agent/src/iface_enum.h src/agent/src/iface_enum.c src/agent/tests/test_iface_enum.c src/agent/CMakeLists.txt
git commit -m "agent: add iface_enum (enumerate interfaces minus lo + prefix exclude list)"
```

---

## Task 2: `config_to_env` — `[capture] exclude`

**Files:** Modify `src/agent/src/config_to_env.c`

- [ ] **Step 1: Add the mapping** — in the `MAPPINGS[]` table (after the `agent_listen` block), add:

```c
    /* capture -- passive pcap interface selection */
    { "capture", "exclude",          "PS_CAPTURE_EXCLUDE" },
```

- [ ] **Step 2: Build to confirm it compiles**

Run: `cd build && make packetsonde-agent >/dev/null 2>&1 && echo OK`
Expected: `OK`.

- [ ] **Step 3: Commit**

```bash
git add src/agent/src/config_to_env.c
git commit -m "config_to_env: map [capture] exclude -> PS_CAPTURE_EXCLUDE"
```

---

## Task 3: `main.c` — resolve + open per-interface captures

**Files:** Modify `src/agent/src/main.c` (the capture-iface block, ~983-1003)

- [ ] **Step 1: Replace the resolve + open block.** Find (lines ~983-1003):

```c
    const char *capture_iface = ps_config_get(&cfg, "agent", "interface");
    if (!capture_iface || capture_iface[0] == '\0')
        capture_iface = getenv("PS_CAPTURE_INTERFACE");
    if (!capture_iface || capture_iface[0] == '\0') {
#ifdef __FreeBSD__
        capture_iface = "em0";
#elif defined(__APPLE__)
        capture_iface = "en0";
#else
        capture_iface = "eth0";
#endif
    }
    ps_info("main: capture interface: %s (config > $PS_CAPTURE_INTERFACE > default)",
            capture_iface);

    ps_capture_open(&g_capture,
        (ps_open_pcap_fn)ctx_open_pcap, NULL,
        capture_iface);

    ps_info("main: shared capture on %s with filter: %s",
            capture_iface, ps_capture_get_bpf_filter());
```

Replace with (and add `#include "iface_enum.h"` near the top includes):

```c
    /* Capture targets: explicit [agent] interface (or $PS_CAPTURE_INTERFACE) pins a
     * single iface; otherwise capture every real interface (all minus lo minus
     * [capture] exclude). No interface names are hardcoded. */
    char cap_ifaces[PS_CAPTURE_MAX_INTERFACES][64];
    int  cap_n = 0;
    const char *pin = ps_config_get(&cfg, "agent", "interface");
    if (!pin || !pin[0]) pin = getenv("PS_CAPTURE_INTERFACE");
    if (pin && pin[0]) {
        snprintf(cap_ifaces[0], sizeof cap_ifaces[0], "%s", pin);
        cap_n = 1;
    } else {
        cap_n = ps_iface_enumerate(getenv("PS_CAPTURE_EXCLUDE"),
                                   cap_ifaces, PS_CAPTURE_MAX_INTERFACES);
    }

    if (cap_n <= 0) {
        ps_warn("main: no capture interfaces resolved — passive capture disabled");
    } else {
        for (int i = 0; i < cap_n; i++) {
            if (ps_capture_open(&g_capture, (ps_open_pcap_fn)ctx_open_pcap, NULL,
                                cap_ifaces[i]) != 0)
                ps_warn("main: capture open failed for %s — continuing", cap_ifaces[i]);
            else
                ps_info("main: shared capture on %s", cap_ifaces[i]);
        }
        ps_info("main: capture BPF filter: %s", ps_capture_get_bpf_filter());
    }
```

- [ ] **Step 2: Build**

Run: `cd build && make packetsonde-agent 2>&1 | tail -4`
Expected: builds clean.

- [ ] **Step 3: Commit**

```bash
git add src/agent/src/main.c
git commit -m "main: open a capture per resolved interface (all-minus-exclude); drop hardcoded iface names"
```

---

## Task 4: Remove hardcoded `en0` from the listeners

**Files:** Modify `src/agent/src/modules/{cdp,lldp,ssdp,netbios,ospf,vrrp,broadcast}_listener.c`, `{dhcp,mld,stp}_listener.c`

The listeners receive frames via `on_packet` from the shared pipeline; their stored `iface` is cosmetic. Replace the `en0` fallback with an empty/neutral value (no hardcoded name).

- [ ] **Step 1: Fix the 7 `iface = "en0"` fallbacks** — in each of `cdp_listener.c:265`, `lldp_listener.c:258`, `ssdp_listener.c:238`, `netbios_listener.c:444`, `ospf_listener.c:225`, `vrrp_listener.c:181`, `broadcast_listener.c:136`, change:

```c
    if (!iface || iface[0] == '\0') iface = "en0";
```
to:
```c
    if (!iface) iface = "";   /* shared-pipeline listener; iface label is informational */
```

- [ ] **Step 2: Fix the 3 `*_DEFAULT_IFACE` defines** — in `dhcp_listener.c:28`, `mld_listener.c:37`, `stp_listener.c:28`, change the define value from `"en0"` to `""`:

```c
#define DHCP_DEFAULT_IFACE       ""
```
```c
#define MLD_DEFAULT_IFACE        ""
```
```c
#define STP_DEFAULT_IFACE        ""
```
(`mld_listener.c:243` uses `iface = MLD_DEFAULT_IFACE;` — unchanged, now resolves to `""`.)

- [ ] **Step 3: Build**

Run: `cd build && make packetsonde-agent 2>&1 | tail -4`
Expected: builds clean.

- [ ] **Step 4: Commit**

```bash
git add src/agent/src/modules/*_listener.c
git commit -m "listeners: drop hardcoded en0 iface defaults (cosmetic; they share the capture pipeline)"
```

---

## Task 5: Verify no hardcoded interface names remain + full build/tests

**Files:** none (verification)

- [ ] **Step 1: Grep for remaining hardcoded iface-name literals in code (comments excluded)**

Run:
```bash
cd /data/opt/repo/packetsonde
grep -rnE '"(en0|em0|eth0)"' src/agent/src --include='*.c' --include='*.h' | grep -vE '^\s*\*|//|/\*'
```
Expected: **no output** (the only remaining `en0` mentions are in comment blocks at `main.c:369-370` and `flow_tracker_mod.c:12-13`, which are illustrative JSON examples — acceptable, or update them to a generic `"<iface>"` if you prefer).

- [ ] **Step 2: Full build + agent test suite**

Run: `cd build && cmake .. -DBUILD_TESTING=ON >/dev/null && make -j4 >/dev/null 2>&1 && echo OK && ctest --timeout 30 -R 'iface_enum|config_to_env|agent_proto|json' --output-on-failure 2>&1 | tail -4`
Expected: `OK` + tests pass.

- [ ] **Step 3: (no commit — verification only)**

---

## Task 6: Deploy + live verify (GATED — after PR merged)

**Files:** none (operational). Run after the PR merges.

- [ ] **Step 1: Rebuild + restage + re-apply to the fleet**

```bash
cd /data/opt/repo/packetsonde/build && make packetsonde-agent >/dev/null
install -m755 src/agent/packetsonded /opt/salt-states/states/packetsonde/bin/packetsonded
sudo -n salt '*' state.apply packetsonde --out=txt 2>&1 | grep -iE 'Failed: [^0]' | tail
```

- [ ] **Step 2: Verify capture opens on the real interfaces (no hardcoded name, no "bad interface")**

```bash
sudo -n salt '<a-node>' cmd.run 'journalctl -u packetsonded --no-pager | grep -iE "shared capture on|bad interface|no capture interfaces" | tail' --out=txt
```
Expected: `shared capture on <real iface>` lines for each of the node's interfaces; **no** `bad interface`.

- [ ] **Step 3: Verify passive capture is live + knock works on a knock-mode node**

- Confirm a passive finding appears (e.g. ARP/mDNS) or the capture handles are open.
- From an authorized client, knock the knock-mode node (`--via <knock-node>` with `knock=true` in the registry) and confirm the session opens (it couldn't before, because the broadcast capture was dead).

---

## Self-Review

**Spec coverage:**
- §2 D1 all-minus-(lo+exclude) → Task 1 (`ps_iface_excluded`/`enumerate`) + Task 3 (resolve) ✓
- §2 D2 pin override → Task 3 (`pin` path) ✓
- §2 D3 per-iface shared capture (max 8) → Task 3 (loop `ps_capture_open`) ✓
- §2 D4 remove hardcoded names → Task 3 (main.c block) + Task 4 (listeners) + Task 5 (grep gate) ✓
- §2 D5 prefix-match exclude → Task 1 (`ps_iface_excluded`) ✓
- §3.3 config_to_env `[capture] exclude` → Task 2 ✓
- §4 error handling (open-fail → warn+continue; zero ifaces → warn; lo always) → Task 3 (warn-continue loop, `cap_n<=0` warn) + Task 1 (lo in `ps_iface_excluded`) ✓
- §5 testing (ps_iface_excluded unit; enumerate non-lo; build/grep; live) → Tasks 1, 5, 6 ✓
- §6 deploy → Task 6 ✓

**Gaps noted + accepted:** (a) the `>8 interfaces` warning (spec §4) isn't separately logged — `ps_iface_enumerate` simply caps at `max=8` (caller passes `PS_CAPTURE_MAX_INTERFACES`); the cap is silent. Acceptable (8 real ifaces on one node is exotic in this fleet); a follow-up could log the truncation. (b) `main.c:369-370` + `flow_tracker_mod.c:12-13` keep `en0` in **comment** example JSON — Task 5 flags them as optional cleanup, not code.

**Placeholder scan:** No TBD/TODO. All code shown complete (helper, main.c block, each listener edit). The `<a-node>`/`<knock-node>` in Task 6 are deliberately generic (lab nodes filled at run time, not committed).

**Type/name consistency:** `ps_iface_excluded`/`ps_iface_enumerate` (Task 1) used in Task 3; `PS_CAPTURE_EXCLUDE` (Task 2 → Task 3 `getenv`); `PS_CAPTURE_MAX_INTERFACES`/`ps_capture_open`/`ctx_open_pcap`/`g_capture` match main.c's existing symbols; `out[][64]` signature consistent between header, impl, and the test.
```
