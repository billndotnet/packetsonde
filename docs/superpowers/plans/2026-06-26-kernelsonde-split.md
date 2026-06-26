# kernelsonde Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the Linux detect track out of `packetsonded` into a new, independently-deployable `kernelsonded` daemon (own priv worker, caps, user, socket, config, central identity), in the same repo on shared code.

**Architecture:** A new `packetsonde_daemon` static lib holds the runtime shared by both daemons (config, IPC server, central checkin, module registry, obs queue, priv client, platform). Detect-only sources relocate to `src/kernel/`. `kernelsonded` + `kernelsonde-priv` are new binaries; `packetsonded` + `packetsonde-priv` shed detect and the fanotify caps. The tree builds and `packetsonded`'s detect keeps working until a single late task flips the detect responsibility to `kernelsonded`.

**Tech Stack:** C11, CMake 3.20+, fanotify, systemd, debhelper, Ed25519 (OpenSSL), AF_UNIX IPC.

## Global Constraints

- Both binaries in the **same repo**, sharing `src/lib` (`packetsonde_lib`) and a new `packetsonde_daemon` static lib. No new git repo.
- Detect logic primitives already live in `src/lib` (`activity_record`, `provenance`, `proc_parse`, `sock_parse`, `proc_profile*`, `cgroup_unit`, `systemd_policy`, `policy_eval`, `unit_envelope`, `sandbox_synth`, `exe_slug`, `baseline_set`, `baseline_decide`, `dest_match`) — **do not move these**; both daemons keep linking `packetsonde_lib`.
- Detect-only runtime sources that move to `src/kernel/`: `fan_monitor`, `proc_enrich`, `sock_snapshot`, `activity_ring`, `baseline_store`, `capture_session`, `modules/policy_overwatch`, `modules/baseline_monitor` (with their headers).
- **`capture/capture_handle.c` and `capture/protocol_demux.c` are NETWORK-ONLY — they stay in `packetsonded`.** (Corrects the spec, which grouped `capture/` with the move.)
- The detect CLI verbs `watch`/`inspect`/`baseline`/`sandbox-suggest` are **file-readers**: they repoint their default file/dir paths from `/var/lib/packetsonde/...` to `/var/lib/kernelsonde/...`. The **`detect`** verb (`src/cli/verbs/detect.c`) is the socket client: its default socket repoints to `/run/kernelsonde/agent.sock`. (Corrects the spec, which said all four verbs use the socket.)
- Capability isolation: `kernelsonde-priv` carries `CAP_SYS_ADMIN`+`CAP_DAC_READ_SEARCH`; `packetsonde-priv` keeps only the pcap/raw path; `packetsonded.service` drops the fanotify-caps comment.
- Runtime layout for kernelsonded: user `kernelsonded`; `/etc/kernelsonded/kernelsonded.toml` (+ `keys/`); `RuntimeDirectory=kernelsonde` → `/run/kernelsonde/agent.sock`; `StateDirectory=kernelsonde` → `/var/lib/kernelsonde`.
- Config keeps the `[detect]` section name, now in `kernelsonded.toml`. `packetsonded` warns-and-ignores a stale `[detect]` block.
- Packaging: **one** `packetsonde` `.deb`, now shipping both daemons as **two units, both disabled**; postinst creates both users; prerm stops both units.
- `kernelsonded` enrolls as its **own** Ed25519 agent via the existing central-protocol-v1 (no protocol change, no role tag).
- **No Claude/Co-Authored-By footers** in commits (CLAUDE.md). Use `git`/SSH; never `gh`.
- Bump `PS_VERSION_STR` (patch) once for the build that introduces kernelsonded; keep `debian/changelog` in lockstep (the `build-deb.sh` guard enforces it).
- ctest must be run on a **Debug/default build** (not Release/`-DNDEBUG`, which strips asserts and segfaults 5 tests spuriously).

---

### Task 1: Extract the shared daemon runtime into a `packetsonde_daemon` static lib

Pure refactor — no behavior change. `packetsonded`/`packetsonde-priv` relink against a new lib; the build and ctest are byte-for-byte equivalent in behavior.

**Files:**
- Modify: `src/agent/CMakeLists.txt` (define the lib; relink targets)

**Interfaces:**
- Produces: CMake static lib target `packetsonde_daemon` compiling, in place from `src/agent/src/`: `config.c`, `config_to_env.c`, `central_checkin.c`, `ipc_server.c`, `module.c`, `obs_queue.c`, `priv_client.c`, `iso8601.c`, `platform/unix.c`. Public include dirs: `src/agent/src`, `src/agent/include`. Links `packetsonde_lib`. Both daemon binaries and the priv workers link `packetsonde_daemon`.

- [ ] **Step 1: Add the lib target.** In `src/agent/CMakeLists.txt`, before `add_executable(packetsonde-agent …)`, add:

```cmake
# Runtime shared by both daemons (packetsonded + kernelsonded). Pure-logic
# primitives stay in packetsonde_lib; this lib is the daemon plumbing.
add_library(packetsonde_daemon STATIC
    src/config.c
    src/config_to_env.c
    src/central_checkin.c
    src/ipc_server.c
    src/module.c
    src/obs_queue.c
    src/priv_client.c
    src/iso8601.c
    src/platform/unix.c
)
target_include_directories(packetsonde_daemon PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(packetsonde_daemon PUBLIC packetsonde_lib pthread)
set_target_properties(packetsonde_daemon PROPERTIES POSITION_INDEPENDENT_CODE ON)
```

- [ ] **Step 2: Remove those 9 files from `AGENT_CORE_SOURCES`** in the same file (delete the lines `src/config.c`, `src/config_to_env.c`, `src/central_checkin.c`, `src/module.c`, `src/ipc_server.c`, `src/priv_client.c`, `src/platform/unix.c`, `src/iso8601.c`, `src/obs_queue.c`). Leave all network + detect sources in `AGENT_CORE_SOURCES`.

- [ ] **Step 3: Link the lib into the agent and priv targets.** Change `target_link_libraries(packetsonde-agent PRIVATE packetsonde_lib pthread)` to `target_link_libraries(packetsonde-agent PRIVATE packetsonde_daemon packetsonde_lib pthread)`. Add `packetsonde_daemon` to `packetsonde-priv`'s link line as well (it uses `platform/unix.c`).

- [ ] **Step 4: Configure + build (Debug) and run ctest.**

```bash
cd /data/opt/repo/packetsonde
rm -rf build && cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug >/dev/null && cmake --build build -j"$(nproc)" 2>&1 | tail -5
ctest --test-dir build --output-on-failure 2>&1 | tail -15
```
Expected: build succeeds; ctest 100% pass (same set as before the change).

- [ ] **Step 5: Commit.**

```bash
git add src/agent/CMakeLists.txt
git commit -m "refactor(agent): extract packetsonde_daemon static lib (shared runtime)"
```

---

### Task 2: Relocate detect-only runtime sources to `src/kernel/`

Move (via `git mv`) the detect-only files and rewire the existing agent/priv targets + the three detect unit tests to the new paths. Detect still runs in `packetsonded` afterward (sources just live elsewhere).

**Files:**
- Move: the 8 detect sources + headers from `src/agent/src/` → `src/kernel/src/`
- Modify: `src/agent/CMakeLists.txt` (point source lists + the 3 detect tests at new paths)

**Interfaces:**
- Consumes: `packetsonde_daemon`, `packetsonde_lib` (Task 1).
- Produces: detect sources resident at `src/kernel/src/{fan_monitor,proc_enrich,sock_snapshot,activity_ring,baseline_store,capture_session}.c` and `src/kernel/src/modules/{policy_overwatch,baseline_monitor}.c` (+ headers). A `KERNEL_DETECT_SOURCES` CMake variable lists them.

- [ ] **Step 1: Create the dir and move the files.**

```bash
cd /data/opt/repo/packetsonde
mkdir -p src/kernel/src/modules
git mv src/agent/src/fan_monitor.c   src/kernel/src/
git mv src/agent/src/fan_monitor.h   src/kernel/src/
git mv src/agent/src/proc_enrich.c   src/kernel/src/
git mv src/agent/src/proc_enrich.h   src/kernel/src/
git mv src/agent/src/sock_snapshot.c src/kernel/src/
git mv src/agent/src/sock_snapshot.h src/kernel/src/
git mv src/agent/src/activity_ring.c src/kernel/src/
git mv src/agent/src/activity_ring.h src/kernel/src/
git mv src/agent/src/baseline_store.c src/kernel/src/
git mv src/agent/src/baseline_store.h src/kernel/src/
git mv src/agent/src/capture_session.c src/kernel/src/
git mv src/agent/src/capture_session.h src/kernel/src/
git mv src/agent/src/modules/policy_overwatch.c src/kernel/src/modules/
git mv src/agent/src/modules/policy_overwatch.h src/kernel/src/modules/
git mv src/agent/src/modules/baseline_monitor.c src/kernel/src/modules/
git mv src/agent/src/modules/baseline_monitor.h src/kernel/src/modules/
```

- [ ] **Step 2: Define `KERNEL_DETECT_SOURCES` and add the include dir.** In `src/agent/CMakeLists.txt`, near the top (after `project()`), add:

```cmake
# Detect-track runtime sources now live in ../kernel. During the transition
# packetsonded still compiles them; Task 5 removes them from packetsonded.
set(KERNEL_DETECT_SOURCES
    ${CMAKE_SOURCE_DIR}/src/kernel/src/fan_monitor.c
    ${CMAKE_SOURCE_DIR}/src/kernel/src/proc_enrich.c
    ${CMAKE_SOURCE_DIR}/src/kernel/src/sock_snapshot.c
    ${CMAKE_SOURCE_DIR}/src/kernel/src/activity_ring.c
    ${CMAKE_SOURCE_DIR}/src/kernel/src/baseline_store.c
    ${CMAKE_SOURCE_DIR}/src/kernel/src/capture_session.c
    ${CMAKE_SOURCE_DIR}/src/kernel/src/modules/policy_overwatch.c
    ${CMAKE_SOURCE_DIR}/src/kernel/src/modules/baseline_monitor.c
)
set(KERNEL_DETECT_INCLUDE
    ${CMAKE_SOURCE_DIR}/src/kernel/src
    ${CMAKE_SOURCE_DIR}/src/kernel/src/modules)
```

- [ ] **Step 3: Update `AGENT_CORE_SOURCES`.** Remove the moved entries (`src/fan_monitor.c`, `src/proc_enrich.c`, `src/sock_snapshot.c`, `src/activity_ring.c`, `src/baseline_store.c`, `src/capture_session.c`, `src/modules/policy_overwatch.c`, `src/modules/baseline_monitor.c`) and instead append `${KERNEL_DETECT_SOURCES}` to the `packetsonde-agent` source list. Add `${KERNEL_DETECT_INCLUDE}` to `packetsonde-agent`'s `target_include_directories`. For `packetsonde-priv` (which compiles `fan_monitor.c`, `proc_enrich.c`, `sock_snapshot.c`), point those three at `${CMAKE_SOURCE_DIR}/src/kernel/src/...` and add `${KERNEL_DETECT_INCLUDE}` to its includes.

- [ ] **Step 4: Retarget the three detect unit tests** in `src/agent/CMakeLists.txt`: `test_baseline_store`, `test_baseline_monitor`, `test_capture_session`. Update each `add_executable` source path and `target_include_directories` to the new `src/kernel/src/...` locations. Example for `test_capture_session`:

```cmake
add_executable(test_capture_session tests/test_capture_session.c
    ${CMAKE_SOURCE_DIR}/src/kernel/src/capture_session.c)
target_include_directories(test_capture_session PRIVATE
    ${CMAKE_SOURCE_DIR}/src/kernel/src ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_capture_session PRIVATE pthread)
```
Apply the analogous path fix to `test_baseline_store` and `test_baseline_monitor` (they also pull `src/baseline_store.c` / `src/modules/baseline_monitor.c` + `activity_ring.c`).

- [ ] **Step 5: Build (Debug) + ctest.**

```bash
cd /data/opt/repo/packetsonde
cmake --build build -j"$(nproc)" 2>&1 | tail -5 || (rm -rf build && cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j"$(nproc)" 2>&1 | tail -5)
ctest --test-dir build --output-on-failure 2>&1 | tail -10
```
Expected: build + ctest green (same tests). `packetsonded` still has detect.

- [ ] **Step 6: Commit.**

```bash
git add -A
git commit -m "refactor: relocate detect-track runtime sources to src/kernel"
```

---

### Task 3: Build the `kernelsonde-priv` worker (fanotify only)

A new privilege-separated worker that runs only the fanotify/proc/sock path and emits `PS_OP_ACTIVITY_DATA`. `packetsonde-priv` is untouched in this task (still has fanotify too — removed in Task 5).

**Files:**
- Create: `src/kernel/src/kernel_priv_worker.c`
- Modify: `src/agent/CMakeLists.txt` (new `kernelsonde-priv` target) — or a new `src/kernel/CMakeLists.txt` added via `add_subdirectory` from the root. Use a new `src/kernel/CMakeLists.txt` (cleaner).
- Modify: root `CMakeLists.txt` (`add_subdirectory(src/kernel)` after `src/agent`)

**Interfaces:**
- Consumes: `priv_protocol.h` (shared wire format, in `src/agent/src/`), `fan_monitor` API (`ps_fan_monitor_run` + the `fan_cfg` struct), `packetsonde_daemon` (for `platform/unix.c` if needed).
- Produces: binary `kernelsonde-priv`. Reads `PS_DETECT_*` env, runs `fan_thread` logic, writes `PS_OP_ACTIVITY_DATA` frames to fd 3 (the `--fd` socketpair end). It ignores command opcodes (no pcap/raw slots).

- [ ] **Step 1: Write `src/kernel/src/kernel_priv_worker.c`.** Lift the fanotify half of `src/agent/src/priv_worker.c`: the `emit_activity()` callback (priv_worker.c:65), `fan_thread()` (priv_worker.c:88), and the `PS_DETECT_ENABLED` env→`fan_cfg` setup from its `main()` (priv_worker.c:623–638). Its `main()` parses `--fd N`, builds `fan_cfg` from `PS_DETECT_*`, starts the fan thread, and runs a minimal poll loop on the brain fd that simply drains/ignores inbound frames (no pcap/raw). No `g_write_mu` needed (single writer). Reuse the same `ps_priv_msg` framing helpers from `priv_protocol.h`.

```c
/* kernel_priv_worker.c — fanotify-only privilege-separated worker for
 * kernelsonded. Speaks the shared ps_priv_msg wire format but only ever
 * produces PS_OP_ACTIVITY_DATA frames. See priv_protocol.h. */
/* Structure (mirror priv_worker.c's fanotify path):
 *   - parse --fd N  -> g_brain_fd
 *   - emit_activity(const char *json, size_t len): frame as PS_OP_ACTIVITY_DATA, write to g_brain_fd
 *   - fan_thread(void *cfg): call ps_fan_monitor_run(cfg, emit_activity)
 *   - main(): read PS_DETECT_* env into struct fan_monitor_cfg, pthread_create(fan_thread),
 *             then poll(g_brain_fd) discarding any inbound frames until EOF, then exit.
 */
```
(Use the exact `fan_monitor` entry signature from `src/kernel/src/fan_monitor.h`; copy the env-parsing block verbatim from `priv_worker.c:623–638`.)

- [ ] **Step 2: Create `src/kernel/CMakeLists.txt`** with the priv target:

```cmake
# kernelsonde — Linux host behavioral-detection daemon + priv worker.
add_executable(kernelsonde-priv
    src/kernel_priv_worker.c
    src/fan_monitor.c
    src/proc_enrich.c
    src/sock_snapshot.c
)
target_include_directories(kernelsonde-priv PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/agent/src        # priv_protocol.h
    ${CMAKE_SOURCE_DIR}/src/agent/include)
target_link_libraries(kernelsonde-priv PRIVATE packetsonde_lib pthread)
```

- [ ] **Step 3: Wire the subdir.** In root `CMakeLists.txt`, after `add_subdirectory(src/agent)` add `add_subdirectory(src/kernel)`.

- [ ] **Step 4: Build.**

```bash
cd /data/opt/repo/packetsonde
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug >/dev/null && cmake --build build -j"$(nproc)" --target kernelsonde-priv 2>&1 | tail -8
test -x build/src/kernel/kernelsonde-priv && echo "kernelsonde-priv built"
```
Expected: builds; binary present.

- [ ] **Step 5: Commit.**

```bash
git add src/kernel/src/kernel_priv_worker.c src/kernel/CMakeLists.txt CMakeLists.txt
git commit -m "feat(kernel): kernelsonde-priv fanotify worker"
```

---

### Task 4: Build the `kernelsonded` daemon

The new brain: fork `kernelsonde-priv`, drop privs, build the activity ring, register the two detect modules, wire the activity sink / provenance / capture-control, serve the IPC socket, and check in to central.

**Files:**
- Create: `src/kernel/src/main.c`
- Modify: `src/kernel/CMakeLists.txt` (add `kernelsonded` target)

**Interfaces:**
- Consumes: `packetsonde_daemon` (config, ipc_server, central_checkin, module registry, obs_queue, priv_client, platform), `packetsonde_lib` (provenance, activity_record), and the moved detect sources (activity_ring, capture_session, baseline_store, the two modules).
- Produces: binary `kernelsonded`. Default IPC socket `/run/kernelsonde/agent.sock`; default sink `/var/lib/kernelsonde/activity.jsonl`; config dir `/etc/kernelsonded`. Externs the two modules: `ps_policy_overwatch_module`, `ps_baseline_monitor_module`.

- [ ] **Step 1: Write `src/kernel/src/main.c`** modeled on `src/agent/src/main.c`'s detect path (cited lines are in agent/main.c). Include the detect-relevant wiring only:
  - Find priv binary as `"%s/kernelsonde-priv"` via `ps_platform_exe_dir()` (cf. agent/main.c:1174), fork via `ps_platform_fork_priv_worker()` (1178), drop privs via `ps_platform_drop_privs()` reading `[kernel] user` / `PS_KERNEL_USER` (default `kernelsonded`).
  - Build `ps_act_ring_init()` (cf. 1295).
  - Register modules: `ps_module_registry_add(&reg, &ps_policy_overwatch_module)` and `&ps_baseline_monitor_module` (cf. 1341–1342); `ps_module_registry_init_all(&reg)` (1403).
  - `dispatch_priv_msg()` handling **only** `PS_OP_ACTIVITY_DATA`: `ps_act_ring_push()` → `activity_sink_append()` (sink default `/var/lib/kernelsonde/activity.jsonl`, env `PS_DETECT_SINK`) → `ps_capture_session_append()` → `maybe_ship_provenance()` (build `detect.file_provenance` via `ps_provenance_build_record()` + `ps_obs_queue_push()`). Lift these functions verbatim from agent/main.c:909–997, changing only the sink default path.
  - IPC server (`ps_ipc_server_*`) bound to `/run/kernelsonde/agent.sock` (resolution order: `[agent] socket` / `PS_AGENT_SOCKET` / Linux default `/run/kernelsonde/agent.sock`); handle the `detect.capture.control` frame (start/stop → `ps_capture_session_set/clear`), lifted from agent/main.c:833–885.
  - Central check-in via `packetsonde_daemon`'s `central_checkin` against `/etc/kernelsonded/keys` (own identity), reusing the same code path packetsonded uses.
  - Do **not** include any network module, discovery, `--via`, relay, flow, or pcap code.

- [ ] **Step 2: Add the `kernelsonded` target** to `src/kernel/CMakeLists.txt`:

```cmake
add_executable(kernelsonded
    src/main.c
    src/activity_ring.c
    src/baseline_store.c
    src/capture_session.c
    src/modules/policy_overwatch.c
    src/modules/baseline_monitor.c
)
target_include_directories(kernelsonded PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/modules
    ${CMAKE_SOURCE_DIR}/src/agent/src
    ${CMAKE_SOURCE_DIR}/src/agent/include)
target_link_libraries(kernelsonded PRIVATE packetsonde_daemon packetsonde_lib pthread)
```

- [ ] **Step 3: Build.**

```bash
cd /data/opt/repo/packetsonde
cmake --build build -j"$(nproc)" --target kernelsonded 2>&1 | tail -10
test -x build/src/kernel/kernelsonded && echo "kernelsonded built"
```
Expected: builds; binary present.

- [ ] **Step 4: Smoke test (no caps needed — should start, attempt priv fork, bind socket).**

```bash
cd /data/opt/repo/packetsonde
PS_AGENT_SOCKET=/tmp/ks-smoke.sock PS_DETECT_ENABLED=0 timeout 3 build/src/kernel/kernelsonded -c /dev/null 2>&1 | head -15 || true
test -S /tmp/ks-smoke.sock && echo "bound socket ok" ; rm -f /tmp/ks-smoke.sock
```
Expected: starts, logs its banner, binds the socket (full fanotify behavior is validated in Task 10).

- [ ] **Step 5: Commit.**

```bash
git add src/kernel/src/main.c src/kernel/CMakeLists.txt
git commit -m "feat(kernel): kernelsonded daemon (detect track)"
```

---

### Task 5: Decommission the detect track from `packetsonded`

Now that `kernelsonded` exists, strip detect from `packetsonded` and `packetsonde-priv` and drop the fanotify caps. This is the flip.

**Files:**
- Modify: `src/agent/src/main.c` (remove detect wiring)
- Modify: `src/agent/src/priv_worker.c` (remove fanotify path)
- Modify: `src/agent/CMakeLists.txt` (drop `KERNEL_DETECT_SOURCES` from `packetsonde-agent` + the moved files from `packetsonde-priv`)

**Interfaces:**
- Consumes: nothing new.
- Produces: a `packetsonded` with no fanotify/activity-ring/detect code; a `packetsonde-priv` handling only opcodes `0x01–0x05` (pcap/raw). `config_to_env.c`'s `[detect]` mapping stays (harmless) but `packetsonded` no longer acts on it; add a one-line warn if `[detect] enabled` is truthy.

- [ ] **Step 1: Strip detect from `src/agent/src/main.c`.** Remove: the detect includes (`activity_ring.h`, `activity_record.h`, `capture_session.h`, `provenance.h` — keep `priv_client.h`); `ps_act_ring_init()`; the two `ps_module_registry_add` lines for `ps_policy_overwatch_module` / `ps_baseline_monitor_module` and their `extern` decls; `activity_sink_append()`, `maybe_ship_provenance()`, and the `PS_OP_ACTIVITY_DATA` case in `dispatch_priv_msg()`; the `detect.capture.control` branch in `on_ipc_frame()`. Add, where the old `[detect]` was honored, a guard:

```c
if (ps_config_get_bool(&cfg, "detect", "enabled", false)) {
    ps_warn("main: [detect] is no longer handled by packetsonded; it moved to "
            "kernelsonded. Configure /etc/kernelsonded/kernelsonded.toml instead.");
}
```

- [ ] **Step 2: Strip fanotify from `src/agent/src/priv_worker.c`.** Remove `emit_activity()`, `fan_thread()`, the `PS_DETECT_ENABLED` branch in `main()`, and the `PS_OP_ACTIVITY_DATA` producer path. Keep opcodes `0x01–0x05`, `g_pcap[]`/`g_raw[]`, and the pcap/raw branches of `run_loop()`. Keep `g_write_mu` (still two writers? no — only pcap+raw now, both in run_loop; keep the mutex, it's harmless and guards the write path).

- [ ] **Step 3: Update `src/agent/CMakeLists.txt`.** Remove `${KERNEL_DETECT_SOURCES}` from `packetsonde-agent`'s source list (and `${KERNEL_DETECT_INCLUDE}` from its includes). For `packetsonde-priv`, remove the three `src/kernel/src/{fan_monitor,proc_enrich,sock_snapshot}.c` entries and the kernel include dir. Leave `KERNEL_DETECT_SOURCES` defined (Task 4's kernel target doesn't use it, but leaving it is harmless) — or delete it; deleting is cleaner since nothing references it now. Delete it.

- [ ] **Step 4: Build (Debug) + ctest + confirm packetsonded has no fanotify.**

```bash
cd /data/opt/repo/packetsonde
rm -rf build && cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug >/dev/null && cmake --build build -j"$(nproc)" 2>&1 | tail -6
ctest --test-dir build --output-on-failure 2>&1 | tail -10
echo "=== packetsonded must NOT reference fanotify ==="; /bin/grep -c fanotify build/src/agent/packetsonded 2>/dev/null; nm build/src/agent/packetsonded 2>/dev/null | /bin/grep -i fanotify && echo "!! still linked" || echo "no fanotify symbols ✓"
```
Expected: build + ctest green; `packetsonded` has no fanotify symbols; `kernelsonded`/`kernelsonde-priv` still build.

- [ ] **Step 5: Commit.**

```bash
git add src/agent/src/main.c src/agent/src/priv_worker.c src/agent/CMakeLists.txt
git commit -m "refactor(agent): remove detect track from packetsonded (moved to kernelsonded)"
```

---

### Task 6: systemd unit + example config + from-source install for kernelsonded

**Files:**
- Create: `packaging/kernelsonded.service`
- Create: `packaging/kernelsonded.toml`
- Modify: `packaging/packetsonded.service` (drop the detect-caps comment block)
- Modify: `src/kernel/CMakeLists.txt` (install rules, gated by `PS_PACKAGED_BUILD`)

**Interfaces:**
- Consumes: the `kernelsonded` + `kernelsonde-priv` targets.
- Produces: `/usr/sbin/kernelsonded` + `/usr/sbin/kernelsonde-priv` install; `/etc/kernelsonded/kernelsonded.toml.example`; `/etc/kernelsonded/keys/authorized/`; and (from-source, non-packaged) the unit at `/etc/systemd/system/kernelsonded.service`.

- [ ] **Step 1: Write `packaging/kernelsonded.service`** mirroring `packetsonded.service` but: `Description=kernelsonde host behavioral-detection agent`; `ExecStart=/usr/local/sbin/kernelsonded -c /etc/kernelsonded/kernelsonded.toml`; `User=kernelsonded`/`Group=kernelsonded`; caps `AmbientCapabilities=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH` + matching `CapabilityBoundingSet`; `ReadOnlyPaths=/etc/kernelsonded`; `RuntimeDirectory=kernelsonde`, `RuntimeDirectoryMode=0755`, `StateDirectory=kernelsonde`, `LogsDirectory=kernelsonde`; keep `ProtectSystem=strict`, `NoNewPrivileges=yes`, `MemoryDenyWriteExecute=yes`, etc. (Note: fanotify needs `CAP_SYS_ADMIN`, which is broad — keep the rest of the hardening tight.)

- [ ] **Step 2: Write `packaging/kernelsonded.toml`** from the existing `[detect]` keys (copy the `[detect]` section out of `packaging/packetsonded.toml`), with `sink`/`baseline_state_dir`/`learn_state_dir` defaults under `/var/lib/kernelsonde`, plus an `[agent]` block for `user = "kernelsonded"` and `socket` default note.

- [ ] **Step 3: Trim `packaging/packetsonded.toml` and `packaging/packetsonded.service`.** Remove the `[detect]` section from `packetsonded.toml`. Remove the detect-caps NOTE comment (the `CAP_SYS_ADMIN`/`CAP_DAC_READ_SEARCH` lines) from `packetsonded.service`, leaving only the `CAP_NET_RAW`/`CAP_NET_ADMIN` block.

- [ ] **Step 4: Add install rules to `src/kernel/CMakeLists.txt`** (mirror `src/agent`'s pattern, gated by the existing `PS_PACKAGED_BUILD` option):

```cmake
include(GNUInstallDirs)
install(TARGETS kernelsonded kernelsonde-priv RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
set(KS_CONFIG_DIR "/etc/kernelsonded" CACHE PATH "kernelsonded config + keys dir")
install(DIRECTORY DESTINATION ${KS_CONFIG_DIR})
install(DIRECTORY DESTINATION ${KS_CONFIG_DIR}/keys/authorized)
install(FILES ${CMAKE_SOURCE_DIR}/packaging/kernelsonded.toml
        DESTINATION ${KS_CONFIG_DIR} RENAME kernelsonded.toml.example)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT PS_PACKAGED_BUILD)
    install(FILES ${CMAKE_SOURCE_DIR}/packaging/kernelsonded.service
            DESTINATION /etc/systemd/system)
endif()
```

- [ ] **Step 5: Verify configure picks up the new install rules (packaged + non-packaged).**

```bash
cd /data/opt/repo/packetsonde
cmake -S . -B /tmp/ks-pkg -DPS_PACKAGED_BUILD=ON >/dev/null 2>&1 && /bin/grep -rq 'kernelsonded' /tmp/ks-pkg/src/kernel/cmake_install.cmake && echo "packaged install rules ok"
cmake -S . -B /tmp/ks-src >/dev/null 2>&1 && /bin/grep -rq 'etc/systemd/system' /tmp/ks-src/src/kernel/cmake_install.cmake && echo "from-source unit install ok"
rm -rf /tmp/ks-pkg /tmp/ks-src
```
Expected: both echoes print.

- [ ] **Step 6: Commit.**

```bash
git add packaging/kernelsonded.service packaging/kernelsonded.toml packaging/packetsonded.service packaging/packetsonded.toml src/kernel/CMakeLists.txt
git commit -m "feat(kernel): kernelsonded systemd unit, example config, install rules"
```

---

### Task 7: Debian packaging — ship both daemons as two disabled units

**Files:**
- Modify: `debian/rules` (generate + install the second unit; `-DPS_PACKAGED_BUILD=ON` already passed)
- Modify: `debian/packetsonde.postinst` (create `kernelsonded` user; chown its key dir)
- Modify: `debian/packetsonde.prerm` (stop both units on remove)
- Modify: `.gitignore` (generated `debian/kernelsonded.service`)
- Modify: root `CMakeLists.txt` + `debian/changelog` (version bump in lockstep)

**Interfaces:**
- Consumes: Task 6 install rules; the existing `debian/` packaging.
- Produces: one `.deb` shipping `kernelsonded` + `kernelsonde-priv` + `/lib/systemd/system/kernelsonded.service` (disabled) + `/etc/kernelsonded/` tree + the `kernelsonded` user.

- [ ] **Step 1: Extend `override_dh_installsystemd` in `debian/rules`** to generate and install the second unit alongside the first:

```make
override_dh_installsystemd:
	sed 's#/usr/local/sbin/packetsonded#/usr/sbin/packetsonded#' \
	    packaging/packetsonded.service > debian/packetsonded.service
	sed 's#/usr/local/sbin/kernelsonded#/usr/sbin/kernelsonded#' \
	    packaging/kernelsonded.service > debian/kernelsonded.service
	dh_installsystemd --name=packetsonded --no-enable --no-start
	dh_installsystemd --name=kernelsonded --no-enable --no-start
```

- [ ] **Step 2: Extend `debian/packetsonde.postinst`** `configure` case to also create the kernelsonded user and own its key dir (mirror the packetsonded block):

```sh
        if ! getent passwd kernelsonded >/dev/null; then
            adduser --system --group --no-create-home \
                    --home /nonexistent --shell /usr/sbin/nologin kernelsonded
        fi
        if [ -d /etc/kernelsonded/keys ]; then
            chown kernelsonded:kernelsonded /etc/kernelsonded/keys /etc/kernelsonded/keys/authorized
            chmod 0750 /etc/kernelsonded/keys
        fi
```
Update the printed next-steps to mention both daemons (enable `packetsonded` and/or `kernelsonded`).

- [ ] **Step 3: Extend `debian/packetsonde.prerm`** to stop both units on remove:

```sh
if [ "$1" = remove ] || [ "$1" = deconfigure ]; then
    if [ -d /run/systemd/system ]; then
        deb-systemd-invoke stop 'packetsonded.service' >/dev/null || true
        deb-systemd-invoke stop 'kernelsonded.service' >/dev/null || true
    fi
fi
```

- [ ] **Step 4: gitignore the generated unit.** Append `debian/kernelsonded.service` to `.gitignore` under the existing `debian/packetsonded.service` line. Also extend `debian/clean` to include `debian/kernelsonded.service`.

- [ ] **Step 5: Bump version in lockstep.** Edit root `CMakeLists.txt` `set(PS_VERSION_STR "0.1.8")` (next patch above current 0.1.7) and prepend a `debian/changelog` entry for `0.1.8` describing the kernelsonded split, dated newer than the previous entry (use `date -R`).

- [ ] **Step 6: Build the package on an Ubuntu host (ca1) and inspect contents (no install).**

```bash
cd /data/opt/repo/packetsonde
packaging/build-deb.sh 2>&1 | tail -6
DEB=$(ls -1t ../packetsonde_0.1.8_*.deb | head -1)
echo "=== contents (daemons + both units) ==="; dpkg-deb -c "$DEB" | /bin/grep -E 'sbin/(packetsonded|packetsonde-priv|kernelsonded|kernelsonde-priv)|systemd/system/(packetsonded|kernelsonded).service|etc/kernelsonded'
echo "=== lintian E: ==="; lintian "$DEB" 2>&1 | /bin/grep -E '^E:' || echo "no E: tags"
echo "=== kernelsonded unit ExecStart ==="; dpkg-deb --fsys-tarfile "$DEB" | tar -xO ./usr/lib/systemd/system/kernelsonded.service 2>/dev/null | /bin/grep ExecStart
```
Expected: both daemons + both priv workers + both `.service` files + `/etc/kernelsonded/...` present; no `E:`; `ExecStart=/usr/sbin/kernelsonded`.

- [ ] **Step 7: Commit.**

```bash
git add debian/rules debian/packetsonde.postinst debian/packetsonde.prerm debian/clean .gitignore CMakeLists.txt debian/changelog
git commit -m "deb: ship kernelsonded (second disabled unit, second user, prerm stop)"
```

---

### Task 8: CLI routing to kernelsonde locations

**Files:**
- Modify: `src/cli/verbs/detect.c` (default socket → `/run/kernelsonde/agent.sock`)
- Modify: `src/cli/verbs/watch.c`, `src/cli/verbs/inspect.c`, `src/cli/verbs/baseline.c`, `src/cli/verbs/sandbox_suggest.c` (default file/dir paths → `/var/lib/kernelsonde/...`)

**Interfaces:**
- Consumes: nothing new; these are default-path string changes.
- Produces: detect CLI verbs that target kernelsonde's runtime locations by default, still overridable by the existing `--socket` / `--source` / `--state-dir` flags.

- [ ] **Step 1: Repoint the `detect` verb socket.** In `src/cli/verbs/detect.c:24`, change `#define DEFAULT_SOCKET "/run/packetsonde/agent.sock"` to `#define DEFAULT_SOCKET "/run/kernelsonde/agent.sock"`. (Line 91's `opts->socket_path ? … : DEFAULT_SOCKET` then routes there; `--socket` still overrides.)

- [ ] **Step 2: Repoint the file-reader defaults.**
  - `src/cli/verbs/watch.c:15`: default `src` `/var/lib/packetsonde/activity.jsonl` → `/var/lib/kernelsonde/activity.jsonl`.
  - `src/cli/verbs/inspect.c:20`: same default path change.
  - `src/cli/verbs/baseline.c:42`: default `dir` `/var/lib/packetsonde/baseline` → `/var/lib/kernelsonde/baseline`.
  - `src/cli/verbs/sandbox_suggest.c:14`: default `/var/lib/packetsonde/sandbox-learn` → `/var/lib/kernelsonde/sandbox-learn`.
  (Each keeps its existing `--source`/`--state-dir` override.)

- [ ] **Step 3: Build the CLI + run CLI-related ctests.**

```bash
cd /data/opt/repo/packetsonde
cmake --build build -j"$(nproc)" --target packetsonde 2>&1 | tail -5
ctest --test-dir build --output-on-failure -R 'inspect|cli' 2>&1 | tail -8
/bin/grep -rn 'kernelsonde' src/cli/verbs/detect.c src/cli/verbs/watch.c src/cli/verbs/inspect.c src/cli/verbs/baseline.c src/cli/verbs/sandbox_suggest.c
```
Expected: CLI builds; the five files show the new `/run/kernelsonde` and `/var/lib/kernelsonde` defaults.

- [ ] **Step 4: Commit.**

```bash
git add src/cli/verbs/detect.c src/cli/verbs/watch.c src/cli/verbs/inspect.c src/cli/verbs/baseline.c src/cli/verbs/sandbox_suggest.c
git commit -m "cli: route detect verbs to kernelsonde socket + state paths"
```

---

### Task 9: Docs + migration notes

**Files:**
- Modify: `docs/build.md` (kernelsonde section + migration)
- Modify: `packaging/README.md` (kernelsonded artifacts)
- Modify: `README.md` (note the detect track now ships as `kernelsonded`)

**Interfaces:**
- Consumes: all prior tasks.
- Produces: operator docs only.

- [ ] **Step 1: Add a "kernelsonde (host detection agent)" subsection to `docs/build.md`** after the Debian-package section: what `kernelsonded` is, that the `.deb` installs it disabled alongside `packetsonded`, its caps/dirs/socket, the enable steps (`cp kernelsonded.toml.example → .toml`, `PS_KEY_DIR=/etc/kernelsonded/keys packetsonde key generate --name agent`, `systemctl enable --now kernelsonded`, `packetsonde register` for its own identity), and a **migration** note: hosts that ran `packetsonded` with `[detect]` move that block to `/etc/kernelsonded/kernelsonded.toml`, enable `kernelsonded`, and re-point `baseline_state_dir` (or copy `/var/lib/packetsonde/baseline` → `/var/lib/kernelsonde/baseline`). Note the salt pillar split is tracked separately (fleet-deploy plan).

- [ ] **Step 2: Add the kernelsonded rows to `packaging/README.md`'s file table** (`kernelsonded.service`, `kernelsonded.toml`).

- [ ] **Step 3: Update `README.md`** — the "Process-level detection track (Linux)" section gains a one-liner that it runs as the separate `kernelsonded` agent (same unprivileged + ambient-caps model), with the CLI verbs unchanged.

- [ ] **Step 4: Verify docs mention kernelsonded.**

```bash
cd /data/opt/repo/packetsonde
/bin/grep -lq kernelsonded docs/build.md packaging/README.md README.md && echo "docs OK"
```
Expected: `docs OK`.

- [ ] **Step 5: Commit.**

```bash
git add docs/build.md packaging/README.md README.md
git commit -m "docs: kernelsonde agent + detect-track migration"
```

---

### Task 10: End-to-end acceptance on an Ubuntu LXD chamber (manual)

No code. Runs on `ca1` + a disposable LXD `ubuntu:24.04` container (see the lxd-disposable-chamber method). Build deb tooling already present on `ca1`.

- [ ] **Step 1: Build the package.** `packaging/build-deb.sh` → `../packetsonde_0.1.8_amd64.deb`; `lintian` no `E:` tags.

- [ ] **Step 2: Launch container + install.** `sudo lxc launch ubuntu:24.04 ks-test`; push the `.deb`; `apt install ./pkg.deb`. Confirm `packetsonde version` = 0.1.8; both `/usr/sbin/kernelsonded` and `/usr/sbin/kernelsonde-priv` present; users `packetsonded` + `kernelsonded` exist; both units `disabled`+`inactive`.

- [ ] **Step 3: Capability isolation.** Enable `kernelsonded` only (`cp` config, `key generate` into `/etc/kernelsonded/keys`, `systemctl enable --now kernelsonded`). Confirm `systemctl show kernelsonded -p AmbientCapabilities` lists `CAP_SYS_ADMIN cap_dac_read_search`, and `systemctl show packetsonded -p AmbientCapabilities` does **not** (only NET_RAW/NET_ADMIN).

- [ ] **Step 4: Detect actually captures.** With `[detect] enabled=true` in `kernelsonded.toml`, generate file activity in a watched path; confirm records land in `/var/lib/kernelsonde/activity.jsonl` and `packetsonde watch` (default source now `/var/lib/kernelsonde/...`) shows them; `packetsonde detect` reaches `/run/kernelsonde/agent.sock`.

- [ ] **Step 5: Independent enrollment.** `kernelsonded` registers as its own agent (own key); if a central is reachable in the lab, confirm it lands as a distinct `pending` agent from `packetsonded`. (Otherwise verify the local key + register path runs without error.)

- [ ] **Step 6: Lifecycle.** Enable both units; `apt remove packetsonde` stops **both** (`is-active` inactive, processes gone); `apt purge` removes both config trees' conffiles; both users retained.

- [ ] **Step 7: Record results** in the SDD ledger; tear down the container (`sudo lxc delete -f ks-test`). No commit.

---

## Notes for the implementer

- Work on branch `feat/kernelsonde-split` (already created off `main`).
- Tasks 1–9 build + ctest on `ca1` (Debug builds; never Release for ctest). Task 10 needs the LXD chamber.
- Keep the tree building at every task: detect stays functional in `packetsonded` through Task 4 and only moves to `kernelsonded` in Task 5.
- No Claude/Co-Authored-By footers; SSH `git`, never `gh`.
