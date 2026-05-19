# packetsonde CLI Foundation — Plan 1 of 3


**Goal:** Restructure the repo, extract `libpacketsonde`, stand up the `packetsonde` CLI skeleton, fold `psctl` into `packetsonde agent`, and retire the `psctl` binary. End state: a working `packetsonde` binary that supports `version` and `agent <subcmd>` against a running `packetsonded`.

**Architecture:** Rename `agent/` → `src/agent/` and add siblings `src/lib/` (shared static library) and `src/cli/` (new CLI). Top-level CMake aggregates the three. Shared helpers (`json`, `log`, IPC client, ULID) move into `libpacketsonde`; the agent links it. The new CLI dispatches verbs through a small table; the `agent` verb reuses the existing psctl command handlers, now linked into `packetsonde` instead of a separate binary.

**Tech Stack:** C11, CMake 3.20+, pthreads (later plans), libedit (already used by psctl shell on macOS), getopt_long. No new third-party deps in Plan 1.

**Spec reference:** `docs/specs/2026-05-18-packetsonde-cli-design.md` §2 (architecture), §6.1 (`agent` and `version` verbs), §6.4 (DoD).

---

## File structure produced by this plan

```
packetsonde/
├── CMakeLists.txt                  # NEW — top-level, includes 3 subdirs
├── build.sh                        # MODIFIED — point at top-level CMake
├── src/
│   ├── lib/                        # NEW — libpacketsonde (static)
│   │   ├── CMakeLists.txt
│   │   ├── json.c                  # MOVED from agent/src
│   │   ├── json.h                  # MOVED from agent/src
│   │   ├── log.c                   # MOVED from agent/src
│   │   ├── log.h                   # MOVED from agent/src
│   │   ├── ipc.c                   # NEW — IPC client (UNIX socket)
│   │   ├── ipc.h
│   │   ├── ulid.c                  # NEW — ULID generator
│   │   └── ulid.h
│   ├── agent/                      # RENAMED from agent/
│   │   ├── CMakeLists.txt          # MODIFIED — link libpacketsonde
│   │   ├── src/…                   # unchanged source layout
│   │   ├── include/…
│   │   └── tests/…
│   └── cli/                        # NEW
│       ├── CMakeLists.txt
│       ├── main.c                  # entry point, arg parsing, dispatch
│       ├── verbs.h                 # verb dispatch table type
│       ├── verbs/
│       │   ├── version.c           # `packetsonde version`
│       │   └── agent.c             # `packetsonde agent <subcmd>` — wraps psctl handlers
│       └── tests/
│           └── test_args.c
```

Removed at end of plan:
- `agent/src/psctl/*` — moved/folded.
- `psctl` build target.
- Old top-level path `agent/` is gone (renamed).

---

## Task 1: Snapshot baseline build

Establish that the current tree builds before any restructure. If it doesn't build now, we won't know whether the restructure broke it.

**Files:** none modified.

- [ ] **Step 1: Run the baseline build**

Run: `cd /Users/billn/packetsonde && ./build.sh agent`
Expected: build completes with no errors; `agent/build/packetsonde-agent`, `agent/build/packetsonde-priv`, `agent/build/psctl` exist.

- [ ] **Step 2: Run the existing tests**

Run: `cd /Users/billn/packetsonde/agent/build && ctest --output-on-failure`
Expected: all tests pass.

- [ ] **Step 3: Record baseline binary list**

Run: `ls /Users/billn/packetsonde/agent/build/ | grep -E '^(packetsonde-agent|packetsonde-priv|psctl)$'`
Expected output:
```
packetsonde-agent
packetsonde-priv
psctl
```

No commit. This is a verification gate; if it fails, stop and fix before touching anything else.

---

## Task 2: Rename `agent/` → `src/agent/`

Pure git move so history follows. Done in its own commit so a reviewer can see "rename only, no content changes."

**Files:** all of `agent/` moved into `src/agent/`.

- [ ] **Step 1: Create `src/` and move the tree**

Run:
```bash
cd /Users/billn/packetsonde
mkdir -p src
git mv agent src/agent
```

- [ ] **Step 2: Verify the move**

Run: `ls src/agent/`
Expected: contains `CMakeLists.txt`, `src/`, `include/`, `tests/`, `conf/`, `debian/`, `scripts/`, `freebsd/`, `build-deb.sh`, `build-pkg.sh`, `configure`.

- [ ] **Step 3: Confirm history is preserved**

Run: `git log --follow src/agent/src/main.c | head -5`
Expected: shows commits from before the rename (e.g. `aa6307d`, `3b66350`).

- [ ] **Step 4: Commit the rename only**

Run:
```bash
git add -A
git commit -m "refactor(repo): rename agent/ to src/agent/

Prepares the tree for libpacketsonde extraction and a sibling
src/cli/ directory. Pure git mv; no content changes."
```

---

## Task 3: Update `build.sh` to drive the new layout

Build.sh currently does `cd agent/build && cmake ..`. We're going to introduce a top-level CMakeLists.txt that includes the three subdirs. For this task, just rewrite build.sh to use the top-level build dir; the top-level CMakeLists.txt is created in Task 4.

**Files:**
- Modify: `build.sh`

- [ ] **Step 1: Rewrite build.sh**

Replace `/Users/billn/packetsonde/build.sh` with:

```bash
#!/bin/bash
# Build packetsonde — agent + CLI + UE editor module.
#   ./build.sh           build agent + cli (default)
#   ./build.sh agent     agent only
#   ./build.sh cli       cli only
#   ./build.sh native    agent + cli (alias)
#   ./build.sh editor    UE editor only
#   ./build.sh all       everything (native + editor)

set -e
trap 'echo ""; echo "=== BUILD FAILED ==="' ERR

PROJECT_DIR="/Users/billn/packetsonde"
PROJECT_FILE="$PROJECT_DIR/packetsonde.uproject"
UE_DIR="/Users/Shared/Epic Games/UE_5.7"
BUILD_SCRIPT="$UE_DIR/Engine/Build/BatchFiles/Mac/Build.sh"

BUILD_DIR="$PROJECT_DIR/build"

TARGET="${1:-native}"

echo "=== packetsonde build ($TARGET) ==="
echo "    Branch: $(cd "$PROJECT_DIR" && git branch --show-current 2>/dev/null || echo none)"
echo "    HEAD:   $(cd "$PROJECT_DIR" && git log --oneline -1 2>/dev/null || echo none)"
echo ""

build_native() {
    local goal="$1"   # all|agent|cli
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake "$PROJECT_DIR" 2>&1 | tail -5
    case "$goal" in
        agent) make -j"$(sysctl -n hw.ncpu)" packetsonde-agent packetsonde-priv 2>&1 | tail -20 ;;
        cli)   make -j"$(sysctl -n hw.ncpu)" packetsonde                          2>&1 | tail -20 ;;
        all)   make -j"$(sysctl -n hw.ncpu)"                                       2>&1 | tail -20 ;;
    esac
}

case "$TARGET" in
    agent)         echo "--- Agent ---";   build_native agent ;;
    cli)           echo "--- CLI ---";     build_native cli ;;
    native|all)    echo "--- Native ---";  build_native all ;;
    editor)
        echo "--- Editor ---"
        cd "$PROJECT_DIR"
        "$BUILD_SCRIPT" packetsondeEditor Mac Development "$PROJECT_FILE" 2>&1 | tail -15
        ;;
    everything)
        echo "--- Native ---"; build_native all
        echo ""
        echo "--- Editor ---"
        cd "$PROJECT_DIR"
        "$BUILD_SCRIPT" packetsondeEditor Mac Development "$PROJECT_FILE" 2>&1 | tail -15
        ;;
    *)
        echo "Unknown target: $TARGET"
        echo "Usage: $0 [agent|cli|native|editor|everything]"
        exit 2
        ;;
esac

echo ""
echo "=== Build complete ==="
```

- [ ] **Step 2: Verify executable bit**

Run: `chmod +x /Users/billn/packetsonde/build.sh && ls -l /Users/billn/packetsonde/build.sh`
Expected: `-rwxr-xr-x ... build.sh`

- [ ] **Step 3: Add `build/` to .gitignore (if not already)**

Run: `grep -qxF 'build/' /Users/billn/packetsonde/.gitignore || echo 'build/' >> /Users/billn/packetsonde/.gitignore`
Then: `git diff .gitignore` — expected: either no diff (already present) or one added line `build/`.

- [ ] **Step 4: Commit**

```bash
cd /Users/billn/packetsonde
git add build.sh .gitignore
git commit -m "build: top-level build.sh and build/ dir

Single build root at ./build. New targets: cli, native, everything."
```

(Build will be broken until Task 4 lands the top-level CMakeLists.txt — that's expected.)

---

## Task 4: Top-level `CMakeLists.txt` (aggregator)

Add a top-level CMake that includes `src/lib`, `src/agent`, and `src/cli` subdirectories. Defers all real configuration to those subdirs.

**Files:**
- Create: `CMakeLists.txt`

- [ ] **Step 1: Create `/Users/billn/packetsonde/CMakeLists.txt`**

```cmake
cmake_minimum_required(VERSION 3.20)
project(packetsonde VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

enable_testing()

# Project-wide options propagate to subdirs.
option(WITH_REDIS    "Enable Redis bridge"             ON)
option(WITH_PCAP     "Enable libpcap"                  ON)
option(WITH_SSL      "Enable OpenSSL/TLS"              ON)
option(BUILD_STATIC  "Build statically linked binaries" OFF)

if(BUILD_STATIC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

# Order matters: lib first (others depend on it), then agent and cli.
add_subdirectory(src/lib)
add_subdirectory(src/agent)
add_subdirectory(src/cli)
```

- [ ] **Step 2: Create a placeholder `src/lib/CMakeLists.txt`**

So the top-level config succeeds before Task 5 fills in real content.

`/Users/billn/packetsonde/src/lib/CMakeLists.txt`:
```cmake
# libpacketsonde — shared static library used by agent and cli.
# Real contents land in Task 5.
add_library(packetsonde_lib INTERFACE)
target_include_directories(packetsonde_lib INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
```

- [ ] **Step 3: Create a placeholder `src/cli/CMakeLists.txt`**

`/Users/billn/packetsonde/src/cli/CMakeLists.txt`:
```cmake
# packetsonde CLI — real target lands in Task 8.
# Placeholder so the top-level CMake configures cleanly.
```

- [ ] **Step 4: Verify configure-only succeeds**

Run:
```bash
cd /Users/billn/packetsonde
mkdir -p build
cd build
cmake ..
```
Expected: configures cleanly, no errors. (The existing `src/agent/CMakeLists.txt` still references `src/...` relative to itself, so it should keep building the agent.)

- [ ] **Step 5: Verify agent still builds**

Run: `cd /Users/billn/packetsonde/build && make -j$(sysctl -n hw.ncpu) packetsonde-agent packetsonde-priv psctl`
Expected: all three binaries build with no errors.

- [ ] **Step 6: Commit**

```bash
cd /Users/billn/packetsonde
git add CMakeLists.txt src/lib/CMakeLists.txt src/cli/CMakeLists.txt
git commit -m "build: top-level CMake aggregator

Adds src/lib and src/cli stubs alongside src/agent."
```

---

## Task 5: Extract `json` and `log` into `libpacketsonde`

Move `json.c/h` and `log.c/h` from `src/agent/src/` into `src/lib/`. Replace the agent's compilation of those files with a link to the new static library. Tests inside `src/agent/tests/` that compiled `src/json.c` directly are updated to link `packetsonde_lib` instead.

**Files:**
- Move: `src/agent/src/json.c` → `src/lib/json.c`
- Move: `src/agent/src/json.h` → `src/lib/json.h`
- Move: `src/agent/src/log.c` → `src/lib/log.c`
- Move: `src/agent/src/log.h` → `src/lib/log.h`
- Modify: `src/lib/CMakeLists.txt`
- Modify: `src/agent/CMakeLists.txt`

- [ ] **Step 1: Move the files preserving history**

```bash
cd /Users/billn/packetsonde
git mv src/agent/src/json.c src/lib/json.c
git mv src/agent/src/json.h src/lib/json.h
git mv src/agent/src/log.c  src/lib/log.c
git mv src/agent/src/log.h  src/lib/log.h
```

- [ ] **Step 2: Replace `src/lib/CMakeLists.txt`**

Overwrite `/Users/billn/packetsonde/src/lib/CMakeLists.txt`:
```cmake
# libpacketsonde — shared static library used by agent and cli.
add_library(packetsonde_lib STATIC
    json.c
    log.c
)
target_include_directories(packetsonde_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# Keep position-independent so a future shared-lib build is painless.
set_target_properties(packetsonde_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)
```

- [ ] **Step 3: Edit `src/agent/CMakeLists.txt`** to drop `src/json.c` and `src/log.c` from `AGENT_CORE_SOURCES` and link the library.

In `/Users/billn/packetsonde/src/agent/CMakeLists.txt`:

Remove these two lines from `AGENT_CORE_SOURCES` (originally lines 67–68):
```
    src/log.c
    src/json.c
```

After the `add_executable(packetsonde-agent ...)` block, link the library. Find:
```cmake
target_include_directories(packetsonde-agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/compat
    ${CMAKE_CURRENT_BINARY_DIR}
)
```
Add immediately after:
```cmake
target_link_libraries(packetsonde-agent PRIVATE packetsonde_lib)
```

Do the same for `packetsonde-priv`. Find:
```cmake
add_executable(packetsonde-priv src/priv_worker.c src/log.c src/platform/unix.c)
```
Replace with:
```cmake
add_executable(packetsonde-priv src/priv_worker.c src/platform/unix.c)
```
Then after the `target_include_directories(packetsonde-priv …)` block add:
```cmake
target_link_libraries(packetsonde-priv PRIVATE packetsonde_lib)
```

Do the same for the `psctl` target. Find:
```cmake
add_executable(psctl
    src/psctl/psctl_main.c
    src/psctl/psctl_connection.c
    src/psctl/psctl_commands.c
    src/psctl/psctl_shell.c
    src/psctl/psctl_format.c
    src/json.c
    src/log.c
    src/platform/unix.c
)
```
Replace with:
```cmake
add_executable(psctl
    src/psctl/psctl_main.c
    src/psctl/psctl_connection.c
    src/psctl/psctl_commands.c
    src/psctl/psctl_shell.c
    src/psctl/psctl_format.c
    src/platform/unix.c
)
```
Add after `target_include_directories(psctl …)`:
```cmake
target_link_libraries(psctl PRIVATE packetsonde_lib)
```

For each test target that lists `src/json.c` or `src/log.c` in its sources, remove those entries and add `target_link_libraries(<test_target> PRIVATE packetsonde_lib)` immediately after the `target_include_directories(...)` for that test.

Test targets to update: `test_config`, `test_ipc_framing`, `test_module_registry`, `test_icmp_traceroute`, `test_tcp_traceroute`, `test_udp_traceroute`, `test_tcp_probe`, `test_udp_probe`, `test_flow_tracker`, `test_neighbor_listener`, `test_dns_listener`, `test_honeypot_listener`.

(`test_priv_protocol` does not link json/log so it's unchanged.)

- [ ] **Step 4: Clean build and verify**

```bash
cd /Users/billn/packetsonde
rm -rf build
mkdir build && cd build
cmake ..
make -j$(sysctl -n hw.ncpu)
```
Expected: agent, priv, psctl, and all test executables build with no errors. Look for the line `Built target packetsonde_lib` in output.

- [ ] **Step 5: Run all tests**

Run: `cd /Users/billn/packetsonde/build && ctest --output-on-failure`
Expected: same tests pass as in Task 1, Step 2.

- [ ] **Step 6: Commit**

```bash
cd /Users/billn/packetsonde
git add -A
git commit -m "build(lib): extract json/log into libpacketsonde

Moves src/agent/src/{json,log}.{c,h} into src/lib/ and makes the agent,
priv worker, psctl, and all tests link the new static library.
Preserves git history via git mv."
```

---

## Task 6: ULID generator in `libpacketsonde` (TDD)

The finding record requires monotonic-within-millisecond IDs. ULID is the canonical choice: 48-bit timestamp + 80-bit randomness, Crockford base32, sortable. Add it to `libpacketsonde` now because run IDs land in Plan 2 and Plan 1's `version` verb is a good early consumer (it generates a build-stamp ULID for the build).

**Files:**
- Create: `src/lib/ulid.h`, `src/lib/ulid.c`
- Create: `src/lib/tests/test_ulid.c`
- Modify: `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test**

Create `/Users/billn/packetsonde/src/lib/tests/test_ulid.c`:
```c
#include "../ulid.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static void test_length_and_charset(void) {
    char buf[PS_ULID_STRLEN + 1];
    int rc = ps_ulid_new(buf, sizeof(buf));
    assert(rc == 0);
    assert(strlen(buf) == PS_ULID_STRLEN);
    /* Crockford base32: 0-9, A-Z minus I, L, O, U */
    for (size_t i = 0; i < PS_ULID_STRLEN; i++) {
        char c = buf[i];
        int ok = (c >= '0' && c <= '9') ||
                 (c >= 'A' && c <= 'Z' && c != 'I' && c != 'L' && c != 'O' && c != 'U');
        if (!ok) {
            fprintf(stderr, "bad char '%c' at pos %zu\n", c, i);
            assert(0);
        }
    }
}

static void test_monotonic_within_ms(void) {
    /* Two ULIDs generated back-to-back must be strictly increasing
     * as strings (sortable property). */
    char a[PS_ULID_STRLEN + 1], b[PS_ULID_STRLEN + 1];
    ps_ulid_new(a, sizeof(a));
    ps_ulid_new(b, sizeof(b));
    assert(strcmp(a, b) < 0);
}

static void test_short_buffer_errors(void) {
    char small[5];
    int rc = ps_ulid_new(small, sizeof(small));
    assert(rc != 0);
}

int main(void) {
    test_length_and_charset();
    test_monotonic_within_ms();
    test_short_buffer_errors();
    printf("test_ulid: OK\n");
    return 0;
}
```

- [ ] **Step 2: Wire the test into CMake**

In `/Users/billn/packetsonde/src/lib/CMakeLists.txt`, append:
```cmake
if(BUILD_TESTING)
    add_executable(test_ulid tests/test_ulid.c)
    target_link_libraries(test_ulid PRIVATE packetsonde_lib)
    add_test(NAME test_ulid COMMAND test_ulid)
endif()
```

Also add `BUILD_TESTING` to top-level CMakeLists.txt — already implied by `enable_testing()`, but to be explicit, in `/Users/billn/packetsonde/CMakeLists.txt` after `enable_testing()` add:
```cmake
set(BUILD_TESTING ON)
```

- [ ] **Step 3: Run test to verify it fails (no `ulid.h` yet)**

```bash
cd /Users/billn/packetsonde/build
cmake ..
make test_ulid 2>&1 | tail -10
```
Expected: build error referencing missing `ulid.h`.

- [ ] **Step 4: Implement `src/lib/ulid.h`**

```c
#ifndef PS_ULID_H
#define PS_ULID_H

#include <stddef.h>

/* ULID: 26-char Crockford base32 string (no NUL). */
#define PS_ULID_STRLEN 26

/* Generate a new ULID into buf. buf must be >= PS_ULID_STRLEN+1.
 * Writes a NUL-terminated string. Returns 0 on success, -1 on failure
 * (bad buf size, RNG error). Thread-safe; monotonic within the same
 * millisecond for a single process. */
int ps_ulid_new(char *buf, size_t bufsz);

#endif
```

- [ ] **Step 5: Implement `src/lib/ulid.c`**

```c
#include "ulid.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

static const char CROCKFORD[33] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_last_ms = 0;
static uint8_t  g_last_rand[10] = {0};

static int read_random(uint8_t *out, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, out + got, n - got);
        if (r <= 0) { close(fd); return -1; }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}

/* Increment an 80-bit big-endian counter in place. Used for the
 * monotonic-within-the-same-ms guarantee. */
static void inc80(uint8_t *r) {
    for (int i = 9; i >= 0; i--) {
        if (++r[i] != 0) return;
    }
}

int ps_ulid_new(char *buf, size_t bufsz) {
    if (!buf || bufsz < PS_ULID_STRLEN + 1) return -1;

    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) return -1;
    uint64_t ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);

    pthread_mutex_lock(&g_lock);
    uint8_t r[10];
    if (ms == g_last_ms) {
        memcpy(r, g_last_rand, 10);
        inc80(r);
    } else {
        if (read_random(r, 10) != 0) {
            pthread_mutex_unlock(&g_lock);
            return -1;
        }
    }
    g_last_ms = ms;
    memcpy(g_last_rand, r, 10);
    pthread_mutex_unlock(&g_lock);

    /* Timestamp: 48 bits → 10 base32 chars (top 2 bits of the 50-bit
     * field are always zero for ms-since-epoch in our era). */
    uint64_t t = ms & 0xFFFFFFFFFFFFULL;
    for (int i = 9; i >= 0; i--) {
        buf[i] = CROCKFORD[t & 0x1F];
        t >>= 5;
    }

    /* Randomness: 80 bits → 16 base32 chars. Treat r as one big number
     * split into a 16-bit high half and a 64-bit low half; shift the
     * combined value right 5 bits at a time, emitting from the back. */
    uint64_t lo = 0;
    for (int i = 2; i < 10; i++) lo = (lo << 8) | r[i];
    uint64_t hi = ((uint64_t)r[0] << 8) | r[1];

    for (int i = 15; i >= 0; i--) {
        uint32_t five = (uint32_t)(lo & 0x1F);
        uint64_t carry = (hi & 0x1F);
        lo = (lo >> 5) | (carry << 59);
        hi = (hi >> 5);
        buf[10 + i] = CROCKFORD[five];
    }
    buf[PS_ULID_STRLEN] = '\0';
    return 0;
}
```

- [ ] **Step 6: Build and run test**

```bash
cd /Users/billn/packetsonde/build
cmake ..
make test_ulid
ctest -R '^test_ulid$' --output-on-failure
```
Expected: `test_ulid: OK` and PASS.

- [ ] **Step 7: Commit**

```bash
cd /Users/billn/packetsonde
git add src/lib/ulid.h src/lib/ulid.c src/lib/tests/test_ulid.c src/lib/CMakeLists.txt CMakeLists.txt
git commit -m "feat(lib): add ULID generator

48-bit ms timestamp + 80-bit randomness, Crockford base32, monotonic
within a millisecond. Used by run_id and finding.id in Plan 2."
```

---

## Task 7: IPC client (`ipc.c`) in `libpacketsonde`

The CLI's `agent` verb needs to connect to the agent's UNIX socket. The existing implementation lives in `src/agent/src/psctl/psctl_connection.c`. Move it into `libpacketsonde` with the prefix `ps_ipc_*` and have `psctl_connection.c` become a thin compatibility shim (for the duration of Plan 1 only — Task 10 retires it).

**Files:**
- Create: `src/lib/ipc.c`, `src/lib/ipc.h`
- Modify: `src/agent/src/psctl/psctl_connection.c` (becomes a shim)
- Modify: `src/lib/CMakeLists.txt`

- [ ] **Step 1: Create `src/lib/ipc.h`**

```c
#ifndef PS_IPC_H
#define PS_IPC_H

#include <stddef.h>

struct ps_ipc_conn {
    int fd;
};

int  ps_ipc_connect(struct ps_ipc_conn *conn, const char *socket_path);
void ps_ipc_disconnect(struct ps_ipc_conn *conn);

int  ps_ipc_send(struct ps_ipc_conn *conn, const char *channel, const char *payload);

/* Receive one frame. Returns 0 on success, -1 on error/timeout. */
int  ps_ipc_recv(struct ps_ipc_conn *conn,
                 char *channel_buf, size_t ch_bufsz,
                 char *payload_buf, size_t pl_bufsz,
                 int timeout_ms);

typedef void (*ps_ipc_frame_fn)(const char *channel, const char *payload, void *userdata);

int  ps_ipc_recv_loop(struct ps_ipc_conn *conn, int timeout_ms,
                      ps_ipc_frame_fn fn, void *userdata);

#endif
```

- [ ] **Step 2: Create `src/lib/ipc.c`**

Copy the body of `/Users/billn/packetsonde/src/agent/src/psctl/psctl_connection.c` into `/Users/billn/packetsonde/src/lib/ipc.c`, then rename symbols:
- `psctl_conn` → `ps_ipc_conn`
- `psctl_connect` → `ps_ipc_connect`
- `psctl_disconnect` → `ps_ipc_disconnect`
- `psctl_send` → `ps_ipc_send`
- `psctl_recv` → `ps_ipc_recv`
- `psctl_recv_loop` → `ps_ipc_recv_loop`
- `psctl_frame_fn` → `ps_ipc_frame_fn`

Change the `#include "psctl_connection.h"` to `#include "ipc.h"`.

- [ ] **Step 3: Make the old `psctl_connection.c` a shim**

Replace `/Users/billn/packetsonde/src/agent/src/psctl/psctl_connection.c` with:
```c
/* Compatibility shim — forwards psctl_* names to libpacketsonde ps_ipc_*.
 * Retired in the task that retires the psctl binary. */
#include "psctl_connection.h"
#include "ipc.h"
#include <string.h>

_Static_assert(sizeof(struct psctl_conn) == sizeof(struct ps_ipc_conn),
               "psctl_conn must layout-match ps_ipc_conn");

int psctl_connect(struct psctl_conn *c, const char *p) {
    return ps_ipc_connect((struct ps_ipc_conn *)c, p);
}
void psctl_disconnect(struct psctl_conn *c) {
    ps_ipc_disconnect((struct ps_ipc_conn *)c);
}
int psctl_send(struct psctl_conn *c, const char *ch, const char *pl) {
    return ps_ipc_send((struct ps_ipc_conn *)c, ch, pl);
}
int psctl_recv(struct psctl_conn *c, char *cb, size_t cs, char *pb, size_t ps, int t) {
    return ps_ipc_recv((struct ps_ipc_conn *)c, cb, cs, pb, ps, t);
}
int psctl_recv_loop(struct psctl_conn *c, int t, psctl_frame_fn fn, void *u) {
    /* psctl_frame_fn and ps_ipc_frame_fn have identical signatures. */
    return ps_ipc_recv_loop((struct ps_ipc_conn *)c, t, (ps_ipc_frame_fn)fn, u);
}
```

- [ ] **Step 4: Wire ipc.c into libpacketsonde**

In `/Users/billn/packetsonde/src/lib/CMakeLists.txt`, edit the source list to:
```cmake
add_library(packetsonde_lib STATIC
    json.c
    log.c
    ulid.c
    ipc.c
)
```

- [ ] **Step 5: Build and verify**

```bash
cd /Users/billn/packetsonde/build
cmake ..
make -j$(sysctl -n hw.ncpu) packetsonde-agent packetsonde-priv psctl
```
Expected: builds clean.

- [ ] **Step 6: Smoke-test psctl still works**

Start the agent if not running (in another terminal): `cd /Users/billn/packetsonde/build/src/agent && ./packetsonde-agent ...`
(If you don't have an agent running locally, skip this; the build success is the main signal.)

Run: `/Users/billn/packetsonde/build/src/agent/psctl version`
Expected: prints version text. (If no agent: prints psctl version then errors about socket — acceptable, the IPC path is the same code as before.)

- [ ] **Step 7: Commit**

```bash
cd /Users/billn/packetsonde
git add src/lib/ipc.c src/lib/ipc.h src/lib/CMakeLists.txt src/agent/src/psctl/psctl_connection.c
git commit -m "feat(lib): move IPC client into libpacketsonde

ps_ipc_* takes ownership; psctl_connection.c is now a thin shim that
forwards to the library. The shim disappears with psctl in Plan 1's
final tasks."
```

---

## Task 8: CLI skeleton — `main.c`, arg parsing, dispatch table, `version` verb (TDD)

Stand up the new `packetsonde` binary with a minimal verb-dispatch architecture. Implement `version` end-to-end so we have a smoke target.

**Files:**
- Create: `src/cli/main.c`, `src/cli/verbs.h`
- Create: `src/cli/verbs/version.c`
- Create: `src/cli/tests/test_args.c`
- Modify: `src/cli/CMakeLists.txt`

- [ ] **Step 1: Write the failing arg-parser test**

Create `/Users/billn/packetsonde/src/cli/tests/test_args.c`:
```c
#include "../args.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_defaults(void) {
    char *argv[] = { "packetsonde", "version" };
    struct ps_args a = {0};
    int rc = ps_args_parse(2, argv, &a);
    assert(rc == 0);
    assert(a.fmt == PS_FMT_AUTO);
    assert(a.verb_argc == 1);
    assert(strcmp(a.verb_argv[0], "version") == 0);
    assert(a.via == NULL);
}

static void test_json_flag(void) {
    char *argv[] = { "packetsonde", "--json", "version" };
    struct ps_args a = {0};
    int rc = ps_args_parse(3, argv, &a);
    assert(rc == 0);
    assert(a.fmt == PS_FMT_JSON);
    assert(strcmp(a.verb_argv[0], "version") == 0);
}

static void test_via(void) {
    char *argv[] = { "packetsonde", "--via", "trunkbox", "version" };
    struct ps_args a = {0};
    int rc = ps_args_parse(4, argv, &a);
    assert(rc == 0);
    assert(a.via && strcmp(a.via, "trunkbox") == 0);
}

static void test_no_verb_is_error(void) {
    char *argv[] = { "packetsonde" };
    struct ps_args a = {0};
    int rc = ps_args_parse(1, argv, &a);
    assert(rc != 0);
}

static void test_unknown_flag_is_error(void) {
    char *argv[] = { "packetsonde", "--nope", "version" };
    struct ps_args a = {0};
    int rc = ps_args_parse(3, argv, &a);
    assert(rc != 0);
}

int main(void) {
    test_defaults();
    test_json_flag();
    test_via();
    test_no_verb_is_error();
    test_unknown_flag_is_error();
    printf("test_args: OK\n");
    return 0;
}
```

- [ ] **Step 2: Wire test into CMake**

Replace `/Users/billn/packetsonde/src/cli/CMakeLists.txt` with:
```cmake
set(CLI_SOURCES
    main.c
    args.c
    dispatch.c
    verbs/version.c
)

add_executable(packetsonde ${CLI_SOURCES})
target_include_directories(packetsonde PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/src      # for now, agent headers
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/src/psctl
)
target_link_libraries(packetsonde PRIVATE packetsonde_lib)

if(BUILD_TESTING)
    add_executable(test_args tests/test_args.c args.c)
    target_include_directories(test_args PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_args PRIVATE packetsonde_lib)
    add_test(NAME test_args COMMAND test_args)
endif()
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make test_args 2>&1 | tail -10
```
Expected: build error referencing missing `args.h`.

- [ ] **Step 4: Create `src/cli/args.h`**

```c
#ifndef PS_ARGS_H
#define PS_ARGS_H

#include <stdbool.h>

enum ps_fmt {
    PS_FMT_AUTO = 0,   /* text on tty, jsonl otherwise */
    PS_FMT_TEXT,
    PS_FMT_JSON,
    PS_FMT_JSONL,
    PS_FMT_QUIET
};

struct ps_args {
    enum ps_fmt fmt;
    const char *via;          /* --via name, or NULL */
    const char *config_path;  /* --config path, or NULL */
    const char *socket_path;  /* --socket path (override), or NULL */
    bool no_color;
    bool auto_append;
    int concurrency;          /* --concurrency, 0 = default */
    int rate_pps;             /* --rate, 0 = default */

    int    verb_argc;
    char **verb_argv;         /* points into the original argv */
};

int ps_args_parse(int argc, char **argv, struct ps_args *out);

/* Prints usage to stderr. */
void ps_args_usage(const char *prog);

#endif
```

- [ ] **Step 5: Implement `src/cli/args.c`**

```c
#include "args.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ps_args_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options] <verb> [args...]\n"
        "\n"
        "Verbs (v1):\n"
        "  version              Show version\n"
        "  agent <subcmd>       Control / query the local packetsonded agent\n"
        "  help                 Show help\n"
        "\n"
        "Output:\n"
        "  --text               Force text output\n"
        "  --json               Force JSON output\n"
        "  --jsonl              Force JSONL output\n"
        "  --quiet              Tab-separated minimal output\n"
        "  --no-color           Suppress color (also honors NO_COLOR)\n"
        "  --auto-append        Tee JSONL to ~/.local/state/packetsonde/findings-YYYY-MM-DD.jsonl\n"
        "\n"
        "Execution:\n"
        "  --via <name>         Dispatch to a named agent (v1: only 'local')\n"
        "  --concurrency N      Worker pool size (default 16)\n"
        "  --rate PPS           Probe-rate cap\n"
        "  --socket PATH        Override local agent socket path\n"
        "  --config PATH        Override config file location\n"
        "\n"
        "Run `%s help` for command help, or `%s <verb> --help`.\n",
        prog, prog, prog);
}

enum {
    OPT_TEXT = 1000, OPT_JSON, OPT_JSONL, OPT_QUIET,
    OPT_NO_COLOR, OPT_AUTO_APPEND,
    OPT_VIA, OPT_CONCURRENCY, OPT_RATE, OPT_SOCKET, OPT_CONFIG
};

int ps_args_parse(int argc, char **argv, struct ps_args *out) {
    if (!argv || !out) return -1;
    memset(out, 0, sizeof(*out));
    out->fmt = PS_FMT_AUTO;

    static const struct option longopts[] = {
        { "text",         no_argument,       NULL, OPT_TEXT },
        { "json",         no_argument,       NULL, OPT_JSON },
        { "jsonl",        no_argument,       NULL, OPT_JSONL },
        { "quiet",        no_argument,       NULL, OPT_QUIET },
        { "no-color",     no_argument,       NULL, OPT_NO_COLOR },
        { "auto-append",  no_argument,       NULL, OPT_AUTO_APPEND },
        { "via",          required_argument, NULL, OPT_VIA },
        { "concurrency",  required_argument, NULL, OPT_CONCURRENCY },
        { "rate",         required_argument, NULL, OPT_RATE },
        { "socket",       required_argument, NULL, OPT_SOCKET },
        { "config",       required_argument, NULL, OPT_CONFIG },
        { "help",         no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    /* Allow flags to appear only before the verb. Tell getopt to stop
     * at the first non-option (POSIXLY_CORRECT style). */
    optind = 1;
    opterr = 0;
    int opt;
    while ((opt = getopt_long(argc, argv, "+h", longopts, NULL)) != -1) {
        switch (opt) {
            case OPT_TEXT:        out->fmt = PS_FMT_TEXT; break;
            case OPT_JSON:        out->fmt = PS_FMT_JSON; break;
            case OPT_JSONL:       out->fmt = PS_FMT_JSONL; break;
            case OPT_QUIET:       out->fmt = PS_FMT_QUIET; break;
            case OPT_NO_COLOR:    out->no_color = true; break;
            case OPT_AUTO_APPEND: out->auto_append = true; break;
            case OPT_VIA:         out->via = optarg; break;
            case OPT_CONCURRENCY: out->concurrency = atoi(optarg); break;
            case OPT_RATE:        out->rate_pps = atoi(optarg); break;
            case OPT_SOCKET:      out->socket_path = optarg; break;
            case OPT_CONFIG:      out->config_path = optarg; break;
            case 'h':
                ps_args_usage(argv[0]);
                return 1;   /* not an error, but caller should exit 0 */
            case '?':
            default:
                fprintf(stderr, "%s: unknown option\n", argv[0]);
                return -1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "%s: missing verb\n", argv[0]);
        return -1;
    }

    out->verb_argc = argc - optind;
    out->verb_argv = argv + optind;
    return 0;
}
```

- [ ] **Step 6: Run test to verify it passes**

```bash
cd /Users/billn/packetsonde/build && make test_args && ctest -R '^test_args$' --output-on-failure
```
Expected: `test_args: OK` and PASS.

- [ ] **Step 7: Create dispatch table — `src/cli/verbs.h`**

```c
#ifndef PS_VERBS_H
#define PS_VERBS_H

#include "args.h"

struct ps_verb {
    const char *name;
    int (*run)(int argc, char **argv, const struct ps_args *opts);
    const char *summary;
};

const struct ps_verb *ps_verbs_find(const char *name);

int ps_verb_help_run(int argc, char **argv, const struct ps_args *opts);

#endif
```

- [ ] **Step 8: Create `src/cli/dispatch.c`**

```c
#include "verbs.h"

#include <stdio.h>
#include <string.h>

int  ps_verb_version_run(int argc, char **argv, const struct ps_args *opts);
int  ps_verb_agent_run  (int argc, char **argv, const struct ps_args *opts);  /* Task 9 */

static const struct ps_verb VERBS[] = {
    { "version", ps_verb_version_run, "Show packetsonde and agent version" },
    /* agent verb added in Task 9 */
    { "help",    ps_verb_help_run,    "Show this help" },
    { NULL, NULL, NULL }
};

const struct ps_verb *ps_verbs_find(const char *name) {
    for (const struct ps_verb *v = VERBS; v->name; v++) {
        if (strcmp(v->name, name) == 0) return v;
    }
    return NULL;
}

int ps_verb_help_run(int argc, char **argv, const struct ps_args *opts) {
    (void)argc; (void)argv; (void)opts;
    printf("Verbs:\n");
    for (const struct ps_verb *v = VERBS; v->name; v++) {
        printf("  %-12s %s\n", v->name, v->summary);
    }
    return 0;
}
```

- [ ] **Step 9: Create `src/cli/verbs/version.c`**

```c
#include "../verbs.h"

#include <stdio.h>

#ifndef PS_VERSION
#define PS_VERSION "0.1.0"
#endif

int ps_verb_version_run(int argc, char **argv, const struct ps_args *opts) {
    (void)argc; (void)argv;
    switch (opts->fmt) {
        case PS_FMT_JSON:
        case PS_FMT_JSONL:
            printf("{\"v\":1,\"tool\":\"packetsonde\",\"version\":\"%s\"}\n", PS_VERSION);
            break;
        case PS_FMT_QUIET:
            printf("packetsonde\t%s\n", PS_VERSION);
            break;
        case PS_FMT_AUTO:
        case PS_FMT_TEXT:
        default:
            printf("packetsonde %s\n", PS_VERSION);
            break;
    }
    return 0;
}
```

- [ ] **Step 10: Create `src/cli/main.c`**

```c
#include "args.h"
#include "verbs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    struct ps_args opts;
    int prc = ps_args_parse(argc, argv, &opts);
    if (prc < 0) {
        ps_args_usage(argv[0]);
        return 2;
    }
    if (prc > 0) {
        /* --help printed already */
        return 0;
    }

    const char *verb_name = opts.verb_argv[0];
    const struct ps_verb *v = ps_verbs_find(verb_name);
    if (!v) {
        fprintf(stderr, "%s: unknown verb '%s'\n", argv[0], verb_name);
        ps_args_usage(argv[0]);
        return 2;
    }

    /* Verb sees its own argv starting at the verb name. */
    return v->run(opts.verb_argc, opts.verb_argv, &opts);
}
```

- [ ] **Step 11: Build and smoke-test**

```bash
cd /Users/billn/packetsonde/build
cmake ..
make -j$(sysctl -n hw.ncpu) packetsonde
./src/cli/packetsonde version
./src/cli/packetsonde --json version
./src/cli/packetsonde help
./src/cli/packetsonde nope ; echo "exit=$?"
```
Expected:
- `packetsonde 0.1.0`
- `{"v":1,"tool":"packetsonde","version":"0.1.0"}`
- A verb list including `version` and `help`.
- An error + usage; `exit=2`.

- [ ] **Step 12: Commit**

```bash
cd /Users/billn/packetsonde
git add src/cli/
git commit -m "feat(cli): packetsonde skeleton with version verb

Adds main.c, arg parser, verb dispatch table, and the version verb.
Test coverage on the arg parser; the agent verb arrives in the next
task. Folds psctl into packetsonde in the task after that."
```

---

## Task 9: `packetsonde agent` verb — wrap existing psctl handlers

Add an `agent` verb that dispatches its subcommands to the existing psctl command handlers. The handlers are linked directly into `packetsonde` (no fork/exec to `psctl`). `psctl` the binary still exists at this point; Task 10 retires it.

**Files:**
- Create: `src/cli/verbs/agent.c`
- Modify: `src/cli/CMakeLists.txt`
- Modify: `src/cli/dispatch.c`

- [ ] **Step 1: Write the verb implementation**

Create `/Users/billn/packetsonde/src/cli/verbs/agent.c`:
```c
#include "../verbs.h"

#include "psctl_commands.h"   /* from src/agent/src/psctl */
#include "psctl_connection.h"
#include "psctl_format.h"
#include "psctl_shell.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_SOCKET "/tmp/packetsonde-agent.sock"

static enum psctl_fmt map_fmt(enum ps_fmt f) {
    switch (f) {
        case PS_FMT_JSON:
        case PS_FMT_JSONL:  return PSCTL_FMT_JSON;
        case PS_FMT_QUIET:  return PSCTL_FMT_QUIET;
        default:            return PSCTL_FMT_TEXT;
    }
}

static void agent_usage(void) {
    fprintf(stderr,
        "Usage: packetsonde agent <subcmd> [args...]\n"
        "\n"
        "Subcommands:\n"
        "  status               Agent status / version\n"
        "  modules              List discovery modules\n"
        "  enable <module>      Enable a module\n"
        "  disable <module>     Disable a module\n"
        "  hosts                List discovered hosts\n"
        "  host <ip>            Show host detail\n"
        "  stats                Agent statistics\n"
        "  listen [filter]      Stream live events\n"
        "  shell                Interactive REPL\n");
}

int ps_verb_agent_run(int argc, char **argv, const struct ps_args *opts) {
    /* argv[0] is "agent"; agent's own subcommands start at argv[1]. */
    if (argc < 2) {
        agent_usage();
        return 2;
    }

    const char *socket_path = opts->socket_path ? opts->socket_path : DEFAULT_SOCKET;
    enum psctl_fmt fmt = map_fmt(opts->fmt);

    const char *sub = argv[1];
    int sub_argc = argc - 2;
    char **sub_argv = argv + 2;

    /* `status` is a CLI-friendly alias for `version`. */
    if (strcmp(sub, "status") == 0) sub = "version";

    if (strcmp(sub, "shell") == 0) {
        return psctl_shell(socket_path, fmt);
    }

    struct psctl_conn conn;
    if (psctl_connect(&conn, socket_path) < 0) {
        fprintf(stderr, "packetsonde agent: cannot connect to %s\n", socket_path);
        return 1;
    }

    int rc = psctl_dispatch(&conn, sub, sub_argc, sub_argv, fmt);
    psctl_disconnect(&conn);
    return rc == 0 ? 0 : 1;
}
```

- [ ] **Step 2: Wire `agent.c` into CMake**

In `/Users/billn/packetsonde/src/cli/CMakeLists.txt`, expand the `CLI_SOURCES` list:
```cmake
set(CLI_SOURCES
    main.c
    args.c
    dispatch.c
    verbs/version.c
    verbs/agent.c
    # psctl handlers, linked directly into packetsonde:
    ../agent/src/psctl/psctl_commands.c
    ../agent/src/psctl/psctl_format.c
    ../agent/src/psctl/psctl_shell.c
    ../agent/src/platform/unix.c
)
```

Add libedit linkage on macOS (psctl shell uses it). Append to the file:
```cmake
if(APPLE)
    target_link_libraries(packetsonde PRIVATE edit)
endif()
```

The `psctl_connection.c` (the shim) is *not* added here — `packetsonde` uses `ps_ipc_*` via the shim through `psctl_commands.c`, which still calls `psctl_connect`/`psctl_send`/etc. So we *do* need the shim. Add it:
```cmake
set(CLI_SOURCES
    main.c
    args.c
    dispatch.c
    verbs/version.c
    verbs/agent.c
    ../agent/src/psctl/psctl_commands.c
    ../agent/src/psctl/psctl_connection.c   # shim forwards to ps_ipc_*
    ../agent/src/psctl/psctl_format.c
    ../agent/src/psctl/psctl_shell.c
    ../agent/src/platform/unix.c
)
```

(Final `src/cli/CMakeLists.txt` after this step:)
```cmake
set(CLI_SOURCES
    main.c
    args.c
    dispatch.c
    verbs/version.c
    verbs/agent.c
    ../agent/src/psctl/psctl_commands.c
    ../agent/src/psctl/psctl_connection.c
    ../agent/src/psctl/psctl_format.c
    ../agent/src/psctl/psctl_shell.c
    ../agent/src/platform/unix.c
)

add_executable(packetsonde ${CLI_SOURCES})
target_include_directories(packetsonde PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/src/psctl
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/include
    ${CMAKE_BINARY_DIR}/src/agent
)
target_link_libraries(packetsonde PRIVATE packetsonde_lib)
if(APPLE)
    target_link_libraries(packetsonde PRIVATE edit)
endif()

if(BUILD_TESTING)
    add_executable(test_args tests/test_args.c args.c)
    target_include_directories(test_args PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_args PRIVATE packetsonde_lib)
    add_test(NAME test_args COMMAND test_args)
endif()
```

- [ ] **Step 3: Register the `agent` verb in dispatch**

In `/Users/billn/packetsonde/src/cli/dispatch.c`, update the `VERBS` array:
```c
static const struct ps_verb VERBS[] = {
    { "version", ps_verb_version_run, "Show packetsonde version" },
    { "agent",   ps_verb_agent_run,   "Control / query the local agent" },
    { "help",    ps_verb_help_run,    "Show this help" },
    { NULL, NULL, NULL }
};
```

(Remove the comment `/* agent verb added in Task 9 */` placeholder.)

- [ ] **Step 4: Build**

```bash
cd /Users/billn/packetsonde/build
cmake ..
make -j$(sysctl -n hw.ncpu) packetsonde
```
Expected: builds clean. If the linker complains about missing `psctl_connect`, the shim isn't in the source list — re-check Step 2.

- [ ] **Step 5: Smoke-test offline**

Run: `/Users/billn/packetsonde/build/src/cli/packetsonde agent`
Expected: prints the agent subcommand usage and exits 2.

Run: `/Users/billn/packetsonde/build/src/cli/packetsonde agent status`
Expected: error "cannot connect to /tmp/packetsonde-agent.sock" if no agent is running; exit 1. (That's the success signal — the dispatch reached the connection step.)

- [ ] **Step 6: Smoke-test against a running agent (if available)**

If `packetsonded` is running locally with its socket at the default path:
```bash
/Users/billn/packetsonde/build/src/cli/packetsonde agent status
/Users/billn/packetsonde/build/src/cli/packetsonde agent modules
/Users/billn/packetsonde/build/src/cli/packetsonde --json agent stats
```
Expected: each command produces the same output as the old `psctl <cmd>` did.

If no agent is reachable on this machine, skip this step — Task 10's verification will revisit on a host where one runs.

- [ ] **Step 7: Commit**

```bash
cd /Users/billn/packetsonde
git add src/cli/verbs/agent.c src/cli/CMakeLists.txt src/cli/dispatch.c
git commit -m "feat(cli): packetsonde agent <subcmd>

Folds psctl command handlers into packetsonde via direct linkage.
psctl the binary still ships; it is removed in the next task."
```

---

## Task 10: Retire the `psctl` binary

Remove the `psctl` build target and its install entry. Delete the `src/agent/src/psctl/` source tree since its files are now consumed directly by the CLI's CMake. Replace any remaining references to "psctl" in install rules with "packetsonde".

**Files:**
- Modify: `src/agent/CMakeLists.txt`
- Move: `src/agent/src/psctl/*` → `src/cli/psctl/*` (so the CLI build keeps finding the source)

Rationale: the CLI build references the psctl handler `.c` files via `../agent/src/psctl/...` paths. Move those files under `src/cli/psctl/` so the CLI owns them, and remove the now-empty path from the agent.

- [ ] **Step 1: Move the psctl source files into the CLI tree**

```bash
cd /Users/billn/packetsonde
mkdir -p src/cli/psctl
git mv src/agent/src/psctl/psctl_commands.c    src/cli/psctl/psctl_commands.c
git mv src/agent/src/psctl/psctl_commands.h    src/cli/psctl/psctl_commands.h
git mv src/agent/src/psctl/psctl_connection.c  src/cli/psctl/psctl_connection.c
git mv src/agent/src/psctl/psctl_connection.h  src/cli/psctl/psctl_connection.h
git mv src/agent/src/psctl/psctl_format.c      src/cli/psctl/psctl_format.c
git mv src/agent/src/psctl/psctl_format.h      src/cli/psctl/psctl_format.h
git mv src/agent/src/psctl/psctl_shell.c       src/cli/psctl/psctl_shell.c
git mv src/agent/src/psctl/psctl_shell.h       src/cli/psctl/psctl_shell.h
# psctl_main.c was the standalone entry point — no longer needed.
git rm src/agent/src/psctl/psctl_main.c
rmdir src/agent/src/psctl
```

- [ ] **Step 2: Update `src/cli/CMakeLists.txt`** to reference the new paths.

Replace the `CLI_SOURCES` block with:
```cmake
set(CLI_SOURCES
    main.c
    args.c
    dispatch.c
    verbs/version.c
    verbs/agent.c
    psctl/psctl_commands.c
    psctl/psctl_connection.c
    psctl/psctl_format.c
    psctl/psctl_shell.c
    ../agent/src/platform/unix.c
)
```

And update the include directories:
```cmake
target_include_directories(packetsonde PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/psctl
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/include
    ${CMAKE_BINARY_DIR}/src/agent
)
```

In `src/cli/verbs/agent.c`, update the includes to relative paths inside CLI:
```c
#include "../psctl/psctl_commands.h"
#include "../psctl/psctl_connection.h"
#include "../psctl/psctl_format.h"
#include "../psctl/psctl_shell.h"
```

- [ ] **Step 3: Remove `psctl` from `src/agent/CMakeLists.txt`**

Delete the entire `psctl` target block (the `add_executable(psctl ...)`, its `target_include_directories`, its `target_compile_definitions`, and its `if(APPLE) target_link_libraries(psctl PRIVATE edit) endif()`).

Update the install section. Find:
```cmake
install(TARGETS packetsonde-agent packetsonde-priv
        RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(TARGETS psctl
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
```
Replace with:
```cmake
install(TARGETS packetsonde-agent packetsonde-priv
        RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
```

The `packetsonde` CLI install entry is added in Step 4 below in the CLI's own CMakeLists.

- [ ] **Step 4: Add install entry for `packetsonde` in `src/cli/CMakeLists.txt`**

Append to the file:
```cmake
include(GNUInstallDirs)
install(TARGETS packetsonde RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
```

- [ ] **Step 5: Clean build and verify**

```bash
cd /Users/billn/packetsonde
rm -rf build
mkdir build && cd build
cmake ..
make -j$(sysctl -n hw.ncpu)
```
Expected: builds `packetsonde-agent`, `packetsonde-priv`, `packetsonde`, all tests. **No `psctl` binary anywhere in the build tree.**

Run: `find build -name psctl -type f`
Expected: empty.

- [ ] **Step 6: Run all tests**

```bash
cd /Users/billn/packetsonde/build && ctest --output-on-failure
```
Expected: all tests pass, including `test_args` and `test_ulid` (new) and the original agent tests.

- [ ] **Step 7: Smoke-test the CLI surface**

```bash
./build/src/cli/packetsonde version
./build/src/cli/packetsonde --json version
./build/src/cli/packetsonde help
./build/src/cli/packetsonde agent
./build/src/cli/packetsonde agent status ; echo "exit=$?"
```
Expected behavior matches Task 8 / Task 9 smoke tests.

- [ ] **Step 8: Commit**

```bash
cd /Users/billn/packetsonde
git add -A
git commit -m "refactor(cli): retire psctl binary

psctl handler sources move into src/cli/psctl/. The agent build no
longer produces a psctl executable. packetsonde agent <subcmd> is the
only surface for agent control."
```

---

## Task 11: Verification gate (end of plan)

Confirm the end state of Plan 1 against the spec's Definition of Done items in scope.

**Files:** none modified.

- [ ] **Step 1: Build everything from a clean tree**

```bash
cd /Users/billn/packetsonde
rm -rf build
./build.sh native
```
Expected: completes with no errors. Output should mention building `packetsonde-agent`, `packetsonde-priv`, `packetsonde`.

- [ ] **Step 2: Confirm binaries exist**

```bash
ls /Users/billn/packetsonde/build/src/agent/packetsonde-agent
ls /Users/billn/packetsonde/build/src/agent/packetsonde-priv
ls /Users/billn/packetsonde/build/src/cli/packetsonde
find /Users/billn/packetsonde/build -name psctl -type f
```
Expected: first three exist, `psctl` find is empty.

- [ ] **Step 3: All tests pass**

```bash
cd /Users/billn/packetsonde/build && ctest --output-on-failure
```
Expected: all PASS.

- [ ] **Step 4: CLI surface smoke**

```bash
./build/src/cli/packetsonde version
./build/src/cli/packetsonde --json version | head -1
./build/src/cli/packetsonde help
./build/src/cli/packetsonde nope ; echo "exit=$?"
./build/src/cli/packetsonde agent ; echo "exit=$?"
```
Expected:
- text version line
- one JSON object line containing `"packetsonde"`
- verb listing
- error + usage; exit 2
- agent subcommand usage; exit 2

- [ ] **Step 5: Verify git history preserved across moves**

```bash
git log --follow src/lib/json.c | wc -l
git log --follow src/lib/log.c | wc -l
git log --follow src/cli/psctl/psctl_commands.c | wc -l
```
Expected: each > 0 (history follows the rename).

- [ ] **Step 6: Tag the plan completion**

```bash
cd /Users/billn/packetsonde
git tag -a plan-1-foundation -m "Plan 1 (CLI foundation) complete

- agent/ renamed to src/agent/
- libpacketsonde (json, log, ipc, ulid)
- packetsonde CLI skeleton with version verb
- agent verb folds in psctl handlers
- psctl binary retired"
```

Plan complete. Plan 2 (findings & first audit) is next.

---

## Self-review notes

- Every spec requirement Plan 1 claims to cover (§2 rename, §2 libpacketsonde, §2 retire psctl, §6.1 version + agent verbs) is implemented by a named task.
- The shim in `psctl_connection.c` (Task 7) is what lets Task 9 link the unmodified `psctl_commands.c` against the new `ps_ipc_*` API.  Tasks 9 → 10 are sequenced so that `psctl_commands.c` is moved into the CLI tree only after we've proven the CLI links it correctly.
- No placeholder strings remain: all "v1.x" / "follow-on" references point at named follow-on plans, not at gaps inside Plan 1.
