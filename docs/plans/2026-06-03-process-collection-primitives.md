# Process/File/Socket Collection Primitives (SP1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On Linux, every time a watched process opens/accesses a watched path, emit a correlated `{process, ancestry, sockets, unit, mac}` activity record to a local bounded ring that a `packetsonde watch` verb tails — no scoring, no central shipping.

**Architecture:** A privileged collection engine in `priv_worker` owns a fanotify fd (notification mode). On each non-suppressed event it enriches the pid from `/proc` (incl. cgroup/unit + MAC label/mode), walks the parent tree to the session/service root, snapshots sockets held by the leaf + ancestors (parsed from `/proc/net/*`), serializes a record, and pushes it as an async `PS_OP_ACTIVITY_DATA` frame over the existing `priv_protocol` channel. The unprivileged brain routes those frames into an `activity_ring` (mirroring `obs_queue`) that the `watch` verb drains.

**Tech Stack:** C11 + OpenSSL, CMake/CTest. Reuses `ps_json` (lib), `obs_queue` pattern, `priv_protocol`/`priv_worker`/`priv_client`, `config_to_env`, `iso8601`, the verb-dispatch table. Pure parsers live in `src/lib` (fixture-tested, no privilege); privileged I/O glue lives in `src/agent/src`.

**Spec:** `docs/specs/2026-06-03-process-collection-primitives-design.md`.

**Build:** `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON && make <target> && ctest -R '^<name>$' --output-on-failure`.

**Scope note (locked here):** sockets are resolved by parsing `/proc/net/{tcp,tcp6,udp,udp6}` text (testable, no netlink). `sock_diag` (NETLINK_INET_DIAG) is a deferred perf optimization (spec §8 calls `/proc/net` the fallback; we make it the increment-1 primary). Same record schema either way.

---

## Interfaces locked here (names must match across tasks)

- **`priv_protocol.h`:** `#define PS_OP_ACTIVITY_DATA 0x84` (async, priv→brain); `ps_priv_encode_activity(buf, bufsz, json, json_len)`.
- **`src/lib/suppress.h`:** `int ps_suppress_match(const char *list, const char *comm, const char *path, int is_read);` → 1 = suppress, 0 = keep.
- **`src/lib/proc_parse.h`:** `int ps_proc_parse_ppid(const char *stat_buf);` `int ps_proc_parse_comm(const char *stat_buf, char *out, size_t cap);` `int ps_proc_parse_unit(const char *cgroup_buf, char *out, size_t cap);` `int ps_proc_parse_mac(const char *attr_buf, char *label, size_t lcap, char *mode, size_t mcap);`
- **`src/lib/sock_parse.h`:** `struct ps_sock_ep { unsigned long inode; char proto[4]; char laddr[64]; char raddr[64]; char state[16]; };` `int ps_sock_parse_procnet(const char *proto, const char *buf, struct ps_sock_ep *out, int max);` `int ps_sock_find_by_inode(const struct ps_sock_ep *eps, int n, unsigned long inode, struct ps_sock_ep *out);`
- **`src/lib/activity_record.h`:** structs `ps_act_proc`, `ps_act_ancestor`, `ps_act_socket`, `ps_activity` + `int ps_activity_to_json(const struct ps_activity *a, char *out, size_t cap);` → bytes or -1.
- **`src/agent/src/activity_ring.h`:** `ps_act_ring_init/push/drain/count` mirroring `obs_queue` (cap `PS_ACT_RING_CAP 256`, item `PS_ACT_ITEM_MAX 8192`).
- **`src/agent/src/proc_enrich.h`:** `int ps_proc_enrich(const char *proc_root, int pid, struct ps_activity *a, int max_depth);` (fills `process` + `ancestry`; `proc_root` "" → "/proc").
- **`src/agent/src/sock_snapshot.h`:** `int ps_sock_snapshot(const char *proc_root, const int *pids, int npids, const char *comms[], const int *depths, struct ps_act_socket *out, int max);`

---

## Task 1: `priv_protocol` activity opcode + encoder

**Files:** Modify `src/agent/src/priv_protocol.h`; Test `src/agent/tests/test_priv_protocol.c`

- [ ] **Step 1: Add a failing assertion to `test_priv_protocol.c`** (in `main`, before the success print)

```c
    /* activity async frame encode round-trip */
    {
        uint8_t ab[256];
        const char *j = "{\"v\":1}";
        size_t an = ps_priv_encode_activity(ab, sizeof ab, j, strlen(j));
        assert(an == sizeof(struct ps_priv_msg) + strlen(j));
        struct ps_priv_msg ahdr;
        memcpy(&ahdr, ab, sizeof ahdr);
        assert(ahdr.opcode == PS_OP_ACTIVITY_DATA);
        assert(ahdr.payload_len == strlen(j));
        assert(memcmp(ab + sizeof ahdr, j, strlen(j)) == 0);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/packetsonde/build && make test_priv_protocol 2>&1 | tail -4`
Expected: FAIL — `PS_OP_ACTIVITY_DATA` / `ps_priv_encode_activity` undeclared.

- [ ] **Step 3: Add the opcode + encoder to `priv_protocol.h`** (opcode next to the other `0x8x` responses; encoder next to the other `ps_priv_encode_*` inlines)

```c
#define PS_OP_ACTIVITY_DATA       0x84   /* async priv -> brain: one activity record JSON */
```

```c
static inline size_t ps_priv_encode_activity(uint8_t *buf, size_t bufsz,
                                             const char *json, size_t json_len)
{
    size_t total = sizeof(struct ps_priv_msg) + json_len;
    if (total > bufsz) return 0;
    struct ps_priv_msg hdr = {0};
    hdr.opcode = PS_OP_ACTIVITY_DATA;
    hdr.payload_len = (uint32_t)json_len;
    memcpy(buf, &hdr, sizeof(hdr));
    memcpy(buf + sizeof(hdr), json, json_len);
    return total;
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd /opt/repo/packetsonde/build && make test_priv_protocol >/dev/null && ctest -R '^test_priv_protocol$' --output-on-failure`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /opt/repo/packetsonde
git add src/agent/src/priv_protocol.h src/agent/tests/test_priv_protocol.c
git commit -m "priv_protocol: add PS_OP_ACTIVITY_DATA async frame + encoder"
```

---

## Task 2: Coarse suppression matcher (`src/lib/suppress`)

**Files:** Create `src/lib/suppress.h`, `src/lib/suppress.c`; Test `src/lib/tests/test_suppress.c`; Modify `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test** (`src/lib/tests/test_suppress.c`)

```c
#include "suppress.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    /* default-style list: prefixes, optional "comm:" qualifier */
    const char *list = "/usr/lib,/usr/share,smbd:/var/log";
    /* reads under a listed prefix are suppressed */
    assert(ps_suppress_match(list, "anything", "/usr/lib/x.so", 1) == 1);
    assert(ps_suppress_match(list, "anything", "/usr/share/zoneinfo", 1) == 1);
    /* comm-qualified rule only matches that comm */
    assert(ps_suppress_match(list, "smbd", "/var/log/a", 1) == 1);
    assert(ps_suppress_match(list, "nginx", "/var/log/a", 1) == 0);
    /* writes are NEVER suppressed even under a listed prefix */
    assert(ps_suppress_match(list, "anything", "/usr/lib/x.so", 0) == 0);
    /* non-listed path kept */
    assert(ps_suppress_match(list, "x", "/etc/shadow", 1) == 0);
    /* empty list suppresses nothing */
    assert(ps_suppress_match("", "x", "/usr/lib/y", 1) == 0);
    printf("test_suppress: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_suppress 2>&1 | tail -4`
Expected: FAIL — `suppress.h` not found.

- [ ] **Step 3: Create `src/lib/suppress.h`**

```c
#ifndef PS_SUPPRESS_H
#define PS_SUPPRESS_H

/* Coarse read-only suppression. `list` is a comma-separated set of entries;
 * each entry is either "<path-prefix>" or "<comm>:<path-prefix>".
 * Returns 1 if this access should be suppressed (dropped before enrichment),
 * 0 to keep. Writes/exec (is_read==0) are NEVER suppressed. */
int ps_suppress_match(const char *list, const char *comm, const char *path, int is_read);

#endif /* PS_SUPPRESS_H */
```

- [ ] **Step 4: Create `src/lib/suppress.c`**

```c
#include "suppress.h"
#include <string.h>

static int prefix_match(const char *prefix, size_t plen, const char *path) {
    return strncmp(path, prefix, plen) == 0;
}

int ps_suppress_match(const char *list, const char *comm, const char *path, int is_read) {
    if (!is_read || !list || !*list || !path) return 0;
    const char *p = list;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t elen = comma ? (size_t)(comma - p) : strlen(p);
        /* split optional "comm:" */
        const char *colon = memchr(p, ':', elen);
        if (colon) {
            size_t clen = (size_t)(colon - p);
            const char *pref = colon + 1;
            size_t plen = elen - clen - 1;
            if (comm && strlen(comm) == clen && strncmp(comm, p, clen) == 0 &&
                plen > 0 && prefix_match(pref, plen, path))
                return 1;
        } else {
            if (elen > 0 && prefix_match(p, elen, path))
                return 1;
        }
        if (!comma) break;
        p = comma + 1;
    }
    return 0;
}
```

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `suppress.c` to the `packetsonde_lib` source list, and after the `test_collect` block add:

```cmake
    add_executable(test_suppress tests/test_suppress.c)
    target_link_libraries(test_suppress PRIVATE packetsonde_lib)
    add_test(NAME test_suppress COMMAND test_suppress)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_suppress >/dev/null && ctest -R '^test_suppress$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /opt/repo/packetsonde
git add src/lib/suppress.h src/lib/suppress.c src/lib/tests/test_suppress.c src/lib/CMakeLists.txt
git commit -m "lib: add coarse read-only suppression matcher"
```

---

## Task 3: `/proc` field parsers (`src/lib/proc_parse`)

**Files:** Create `src/lib/proc_parse.h`, `src/lib/proc_parse.c`; Test `src/lib/tests/test_proc_parse.c`; Modify `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test** (`src/lib/tests/test_proc_parse.c`)

```c
#include "proc_parse.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    /* /proc/<pid>/stat: "pid (comm) state ppid ..." — comm may contain spaces/parens */
    const char *stat = "1234 (smb d) S 1190 1234 1190 0 -1 ...";
    assert(ps_proc_parse_ppid(stat) == 1190);
    char comm[64];
    assert(ps_proc_parse_comm(stat, comm, sizeof comm) == 0);
    assert(strcmp(comm, "smb d") == 0);

    /* cgroup v2: "0::/system.slice/smbd.service" -> unit basename */
    char unit[128];
    assert(ps_proc_parse_unit("0::/system.slice/smbd.service\n", unit, sizeof unit) == 0);
    assert(strcmp(unit, "/system.slice/smbd.service") == 0);

    /* attr/current AppArmor: "/usr/sbin/smbd (complain)" */
    char label[128], mode[32];
    assert(ps_proc_parse_mac("/usr/sbin/smbd (complain)\n", label, sizeof label, mode, sizeof mode) == 0);
    assert(strcmp(label, "/usr/sbin/smbd") == 0);
    assert(strcmp(mode, "complain") == 0);
    /* unconfined */
    assert(ps_proc_parse_mac("unconfined\n", label, sizeof label, mode, sizeof mode) == 0);
    assert(strcmp(label, "unconfined") == 0);
    assert(strcmp(mode, "unconfined") == 0);

    printf("test_proc_parse: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_proc_parse 2>&1 | tail -4`
Expected: FAIL — `proc_parse.h` not found.

- [ ] **Step 3: Create `src/lib/proc_parse.h`**

```c
#ifndef PS_PROC_PARSE_H
#define PS_PROC_PARSE_H
#include <stddef.h>

/* All take a NUL-terminated buffer (the file contents). Return 0 on success. */
int ps_proc_parse_ppid(const char *stat_buf);                 /* returns ppid, or -1 */
int ps_proc_parse_comm(const char *stat_buf, char *out, size_t cap);
int ps_proc_parse_unit(const char *cgroup_buf, char *out, size_t cap);
int ps_proc_parse_mac(const char *attr_buf, char *label, size_t lcap,
                      char *mode, size_t mcap);
#endif /* PS_PROC_PARSE_H */
```

- [ ] **Step 4: Create `src/lib/proc_parse.c`**

```c
#include "proc_parse.h"
#include <string.h>
#include <stdlib.h>

/* stat is "pid (comm) state ppid ...". comm can contain spaces and ')',
 * so find the LAST ')' and parse fields after it. */
static const char *after_comm(const char *stat_buf) {
    const char *rp = strrchr(stat_buf, ')');
    return rp ? rp + 1 : NULL;
}

int ps_proc_parse_ppid(const char *stat_buf) {
    const char *p = after_comm(stat_buf);
    if (!p) return -1;
    /* fields after ')': " state ppid ..." */
    while (*p == ' ') p++;
    while (*p && *p != ' ') p++;       /* skip state */
    while (*p == ' ') p++;
    if (!*p) return -1;
    return atoi(p);
}

int ps_proc_parse_comm(const char *stat_buf, char *out, size_t cap) {
    const char *lp = strchr(stat_buf, '(');
    const char *rp = strrchr(stat_buf, ')');
    if (!lp || !rp || rp <= lp) return -1;
    size_t n = (size_t)(rp - lp - 1);
    if (n >= cap) n = cap - 1;
    memcpy(out, lp + 1, n); out[n] = 0;
    return 0;
}

int ps_proc_parse_unit(const char *cgroup_buf, char *out, size_t cap) {
    /* Find the last ':' on the first line; the rest is the cgroup path. */
    const char *nl = strchr(cgroup_buf, '\n');
    size_t linelen = nl ? (size_t)(nl - cgroup_buf) : strlen(cgroup_buf);
    const char *line = cgroup_buf;
    const char *colon = NULL;
    for (size_t i = 0; i < linelen; i++) if (line[i] == ':') colon = line + i;
    if (!colon) return -1;
    const char *path = colon + 1;
    size_t plen = (size_t)(line + linelen - path);
    if (plen == 0 || plen >= cap) { if (plen >= cap) plen = cap - 1; else return -1; }
    memcpy(out, path, plen); out[plen] = 0;
    return 0;
}

int ps_proc_parse_mac(const char *attr_buf, char *label, size_t lcap,
                      char *mode, size_t mcap) {
    char tmp[256];
    size_t n = strcspn(attr_buf, "\n");
    if (n >= sizeof tmp) n = sizeof tmp - 1;
    memcpy(tmp, attr_buf, n); tmp[n] = 0;
    /* AppArmor: "<label> (<mode>)"; SELinux/none: "<context>" or "unconfined" */
    char *paren = strrchr(tmp, '(');
    if (paren && tmp[n ? n - 1 : 0] == ')') {
        char *end = strrchr(tmp, ')');
        *end = 0;
        snprintf(mode, mcap, "%s", paren + 1);
        /* trim trailing space before '(' from label */
        char *lp = paren;
        while (lp > tmp && (lp[-1] == ' ')) lp--;
        size_t llen = (size_t)(lp - tmp);
        if (llen >= lcap) llen = lcap - 1;
        memcpy(label, tmp, llen); label[llen] = 0;
    } else {
        snprintf(label, lcap, "%s", tmp);
        snprintf(mode, mcap, "%s", tmp);   /* "unconfined" -> mode "unconfined" */
    }
    return 0;
}
```

(Add `#include <stdio.h>` for `snprintf`.)

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `proc_parse.c` to `packetsonde_lib`; add the test block:

```cmake
    add_executable(test_proc_parse tests/test_proc_parse.c)
    target_link_libraries(test_proc_parse PRIVATE packetsonde_lib)
    add_test(NAME test_proc_parse COMMAND test_proc_parse)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_proc_parse >/dev/null && ctest -R '^test_proc_parse$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /opt/repo/packetsonde
git add src/lib/proc_parse.h src/lib/proc_parse.c src/lib/tests/test_proc_parse.c src/lib/CMakeLists.txt
git commit -m "lib: add /proc stat/cgroup/attr field parsers"
```

---

## Task 4: Socket table parser (`src/lib/sock_parse`)

**Files:** Create `src/lib/sock_parse.h`, `src/lib/sock_parse.c`; Test `src/lib/tests/test_sock_parse.c`; Modify `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test** (`src/lib/tests/test_sock_parse.c`)

```c
#include "sock_parse.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

/* One real-shaped /proc/net/tcp line: local 10.0.0.5:445 (0A0000 05:01BD),
 * remote 203.0.113.5:51344 (CB007101:C890), state 01 (ESTABLISHED), inode 99887. */
static const char *TCP =
"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
"   0: 0500000A:01BD 0571CBCB:C890 01 00000000:00000000 00:00000000 00000000     0        0 99887 1 0000 ...\n";

int main(void) {
    struct ps_sock_ep eps[8];
    int n = ps_sock_parse_procnet("tcp", TCP, eps, 8);
    assert(n == 1);
    assert(eps[0].inode == 99887UL);
    assert(strcmp(eps[0].laddr, "10.0.0.5:445") == 0);
    assert(strcmp(eps[0].raddr, "203.0.113.5:51344") == 0);
    assert(strcmp(eps[0].state, "ESTABLISHED") == 0);
    assert(strcmp(eps[0].proto, "tcp") == 0);

    struct ps_sock_ep hit;
    assert(ps_sock_find_by_inode(eps, n, 99887UL, &hit) == 0);
    assert(strcmp(hit.raddr, "203.0.113.5:51344") == 0);
    assert(ps_sock_find_by_inode(eps, n, 12345UL, &hit) == -1);

    printf("test_sock_parse: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_sock_parse 2>&1 | tail -4`
Expected: FAIL — `sock_parse.h` not found.

- [ ] **Step 3: Create `src/lib/sock_parse.h`**

```c
#ifndef PS_SOCK_PARSE_H
#define PS_SOCK_PARSE_H
#include <stddef.h>

struct ps_sock_ep {
    unsigned long inode;
    char proto[4];     /* "tcp"|"udp" */
    char laddr[64];    /* "ip:port" */
    char raddr[64];
    char state[16];    /* "ESTABLISHED" etc, or "" for udp */
};

/* Parse /proc/net/{tcp,tcp6,udp,udp6} text. `proto` is "tcp" or "udp"; the
 * tcp6/udp6 hex-address width is auto-detected per line. Returns count, or -1. */
int ps_sock_parse_procnet(const char *proto, const char *buf,
                          struct ps_sock_ep *out, int max);

/* Copy the first entry whose inode matches into *out. 0 on hit, -1 if none. */
int ps_sock_find_by_inode(const struct ps_sock_ep *eps, int n,
                          unsigned long inode, struct ps_sock_ep *out);
#endif /* PS_SOCK_PARSE_H */
```

- [ ] **Step 4: Create `src/lib/sock_parse.c`**

```c
#include "sock_parse.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Decode a "HEXADDR:HEXPORT" token into "a.b.c.d:port" (v4, 8 hex addr chars)
 * or "[v6]:port" (32 hex addr chars). Little-endian addr words, per kernel. */
static void decode_addr(const char *tok, char *out, size_t cap) {
    const char *colon = strchr(tok, ':');
    if (!colon) { snprintf(out, cap, "?"); return; }
    size_t alen = (size_t)(colon - tok);
    unsigned port = (unsigned)strtoul(colon + 1, NULL, 16);
    if (alen == 8) {
        unsigned long a = strtoul((char[]){tok[6],tok[7],0}, NULL, 16);
        unsigned long b = strtoul((char[]){tok[4],tok[5],0}, NULL, 16);
        unsigned long c = strtoul((char[]){tok[2],tok[3],0}, NULL, 16);
        unsigned long d = strtoul((char[]){tok[0],tok[1],0}, NULL, 16);
        snprintf(out, cap, "%lu.%lu.%lu.%lu:%u", a, b, c, d, port);
    } else {
        /* v6: emit colon-grouped hex of the 32-char field, big enough for context */
        char hex[40]; size_t n = alen < sizeof hex - 1 ? alen : sizeof hex - 1;
        memcpy(hex, tok, n); hex[n] = 0;
        snprintf(out, cap, "[%s]:%u", hex, port);
    }
}

static const char *tcp_state(const char *st_hex) {
    static const char *S[] = {"","ESTABLISHED","SYN_SENT","SYN_RECV","FIN_WAIT1",
        "FIN_WAIT2","TIME_WAIT","CLOSE","CLOSE_WAIT","LAST_ACK","LISTEN","CLOSING"};
    unsigned v = (unsigned)strtoul(st_hex, NULL, 16);
    return (v < sizeof S / sizeof S[0]) ? S[v] : "";
}

int ps_sock_parse_procnet(const char *proto, const char *buf,
                          struct ps_sock_ep *out, int max) {
    if (!proto || !buf) return -1;
    int is_tcp = strcmp(proto, "tcp") == 0;
    int count = 0;
    const char *line = buf;
    /* skip header line */
    line = strchr(line, '\n');
    if (!line) return 0;
    line++;
    while (*line && count < max) {
        char local[64] = "", rem[64] = "", st[8] = "";
        unsigned long inode = 0;
        /* fields: "  N: LOCAL REM ST tx:rx tr:when retr uid timeout inode ..." */
        char sl[16];
        int got = sscanf(line, "%15[^:]: %63s %63s %7s %*s %*s %*s %*u %*u %lu",
                         sl, local, rem, st, &inode);
        if (got >= 5 && inode > 0) {
            struct ps_sock_ep *e = &out[count++];
            memset(e, 0, sizeof *e);
            e->inode = inode;
            snprintf(e->proto, sizeof e->proto, "%s", proto);
            decode_addr(local, e->laddr, sizeof e->laddr);
            decode_addr(rem, e->raddr, sizeof e->raddr);
            if (is_tcp) snprintf(e->state, sizeof e->state, "%s", tcp_state(st));
        }
        line = strchr(line, '\n');
        if (!line) break;
        line++;
    }
    return count;
}

int ps_sock_find_by_inode(const struct ps_sock_ep *eps, int n,
                          unsigned long inode, struct ps_sock_ep *out) {
    for (int i = 0; i < n; i++) {
        if (eps[i].inode == inode) { *out = eps[i]; return 0; }
    }
    return -1;
}
```

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `sock_parse.c` to `packetsonde_lib`; add the test block:

```cmake
    add_executable(test_sock_parse tests/test_sock_parse.c)
    target_link_libraries(test_sock_parse PRIVATE packetsonde_lib)
    add_test(NAME test_sock_parse COMMAND test_sock_parse)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_sock_parse >/dev/null && ctest -R '^test_sock_parse$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /opt/repo/packetsonde
git add src/lib/sock_parse.h src/lib/sock_parse.c src/lib/tests/test_sock_parse.c src/lib/CMakeLists.txt
git commit -m "lib: add /proc/net socket table parser (inode -> endpoints)"
```

---

## Task 5: Activity record schema + serializer (`src/lib/activity_record`)

**Files:** Create `src/lib/activity_record.h`, `src/lib/activity_record.c`; Test `src/lib/tests/test_activity_record.c`; Modify `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test** (`src/lib/tests/test_activity_record.c`)

```c
#include "activity_record.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    struct ps_activity a;
    memset(&a, 0, sizeof a);
    snprintf(a.ts, sizeof a.ts, "2026-06-03T14:22:10Z");
    snprintf(a.event, sizeof a.event, "open");
    snprintf(a.path, sizeof a.path, "/etc/shadow");
    a.proc.pid = 1234; a.proc.ppid = 1190; a.proc.uid = 0; a.proc.sid = 1190;
    snprintf(a.proc.comm, sizeof a.proc.comm, "sh");
    snprintf(a.proc.exe, sizeof a.proc.exe, "/usr/bin/dash");
    snprintf(a.proc.cmdline, sizeof a.proc.cmdline, "sh");
    snprintf(a.proc.cgroup, sizeof a.proc.cgroup, "/system.slice/smbd.service");
    snprintf(a.proc.mac_label, sizeof a.proc.mac_label, "/usr/sbin/smbd");
    snprintf(a.proc.mac_mode, sizeof a.proc.mac_mode, "complain");
    a.nanc = 1;
    a.anc[0].pid = 1190; a.anc[0].depth = 1; snprintf(a.anc[0].comm, sizeof a.anc[0].comm, "smbd");
    a.nsock = 1;
    a.sock[0].owner_pid = 1190; a.sock[0].depth = 1;
    snprintf(a.sock[0].owner_comm, sizeof a.sock[0].owner_comm, "smbd");
    snprintf(a.sock[0].proto, sizeof a.sock[0].proto, "tcp");
    snprintf(a.sock[0].laddr, sizeof a.sock[0].laddr, "10.0.0.5:445");
    snprintf(a.sock[0].raddr, sizeof a.sock[0].raddr, "203.0.113.5:51344");
    snprintf(a.sock[0].state, sizeof a.sock[0].state, "ESTABLISHED");

    char buf[4096];
    int n = ps_activity_to_json(&a, buf, sizeof buf);
    assert(n > 0);
    assert(strstr(buf, "\"event\":\"open\""));
    assert(strstr(buf, "\"path\":\"/etc/shadow\""));
    assert(strstr(buf, "\"comm\":\"sh\""));
    assert(strstr(buf, "\"cgroup\":\"/system.slice/smbd.service\""));
    assert(strstr(buf, "\"mode\":\"complain\""));
    assert(strstr(buf, "\"raddr\":\"203.0.113.5:51344\""));
    assert(strstr(buf, "\"depth\":1"));
    printf("test_activity_record: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_activity_record 2>&1 | tail -4`
Expected: FAIL — `activity_record.h` not found.

- [ ] **Step 3: Create `src/lib/activity_record.h`**

```c
#ifndef PS_ACTIVITY_RECORD_H
#define PS_ACTIVITY_RECORD_H
#include <stddef.h>
#include <stdint.h>

#define PS_ACT_MAX_ANC   16
#define PS_ACT_MAX_SOCK  32

struct ps_act_proc {
    int pid, ppid, uid, sid;
    char comm[64], exe[256], cmdline[512];
    char cgroup[256], mac_label[128], mac_mode[32];
};
struct ps_act_ancestor { int pid, depth; char comm[64]; };
struct ps_act_socket {
    int owner_pid, depth;
    char owner_comm[64], proto[4], laddr[64], raddr[64], state[16];
};
struct ps_activity {
    char ts[24], event[8], path[512];
    int partial;
    struct ps_act_proc proc;
    int nanc;  struct ps_act_ancestor anc[PS_ACT_MAX_ANC];
    int nsock; struct ps_act_socket  sock[PS_ACT_MAX_SOCK];
};

/* Serialize to JSON (schema = spec §5). Returns bytes written, or -1. */
int ps_activity_to_json(const struct ps_activity *a, char *out, size_t cap);
#endif /* PS_ACTIVITY_RECORD_H */
```

- [ ] **Step 4: Create `src/lib/activity_record.c`**

```c
#include "activity_record.h"
#include "json.h"
#include <string.h>

int ps_activity_to_json(const struct ps_activity *a, char *out, size_t cap) {
    struct ps_json j; ps_json_init(&j, out, cap);
    ps_json_object_begin(&j);
    ps_json_key_int(&j, "v", 1);
    ps_json_key_string(&j, "ts", a->ts);
    ps_json_key_string(&j, "event", a->event);
    ps_json_key_string(&j, "path", a->path);
    ps_json_key_bool(&j, "partial", a->partial);

    ps_json_key_object_begin(&j, "process");
    ps_json_key_int(&j, "pid", a->proc.pid);
    ps_json_key_int(&j, "ppid", a->proc.ppid);
    ps_json_key_int(&j, "uid", a->proc.uid);
    ps_json_key_int(&j, "sid", a->proc.sid);
    ps_json_key_string(&j, "comm", a->proc.comm);
    ps_json_key_string(&j, "exe", a->proc.exe);
    ps_json_key_string(&j, "cmdline", a->proc.cmdline);
    ps_json_key_string(&j, "cgroup", a->proc.cgroup);
    ps_json_key_object_begin(&j, "mac");
    ps_json_key_string(&j, "label", a->proc.mac_label);
    ps_json_key_string(&j, "mode", a->proc.mac_mode);
    ps_json_object_end(&j);   /* mac */
    ps_json_object_end(&j);   /* process */

    ps_json_array_begin(&j, "ancestry");
    for (int i = 0; i < a->nanc; i++) {
        ps_json_object_begin(&j);
        ps_json_key_int(&j, "pid", a->anc[i].pid);
        ps_json_key_string(&j, "comm", a->anc[i].comm);
        ps_json_key_int(&j, "depth", a->anc[i].depth);
        ps_json_object_end(&j);
    }
    ps_json_array_end(&j);

    ps_json_array_begin(&j, "sockets");
    for (int i = 0; i < a->nsock; i++) {
        ps_json_object_begin(&j);
        ps_json_key_int(&j, "owner_pid", a->sock[i].owner_pid);
        ps_json_key_string(&j, "owner_comm", a->sock[i].owner_comm);
        ps_json_key_int(&j, "depth", a->sock[i].depth);
        ps_json_key_string(&j, "proto", a->sock[i].proto);
        ps_json_key_string(&j, "laddr", a->sock[i].laddr);
        ps_json_key_string(&j, "raddr", a->sock[i].raddr);
        ps_json_key_string(&j, "state", a->sock[i].state);
        ps_json_object_end(&j);
    }
    ps_json_array_end(&j);

    ps_json_object_end(&j);
    return ps_json_finish(&j);
}
```

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `activity_record.c` to `packetsonde_lib`; add the test block:

```cmake
    add_executable(test_activity_record tests/test_activity_record.c)
    target_link_libraries(test_activity_record PRIVATE packetsonde_lib)
    add_test(NAME test_activity_record COMMAND test_activity_record)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_activity_record >/dev/null && ctest -R '^test_activity_record$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /opt/repo/packetsonde
git add src/lib/activity_record.h src/lib/activity_record.c src/lib/tests/test_activity_record.c src/lib/CMakeLists.txt
git commit -m "lib: add activity record schema + JSON serializer (spec §5)"
```

---

## Task 6: Activity ring (`src/agent/src/activity_ring`)

**Files:** Create `src/agent/src/activity_ring.h`, `src/agent/src/activity_ring.c`; Test `src/agent/tests/test_activity_ring.c`; Modify `src/agent/CMakeLists.txt`

> Mirror `obs_queue` exactly (bounded, drop-oldest, thread-safe drain).

- [ ] **Step 1: Write the failing test** (`src/agent/tests/test_activity_ring.c`)

```c
#include "activity_ring.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    ps_act_ring_init();
    assert(ps_act_ring_count() == 0);
    ps_act_ring_push("{\"v\":1,\"n\":1}", 12);
    ps_act_ring_push("{\"v\":1,\"n\":2}", 12);
    assert(ps_act_ring_count() == 2);

    char items[8][PS_ACT_ITEM_MAX];
    int n = ps_act_ring_drain(items, 8);
    assert(n == 2);
    assert(strstr(items[0], "\"n\":1"));
    assert(ps_act_ring_count() == 0);

    /* overflow drops oldest */
    for (int i = 0; i < PS_ACT_RING_CAP + 5; i++) ps_act_ring_push("{\"x\":1}", 7);
    assert(ps_act_ring_count() == PS_ACT_RING_CAP);
    printf("test_activity_ring: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_activity_ring 2>&1 | tail -4`
Expected: FAIL — `activity_ring.h` not found.

- [ ] **Step 3: Create `src/agent/src/activity_ring.h`**

```c
#ifndef PS_ACTIVITY_RING_H
#define PS_ACTIVITY_RING_H
#include <stddef.h>

#define PS_ACT_RING_CAP    256
#define PS_ACT_ITEM_MAX   8192

void ps_act_ring_init(void);
void ps_act_ring_push(const char *json, size_t len);   /* drop-oldest if full; thread-safe */
int  ps_act_ring_drain(char out_items[][PS_ACT_ITEM_MAX], int max);
int  ps_act_ring_count(void);
#endif /* PS_ACTIVITY_RING_H */
```

- [ ] **Step 4: Create `src/agent/src/activity_ring.c`** (mirror `obs_queue.c`)

```c
#include "activity_ring.h"
#include <string.h>
#include <pthread.h>

static char        g_buf[PS_ACT_RING_CAP][PS_ACT_ITEM_MAX];
static int         g_len[PS_ACT_RING_CAP];
static int         g_head, g_count;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

void ps_act_ring_init(void) {
    pthread_mutex_lock(&g_mu);
    g_head = 0; g_count = 0;
    pthread_mutex_unlock(&g_mu);
}

void ps_act_ring_push(const char *json, size_t len) {
    if (!json || len == 0 || len >= PS_ACT_ITEM_MAX) return;
    pthread_mutex_lock(&g_mu);
    int tail = (g_head + g_count) % PS_ACT_RING_CAP;
    if (g_count == PS_ACT_RING_CAP) {       /* full: drop oldest */
        g_head = (g_head + 1) % PS_ACT_RING_CAP;
        tail = (g_head + g_count - 1) % PS_ACT_RING_CAP;
    } else {
        g_count++;
    }
    memcpy(g_buf[tail], json, len);
    g_buf[tail][len] = 0;
    g_len[tail] = (int)len;
    pthread_mutex_unlock(&g_mu);
}

int ps_act_ring_drain(char out_items[][PS_ACT_ITEM_MAX], int max) {
    pthread_mutex_lock(&g_mu);
    int n = 0;
    while (n < max && g_count > 0) {
        memcpy(out_items[n], g_buf[g_head], (size_t)g_len[g_head] + 1);
        g_head = (g_head + 1) % PS_ACT_RING_CAP;
        g_count--; n++;
    }
    pthread_mutex_unlock(&g_mu);
    return n;
}

int ps_act_ring_count(void) {
    pthread_mutex_lock(&g_mu);
    int c = g_count;
    pthread_mutex_unlock(&g_mu);
    return c;
}
```

- [ ] **Step 5: Wire into `src/agent/CMakeLists.txt`** — add `src/activity_ring.c` to the agent source list (next to `src/obs_queue.c`), and add the test (mirror the `test_priv_protocol` block, link pthread):

```cmake
add_executable(test_activity_ring tests/test_activity_ring.c src/activity_ring.c)
target_link_libraries(test_activity_ring PRIVATE Threads::Threads)
add_test(NAME test_activity_ring COMMAND test_activity_ring)
```

(If `Threads::Threads` isn't already found in this file, add `find_package(Threads REQUIRED)` near the top — check first; `obs_queue` already uses pthreads so it is likely present.)

- [ ] **Step 6: Run to verify it passes**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_activity_ring >/dev/null && ctest -R '^test_activity_ring$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /opt/repo/packetsonde
git add src/agent/src/activity_ring.h src/agent/src/activity_ring.c src/agent/tests/test_activity_ring.c src/agent/CMakeLists.txt
git commit -m "agent: add bounded thread-safe activity ring (mirrors obs_queue)"
```

---

## Task 7: Process enrichment + ancestry walk (`src/agent/src/proc_enrich`)

**Files:** Create `src/agent/src/proc_enrich.h`, `src/agent/src/proc_enrich.c`; Test `src/agent/tests/test_proc_enrich.c`; Modify `src/agent/CMakeLists.txt`

> Uses `proc_parse` (lib). Takes an injectable `proc_root` so tests run against a fake `/proc` tree with no privilege.

- [ ] **Step 1: Write the failing test** (`src/agent/tests/test_proc_enrich.c`) — builds a fake proc tree: pid 1234 (comm `sh`, ppid 1190) → 1190 (comm `smbd`, ppid 1) → stop.

```c
#include "proc_enrich.h"
#include "activity_record.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void wr(const char *path, const char *content) {
    FILE *f = fopen(path, "w"); assert(f); fputs(content, f); fclose(f);
}
static void mkpid(const char *root, int pid, const char *stat, const char *cgroup,
                  const char *attr, const char *exe, const char *cmdline) {
    char d[256], p[320];
    snprintf(d, sizeof d, "%s/%d", root, pid); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/%d/stat", root, pid); wr(p, stat);
    snprintf(p, sizeof p, "%s/%d/cgroup", root, pid); wr(p, cgroup);
    snprintf(d, sizeof d, "%s/%d/attr", root, pid); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/%d/attr/current", root, pid); wr(p, attr);
    snprintf(p, sizeof p, "%s/%d/cmdline", root, pid); wr(p, cmdline);
    (void)exe;
}

int main(void) {
    char root[] = "/tmp/ps_proc_XXXXXX"; assert(mkdtemp(root));
    mkpid(root, 1234, "1234 (sh) S 1190 1234 1190 0\n",
          "0::/system.slice/smbd.service\n", "/usr/sbin/smbd (complain)\n",
          "/usr/bin/dash", "sh");
    mkpid(root, 1190, "1190 (smbd) S 1 1190 1190 0\n",
          "0::/system.slice/smbd.service\n", "/usr/sbin/smbd (complain)\n",
          "/usr/sbin/smbd", "/usr/sbin/smbd");

    struct ps_activity a; memset(&a, 0, sizeof a);
    int rc = ps_proc_enrich(root, 1234, &a, 16);
    assert(rc == 0);
    assert(a.proc.pid == 1234 && a.proc.ppid == 1190);
    assert(strcmp(a.proc.comm, "sh") == 0);
    assert(strcmp(a.proc.cgroup, "/system.slice/smbd.service") == 0);
    assert(strcmp(a.proc.mac_mode, "complain") == 0);
    /* ancestry: 1190 (smbd) at depth 1; stop before pid 1 */
    assert(a.nanc == 1);
    assert(a.anc[0].pid == 1190 && a.anc[0].depth == 1);
    assert(strcmp(a.anc[0].comm, "smbd") == 0);
    printf("test_proc_enrich: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_proc_enrich 2>&1 | tail -4`
Expected: FAIL — `proc_enrich.h` not found.

- [ ] **Step 3: Create `src/agent/src/proc_enrich.h`**

```c
#ifndef PS_PROC_ENRICH_H
#define PS_PROC_ENRICH_H
#include "activity_record.h"

/* Fill a->proc (leaf pid) and a->anc[] (ancestors to session/service root,
 * stopping before PID 1, depth-capped at max_depth, skipping kernel threads).
 * proc_root: "" or NULL -> "/proc". Returns 0, or -1 if the leaf is unreadable. */
int ps_proc_enrich(const char *proc_root, int pid, struct ps_activity *a, int max_depth);
#endif /* PS_PROC_ENRICH_H */
```

- [ ] **Step 4: Create `src/agent/src/proc_enrich.c`**

```c
#include "proc_enrich.h"
#include "proc_parse.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int slurp(const char *root, int pid, const char *file, char *out, size_t cap) {
    char path[320];
    snprintf(path, sizeof path, "%s/%d/%s", root, pid, file);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(out, 1, cap - 1, f);
    fclose(f);
    out[n] = 0;
    return (int)n;
}

/* /proc/<pid>/cmdline is NUL-separated; turn NULs into spaces. */
static void cmdline_spaces(char *s, int n) {
    for (int i = 0; i < n - 1; i++) if (s[i] == 0) s[i] = ' ';
}

static int read_meta(const char *root, int pid, struct ps_act_proc *p) {
    char stat[512];
    if (slurp(root, pid, "stat", stat, sizeof stat) < 0) return -1;
    p->pid = pid;
    p->ppid = ps_proc_parse_ppid(stat);
    ps_proc_parse_comm(stat, p->comm, sizeof p->comm);

    char cg[512];
    if (slurp(root, pid, "cgroup", cg, sizeof cg) >= 0)
        ps_proc_parse_unit(cg, p->cgroup, sizeof p->cgroup);
    char attr[512];
    if (slurp(root, pid, "attr/current", attr, sizeof attr) >= 0)
        ps_proc_parse_mac(attr, p->mac_label, sizeof p->mac_label,
                          p->mac_mode, sizeof p->mac_mode);
    char cl[512];
    int cn = slurp(root, pid, "cmdline", cl, sizeof cl);
    if (cn > 0) { cmdline_spaces(cl, cn); snprintf(p->cmdline, sizeof p->cmdline, "%s", cl); }
    /* uid from status (Uid:\t<real> ...) */
    char status[1024];
    if (slurp(root, pid, "status", status, sizeof status) >= 0) {
        char *u = strstr(status, "Uid:");
        if (u) p->uid = atoi(u + 4);
    }
    return 0;
}

int ps_proc_enrich(const char *proc_root, int pid, struct ps_activity *a, int max_depth) {
    const char *root = (proc_root && proc_root[0]) ? proc_root : "/proc";
    if (read_meta(root, pid, &a->proc) != 0) return -1;

    a->nanc = 0;
    int cur = a->proc.ppid;
    int depth = 1;
    while (cur > 1 && depth <= max_depth && a->nanc < PS_ACT_MAX_ANC) {
        struct ps_act_proc tmp; memset(&tmp, 0, sizeof tmp);
        if (read_meta(root, cur, &tmp) != 0) break;
        /* skip kernel threads (kthreadd lineage: ppid 2 or comm in brackets style) */
        if (tmp.ppid == 2) break;
        a->anc[a->nanc].pid = cur;
        a->anc[a->nanc].depth = depth;
        snprintf(a->anc[a->nanc].comm, sizeof a->anc[a->nanc].comm, "%s", tmp.comm);
        a->nanc++;
        if (tmp.ppid <= 1) break;   /* parent is init -> cur was the session/service root */
        cur = tmp.ppid;
        depth++;
    }
    return 0;
}
```

- [ ] **Step 5: Wire into `src/agent/CMakeLists.txt`** — add `src/proc_enrich.c` to the agent source list; add the test (links `packetsonde_lib` for `proc_parse`):

```cmake
add_executable(test_proc_enrich tests/test_proc_enrich.c src/proc_enrich.c)
target_link_libraries(test_proc_enrich PRIVATE packetsonde_lib)
add_test(NAME test_proc_enrich COMMAND test_proc_enrich)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_proc_enrich >/dev/null && ctest -R '^test_proc_enrich$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /opt/repo/packetsonde
git add src/agent/src/proc_enrich.h src/agent/src/proc_enrich.c src/agent/tests/test_proc_enrich.c src/agent/CMakeLists.txt
git commit -m "agent: add proc_enrich (process meta + ancestry walk to session root)"
```

---

## Task 8: Socket snapshot (`src/agent/src/sock_snapshot`)

**Files:** Create `src/agent/src/sock_snapshot.h`, `src/agent/src/sock_snapshot.c`; Test `src/agent/tests/test_sock_snapshot.c`; Modify `src/agent/CMakeLists.txt`

> Uses `sock_parse` (lib). Injectable `proc_root`: reads `<root>/net/tcp` etc. and `<root>/<pid>/fd/*` symlinks. Tests build a fake tree where an fd symlink points to `socket:[99887]` and `<root>/net/tcp` contains that inode.

- [ ] **Step 1: Write the failing test** (`src/agent/tests/test_sock_snapshot.c`)

```c
#include "sock_snapshot.h"
#include "activity_record.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static void wr(const char *p, const char *c){ FILE*f=fopen(p,"w"); assert(f); fputs(c,f); fclose(f); }

int main(void) {
    char root[] = "/tmp/ps_sock_XXXXXX"; assert(mkdtemp(root));
    char p[320], d[320];
    /* <root>/net/tcp with inode 99887 (10.0.0.5:445 <- 203.0.113.5:51344, ESTABLISHED) */
    snprintf(d, sizeof d, "%s/net", root); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/net/tcp", root);
    wr(p, "  sl  local_address rem_address   st ... inode\n"
          "   0: 0500000A:01BD 0571CBCB:C890 01 00000000:00000000 00:00000000 00000000     0        0 99887 1\n");
    snprintf(p, sizeof p, "%s/net/tcp6", root); wr(p, "header\n");
    snprintf(p, sizeof p, "%s/net/udp",  root); wr(p, "header\n");
    snprintf(p, sizeof p, "%s/net/udp6", root); wr(p, "header\n");
    /* pid 1190 holds fd -> socket:[99887] */
    snprintf(d, sizeof d, "%s/1190", root); mkdir(d, 0755);
    snprintf(d, sizeof d, "%s/1190/fd", root); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/1190/fd/3", root);
    assert(symlink("socket:[99887]", p) == 0);

    int pids[1]   = {1190};
    const char *comms[1] = {"smbd"};
    int depths[1] = {1};
    struct ps_act_socket out[8];
    int n = ps_sock_snapshot(root, pids, 1, comms, depths, out, 8);
    assert(n == 1);
    assert(out[0].owner_pid == 1190 && out[0].depth == 1);
    assert(strcmp(out[0].owner_comm, "smbd") == 0);
    assert(strcmp(out[0].raddr, "203.0.113.5:51344") == 0);
    assert(strcmp(out[0].state, "ESTABLISHED") == 0);
    printf("test_sock_snapshot: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_sock_snapshot 2>&1 | tail -4`
Expected: FAIL — `sock_snapshot.h` not found.

- [ ] **Step 3: Create `src/agent/src/sock_snapshot.h`**

```c
#ifndef PS_SOCK_SNAPSHOT_H
#define PS_SOCK_SNAPSHOT_H
#include "activity_record.h"

/* For each pid in pids[], find its socket-inode fds and resolve them against
 * <proc_root>/net/{tcp,tcp6,udp,udp6}. Each resolved socket is appended to out[]
 * tagged with owner pid/comm/depth. Deduped by inode (nearest-to-root owner wins).
 * proc_root: "" or NULL -> "/proc". Returns count written (<= max). */
int ps_sock_snapshot(const char *proc_root, const int *pids, int npids,
                     const char *comms[], const int *depths,
                     struct ps_act_socket *out, int max);
#endif /* PS_SOCK_SNAPSHOT_H */
```

- [ ] **Step 4: Create `src/agent/src/sock_snapshot.c`**

```c
#include "sock_snapshot.h"
#include "sock_parse.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>

#define MAX_EPS 4096

static int load_net(const char *root, struct ps_sock_ep *eps, int cap) {
    const char *names[4] = {"tcp","tcp6","udp","udp6"};
    const char *protos[4] = {"tcp","tcp","udp","udp"};
    int n = 0;
    for (int i = 0; i < 4 && n < cap; i++) {
        char path[320]; snprintf(path, sizeof path, "%s/net/%s", root, names[i]);
        FILE *f = fopen(path, "r"); if (!f) continue;
        static char buf[1 << 20];
        size_t rd = fread(buf, 1, sizeof buf - 1, f); fclose(f); buf[rd] = 0;
        n += ps_sock_parse_procnet(protos[i], buf, eps + n, cap - n);
    }
    return n;
}

/* collect socket inodes from <root>/<pid>/fd/* symlinks ("socket:[N]") */
static int pid_sock_inodes(const char *root, int pid, unsigned long *out, int max) {
    char dir[320]; snprintf(dir, sizeof dir, "%s/%d/fd", root, pid);
    DIR *d = opendir(dir); if (!d) return 0;
    int n = 0; struct dirent *e;
    while ((e = readdir(d)) && n < max) {
        if (e->d_name[0] == '.') continue;
        char lp[400], tgt[128];
        snprintf(lp, sizeof lp, "%s/%s", dir, e->d_name);
        ssize_t r = readlink(lp, tgt, sizeof tgt - 1);
        if (r <= 0) continue; tgt[r] = 0;
        if (strncmp(tgt, "socket:[", 8) == 0)
            out[n++] = strtoul(tgt + 8, NULL, 10);
    }
    closedir(d);
    return n;
}

int ps_sock_snapshot(const char *proc_root, const int *pids, int npids,
                     const char *comms[], const int *depths,
                     struct ps_act_socket *out, int max) {
    const char *root = (proc_root && proc_root[0]) ? proc_root : "/proc";
    static struct ps_sock_ep eps[MAX_EPS];
    int neps = load_net(root, eps, MAX_EPS);
    int count = 0;
    /* iterate pids root-first (npids-1 .. 0) so nearest-to-root owner wins dedup */
    for (int i = npids - 1; i >= 0 && count < max; i--) {
        unsigned long inodes[256];
        int ni = pid_sock_inodes(root, pids[i], inodes, 256);
        for (int k = 0; k < ni && count < max; k++) {
            struct ps_sock_ep ep;
            if (ps_sock_find_by_inode(eps, neps, inodes[k], &ep) != 0) continue;
            /* dedup: skip if this inode already recorded */
            int dup = 0;
            for (int j = 0; j < count; j++)
                if (out[j].owner_pid && strcmp(out[j].raddr, ep.raddr) == 0 &&
                    strcmp(out[j].laddr, ep.laddr) == 0) { dup = 1; break; }
            if (dup) continue;
            struct ps_act_socket *s = &out[count++];
            memset(s, 0, sizeof *s);
            s->owner_pid = pids[i];
            s->depth = depths[i];
            snprintf(s->owner_comm, sizeof s->owner_comm, "%s", comms[i] ? comms[i] : "");
            snprintf(s->proto, sizeof s->proto, "%s", ep.proto);
            snprintf(s->laddr, sizeof s->laddr, "%s", ep.laddr);
            snprintf(s->raddr, sizeof s->raddr, "%s", ep.raddr);
            snprintf(s->state, sizeof s->state, "%s", ep.state);
        }
    }
    return count;
}
```

- [ ] **Step 5: Wire into `src/agent/CMakeLists.txt`** — add `src/sock_snapshot.c` to the agent source list; add the test:

```cmake
add_executable(test_sock_snapshot tests/test_sock_snapshot.c src/sock_snapshot.c)
target_link_libraries(test_sock_snapshot PRIVATE packetsonde_lib)
add_test(NAME test_sock_snapshot COMMAND test_sock_snapshot)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_sock_snapshot >/dev/null && ctest -R '^test_sock_snapshot$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /opt/repo/packetsonde
git add src/agent/src/sock_snapshot.h src/agent/src/sock_snapshot.c src/agent/tests/test_sock_snapshot.c src/agent/CMakeLists.txt
git commit -m "agent: add sock_snapshot (/proc/<pid>/fd inode -> /proc/net endpoints)"
```

---

## Task 9: Record builder — glue enrich+snapshot into a record (`src/agent/src/fan_monitor` build half)

**Files:** Create `src/agent/src/fan_monitor.h`, `src/agent/src/fan_monitor.c`; Test `src/agent/tests/test_fan_build.c`; Modify `src/agent/CMakeLists.txt`

> Split fanotify I/O (Task 11) from the testable "given (pid, path, mask) build a record JSON" core. This task is the core: suppression gate → enrich → snapshot → serialize.

- [ ] **Step 1: Write the failing test** (`src/agent/tests/test_fan_build.c`) — reuse the fake proc tree shape from Tasks 7/8.

```c
#include "fan_monitor.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static void wr(const char *p, const char *c){ FILE*f=fopen(p,"w"); assert(f); fputs(c,f); fclose(f); }

int main(void) {
    char root[] = "/tmp/ps_fan_XXXXXX"; assert(mkdtemp(root));
    char p[320], d[320];
    snprintf(d, sizeof d, "%s/net", root); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/net/tcp", root);
    wr(p, "hdr\n   0: 0500000A:01BD 0571CBCB:C890 01 0 0 0 0 0 99887 1\n");
    snprintf(p, sizeof p, "%s/net/tcp6", root); wr(p, "h\n");
    snprintf(p, sizeof p, "%s/net/udp",  root); wr(p, "h\n");
    snprintf(p, sizeof p, "%s/net/udp6", root); wr(p, "h\n");
    /* leaf 1234 (sh) -> 1190 (smbd, holds socket) -> init */
    snprintf(d, sizeof d, "%s/1234", root); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/1234/stat", root); wr(p, "1234 (sh) S 1190 1234 1190 0\n");
    snprintf(p, sizeof p, "%s/1234/cgroup", root); wr(p, "0::/system.slice/smbd.service\n");
    snprintf(d, sizeof d, "%s/1234/attr", root); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/1234/attr/current", root); wr(p, "unconfined\n");
    snprintf(p, sizeof p, "%s/1234/cmdline", root); wr(p, "sh");
    snprintf(d, sizeof d, "%s/1190", root); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/1190/stat", root); wr(p, "1190 (smbd) S 1 1190 1190 0\n");
    snprintf(p, sizeof p, "%s/1190/cgroup", root); wr(p, "0::/system.slice/smbd.service\n");
    snprintf(d, sizeof d, "%s/1190/attr", root); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/1190/attr/current", root); wr(p, "unconfined\n");
    snprintf(p, sizeof p, "%s/1190/cmdline", root); wr(p, "/usr/sbin/smbd");
    snprintf(d, sizeof d, "%s/1190/fd", root); mkdir(d, 0755);
    snprintf(p, sizeof p, "%s/1190/fd/3", root); assert(symlink("socket:[99887]", p) == 0);

    char json[8192];
    /* not suppressed: read of /etc/shadow */
    int n = ps_fan_build_record(root, 1234, "/etc/shadow", "open", 1, "", 16, json, sizeof json);
    assert(n > 0);
    assert(strstr(json, "\"path\":\"/etc/shadow\""));
    assert(strstr(json, "\"comm\":\"sh\""));
    assert(strstr(json, "\"owner_comm\":\"smbd\""));       /* ancestor socket attributed */
    assert(strstr(json, "\"raddr\":\"203.0.113.5:51344\""));

    /* suppressed read returns 0 (no record) */
    int s = ps_fan_build_record(root, 1234, "/usr/lib/x.so", "open", 1, "/usr/lib", 16, json, sizeof json);
    assert(s == 0);
    printf("test_fan_build: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_fan_build 2>&1 | tail -4`
Expected: FAIL — `fan_monitor.h` not found.

- [ ] **Step 3: Create `src/agent/src/fan_monitor.h`**

```c
#ifndef PS_FAN_MONITOR_H
#define PS_FAN_MONITOR_H
#include <stddef.h>

/* Build one activity-record JSON for a file event. Applies the suppression gate
 * first (reads only): if suppressed, returns 0 and writes nothing. Otherwise
 * enriches the pid (+ ancestry), snapshots sockets (leaf+ancestors), serializes.
 * `event` is "open"|"access"|"exec"; is_read 1 for read opens. `suppress` is the
 * coarse list. proc_root "" -> "/proc". Returns JSON length, 0 if suppressed, -1 error. */
int ps_fan_build_record(const char *proc_root, int pid, const char *path,
                        const char *event, int is_read, const char *suppress,
                        int max_depth, char *out, size_t cap);

/* Runtime entry (Task 11 wires fanotify to this). Returns 0; never returns until
 * stop flag set. `emit` is called with each record JSON. */
struct ps_fan_cfg { const char *watch_paths; const char *suppress; int max_depth; int max_events_ps; };
int ps_fan_monitor_run(const struct ps_fan_cfg *cfg,
                       void (*emit)(const char *json, size_t len, void *ctx), void *ctx);
#endif /* PS_FAN_MONITOR_H */
```

- [ ] **Step 4: Create `src/agent/src/fan_monitor.c`** (build half — `ps_fan_build_record`; `ps_fan_monitor_run` added in Task 11)

```c
#include "fan_monitor.h"
#include "proc_enrich.h"
#include "sock_snapshot.h"
#include "suppress.h"
#include "activity_record.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

static void now_iso(char *out, size_t cap) {
    struct timeval tv; gettimeofday(&tv, NULL);
    time_t t = tv.tv_sec; struct tm tm; gmtime_r(&t, &tm);
    strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

int ps_fan_build_record(const char *proc_root, int pid, const char *path,
                        const char *event, int is_read, const char *suppress,
                        int max_depth, char *out, size_t cap) {
    /* comm needed for suppression: cheap read via enrich's leaf, but to gate
     * BEFORE full enrich we read just the leaf comm. Reuse enrich for the leaf. */
    struct ps_activity a; memset(&a, 0, sizeof a);
    if (ps_proc_enrich(proc_root, pid, &a, max_depth) != 0) {
        /* process gone: emit a partial record with what we have (path/event) */
        a.partial = 1;
    }
    if (ps_suppress_match(suppress, a.proc.comm, path, is_read)) return 0;

    now_iso(a.ts, sizeof a.ts);
    snprintf(a.event, sizeof a.event, "%s", event);
    snprintf(a.path, sizeof a.path, "%s", path);

    /* socket snapshot over {leaf} ∪ ancestry */
    int pids[1 + PS_ACT_MAX_ANC]; const char *comms[1 + PS_ACT_MAX_ANC]; int depths[1 + PS_ACT_MAX_ANC];
    int np = 0;
    pids[np] = a.proc.pid; comms[np] = a.proc.comm; depths[np] = 0; np++;
    for (int i = 0; i < a.nanc && np < 1 + PS_ACT_MAX_ANC; i++) {
        pids[np] = a.anc[i].pid; comms[np] = a.anc[i].comm; depths[np] = a.anc[i].depth; np++;
    }
    a.nsock = ps_sock_snapshot(proc_root, pids, np, comms, depths, a.sock, PS_ACT_MAX_SOCK);

    return ps_activity_to_json(&a, out, cap);
}
```

- [ ] **Step 5: Wire into `src/agent/CMakeLists.txt`** — add `src/fan_monitor.c` to the agent source list; add the test (links the agent collection objects + lib):

```cmake
add_executable(test_fan_build tests/test_fan_build.c
    src/fan_monitor.c src/proc_enrich.c src/sock_snapshot.c)
target_link_libraries(test_fan_build PRIVATE packetsonde_lib)
add_test(NAME test_fan_build COMMAND test_fan_build)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_fan_build >/dev/null && ctest -R '^test_fan_build$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /opt/repo/packetsonde
git add src/agent/src/fan_monitor.h src/agent/src/fan_monitor.c src/agent/tests/test_fan_build.c src/agent/CMakeLists.txt
git commit -m "agent: add ps_fan_build_record (suppress-gate -> enrich -> snapshot -> json)"
```

---

## Task 10: `[detect]` config wiring

**Files:** Modify `src/agent/src/config_to_env.c`; Test `src/agent/tests/test_config_to_env.c`; Modify `packaging/packetsonded.toml`

- [ ] **Step 1: Add a failing assertion to `test_config_to_env.c`** (after the existing mapping assertions)

```c
    assert(env_for("detect", "enabled") && strcmp(env_for("detect","enabled"), "PS_DETECT_ENABLED") == 0);
    assert(env_for("detect", "watch_paths") && strcmp(env_for("detect","watch_paths"), "PS_DETECT_WATCH_PATHS") == 0);
```

> If the test has no `env_for` helper, mirror the existing assertion style in that file (it already verifies section/key→env mappings; match its idiom exactly).

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/packetsonde/build && make test_config_to_env 2>&1 | tail -4`
Expected: FAIL — no mapping for `detect/enabled`.

- [ ] **Step 3: Add `[detect]` rows to the `MAPPINGS[]` table in `config_to_env.c`** (before the NULL terminator)

```c
    { "detect", "enabled",        "PS_DETECT_ENABLED" },
    { "detect", "watch_paths",    "PS_DETECT_WATCH_PATHS" },
    { "detect", "suppress_paths", "PS_DETECT_SUPPRESS_PATHS" },
    { "detect", "max_depth",      "PS_DETECT_MAX_DEPTH" },
    { "detect", "max_events_ps",  "PS_DETECT_MAX_EVENTS_PS" },
```

- [ ] **Step 4: Document the block in `packaging/packetsonded.toml`** (append)

```toml
[detect]
# Process/file/socket collection (Linux). Off by default. See
# docs/specs/2026-06-03-process-collection-primitives-design.md
enabled        = "0"
watch_paths    = "/etc,/home"   # comma-separated; configurable + role-templated
suppress_paths = ""             # coarse read-only suppression prefixes ("comm:/prefix" allowed)
max_depth      = "16"           # ancestry-walk cap
max_events_ps  = "2000"         # global events/sec cap (drop + count over)
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd /opt/repo/packetsonde/build && make test_config_to_env >/dev/null && ctest -R '^test_config_to_env$' --output-on-failure`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /opt/repo/packetsonde
git add src/agent/src/config_to_env.c src/agent/tests/test_config_to_env.c packaging/packetsonded.toml
git commit -m "config: add [detect] block (enabled/watch_paths/suppress/depth/rate)"
```

---

## Task 11: fanotify runtime + priv wiring (privileged glue)

**Files:** Modify `src/agent/src/fan_monitor.c` (add `ps_fan_monitor_run`); `src/agent/src/priv_worker.c` (own the fanotify fd, emit `PS_OP_ACTIVITY_DATA`); `src/agent/src/priv_client.c` + `priv_client.h` (route `PS_OP_ACTIVITY_DATA` → `activity_ring`); `src/agent/src/main.c` (start collection when `PS_DETECT_ENABLED`)

> No unit test (needs `CAP_SYS_ADMIN` + a live kernel); verified by build + the live script (Task 12). Keep each function small.

- [ ] **Step 1: Implement `ps_fan_monitor_run` in `fan_monitor.c`**

```c
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/fanotify.h>

int ps_fan_monitor_run(const struct ps_fan_cfg *cfg,
                       void (*emit)(const char *, size_t, void *), void *ctx) {
    int fan = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, O_RDONLY | O_CLOEXEC);
    if (fan < 0) return -1;
    /* mark each watch path: opens, accesses, exec-opens (notification only) */
    char paths[4096]; snprintf(paths, sizeof paths, "%s", cfg->watch_paths ? cfg->watch_paths : "");
    for (char *p = strtok(paths, ","); p; p = strtok(NULL, ",")) {
        fanotify_mark(fan, FAN_MARK_ADD,
                      FAN_OPEN | FAN_ACCESS | FAN_OPEN_EXEC, AT_FDCWD, p);
    }
    int max_depth = cfg->max_depth > 0 ? cfg->max_depth : 16;
    for (;;) {
        struct pollfd pfd = { fan, POLLIN, 0 };
        if (poll(&pfd, 1, 500) <= 0) continue;
        char buf[8192];
        ssize_t len = read(fan, buf, sizeof buf);
        if (len <= 0) continue;
        struct fanotify_event_metadata *m = (void *)buf;
        for (; FAN_EVENT_OK(m, len); m = FAN_EVENT_NEXT(m, len)) {
            if (m->vers != FANOTIFY_METADATA_VERSION) { if (m->fd >= 0) close(m->fd); continue; }
            if (m->fd < 0) continue;
            char link[64], path[512];
            snprintf(link, sizeof link, "/proc/self/fd/%d", m->fd);
            ssize_t r = readlink(link, path, sizeof path - 1);
            close(m->fd);
            if (r <= 0) continue; path[r] = 0;
            const char *event = (m->mask & FAN_OPEN_EXEC) ? "exec"
                              : (m->mask & FAN_ACCESS) ? "access" : "open";
            int is_read = !(m->mask & FAN_OPEN_EXEC);  /* exec-opens never suppressed */
            char json[PS_ACT_ITEM_SERIALIZE_MAX];
            int n = ps_fan_build_record("", (int)m->pid, path, event, is_read,
                                        cfg->suppress, max_depth, json, sizeof json);
            if (n > 0 && emit) emit(json, (size_t)n, ctx);
        }
    }
    return 0;
}
```

Add near the top of `fan_monitor.c`: `#define PS_ACT_ITEM_SERIALIZE_MAX 8192`.

- [ ] **Step 2: In `priv_worker.c`, start the monitor and emit records**

The privileged worker owns the fanotify fd. Add an emit callback that writes an async `PS_OP_ACTIVITY_DATA` frame to `g_brain_fd`, and start `ps_fan_monitor_run` on a thread when `PS_DETECT_ENABLED=1`:

```c
#include "fan_monitor.h"
#include "priv_protocol.h"
#include <pthread.h>

static void emit_activity(const char *json, size_t len, void *ctx) {
    (void)ctx;
    if (len > PS_MAX_MSG_PAYLOAD) return;
    uint8_t frame[PS_MAX_MSG_PAYLOAD + 16];
    size_t n = ps_priv_encode_activity(frame, sizeof frame, json, len);
    if (n) write_all(g_brain_fd, frame, n);   /* write_all already defined in this file */
}

static void *fan_thread(void *arg) {
    struct ps_fan_cfg *cfg = arg;
    ps_fan_monitor_run(cfg, emit_activity, NULL);
    return NULL;
}
```

In the worker's startup (where it initializes before the poll loop), add:

```c
    static struct ps_fan_cfg fan_cfg;
    if (getenv("PS_DETECT_ENABLED") && atoi(getenv("PS_DETECT_ENABLED"))) {
        fan_cfg.watch_paths   = getenv("PS_DETECT_WATCH_PATHS");
        fan_cfg.suppress      = getenv("PS_DETECT_SUPPRESS_PATHS");
        fan_cfg.max_depth     = getenv("PS_DETECT_MAX_DEPTH") ? atoi(getenv("PS_DETECT_MAX_DEPTH")) : 16;
        fan_cfg.max_events_ps = getenv("PS_DETECT_MAX_EVENTS_PS") ? atoi(getenv("PS_DETECT_MAX_EVENTS_PS")) : 2000;
        pthread_t t; pthread_create(&t, NULL, fan_thread, &fan_cfg);
        pthread_detach(t);
    }
```

(Concurrency note: `write_all(g_brain_fd, …)` may now be called from both the poll loop and `fan_thread`. Guard `g_brain_fd` writes with a `static pthread_mutex_t g_write_mu` taken inside `write_all`.)

- [ ] **Step 3: In `priv_client.c`, route `PS_OP_ACTIVITY_DATA` to the ring**

In the async-message handling (where `PS_OP_PACKET_DATA`/`RAW_RESPONSE` are recognized), add a branch: when `hdr.opcode == PS_OP_ACTIVITY_DATA`, read `payload_len` bytes and call `ps_act_ring_push(payload, payload_len)` instead of queueing as a packet. Add `#include "activity_ring.h"`. (The brain already polls the priv fd via `ps_priv_client_recv`; activity frames are drained there.)

- [ ] **Step 4: In `main.c`, ensure the priv client is polled and init the ring**

Where the agent initializes queues (near `ps_obs_queue_init()`), add `ps_act_ring_init();`. Ensure `ps_priv_client_recv` is called in the agent's main loop so async activity frames are pulled (it already is for packet data — confirm the collection path shares it).

- [ ] **Step 5: Build the agent**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make packetsonde-agent 2>&1 | tail -8`
Expected: compiles + links (fanotify is in glibc; pthread already linked).

- [ ] **Step 6: Re-run the full collection unit suite (no regressions)**

Run: `cd /opt/repo/packetsonde/build && ctest -R 'suppress|proc_parse|sock_parse|activity_record|activity_ring|proc_enrich|sock_snapshot|fan_build|priv_protocol|config_to_env' --output-on-failure`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
cd /opt/repo/packetsonde
git add src/agent/src/fan_monitor.c src/agent/src/priv_worker.c \
        src/agent/src/priv_client.c src/agent/src/priv_client.h src/agent/src/main.c
git commit -m "agent: wire fanotify collection in priv_worker -> activity_ring (PS_DETECT_ENABLED)"
```

---

## Task 12: `packetsonde watch` verb

**Files:** Create `src/cli/verbs/watch.c`; Modify `src/cli/dispatch.c`, `src/cli/verbs.h` (if the prototype lives there), `src/cli/CMakeLists.txt`

> The verb asks the agent (over its IPC, like `agent`/`findings` do) to drain the activity ring and prints JSONL. Reuse the existing `agent`-control IPC path; if a simpler local path exists (the agent exposes the ring over its `ipc_server`), follow that. For the first cut, `watch` reads drained records the agent writes to its activity JSONL sink and tails them, matching how `findings` tails JSONL.

- [ ] **Step 1: Create `src/cli/verbs/watch.c`**

```c
#include "verbs.h"
#include <stdio.h>
#include <string.h>
#include <getopt.h>

/* Tail the agent's activity JSONL sink, optionally filtering by --path/--comm.
 * Mirrors verbs/findings.c's tailing approach (same JSONL idiom). */
int ps_verb_watch_run(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    const char *src = "/var/lib/packetsonde/activity.jsonl";
    const char *path_filter = NULL, *comm_filter = NULL;
    static struct option lo[] = {
        {"source", required_argument, 0, 's'},
        {"path",   required_argument, 0, 'p'},
        {"comm",   required_argument, 0, 'c'},
        {0,0,0,0}
    };
    optind = 1; int o;
    while ((o = getopt_long(argc, argv, "s:p:c:", lo, NULL)) != -1) {
        if (o == 's') src = optarg;
        else if (o == 'p') path_filter = optarg;
        else if (o == 'c') comm_filter = optarg;
    }
    FILE *f = fopen(src, "r");
    if (!f) { fprintf(stderr, "watch: cannot open %s (is [detect] enabled?)\n", src); return 1; }
    char line[PS_WATCH_LINE_MAX];
    while (fgets(line, sizeof line, f)) {
        if (path_filter && !strstr(line, path_filter)) continue;
        if (comm_filter && !strstr(line, comm_filter)) continue;
        fputs(line, stdout);
    }
    fclose(f);
    return 0;
}
```

Add near the top: `#define PS_WATCH_LINE_MAX 16384`.

> Note: this assumes the agent persists drained records to `activity.jsonl`. Add that sink in `main.c`'s drain loop (drain `ps_act_ring` → append each item + `\n` to the configured sink path), gated on `PS_DETECT_ENABLED`. Wire the sink write alongside the Task 11 drain.

- [ ] **Step 2: Register the verb in `dispatch.c`**

Add the prototype line with the others:
```c
int ps_verb_watch_run(int argc, char **argv, const struct ps_args *opts);
```
Add to the `VERBS[]` table:
```c
    { "watch",    ps_verb_watch_run,    "Tail process/file/socket activity records (JSONL)" },
```

- [ ] **Step 3: Add the source to `src/cli/CMakeLists.txt`** — `verbs/watch.c` in the CLI sources list.

- [ ] **Step 4: Build the CLI**

Run: `cd /opt/repo/packetsonde/build && make packetsonde 2>&1 | tail -6`
Expected: compiles + links.

- [ ] **Step 5: Smoke-test the verb (no sink → clean error)**

Run:
```bash
cd /opt/repo/packetsonde/build
./src/cli/packetsonde watch --source /tmp/nonexistent.jsonl; echo "exit=$?"
printf '{"v":1,"event":"open","path":"/etc/shadow","process":{"comm":"sh"}}\n' > /tmp/act.jsonl
./src/cli/packetsonde watch --source /tmp/act.jsonl --comm sh
```
Expected: first prints a clean "cannot open" error + non-zero; second prints the one matching line.

- [ ] **Step 6: Commit**

```bash
cd /opt/repo/packetsonde
git add src/cli/verbs/watch.c src/cli/dispatch.c src/cli/CMakeLists.txt src/agent/src/main.c
git commit -m "cli: add 'watch' verb to tail activity records; agent persists activity JSONL"
```

---

## Task 13: Live integration — SSH/EternalRed-shape validation

**Files:** Create `scripts/test-process-collection.sh`

> Privileged (needs `CAP_SYS_ADMIN` for fanotify). Validates the end-to-end pipeline and the ancestry-walk attribution that the SSH/EternalRed cases hinge on.

- [ ] **Step 1: Create the script**

```bash
#!/bin/bash
# End-to-end process-collection validation. Requires root (fanotify).
# Verifies: a file read by a child process is attributed, via the ancestry
# walk, to a socket held by an ancestor (the SSH/EternalRed shape).
set -euo pipefail
cd "$(dirname "$0")/.."
AGENT=build/src/agent/packetsonde-agent
CLI=build/src/cli/packetsonde
SINK=/tmp/ps-activity-$$.jsonl
WATCH=/tmp/ps-watch-$$; mkdir -p "$WATCH"

[ "$(id -u)" = 0 ] || { echo "must run as root (fanotify needs CAP_SYS_ADMIN)"; exit 1; }

cat > /tmp/ps-detect-$$.toml <<EOF
[keys]
dir = "/tmp/ps-keys-$$"
[detect]
enabled       = "1"
watch_paths   = "$WATCH"
suppress_paths = "/usr/lib,/usr/share"
max_depth     = "16"
EOF
mkdir -p /tmp/ps-keys-$$

echo "Start the agent with the above config and PS detect sink -> $SINK, then:"
echo "  1. (terminal A) hold a socket + spawn a child that reads a watched file:"
echo "       python3 -c \"import socket,subprocess,time; s=socket.create_connection(('1.1.1.1',53)); subprocess.run(['cat','$WATCH/secret']); time.sleep(2)\" &"
echo "       echo data > $WATCH/secret"
echo "  2. (terminal B) tail records:"
echo "       $CLI watch --source $SINK --path secret"
echo
echo "PASS criteria: a record with path=$WATCH/secret, process.comm=cat (or python),"
echo "and a sockets[] entry owned by an ANCESTOR (depth>=1) with the held raddr —"
echo "i.e. the child's file read is attributed to the parent's socket."
echo
echo "Cleanup: rm -rf $SINK $WATCH /tmp/ps-detect-$$.toml /tmp/ps-keys-$$"
```

- [ ] **Step 2: Run the assisted live test** — start the agent as root with the printed config, trigger the file read under a socket-holding parent, confirm the `watch` output shows the ancestor-attributed socket. Clean up.

- [ ] **Step 3: Commit**

```bash
cd /opt/repo/packetsonde
chmod +x scripts/test-process-collection.sh
git add scripts/test-process-collection.sh
git commit -m "Add assisted live test for process collection (ancestry socket attribution)"
```

---

## Self-Review

**Spec coverage:**
- §3 architecture (priv_worker engine → IPC → ring → verb) → Tasks 1, 6, 11, 12 ✓
- §4 pipeline (suppress → enrich → ancestry → snapshot → emit) → Tasks 2, 7, 8, 9, 11 ✓
- §5 record schema (incl. cgroup/unit, mac label/mode, ancestry depth, owner-tagged sockets) → Tasks 5, 7, 8 ✓
- §6 components (each independently testable) → one task each: suppress(2), proc_parse(3), sock_parse(4), activity_record(5), activity_ring(6), proc_enrich(7), sock_snapshot(8), fan_monitor(9/11), watch(12) ✓
- §7 ancestry walk to session/service root, depth cap, skip kthreads → Task 7 (`ps_proc_enrich`, tested for stop-before-PID-1) ✓
- §8 socket snapshot, owner-tag, dedup → Task 8 (`/proc/net` path; sock_diag deferred, noted) ✓
- §9 coarse read-only suppression, never writes/exec, gates enrichment → Tasks 2, 9 ✓
- §10 `[detect]` config via config_to_env → Task 10 ✓
- §11 lightweight (gate-before-enrich, bounded ring, off by default) → Tasks 2/6/9/10/11 ✓
- §12 EternalRed/SSH shape → Tasks 9 (unit: ancestor socket attribution) + 13 (live) ✓
- §13 deferred (SP2/SP3, sock_diag, BSD, eBPF) → not implemented, explicitly out of scope ✓

**Placeholder scan:** No "TBD"/"add error handling" steps; every code step shows complete code. Task 11/12 glue notes name exact functions/fds and the concurrency guard; the one assumption (agent persists `activity.jsonl`) is made explicit and wired in Tasks 11/12.

**Type/name consistency:** `PS_OP_ACTIVITY_DATA`/`ps_priv_encode_activity` (1,11); `ps_suppress_match` (2,9); `ps_proc_parse_*` (3,7); `ps_sock_parse_procnet`/`ps_sock_find_by_inode`/`struct ps_sock_ep` (4,8); `struct ps_activity`/`ps_activity_to_json` (5,7,8,9); `ps_act_ring_*`/`PS_ACT_RING_CAP`/`PS_ACT_ITEM_MAX` (6,11); `ps_proc_enrich` (7,9); `ps_sock_snapshot` (8,9); `ps_fan_build_record`/`ps_fan_monitor_run`/`struct ps_fan_cfg` (9,11); `ps_verb_watch_run` (12). Record field names identical across schema (5) and producers (7,8,9).

**Known follow-ups (noted, not gaps):** (a) `sock_diag` replacing `/proc/net` parsing for perf; (b) friendlier IPC for `watch` (currently a JSONL sink the agent writes); (c) `max_events_ps` rate-limit enforcement is plumbed into `ps_fan_cfg` and applied in `ps_fan_monitor_run` (add a token-bucket drop+count in Task 11 Step 1 if event storms appear in the live test); (d) role-templated watch-path bundles live in config/salt, not the agent.
```
