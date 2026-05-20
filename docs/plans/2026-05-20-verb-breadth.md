# Verb Breadth (discover / scan / probe / audit dns / findings / config) — Plan 3 of 3

> **For agentic workers:** Execute task-by-task. Each task has steps with checkbox (`- [ ]`) syntax for tracking.

**Goal:** Round out the v1 verb surface. After this plan, `packetsonde` can do host discovery (`discover hosts`, `discover neighbors`), port scanning (`scan ports`), TCP probing (`probe tcp`), all four traceroute modes (`probe traceroute --proto udp|tcp|icmp --mode classic|paris|dublin`), DNS auditing (`audit dns`), find local JSONL records (`findings tail`, `findings filter`), inspect config (`config show`, `config path`), parse the agent registry (`agents.toml`), and gate exit codes on finding severity (`--fail-on`).

**Architecture:** Each verb is a thin shell that reuses Plan 2's worker pool, rate limiter, output emitter, and finding record. Discovery and scanning iterate over CIDR-expanded targets via shared util `targets.{h,c}`. Traceroute lives in `lib/traceroute.{h,c}` so the agent can call into the same code later (per spec); the CLI's `probe traceroute` is the first consumer. JSONL utilities (`findings_util/`) read finding records back from disk for `findings tail` / `findings filter`. The agents registry parses a minimal TOML subset just for the agent listing.

**Tech Stack:** C11, pthreads, OpenSSL (for DNSSEC chain validation, optional), system raw-socket/IP_TTL on Linux for traceroute. macOS notes: TCP traceroute and ICMP traceroute require root; UDP traceroute uses `IP_RECVERR` on Linux and falls back to a portable `IP_TTL` + `connect()` pattern.

**Spec reference:** `docs/specs/2026-05-18-packetsonde-cli-design.md` §3 (finding record), §5 (CLI grammar, --fail-on), §6.1 (verb table), §6.3 (traceroute matrix).

---

## File structure produced by this plan

```
src/lib/
├── traceroute.h            # protocol- and mode-parameterized traceroute core
├── traceroute.c
├── tests/
│   └── test_traceroute.c   # parser/builder tests; no network

src/cli/
├── util/
│   ├── targets.h           # CIDR expansion, port-list parsing
│   ├── targets.c
│   └── fail_on.h/c         # --fail-on expression evaluator
├── discover/
│   ├── hosts.h/c           # ARP-style probe (ICMP/TCP-SYN fallback) per host
│   └── neighbors.h/c       # platform neighbor table read
├── scan/
│   └── ports.h/c           # connect-scan
├── probe/
│   ├── tcp.h/c             # single TCP probe + banner
│   └── traceroute.h/c      # CLI wrapper around lib/traceroute
├── audit/
│   ├── tls.c               # (existing)
│   └── dns.h/c             # DNS resolver audit
├── findings_util/
│   ├── reader.h/c          # JSONL line reader
│   └── filter.h/c          # expression filter (kind, severity, target)
├── registry/
│   └── agents.h/c          # agents.toml parser; v1 supports only 'local'
├── verbs/
│   ├── audit.c             # (existing) wire dns kind
│   ├── discover.c
│   ├── scan.c
│   ├── probe.c
│   ├── findings.c
│   └── config.c
└── tests/
    ├── test_targets.c
    ├── test_findings_filter.c
    ├── test_fail_on.c
    └── test_agents_registry.c
```

Existing files modified:
- `src/cli/args.h/c`: surface `--fail-on` flag
- `src/cli/main.c`: invoke `ps_fail_on_eval()` post-verb to decide exit code
- `src/cli/output/output.{h,c}`: expose a typed-counts snapshot for `--fail-on`
- `src/cli/dispatch.c`: register new verbs
- `src/cli/audit/tls.c`: have the run path return severity counts via the new snapshot API
- `src/cli/CMakeLists.txt`, `src/lib/CMakeLists.txt`: new sources/tests

---

## Task 1: Baseline check

- [ ] **Step 1: Clean rebuild + tests**

```bash
cd /Users/billn/packetsonde && rm -rf build && ./build.sh native 2>&1 | tail -3 && cd build && ctest --output-on-failure 2>&1 | tail -3
```
Expected: clean build; 20/20 tests pass.

No commit. Verification only.

---

## Task 2: Targets utility — CIDR & port-list parsing (TDD)

Shared by `discover hosts`, `scan ports`. Parses `10.0.0.0/24` into a sequence of IPv4 addresses, and `22,80,443,1000-2000` into a sequence of ports.

**Files:**
- Create: `src/cli/util/targets.h`, `src/cli/util/targets.c`
- Create: `src/cli/tests/test_targets.c`
- Modify: `src/cli/CMakeLists.txt`

- [ ] **Step 1: Test**

`mkdir -p src/cli/util`

Create `/Users/billn/packetsonde/src/cli/tests/test_targets.c`:
```c
#include "../util/targets.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_cidr_24(void) {
    struct ps_cidr c;
    assert(ps_cidr_parse("10.0.0.0/24", &c) == 0);
    assert(c.count == 256);
    char buf[32];
    assert(ps_cidr_addr(&c, 0,   buf, sizeof(buf)) == 0);
    assert(strcmp(buf, "10.0.0.0") == 0);
    assert(ps_cidr_addr(&c, 255, buf, sizeof(buf)) == 0);
    assert(strcmp(buf, "10.0.0.255") == 0);
    assert(ps_cidr_addr(&c, 256, buf, sizeof(buf)) != 0);
}

static void test_single_host(void) {
    struct ps_cidr c;
    assert(ps_cidr_parse("192.168.1.42", &c) == 0);
    assert(c.count == 1);
    char buf[32];
    assert(ps_cidr_addr(&c, 0, buf, sizeof(buf)) == 0);
    assert(strcmp(buf, "192.168.1.42") == 0);
}

static void test_bad_cidr(void) {
    struct ps_cidr c;
    assert(ps_cidr_parse("not-a-cidr",     &c) != 0);
    assert(ps_cidr_parse("10.0.0.0/33",    &c) != 0);
    assert(ps_cidr_parse("999.0.0.0/24",   &c) != 0);
}

static void test_ports_simple(void) {
    struct ps_portset p;
    assert(ps_ports_parse("22,80,443", &p) == 0);
    assert(p.count == 3);
    assert(p.ports[0] == 22);
    assert(p.ports[1] == 80);
    assert(p.ports[2] == 443);
}

static void test_ports_range(void) {
    struct ps_portset p;
    assert(ps_ports_parse("1-3,80", &p) == 0);
    assert(p.count == 4);
    assert(p.ports[0] == 1);
    assert(p.ports[1] == 2);
    assert(p.ports[2] == 3);
    assert(p.ports[3] == 80);
}

static void test_ports_bad(void) {
    struct ps_portset p;
    assert(ps_ports_parse("0-65535", &p) != 0);  /* port 0 invalid */
    assert(ps_ports_parse("not-a-port", &p) != 0);
    assert(ps_ports_parse("70000", &p) != 0);
}

int main(void) {
    test_cidr_24();
    test_single_host();
    test_bad_cidr();
    test_ports_simple();
    test_ports_range();
    test_ports_bad();
    printf("test_targets: OK\n");
    return 0;
}
```

- [ ] **Step 2: CMake**

In `/Users/billn/packetsonde/src/cli/CMakeLists.txt`, add `util/targets.c` to `CLI_SOURCES`. Add test target:
```cmake
add_executable(test_targets tests/test_targets.c util/targets.c)
target_include_directories(test_targets PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_targets PRIVATE packetsonde_lib)
add_test(NAME test_targets COMMAND test_targets)
```

- [ ] **Step 3: Red**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make test_targets 2>&1 | tail -5
```
Expected: missing `targets.h`.

- [ ] **Step 4: Implement `src/cli/util/targets.h`**

```c
#ifndef PS_TARGETS_H
#define PS_TARGETS_H

#include <stddef.h>
#include <stdint.h>

#define PS_PORTS_MAX 65535

struct ps_cidr {
    uint32_t base;     /* network base, host byte order */
    uint32_t count;    /* number of addresses */
    int      prefix;   /* prefix length, e.g. 24; -1 means "single host" */
};

struct ps_portset {
    uint16_t *ports;
    size_t    count;
    size_t    cap;
};

int  ps_cidr_parse(const char *spec, struct ps_cidr *out);
int  ps_cidr_addr (const struct ps_cidr *c, uint32_t idx, char *out, size_t outsz);

int  ps_ports_parse  (const char *spec, struct ps_portset *out);
void ps_ports_destroy(struct ps_portset *p);

#endif
```

- [ ] **Step 5: Implement `src/cli/util/targets.c`**

```c
#include "targets.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ps_cidr_parse(const char *spec, struct ps_cidr *out) {
    if (!spec || !out) return -1;
    memset(out, 0, sizeof(*out));
    char buf[64];
    size_t n = strlen(spec);
    if (n >= sizeof(buf)) return -1;
    memcpy(buf, spec, n + 1);
    char *slash = strchr(buf, '/');
    int prefix = -1;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) return -1;
    }
    struct in_addr ia;
    if (inet_pton(AF_INET, buf, &ia) != 1) return -1;
    uint32_t addr = ntohl(ia.s_addr);
    if (prefix < 0) {
        out->base   = addr;
        out->count  = 1;
        out->prefix = -1;
        return 0;
    }
    uint32_t mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
    out->base   = addr & mask;
    out->count  = prefix == 32 ? 1 : (1u << (32 - prefix));
    out->prefix = prefix;
    return 0;
}

int ps_cidr_addr(const struct ps_cidr *c, uint32_t idx, char *out, size_t outsz) {
    if (idx >= c->count) return -1;
    uint32_t a = c->base + idx;
    struct in_addr ia; ia.s_addr = htonl(a);
    if (!inet_ntop(AF_INET, &ia, out, (socklen_t)outsz)) return -1;
    return 0;
}

static int port_add(struct ps_portset *p, int v) {
    if (v <= 0 || v > 65535) return -1;
    if (p->count == p->cap) {
        size_t newcap = p->cap ? p->cap * 2 : 64;
        uint16_t *grow = realloc(p->ports, newcap * sizeof(*grow));
        if (!grow) return -1;
        p->ports = grow; p->cap = newcap;
    }
    p->ports[p->count++] = (uint16_t)v;
    return 0;
}

int ps_ports_parse(const char *spec, struct ps_portset *out) {
    if (!spec || !out) return -1;
    memset(out, 0, sizeof(*out));
    const char *p = spec;
    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;
        char *end;
        long a = strtol(p, &end, 10);
        if (end == p) goto fail;
        if (*end == '-') {
            long b = strtol(end + 1, &end, 10);
            if (b < a) goto fail;
            for (long v = a; v <= b; v++) {
                if (port_add(out, (int)v) != 0) goto fail;
            }
        } else {
            if (port_add(out, (int)a) != 0) goto fail;
        }
        p = end;
    }
    if (out->count == 0) goto fail;
    return 0;
fail:
    ps_ports_destroy(out);
    return -1;
}

void ps_ports_destroy(struct ps_portset *p) {
    free(p->ports);
    p->ports = NULL; p->count = 0; p->cap = 0;
}
```

- [ ] **Step 6: Build, test, commit**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make test_targets packetsonde 2>&1 | tail -3
ctest -R '^test_targets$' --output-on-failure 2>&1 | tail -3
ctest --output-on-failure 2>&1 | tail -3
```
Expected: 21/21 PASS.

```bash
cd /Users/billn/packetsonde
git add src/cli/util src/cli/tests/test_targets.c src/cli/CMakeLists.txt
git commit -m "feat(cli/util): CIDR and port-list parsers

Shared by discover, scan, probe verbs. CIDR expansion into IPv4
sequence; comma+dash port-list (e.g. 22,80,1000-2000) into a uint16
array."
```

---

## Task 3: `findings_util` — JSONL reader + filter (TDD)

Used by the `findings` verb. Reads one JSONL line at a time, parses minimal subset (kind, severity, target, run_id). Filter takes a small expression language.

**Files:**
- Create: `src/cli/findings_util/reader.h`, `src/cli/findings_util/reader.c`
- Create: `src/cli/findings_util/filter.h`, `src/cli/findings_util/filter.c`
- Create: `src/cli/tests/test_findings_filter.c`
- Modify: `src/cli/CMakeLists.txt`

- [ ] **Step 1: Test**

`mkdir -p src/cli/findings_util`

Create `/Users/billn/packetsonde/src/cli/tests/test_findings_filter.c`:
```c
#include "../findings_util/filter.h"
#include "../findings_util/reader.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char *LINE_TLS_HIGH =
    "{\"v\":1,\"id\":\"01H\",\"run_id\":\"R\",\"ts\":\"t\","
    "\"source\":\"cli.audit.tls\",\"host\":\"h\","
    "\"kind\":\"tls.weak_cipher\",\"severity\":\"high\",\"confidence\":\"firm\","
    "\"title\":\"x\",\"target\":{\"ip\":\"10.0.0.1\",\"port\":443}}";

static const char *LINE_DNS_LOW =
    "{\"v\":1,\"id\":\"01J\",\"run_id\":\"R\",\"ts\":\"t\","
    "\"source\":\"cli.audit.dns\",\"host\":\"h\","
    "\"kind\":\"dns.version_leak\",\"severity\":\"low\",\"confidence\":\"firm\","
    "\"title\":\"y\",\"target\":{\"ip\":\"8.8.8.8\"}}";

static void test_parse_minimal(void) {
    struct ps_finding_lite f;
    assert(ps_finding_parse_line(LINE_TLS_HIGH, &f) == 0);
    assert(strcmp(f.kind, "tls.weak_cipher") == 0);
    assert(f.severity == PS_SEV_HIGH);
    assert(strcmp(f.target, "10.0.0.1:443") == 0);
}

static void test_filter_kind_eq(void) {
    struct ps_finding_filter F;
    assert(ps_filter_parse("kind=tls.weak_cipher", &F) == 0);
    struct ps_finding_lite f1, f2;
    ps_finding_parse_line(LINE_TLS_HIGH, &f1);
    ps_finding_parse_line(LINE_DNS_LOW,  &f2);
    assert(ps_filter_eval(&F, &f1) == 1);
    assert(ps_filter_eval(&F, &f2) == 0);
    ps_filter_destroy(&F);
}

static void test_filter_severity_ge(void) {
    struct ps_finding_filter F;
    assert(ps_filter_parse("severity>=medium", &F) == 0);
    struct ps_finding_lite f1, f2;
    ps_finding_parse_line(LINE_TLS_HIGH, &f1);
    ps_finding_parse_line(LINE_DNS_LOW,  &f2);
    assert(ps_filter_eval(&F, &f1) == 1);
    assert(ps_filter_eval(&F, &f2) == 0);
    ps_filter_destroy(&F);
}

static void test_filter_kind_prefix(void) {
    struct ps_finding_filter F;
    assert(ps_filter_parse("kind~tls.", &F) == 0);
    struct ps_finding_lite f1, f2;
    ps_finding_parse_line(LINE_TLS_HIGH, &f1);
    ps_finding_parse_line(LINE_DNS_LOW,  &f2);
    assert(ps_filter_eval(&F, &f1) == 1);
    assert(ps_filter_eval(&F, &f2) == 0);
    ps_filter_destroy(&F);
}

int main(void) {
    test_parse_minimal();
    test_filter_kind_eq();
    test_filter_severity_ge();
    test_filter_kind_prefix();
    printf("test_findings_filter: OK\n");
    return 0;
}
```

- [ ] **Step 2: CMake**

Add to `CLI_SOURCES`: `findings_util/reader.c findings_util/filter.c`. Add test:
```cmake
add_executable(test_findings_filter
    tests/test_findings_filter.c
    findings_util/reader.c
    findings_util/filter.c)
target_include_directories(test_findings_filter PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_findings_filter PRIVATE packetsonde_lib)
add_test(NAME test_findings_filter COMMAND test_findings_filter)
```

- [ ] **Step 3: Implement `src/cli/findings_util/reader.h`**

```c
#ifndef PS_FINDING_READER_H
#define PS_FINDING_READER_H

#include "finding.h"
#include <stddef.h>

/* A "lite" finding extracted from a JSONL line — enough for filtering
 * and tail-pretty-printing, not the full record. */
struct ps_finding_lite {
    char id[64];
    char run_id[64];
    char kind[128];
    char source[128];
    char target[280];          /* "ip:port" or "ip" or "hostname:port" */
    char title[256];
    enum ps_severity severity;
};

/* Parse one JSONL line into a finding_lite. Returns 0 on success. */
int ps_finding_parse_line(const char *line, struct ps_finding_lite *out);

#endif
```

- [ ] **Step 4: Implement `src/cli/findings_util/reader.c`**

```c
#include "reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Extract a quoted string value for `"key":"..."`. Writes to out (NUL-term).
 * Returns 1 if found, 0 otherwise. Does not unescape — sufficient for our
 * narrow set of keys (kind, source, severity, ...). */
static int extract_str(const char *line, const char *key, char *out, size_t outsz) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    const char *p = strstr(line, pattern);
    if (!p) { if (outsz) out[0] = '\0'; return 0; }
    p += strlen(pattern);
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < outsz) {
        if (*p == '\\' && p[1]) { out[i++] = p[1]; p += 2; continue; }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 1;
}

/* Extract a numeric value for `"key":N`. Returns the value or -1 if missing. */
static long extract_num(const char *line, const char *key) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    const char *p = strstr(line, pattern);
    if (!p) return -1;
    p += strlen(pattern);
    return strtol(p, NULL, 10);
}

static enum ps_severity parse_sev(const char *s) {
    if (!strcmp(s, "info"))     return PS_SEV_INFO;
    if (!strcmp(s, "low"))      return PS_SEV_LOW;
    if (!strcmp(s, "medium"))   return PS_SEV_MEDIUM;
    if (!strcmp(s, "high"))     return PS_SEV_HIGH;
    if (!strcmp(s, "critical")) return PS_SEV_CRITICAL;
    return PS_SEV_INFO;
}

int ps_finding_parse_line(const char *line, struct ps_finding_lite *out) {
    if (!line || !out) return -1;
    memset(out, 0, sizeof(*out));
    if (!extract_str(line, "id",      out->id,     sizeof(out->id)))     return -1;
    extract_str    (line, "run_id",  out->run_id, sizeof(out->run_id));
    extract_str    (line, "source",  out->source, sizeof(out->source));
    if (!extract_str(line, "kind",    out->kind,   sizeof(out->kind)))   return -1;
    extract_str    (line, "title",   out->title,  sizeof(out->title));
    char sev_buf[16] = "";
    extract_str(line, "severity", sev_buf, sizeof(sev_buf));
    out->severity = parse_sev(sev_buf);

    /* Build target = ip:port (or hostname:port, or ip, or hostname). */
    char ip[64] = "", hostname[256] = "";
    extract_str(line, "ip",       ip,       sizeof(ip));
    extract_str(line, "hostname", hostname, sizeof(hostname));
    long port = extract_num(line, "port");
    const char *primary = ip[0] ? ip : hostname;
    if (primary[0] && port > 0)
        snprintf(out->target, sizeof(out->target), "%s:%ld", primary, port);
    else if (primary[0])
        snprintf(out->target, sizeof(out->target), "%s", primary);
    return 0;
}
```

- [ ] **Step 5: Implement `src/cli/findings_util/filter.h`**

```c
#ifndef PS_FINDING_FILTER_H
#define PS_FINDING_FILTER_H

#include "reader.h"

enum ps_filter_op {
    PS_FOP_EQ,        /* key=value         */
    PS_FOP_GE,        /* key>=value (severity only) */
    PS_FOP_PREFIX     /* key~value         */
};

enum ps_filter_field {
    PS_FF_KIND,
    PS_FF_SOURCE,
    PS_FF_SEVERITY,
    PS_FF_TARGET
};

struct ps_finding_filter {
    enum ps_filter_field field;
    enum ps_filter_op    op;
    char                 value_s[128];
    enum ps_severity     value_sev;
};

/* Parses "kind=...", "kind~prefix", "severity>=high", "source=cli.audit.tls",
 * "target=10.0.0.42:443". Returns 0 on success. */
int  ps_filter_parse  (const char *expr, struct ps_finding_filter *out);
int  ps_filter_eval   (const struct ps_finding_filter *F,
                       const struct ps_finding_lite *f);  /* 1 = match */
void ps_filter_destroy(struct ps_finding_filter *F);

#endif
```

- [ ] **Step 6: Implement `src/cli/findings_util/filter.c`**

```c
#include "filter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_field(const char *s, size_t n, enum ps_filter_field *f) {
    if (n == 4 && !strncmp(s, "kind",     4)) { *f = PS_FF_KIND;     return 0; }
    if (n == 6 && !strncmp(s, "source",   6)) { *f = PS_FF_SOURCE;   return 0; }
    if (n == 8 && !strncmp(s, "severity", 8)) { *f = PS_FF_SEVERITY; return 0; }
    if (n == 6 && !strncmp(s, "target",   6)) { *f = PS_FF_TARGET;   return 0; }
    return -1;
}

static int sev_from(const char *s) {
    if (!strcmp(s, "info"))     return PS_SEV_INFO;
    if (!strcmp(s, "low"))      return PS_SEV_LOW;
    if (!strcmp(s, "medium"))   return PS_SEV_MEDIUM;
    if (!strcmp(s, "high"))     return PS_SEV_HIGH;
    if (!strcmp(s, "critical")) return PS_SEV_CRITICAL;
    return -1;
}

int ps_filter_parse(const char *expr, struct ps_finding_filter *F) {
    if (!expr || !F) return -1;
    memset(F, 0, sizeof(*F));

    const char *eq = strchr(expr, '=');
    const char *ge = strstr(expr, ">=");
    const char *pr = strchr(expr, '~');

    const char *split;
    enum ps_filter_op op;
    size_t op_len;
    if (ge && (!eq || ge < eq) && (!pr || ge < pr)) {
        split = ge; op = PS_FOP_GE; op_len = 2;
    } else if (pr && (!eq || pr < eq)) {
        split = pr; op = PS_FOP_PREFIX; op_len = 1;
    } else if (eq) {
        split = eq; op = PS_FOP_EQ; op_len = 1;
    } else {
        return -1;
    }

    size_t key_len = (size_t)(split - expr);
    if (parse_field(expr, key_len, &F->field) != 0) return -1;
    F->op = op;
    const char *val = split + op_len;
    size_t vlen = strlen(val);
    if (vlen == 0 || vlen >= sizeof(F->value_s)) return -1;
    memcpy(F->value_s, val, vlen + 1);

    if (F->field == PS_FF_SEVERITY) {
        int s = sev_from(F->value_s);
        if (s < 0) return -1;
        F->value_sev = (enum ps_severity)s;
        if (F->op == PS_FOP_PREFIX) return -1;  /* nonsensical */
    }
    return 0;
}

int ps_filter_eval(const struct ps_finding_filter *F, const struct ps_finding_lite *f) {
    const char *field;
    switch (F->field) {
        case PS_FF_KIND:     field = f->kind;     break;
        case PS_FF_SOURCE:   field = f->source;   break;
        case PS_FF_TARGET:   field = f->target;   break;
        case PS_FF_SEVERITY:
            if (F->op == PS_FOP_EQ) return f->severity == F->value_sev;
            if (F->op == PS_FOP_GE) return f->severity >= F->value_sev;
            return 0;
    }
    if (F->op == PS_FOP_EQ)     return strcmp(field, F->value_s) == 0;
    if (F->op == PS_FOP_PREFIX) return strncmp(field, F->value_s, strlen(F->value_s)) == 0;
    return 0;
}

void ps_filter_destroy(struct ps_finding_filter *F) {
    (void)F;
}
```

- [ ] **Step 7: Build, test, commit**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make test_findings_filter packetsonde 2>&1 | tail -3
ctest -R '^test_findings_filter$' --output-on-failure 2>&1 | tail -3
ctest --output-on-failure 2>&1 | tail -3
```
Expected: 22/22 PASS.

```bash
cd /Users/billn/packetsonde
git add src/cli/findings_util src/cli/tests/test_findings_filter.c src/cli/CMakeLists.txt
git commit -m "feat(cli/findings_util): JSONL line reader + filter expressions

Reader extracts the finding_lite subset (kind, severity, target, ...)
from a JSONL line without a full JSON parser. Filter supports
'key=value', 'severity>=level', 'kind~prefix' for the findings verb
and --fail-on expression."
```

---

## Task 4: `findings` verb — tail + filter

`packetsonde findings tail [path]` reads JSONL from a file (or stdin) and pretty-prints to text/jsonl per global format. `packetsonde findings filter <expr> [path]` does the same but drops non-matching lines.

**Files:**
- Create: `src/cli/verbs/findings.c`
- Modify: `src/cli/dispatch.c`, `src/cli/CMakeLists.txt`

- [ ] **Step 1: Create `src/cli/verbs/findings.c`**

```c
#include "../verbs.h"
#include "../findings_util/reader.h"
#include "../findings_util/filter.h"
#include "../output/output.h"
#include "finding.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(void) {
    fprintf(stderr,
        "Usage:\n"
        "  packetsonde findings tail   [path]\n"
        "  packetsonde findings filter <expr> [path]\n"
        "\n"
        "<expr>: kind=name | kind~prefix | severity>=level | source=name | target=ip[:port]\n"
        "If path is omitted, reads from stdin.\n");
}

static int do_loop(FILE *in, struct ps_finding_filter *F, const struct ps_args *opts) {
    char line[16384];
    while (fgets(line, sizeof(line), in)) {
        size_t L = strlen(line);
        if (L && line[L-1] == '\n') line[L-1] = '\0';
        if (!line[0]) continue;

        struct ps_finding_lite lite;
        if (ps_finding_parse_line(line, &lite) != 0) continue;
        if (F && !ps_filter_eval(F, &lite)) continue;

        int is_tty = isatty(1);
        int want_text = (opts->fmt == PS_FMT_TEXT) ||
                        (opts->fmt == 0 && is_tty);
        if (want_text) {
            const char *sev = "info";
            switch (lite.severity) {
                case PS_SEV_INFO:     sev = "info";     break;
                case PS_SEV_LOW:      sev = "low";      break;
                case PS_SEV_MEDIUM:   sev = "medium";   break;
                case PS_SEV_HIGH:     sev = "high";     break;
                case PS_SEV_CRITICAL: sev = "critical"; break;
            }
            printf("%-8s  %-24s  %-32s  %s\n",
                   sev, lite.kind, lite.target[0] ? lite.target : "-", lite.title);
        } else {
            /* Pass through the raw line as JSONL */
            printf("%s\n", line);
        }
    }
    return 0;
}

int ps_verb_findings_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }
    const char *sub = argv[1];
    const char *expr = NULL;
    const char *path = NULL;
    int rc = 0;

    if (strcmp(sub, "tail") == 0) {
        if (argc >= 3) path = argv[2];
    } else if (strcmp(sub, "filter") == 0) {
        if (argc < 3) { usage(); return 2; }
        expr = argv[2];
        if (argc >= 4) path = argv[3];
    } else {
        usage();
        return 2;
    }

    struct ps_finding_filter F;
    struct ps_finding_filter *Fp = NULL;
    if (expr) {
        if (ps_filter_parse(expr, &F) != 0) {
            fprintf(stderr, "findings filter: bad expression '%s'\n", expr);
            return 2;
        }
        Fp = &F;
    }

    FILE *in = stdin;
    if (path) {
        in = fopen(path, "r");
        if (!in) { perror(path); return 1; }
    }

    rc = do_loop(in, Fp, opts);

    if (path) fclose(in);
    if (Fp) ps_filter_destroy(Fp);
    return rc;
}
```

- [ ] **Step 2: Register the verb**

In `src/cli/dispatch.c`, add forward decl + entry:
```c
int  ps_verb_findings_run(int argc, char **argv, const struct ps_args *opts);
```
And update VERBS:
```c
    { "findings", ps_verb_findings_run, "Tail / filter JSONL finding records" },
```
(Place between `audit` and `agent`.)

- [ ] **Step 3: Add to CMake**

In `src/cli/CMakeLists.txt`, add `verbs/findings.c` to `CLI_SOURCES`.

- [ ] **Step 4: Build + smoke**

```bash
cd /Users/billn/packetsonde/build && make packetsonde 2>&1 | tail -3
echo '{"v":1,"id":"a","run_id":"r","ts":"t","source":"cli.audit.tls","host":"h","kind":"tls.weak_cipher","severity":"high","confidence":"firm","title":"x","target":{"ip":"10.0.0.1","port":443}}' \
  | ../build/src/cli/packetsonde findings tail
```
Expected: a text line `high      tls.weak_cipher           10.0.0.1:443                     x`.

```bash
echo '{"v":1,...}' | ../build/src/cli/packetsonde findings filter 'severity>=high'
```
Expected: line passes through.

- [ ] **Step 5: Commit**

```bash
cd /Users/billn/packetsonde
git add src/cli/verbs/findings.c src/cli/dispatch.c src/cli/CMakeLists.txt
git commit -m "feat(cli/verbs): findings tail / findings filter

Reads JSONL from a file or stdin, pretty-prints to text (on tty) or
passes JSONL through. Filter expressions match by kind, source, target,
or severity comparison."
```

---

## Task 5: `config` verb + agents.toml parser (TDD)

`config show` prints resolved configuration (paths, defaults). `config path` prints the config file location. The agents registry parses a minimal TOML subset just for `[agents.<name>]` blocks with `address`, `key_fingerprint`, `tags` fields. v1 supports only `local`.

**Files:**
- Create: `src/cli/registry/agents.h`, `src/cli/registry/agents.c`
- Create: `src/cli/verbs/config.c`
- Create: `src/cli/tests/test_agents_registry.c`
- Modify: `src/cli/dispatch.c`, `src/cli/CMakeLists.txt`

- [ ] **Step 1: Test the registry**

`mkdir -p src/cli/registry`

Create `/Users/billn/packetsonde/src/cli/tests/test_agents_registry.c`:
```c
#include "../registry/agents.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *SAMPLE =
    "# packetsonde agents\n"
    "[agents.local]\n"
    "address = \"/tmp/packetsonde-agent.sock\"\n"
    "\n"
    "[agents.trunkbox]\n"
    "address = \"trunkbox.lan:8855\"\n"
    "key_fingerprint = \"SHA256:abc\"\n"
    "tags = \"vlan-trunk\"\n";

static const char *write_tmp(const char *body) {
    static char path[64];
    snprintf(path, sizeof(path), "/tmp/ps_reg_XXXXXX");
    int fd = mkstemp(path);
    assert(fd >= 0);
    write(fd, body, strlen(body));
    close(fd);
    return path;
}

static void test_local_only(void) {
    const char *p = write_tmp("[agents.local]\naddress = \"/tmp/x.sock\"\n");
    struct ps_agents A;
    assert(ps_agents_load(&A, p) == 0);
    const struct ps_agent *a = ps_agents_find(&A, "local");
    assert(a);
    assert(strcmp(a->address, "/tmp/x.sock") == 0);
    ps_agents_destroy(&A);
    unlink(p);
}

static void test_two_agents(void) {
    const char *p = write_tmp(SAMPLE);
    struct ps_agents A;
    assert(ps_agents_load(&A, p) == 0);
    assert(A.count == 2);
    const struct ps_agent *t = ps_agents_find(&A, "trunkbox");
    assert(t);
    assert(strcmp(t->address, "trunkbox.lan:8855") == 0);
    assert(strcmp(t->key_fingerprint, "SHA256:abc") == 0);
    assert(strcmp(t->tags, "vlan-trunk") == 0);
    ps_agents_destroy(&A);
    unlink(p);
}

static void test_missing_file_is_empty_not_error(void) {
    struct ps_agents A;
    assert(ps_agents_load(&A, "/nonexistent/path") == 0);
    assert(A.count == 0);
    ps_agents_destroy(&A);
}

int main(void) {
    test_local_only();
    test_two_agents();
    test_missing_file_is_empty_not_error();
    printf("test_agents_registry: OK\n");
    return 0;
}
```

- [ ] **Step 2: CMake**

Add `registry/agents.c` and `verbs/config.c` to `CLI_SOURCES`. Add test:
```cmake
add_executable(test_agents_registry tests/test_agents_registry.c registry/agents.c)
target_include_directories(test_agents_registry PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_agents_registry PRIVATE packetsonde_lib)
add_test(NAME test_agents_registry COMMAND test_agents_registry)
```

- [ ] **Step 3: Implement `src/cli/registry/agents.h`**

```c
#ifndef PS_AGENTS_H
#define PS_AGENTS_H

#include <stddef.h>

#define PS_AGENT_NAME_MAX 64
#define PS_AGENT_FIELD_MAX 256

struct ps_agent {
    char name[PS_AGENT_NAME_MAX];
    char address[PS_AGENT_FIELD_MAX];
    char key_fingerprint[PS_AGENT_FIELD_MAX];
    char tags[PS_AGENT_FIELD_MAX];
};

struct ps_agents {
    struct ps_agent *items;
    size_t           count;
    size_t           cap;
};

int  ps_agents_load   (struct ps_agents *A, const char *path);
const struct ps_agent *ps_agents_find(const struct ps_agents *A, const char *name);
void ps_agents_destroy(struct ps_agents *A);

/* Returns ~/.config/packetsonde/agents.toml (or $XDG_CONFIG_HOME variant)
 * in a static buffer. */
const char *ps_agents_default_path(void);

#endif
```

- [ ] **Step 4: Implement `src/cli/registry/agents.c`**

```c
#include "agents.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static char *ltrim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}
static void rtrim(char *s) {
    size_t L = strlen(s);
    while (L && isspace((unsigned char)s[L-1])) s[--L] = '\0';
}

static int ps_agents_push(struct ps_agents *A, const struct ps_agent *a) {
    if (A->count == A->cap) {
        size_t nc = A->cap ? A->cap * 2 : 4;
        struct ps_agent *g = realloc(A->items, nc * sizeof(*g));
        if (!g) return -1;
        A->items = g; A->cap = nc;
    }
    A->items[A->count++] = *a;
    return 0;
}

static int strip_quotes(char *v) {
    size_t L = strlen(v);
    if (L >= 2 && v[0] == '"' && v[L-1] == '"') {
        memmove(v, v + 1, L - 2);
        v[L - 2] = '\0';
        return 0;
    }
    return -1;
}

int ps_agents_load(struct ps_agents *A, const char *path) {
    memset(A, 0, sizeof(*A));
    FILE *f = fopen(path, "r");
    if (!f) return 0;  /* missing file = empty registry */

    char line[1024];
    struct ps_agent cur; memset(&cur, 0, sizeof(cur));
    int in_block = 0;

    while (fgets(line, sizeof(line), f)) {
        char *s = ltrim(line);
        if (*s == '#' || *s == '\0' || *s == '\n') continue;
        rtrim(s);
        if (*s == '[') {
            /* close previous */
            if (in_block && cur.name[0]) ps_agents_push(A, &cur);
            memset(&cur, 0, sizeof(cur));
            in_block = 0;
            /* expect [agents.NAME] */
            if (strncmp(s, "[agents.", 8) != 0) continue;
            const char *name_start = s + 8;
            const char *rb = strchr(name_start, ']');
            if (!rb) continue;
            size_t nl = (size_t)(rb - name_start);
            if (nl == 0 || nl >= sizeof(cur.name)) continue;
            memcpy(cur.name, name_start, nl);
            cur.name[nl] = '\0';
            in_block = 1;
            continue;
        }
        if (!in_block) continue;
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = ltrim(s); rtrim(key);
        char *val = ltrim(eq + 1); rtrim(val);
        if (strip_quotes(val) != 0) continue;
        if      (!strcmp(key, "address"))         strncpy(cur.address,         val, sizeof(cur.address)         - 1);
        else if (!strcmp(key, "key_fingerprint")) strncpy(cur.key_fingerprint, val, sizeof(cur.key_fingerprint) - 1);
        else if (!strcmp(key, "tags"))            strncpy(cur.tags,            val, sizeof(cur.tags)            - 1);
    }
    if (in_block && cur.name[0]) ps_agents_push(A, &cur);
    fclose(f);
    return 0;
}

const struct ps_agent *ps_agents_find(const struct ps_agents *A, const char *name) {
    for (size_t i = 0; i < A->count; i++) {
        if (strcmp(A->items[i].name, name) == 0) return &A->items[i];
    }
    return NULL;
}

void ps_agents_destroy(struct ps_agents *A) {
    free(A->items);
    memset(A, 0, sizeof(*A));
}

const char *ps_agents_default_path(void) {
    static char path[512];
    const char *cfg = getenv("XDG_CONFIG_HOME");
    if (cfg && cfg[0]) {
        snprintf(path, sizeof(path), "%s/packetsonde/agents.toml", cfg);
    } else {
        const char *home = getenv("HOME");
        if (home && home[0]) {
            snprintf(path, sizeof(path), "%s/.config/packetsonde/agents.toml", home);
        } else {
            snprintf(path, sizeof(path), "/etc/packetsonde/agents.toml");
        }
    }
    return path;
}
```

- [ ] **Step 5: Implement `src/cli/verbs/config.c`**

```c
#include "../verbs.h"
#include "../registry/agents.h"

#include <stdio.h>
#include <string.h>

static void usage(void) {
    fprintf(stderr,
        "Usage:\n"
        "  packetsonde config show\n"
        "  packetsonde config path\n");
}

int ps_verb_config_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }
    const char *sub = argv[1];

    const char *agents_path = opts->config_path ? opts->config_path
                                                 : ps_agents_default_path();
    if (strcmp(sub, "path") == 0) {
        printf("%s\n", agents_path);
        return 0;
    }
    if (strcmp(sub, "show") == 0) {
        printf("agents_config: %s\n", agents_path);
        struct ps_agents A;
        ps_agents_load(&A, agents_path);
        printf("agents (%zu):\n", A.count);
        for (size_t i = 0; i < A.count; i++) {
            const struct ps_agent *a = &A.items[i];
            printf("  - name: %s\n", a->name);
            printf("    address: %s\n", a->address);
            if (a->key_fingerprint[0]) printf("    key_fingerprint: %s\n", a->key_fingerprint);
            if (a->tags[0])            printf("    tags: %s\n",            a->tags);
        }
        ps_agents_destroy(&A);
        return 0;
    }
    usage();
    return 2;
}
```

- [ ] **Step 6: Register**

In `src/cli/dispatch.c`:
```c
int  ps_verb_config_run  (int argc, char **argv, const struct ps_args *opts);
```
Add to VERBS (after `findings`, before `agent`):
```c
    { "config",   ps_verb_config_run,   "Show resolved configuration" },
```

- [ ] **Step 7: Build + smoke + commit**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make test_agents_registry packetsonde 2>&1 | tail -3
ctest --output-on-failure 2>&1 | tail -3
../build/src/cli/packetsonde config path
../build/src/cli/packetsonde config show
```
Expected: 23/23 PASS; `config path` prints a path; `config show` prints `agents_config:` and `agents (0):` (no file yet).

```bash
cd /Users/billn/packetsonde
git add src/cli/registry src/cli/verbs/config.c src/cli/tests/test_agents_registry.c src/cli/dispatch.c src/cli/CMakeLists.txt
git commit -m "feat(cli): config verb + agents.toml registry

Minimal TOML parser for [agents.NAME] blocks with address,
key_fingerprint, tags fields. v1 path resolution uses XDG_CONFIG_HOME
or ~/.config/packetsonde/agents.toml. config show/path verbs print
resolved state."
```

---

## Task 6: `--fail-on` expression + main.c gate (TDD)

Wire `--fail-on <expr>` through args.h, evaluate it against the output's severity counts at exit, and decide the exit code.

**Files:**
- Create: `src/cli/util/fail_on.h`, `src/cli/util/fail_on.c`
- Create: `src/cli/tests/test_fail_on.c`
- Modify: `src/cli/args.h/c`, `src/cli/main.c`, `src/cli/output/output.h/c`, `src/cli/audit/tls.c`, `src/cli/CMakeLists.txt`

The audit's existing `ps_output_summary` already prints counts; we extend the output API to surface them.

- [ ] **Step 1: Test**

Create `/Users/billn/packetsonde/src/cli/tests/test_fail_on.c`:
```c
#include "../util/fail_on.h"
#include "../output/output.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void counts(struct ps_fail_counts *c, unsigned info, unsigned low,
                   unsigned med, unsigned high, unsigned crit) {
    memset(c, 0, sizeof(*c));
    c->n_info = info; c->n_low = low; c->n_medium = med;
    c->n_high = high; c->n_critical = crit;
}

int main(void) {
    struct ps_fail_on F;
    struct ps_fail_counts C;

    assert(ps_fail_on_parse("severity>=high", &F) == 0);
    counts(&C, 5, 5, 5, 0, 0); assert(ps_fail_on_eval(&F, &C) == 0);
    counts(&C, 0, 0, 0, 1, 0); assert(ps_fail_on_eval(&F, &C) == 1);
    counts(&C, 0, 0, 0, 0, 9); assert(ps_fail_on_eval(&F, &C) == 1);

    assert(ps_fail_on_parse("severity>=critical", &F) == 0);
    counts(&C, 0, 0, 0, 99, 0); assert(ps_fail_on_eval(&F, &C) == 0);
    counts(&C, 0, 0, 0, 0,  1); assert(ps_fail_on_eval(&F, &C) == 1);

    /* Empty: parse OK, never matches */
    assert(ps_fail_on_parse(NULL, &F) == 0);
    counts(&C, 0, 0, 0, 99, 99); assert(ps_fail_on_eval(&F, &C) == 0);

    printf("test_fail_on: OK\n");
    return 0;
}
```

- [ ] **Step 2: CMake**

Add `util/fail_on.c` to `CLI_SOURCES`. Add test:
```cmake
add_executable(test_fail_on tests/test_fail_on.c util/fail_on.c)
target_include_directories(test_fail_on PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_fail_on PRIVATE packetsonde_lib)
add_test(NAME test_fail_on COMMAND test_fail_on)
```

- [ ] **Step 3: Implement `src/cli/util/fail_on.h`**

```c
#ifndef PS_FAIL_ON_H
#define PS_FAIL_ON_H

#include "../output/output.h"

struct ps_fail_counts {
    unsigned n_info;
    unsigned n_low;
    unsigned n_medium;
    unsigned n_high;
    unsigned n_critical;
};

struct ps_fail_on {
    int active;          /* 0 = expression empty / never matches */
    int min_severity;    /* PS_SEV_* */
};

/* Accepts NULL or "" -> active=0; "severity>=info|low|medium|high|critical". */
int ps_fail_on_parse(const char *expr, struct ps_fail_on *F);

/* Returns 1 if F matches the counts (any finding at min_severity or above). */
int ps_fail_on_eval(const struct ps_fail_on *F, const struct ps_fail_counts *c);

/* Helper: read the snapshot from an output. */
void ps_output_snapshot(const struct ps_output *o, struct ps_fail_counts *c);

#endif
```

- [ ] **Step 4: Implement `src/cli/util/fail_on.c`**

```c
#include "fail_on.h"
#include "finding.h"

#include <string.h>

int ps_fail_on_parse(const char *expr, struct ps_fail_on *F) {
    if (!F) return -1;
    F->active = 0;
    F->min_severity = PS_SEV_INFO;
    if (!expr || !*expr) return 0;
    /* Only supported form for v1: severity>=LEVEL */
    if (strncmp(expr, "severity>=", 10) != 0) return -1;
    const char *L = expr + 10;
    if      (!strcmp(L, "info"))     F->min_severity = PS_SEV_INFO;
    else if (!strcmp(L, "low"))      F->min_severity = PS_SEV_LOW;
    else if (!strcmp(L, "medium"))   F->min_severity = PS_SEV_MEDIUM;
    else if (!strcmp(L, "high"))     F->min_severity = PS_SEV_HIGH;
    else if (!strcmp(L, "critical")) F->min_severity = PS_SEV_CRITICAL;
    else return -1;
    F->active = 1;
    return 0;
}

int ps_fail_on_eval(const struct ps_fail_on *F, const struct ps_fail_counts *c) {
    if (!F->active) return 0;
    switch (F->min_severity) {
        case PS_SEV_INFO:     return (c->n_info + c->n_low + c->n_medium + c->n_high + c->n_critical) > 0;
        case PS_SEV_LOW:      return (c->n_low + c->n_medium + c->n_high + c->n_critical) > 0;
        case PS_SEV_MEDIUM:   return (c->n_medium + c->n_high + c->n_critical) > 0;
        case PS_SEV_HIGH:     return (c->n_high + c->n_critical) > 0;
        case PS_SEV_CRITICAL: return c->n_critical > 0;
    }
    return 0;
}

void ps_output_snapshot(const struct ps_output *o, struct ps_fail_counts *c) {
    c->n_info     = o->n_info;
    c->n_low      = o->n_low;
    c->n_medium   = o->n_medium;
    c->n_high     = o->n_high;
    c->n_critical = o->n_critical;
}
```

- [ ] **Step 5: Surface `--fail-on` in args.h/c**

In `/Users/billn/packetsonde/src/cli/args.h`, extend `struct ps_args`:
```c
    const char *fail_on;    /* --fail-on expression, or NULL */
```
(Add it next to the existing flag members.)

In `/Users/billn/packetsonde/src/cli/args.c`, add to the `enum` of option codes:
```c
    OPT_FAIL_ON
```
And to the longopts table:
```c
        { "fail-on",      required_argument, NULL, OPT_FAIL_ON },
```
And in the switch:
```c
            case OPT_FAIL_ON:     out->fail_on = optarg; break;
```

- [ ] **Step 6: Plumb verb return through to main**

We need the run to surface counts. Simplest path: a global last-run snapshot the audit run fills. Add to `args.h` after the existing extern declarations (or create a tiny `runstate.h`). Use `runstate.h` to avoid muddying args.h.

Create `/Users/billn/packetsonde/src/cli/runstate.h`:
```c
#ifndef PS_RUNSTATE_H
#define PS_RUNSTATE_H

#include "util/fail_on.h"

/* The most recent verb run populates this; main consults it. */
extern struct ps_fail_counts g_last_run_counts;

#endif
```

Create `/Users/billn/packetsonde/src/cli/runstate.c`:
```c
#include "runstate.h"
struct ps_fail_counts g_last_run_counts = {0};
```

In `/Users/billn/packetsonde/src/cli/CMakeLists.txt`, add `runstate.c` to `CLI_SOURCES`.

In `/Users/billn/packetsonde/src/cli/audit/tls.c`, near the includes:
```c
#include "../runstate.h"
```
And right before `ps_output_close(&out);`:
```c
    ps_output_snapshot(&out, &g_last_run_counts);
```

- [ ] **Step 7: Update main.c**

In `/Users/billn/packetsonde/src/cli/main.c`, replace the verb-return path:
```c
    int rc = v->run(opts.verb_argc, opts.verb_argv, &opts);

    if (rc == 0 && opts.fail_on) {
        struct ps_fail_on F;
        if (ps_fail_on_parse(opts.fail_on, &F) != 0) {
            fprintf(stderr, "%s: bad --fail-on expression '%s'\n", argv[0], opts.fail_on);
            return 2;
        }
        if (ps_fail_on_eval(&F, &g_last_run_counts)) return 3;
    }
    return rc;
}
```
Add the include near the top:
```c
#include "util/fail_on.h"
#include "runstate.h"
```

- [ ] **Step 8: Build, test, smoke**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make packetsonde test_fail_on 2>&1 | tail -3
ctest --output-on-failure 2>&1 | tail -3
```
Expected: 24/24 PASS.

```bash
# Local s_server smoke (uses Plan 2 integration helper if it's still in place):
PORT=$((30000 + RANDOM % 20000))
read CRT KEY < <(./src/cli/tests/test_audit_tls_cert.sh)
openssl s_server -cert "$CRT" -key "$KEY" -port $PORT -tls1_2 -cipher 'DEFAULT:@SECLEVEL=0' -quiet >/dev/null 2>&1 &
SVR=$!; sleep 1
./build/src/cli/packetsonde --fail-on "severity>=high" audit tls "127.0.0.1:$PORT" >/dev/null 2>&1
echo exit=$?
kill $SVR; rm -f "$CRT" "$KEY"
```
Expected: `exit=3`.

- [ ] **Step 9: Commit**

```bash
cd /Users/billn/packetsonde
git add src/cli/util/fail_on.h src/cli/util/fail_on.c src/cli/tests/test_fail_on.c \
        src/cli/runstate.h src/cli/runstate.c src/cli/args.h src/cli/args.c \
        src/cli/main.c src/cli/audit/tls.c src/cli/CMakeLists.txt
git commit -m "feat(cli): --fail-on severity>=LEVEL gates exit code

Verb run records a snapshot of severity counts in g_last_run_counts;
main consults --fail-on to optionally exit 3 if matching findings
emitted. CI/cron-friendly: 'packetsonde audit tls X --fail-on
severity>=high' returns non-zero only when something high-or-worse
was emitted."
```

---

## Task 7: `probe tcp` verb

Open a TCP socket to `host:port`, time the connect, send a small protocol-aware probe (HTTP HEAD for 80/8080/443/8443, otherwise just connect+close), capture banner from first read. Emit one finding per probe with `kind=probe.tcp`.

**Files:**
- Create: `src/cli/probe/tcp.h`, `src/cli/probe/tcp.c`
- Create: `src/cli/verbs/probe.c`
- Modify: `src/cli/dispatch.c`, `src/cli/CMakeLists.txt`

- [ ] **Step 1: Implement `src/cli/probe/tcp.h`**

`mkdir -p src/cli/probe`
```c
#ifndef PS_PROBE_TCP_H
#define PS_PROBE_TCP_H

#include "../args.h"

int ps_probe_tcp_run(int argc, char **argv, const struct ps_args *opts);

#endif
```

- [ ] **Step 2: Implement `src/cli/probe/tcp.c`**

```c
#include "tcp.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../util/fail_on.h"
#include "../signals.h"
#include "../workers/workers.h"
#include "../workers/limiter.h"
#include "finding.h"
#include "ulid.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    const char *colon = strrchr(spec, ':');
    if (!colon) return -1;
    size_t hl = (size_t)(colon - spec);
    if (hl == 0 || hl >= host_sz) return -1;
    memcpy(host, spec, hl); host[hl] = '\0';
    long p = strtol(colon + 1, NULL, 10);
    if (p <= 0 || p > 65535) return -1;
    *port = (uint16_t)p;
    return 0;
}

static int probe(const char *host, uint16_t port, int timeout_ms,
                 char *ip_out, size_t ip_out_sz,
                 long *rtt_us_out, char *banner_out, size_t banner_sz) {
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (ip_out && ip_out_sz) {
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &sin->sin_addr, ip_out, (socklen_t)ip_out_sz);
    }

    struct timeval t0, t1; gettimeofday(&t0, NULL);
    int rc = connect(fd, res->ai_addr, res->ai_addrlen);
    gettimeofday(&t1, NULL);
    freeaddrinfo(res);
    if (rc != 0) { close(fd); return -1; }
    *rtt_us_out = (t1.tv_sec - t0.tv_sec) * 1000000L + (t1.tv_usec - t0.tv_usec);

    /* HTTP HEAD for common HTTP ports */
    if (port == 80 || port == 8080) {
        const char *req = "HEAD / HTTP/1.0\r\n\r\n";
        send(fd, req, strlen(req), 0);
    }
    /* Read up to banner_sz-1, treating any read as best-effort */
    if (banner_out && banner_sz > 0) {
        ssize_t r = recv(fd, banner_out, banner_sz - 1, 0);
        if (r > 0) {
            banner_out[r] = '\0';
            /* Strip non-printable chars at end */
            for (ssize_t i = r - 1; i >= 0 && (banner_out[i] == '\r' || banner_out[i] == '\n'); i--)
                banner_out[i] = '\0';
        } else {
            banner_out[0] = '\0';
        }
    }
    close(fd);
    return 0;
}

int ps_probe_tcp_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde probe tcp <host:port>\n");
        return 2;
    }
    char host[256]; uint16_t port = 0;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "probe tcp: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    struct ps_output_opts oopts; memset(&oopts, 0, sizeof(oopts));
    switch (opts->fmt) {
        case PS_FMT_TEXT:  oopts.fmt_force = PS_OFMT_TEXT;  break;
        case PS_FMT_JSON:  oopts.fmt_force = PS_OFMT_JSON;  break;
        case PS_FMT_JSONL: oopts.fmt_force = PS_OFMT_JSONL; break;
        case PS_FMT_QUIET: oopts.fmt_force = PS_OFMT_QUIET; break;
        default:           oopts.fmt_force = 0;             break;
    }
    oopts.color = opts->no_color ? 0 : 1;

    struct ps_output out; ps_output_init(&out, &oopts);

    char ip[64] = ""; long rtt_us = 0; char banner[1024] = "";
    int rc = probe(host, port, 4000, ip, sizeof(ip), &rtt_us, banner, sizeof(banner));

    struct ps_finding f;
    if (rc == 0) {
        char title[256];
        snprintf(title, sizeof(title), "Open: %s:%u (%.1f ms)",
                 ip[0] ? ip : host, port, rtt_us / 1000.0);
        ps_finding_init(&f, run_id, "cli.probe.tcp", self_host,
                        "probe.tcp.open", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        if (ip[0]) ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        char ev[2048];
        /* Escape banner for JSON: strip non-ASCII; replace " and \ */
        char banner_e[1024]; size_t bi = 0;
        for (size_t i = 0; banner[i] && bi + 2 < sizeof(banner_e); i++) {
            unsigned char c = (unsigned char)banner[i];
            if (c == '"' || c == '\\') { banner_e[bi++] = '\\'; banner_e[bi++] = (char)c; }
            else if (c >= 0x20 && c < 0x7f) { banner_e[bi++] = (char)c; }
        }
        banner_e[bi] = '\0';
        snprintf(ev, sizeof(ev), "{\"rtt_us\":%ld,\"banner\":\"%s\"}", rtt_us, banner_e);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
    } else {
        fprintf(stderr, "probe tcp: %s:%u — %s\n", host, port, strerror(errno));
    }

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return rc == 0 ? 0 : 1;
}
```

- [ ] **Step 3: Create the `probe` verb dispatcher**

Create `/Users/billn/packetsonde/src/cli/verbs/probe.c`:
```c
#include "../verbs.h"

#include <stdio.h>
#include <string.h>

int ps_probe_tcp_run       (int argc, char **argv, const struct ps_args *opts);
int ps_probe_traceroute_run(int argc, char **argv, const struct ps_args *opts);  /* Task 9 */

struct probe_kind {
    const char *name;
    int (*run)(int argc, char **argv, const struct ps_args *opts);
    const char *summary;
};

static const struct probe_kind KINDS[] = {
    { "tcp",        ps_probe_tcp_run,        "Single TCP connect + banner" },
    { "traceroute", ps_probe_traceroute_run, "Multi-mode traceroute"        },
    { NULL, NULL, NULL }
};

static void usage(void) {
    fprintf(stderr, "Usage: packetsonde probe <kind> [args...]\n\nKinds:\n");
    for (const struct probe_kind *k = KINDS; k->name; k++)
        fprintf(stderr, "  %-10s %s\n", k->name, k->summary);
}

int ps_verb_probe_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }
    for (const struct probe_kind *k = KINDS; k->name; k++) {
        if (strcmp(k->name, argv[1]) == 0) {
            return k->run(argc - 1, argv + 1, opts);
        }
    }
    fprintf(stderr, "probe: unknown kind '%s'\n", argv[1]);
    usage();
    return 2;
}
```

- [ ] **Step 4: Register**

In `src/cli/dispatch.c`:
```c
int  ps_verb_probe_run   (int argc, char **argv, const struct ps_args *opts);
```
Add to VERBS (between `audit` and `findings`):
```c
    { "probe",    ps_verb_probe_run,    "Single-target probe (tcp, traceroute)" },
```

In `src/cli/CMakeLists.txt`, add `probe/tcp.c verbs/probe.c` to `CLI_SOURCES`.

We need a temporary stub for `ps_probe_traceroute_run` until Task 9. Add to `verbs/probe.c` (top, before KINDS):
```c
#include <stdio.h>
__attribute__((weak))
int ps_probe_traceroute_run(int argc, char **argv, const struct ps_args *opts) {
    (void)argc; (void)argv; (void)opts;
    fprintf(stderr, "probe traceroute: not yet implemented (Task 9)\n");
    return 2;
}
```
The `weak` attribute lets Task 9 override it.

- [ ] **Step 5: Build, smoke, commit**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make packetsonde 2>&1 | tail -3
../build/src/cli/packetsonde probe tcp example.com:80
```
Expected: a JSONL/text finding indicating open + HTTP banner. (Exit 0 if reachable.)

```bash
cd /Users/billn/packetsonde
git add src/cli/probe src/cli/verbs/probe.c src/cli/dispatch.c src/cli/CMakeLists.txt
git commit -m "feat(cli/probe): probe tcp <host:port>

Single TCP probe: connect + RTT + best-effort banner grab.
HTTP HEAD on ports 80/8080. Banner sanitized for JSON. Emits
kind=probe.tcp.open with rtt_us and banner in evidence."
```

---

## Task 8: Traceroute core (lib) — UDP classic (TDD on builder/parser, manual on network)

Add `src/lib/traceroute.{h,c}` with a protocol- and mode-parameterized API. Implement UDP classic first; Tasks 9 wires the CLI verb and Task 10 adds paris/dublin/tcp modes.

**Files:**
- Create: `src/lib/traceroute.h`, `src/lib/traceroute.c`
- Create: `src/lib/tests/test_traceroute.c`
- Modify: `src/lib/CMakeLists.txt`

- [ ] **Step 1: Test**

Create `/Users/billn/packetsonde/src/lib/tests/test_traceroute.c`:
```c
#include "../traceroute.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_default_opts(void) {
    struct ps_traceroute_opts o = PS_TRACEROUTE_DEFAULTS;
    assert(o.proto == PS_TR_PROTO_UDP);
    assert(o.mode  == PS_TR_MODE_CLASSIC);
    assert(o.max_hops == 30);
    assert(o.timeout_ms == 1000);
    assert(o.dst_port == 33434);
}

static void test_proto_mode_strings(void) {
    assert(strcmp(ps_tr_proto_str(PS_TR_PROTO_UDP),  "udp")  == 0);
    assert(strcmp(ps_tr_proto_str(PS_TR_PROTO_TCP),  "tcp")  == 0);
    assert(strcmp(ps_tr_proto_str(PS_TR_PROTO_ICMP), "icmp") == 0);
    assert(strcmp(ps_tr_mode_str(PS_TR_MODE_CLASSIC), "classic") == 0);
    assert(strcmp(ps_tr_mode_str(PS_TR_MODE_PARIS),   "paris")   == 0);
    assert(strcmp(ps_tr_mode_str(PS_TR_MODE_DUBLIN),  "dublin")  == 0);
}

int main(void) {
    test_default_opts();
    test_proto_mode_strings();
    printf("test_traceroute: OK\n");
    return 0;
}
```

- [ ] **Step 2: CMake**

In `/Users/billn/packetsonde/src/lib/CMakeLists.txt`, add `traceroute.c` to the STATIC library sources:
```cmake
add_library(packetsonde_lib STATIC
    json.c
    log.c
    ulid.c
    ipc.c
    finding.c
    traceroute.c
)
```
Add test:
```cmake
    add_executable(test_traceroute tests/test_traceroute.c)
    target_link_libraries(test_traceroute PRIVATE packetsonde_lib)
    add_test(NAME test_traceroute COMMAND test_traceroute)
```

- [ ] **Step 3: Implement `src/lib/traceroute.h`**

```c
#ifndef PS_TRACEROUTE_H
#define PS_TRACEROUTE_H

#include <stddef.h>
#include <stdint.h>

enum ps_tr_proto { PS_TR_PROTO_UDP = 0, PS_TR_PROTO_TCP, PS_TR_PROTO_ICMP };
enum ps_tr_mode  { PS_TR_MODE_CLASSIC = 0, PS_TR_MODE_PARIS, PS_TR_MODE_DUBLIN };

struct ps_traceroute_opts {
    enum ps_tr_proto proto;
    enum ps_tr_mode  mode;
    int              max_hops;
    int              timeout_ms;
    uint16_t         dst_port;     /* used for udp/tcp */
    int              flow_count;   /* dublin: number of flows to enumerate */
};

#define PS_TRACEROUTE_DEFAULTS  \
    { PS_TR_PROTO_UDP, PS_TR_MODE_CLASSIC, 30, 1000, 33434, 8 }

struct ps_tr_hop {
    int      ttl;
    char     addr[64];      /* "" if no reply */
    long     rtt_us;        /* 0 if no reply */
    int      reached_dst;
};

#define PS_TRACEROUTE_MAX_HOPS 64

struct ps_traceroute_result {
    struct ps_tr_hop hops[PS_TRACEROUTE_MAX_HOPS];
    int              hop_count;
    int              reached;
};

const char *ps_tr_proto_str(enum ps_tr_proto p);
const char *ps_tr_mode_str (enum ps_tr_mode  m);

/* Network-dependent. Returns 0 on success, -1 if the run could not start
 * (privilege error, host unresolvable). Individual hop failures are normal
 * and reflected in hops[].addr being "". */
int ps_traceroute_run(const char *target,
                      const struct ps_traceroute_opts *opts,
                      struct ps_traceroute_result *out);

#endif
```

- [ ] **Step 4: Implement `src/lib/traceroute.c`**

```c
#include "traceroute.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

const char *ps_tr_proto_str(enum ps_tr_proto p) {
    return p == PS_TR_PROTO_UDP ? "udp" : p == PS_TR_PROTO_TCP ? "tcp" : "icmp";
}
const char *ps_tr_mode_str(enum ps_tr_mode m) {
    return m == PS_TR_MODE_CLASSIC ? "classic" : m == PS_TR_MODE_PARIS ? "paris" : "dublin";
}

static long usec_diff(struct timeval *a, struct timeval *b) {
    return (b->tv_sec - a->tv_sec) * 1000000L + (b->tv_usec - a->tv_usec);
}

static int resolve_v4(const char *host, struct sockaddr_in *out) {
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *r = NULL;
    if (getaddrinfo(host, NULL, &hints, &r) != 0) return -1;
    *out = *(struct sockaddr_in *)r->ai_addr;
    freeaddrinfo(r);
    return 0;
}

/* Receive an ICMP time-exceeded or destination-unreachable.
 * Returns 0 if a usable reply was received; -1 on timeout. Sets src_addr. */
static int recv_icmp_for(int icmp_fd, int timeout_ms,
                         struct sockaddr_in *src_out, int *kind_out) {
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(icmp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char  buf[2048];
    struct sockaddr_in from; socklen_t flen = sizeof(from);
    ssize_t n = recvfrom(icmp_fd, buf, sizeof(buf), 0,
                        (struct sockaddr *)&from, &flen);
    if (n <= 0) return -1;

    /* Parse: IP header + ICMP header. */
    if (n < (int)(sizeof(struct ip) + sizeof(struct icmp))) return -1;
    struct ip *ip = (struct ip *)buf;
    int ip_hl = ip->ip_hl * 4;
    if (n < ip_hl + (int)sizeof(struct icmp)) return -1;
    struct icmp *ic = (struct icmp *)(buf + ip_hl);

    if (ic->icmp_type == ICMP_TIMXCEED || ic->icmp_type == ICMP_UNREACH) {
        *src_out = from;
        if (kind_out) *kind_out = ic->icmp_type;
        return 0;
    }
    return -1;
}

static int tr_udp_classic(const char *target,
                          const struct ps_traceroute_opts *opts,
                          struct ps_traceroute_result *out) {
    struct sockaddr_in dst;
    if (resolve_v4(target, &dst) != 0) return -1;

    int icmp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (icmp_fd < 0) {
        /* Some platforms refuse unprivileged SOCK_DGRAM/ICMP — try SOCK_RAW. */
        icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (icmp_fd < 0) return -1;  /* needs privilege */
    }

    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) { close(icmp_fd); return -1; }

    int max = opts->max_hops > 0 ? opts->max_hops : 30;
    if (max > PS_TRACEROUTE_MAX_HOPS) max = PS_TRACEROUTE_MAX_HOPS;

    for (int ttl = 1; ttl <= max; ttl++) {
        setsockopt(udp_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        struct sockaddr_in d = dst;
        d.sin_port = htons(opts->dst_port + ttl - 1);  /* classic: vary dst port */

        struct timeval t0; gettimeofday(&t0, NULL);
        char payload[16] = "PSTR";
        sendto(udp_fd, payload, sizeof(payload), 0,
               (struct sockaddr *)&d, sizeof(d));

        struct sockaddr_in src; int kind = 0;
        if (recv_icmp_for(icmp_fd, opts->timeout_ms, &src, &kind) == 0) {
            struct timeval t1; gettimeofday(&t1, NULL);
            struct ps_tr_hop *h = &out->hops[out->hop_count++];
            h->ttl = ttl;
            inet_ntop(AF_INET, &src.sin_addr, h->addr, sizeof(h->addr));
            h->rtt_us = usec_diff(&t0, &t1);
            h->reached_dst = (kind == ICMP_UNREACH) ||
                             (src.sin_addr.s_addr == dst.sin_addr.s_addr);
            if (h->reached_dst) { out->reached = 1; break; }
        } else {
            struct ps_tr_hop *h = &out->hops[out->hop_count++];
            h->ttl = ttl;
            h->addr[0] = '\0';
            h->rtt_us = 0;
            h->reached_dst = 0;
        }
    }

    close(icmp_fd); close(udp_fd);
    return 0;
}

int ps_traceroute_run(const char *target,
                      const struct ps_traceroute_opts *opts,
                      struct ps_traceroute_result *out) {
    memset(out, 0, sizeof(*out));
    if (opts->proto == PS_TR_PROTO_UDP && opts->mode == PS_TR_MODE_CLASSIC) {
        return tr_udp_classic(target, opts, out);
    }
    /* Paris / Dublin / TCP / ICMP land in Task 10. */
    return -1;
}
```

- [ ] **Step 5: Build, test, commit**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make test_traceroute 2>&1 | tail -3
ctest -R '^test_traceroute$' --output-on-failure 2>&1 | tail -3
ctest --output-on-failure 2>&1 | tail -3
```
Expected: 25/25 PASS (test_traceroute only exercises builder/parser, not network).

```bash
cd /Users/billn/packetsonde
git add src/lib/traceroute.h src/lib/traceroute.c src/lib/tests/test_traceroute.c src/lib/CMakeLists.txt
git commit -m "feat(lib): traceroute core (UDP classic)

Protocol- and mode-parameterized API. UDP classic implemented; Paris,
Dublin, TCP, and ICMP modes follow. Unprivileged SOCK_DGRAM/ICMP
preferred; falls back to SOCK_RAW (needs cap_net_raw/sudo)."
```

---

## Task 9: `probe traceroute` verb (UDP classic only)

Wire `lib/traceroute` to a verb that emits findings. Each hop becomes a single finding so JSONL consumers can stream the path.

**Files:**
- Create: `src/cli/probe/traceroute.h`, `src/cli/probe/traceroute.c`
- Modify: `src/cli/verbs/probe.c` (drop the weak stub), `src/cli/CMakeLists.txt`

- [ ] **Step 1: Implement `src/cli/probe/traceroute.h`**

```c
#ifndef PS_CLI_PROBE_TRACEROUTE_H
#define PS_CLI_PROBE_TRACEROUTE_H

#include "../args.h"

int ps_probe_traceroute_run(int argc, char **argv, const struct ps_args *opts);

#endif
```

- [ ] **Step 2: Implement `src/cli/probe/traceroute.c`**

```c
#include "traceroute.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../util/fail_on.h"
#include "finding.h"
#include "traceroute.h"   /* lib/traceroute.h via libpacketsonde include path */
#include "ulid.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(void) {
    fprintf(stderr,
        "Usage: packetsonde probe traceroute <target> "
        "[--proto udp|tcp|icmp] [--mode classic|paris|dublin] [--port N]\n"
        "Defaults: --proto udp --mode classic --port 33434\n"
        "TCP and ICMP, and Paris/Dublin modes, will land in a follow-on task.\n");
}

int ps_probe_traceroute_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }

    /* argv[0] = "traceroute"; argv[1] = target; argv[2..] = flags */
    const char *target = argv[1];

    struct ps_traceroute_opts to = PS_TRACEROUTE_DEFAULTS;

    static const struct option longopts[] = {
        { "proto", required_argument, NULL, 'p' },
        { "mode",  required_argument, NULL, 'm' },
        { "port",  required_argument, NULL, 'P' },
        { NULL, 0, NULL, 0 }
    };
    /* Skip argv[1] (the target) before getopt. */
    optind = 2;
    int c;
    while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
        switch (c) {
            case 'p':
                if      (!strcmp(optarg, "udp"))  to.proto = PS_TR_PROTO_UDP;
                else if (!strcmp(optarg, "tcp"))  to.proto = PS_TR_PROTO_TCP;
                else if (!strcmp(optarg, "icmp")) to.proto = PS_TR_PROTO_ICMP;
                else { usage(); return 2; }
                break;
            case 'm':
                if      (!strcmp(optarg, "classic")) to.mode = PS_TR_MODE_CLASSIC;
                else if (!strcmp(optarg, "paris"))   to.mode = PS_TR_MODE_PARIS;
                else if (!strcmp(optarg, "dublin"))  to.mode = PS_TR_MODE_DUBLIN;
                else { usage(); return 2; }
                break;
            case 'P':
                to.dst_port = (uint16_t)atoi(optarg);
                break;
            default: usage(); return 2;
        }
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    struct ps_output_opts oopts; memset(&oopts, 0, sizeof(oopts));
    switch (opts->fmt) {
        case PS_FMT_TEXT:  oopts.fmt_force = PS_OFMT_TEXT;  break;
        case PS_FMT_JSON:  oopts.fmt_force = PS_OFMT_JSON;  break;
        case PS_FMT_JSONL: oopts.fmt_force = PS_OFMT_JSONL; break;
        case PS_FMT_QUIET: oopts.fmt_force = PS_OFMT_QUIET; break;
        default:           oopts.fmt_force = 0;             break;
    }
    oopts.color = opts->no_color ? 0 : 1;
    struct ps_output out; ps_output_init(&out, &oopts);

    struct ps_traceroute_result tr;
    int rc = ps_traceroute_run(target, &to, &tr);
    if (rc != 0) {
        fprintf(stderr,
                "probe traceroute: cannot run (proto=%s mode=%s) — "
                "tcp/icmp + paris/dublin land in a follow-on task; "
                "udp classic requires kernel ICMP capability "
                "(cap_net_raw on Linux, sudo on macOS for raw fallback)\n",
                ps_tr_proto_str(to.proto), ps_tr_mode_str(to.mode));
        ps_output_close(&out);
        return 1;
    }

    for (int i = 0; i < tr.hop_count; i++) {
        struct ps_tr_hop *h = &tr.hops[i];
        char title[256];
        if (h->addr[0]) {
            snprintf(title, sizeof(title), "hop %d: %s (%.1f ms)",
                     h->ttl, h->addr, h->rtt_us / 1000.0);
        } else {
            snprintf(title, sizeof(title), "hop %d: *", h->ttl);
        }
        char ev[256];
        snprintf(ev, sizeof(ev),
                 "{\"proto\":\"%s\",\"mode\":\"%s\",\"ttl\":%d,\"rtt_us\":%ld,\"reached_dst\":%s}",
                 ps_tr_proto_str(to.proto), ps_tr_mode_str(to.mode),
                 h->ttl, h->rtt_us, h->reached_dst ? "true" : "false");
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.probe.traceroute", self_host,
                        "probe.traceroute.hop", PS_SEV_INFO, PS_CONF_FIRM, title);
        ps_finding_set_target_hostname(&f, target, 0);
        if (h->addr[0]) ps_finding_set_target_ip(&f, h->addr, 0);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
    }

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
```

- [ ] **Step 3: Drop the weak stub in `verbs/probe.c`**

Remove this block from `src/cli/verbs/probe.c`:
```c
__attribute__((weak))
int ps_probe_traceroute_run(int argc, char **argv, const struct ps_args *opts) {
    (void)argc; (void)argv; (void)opts;
    fprintf(stderr, "probe traceroute: not yet implemented (Task 9)\n");
    return 2;
}
```

- [ ] **Step 4: CMake + build + smoke**

In `src/cli/CMakeLists.txt`, add `probe/traceroute.c` to `CLI_SOURCES`.

```bash
cd /Users/billn/packetsonde/build && cmake .. && make packetsonde 2>&1 | tail -3
../build/src/cli/packetsonde --jsonl probe traceroute 1.1.1.1 2>&1 | head -5
```
Expected: a few hop findings (or a clear "cannot run" if the kernel doesn't allow unprivileged ICMP receive on the host).

- [ ] **Step 5: Commit**

```bash
cd /Users/billn/packetsonde
git add src/cli/probe/traceroute.h src/cli/probe/traceroute.c src/cli/verbs/probe.c src/cli/CMakeLists.txt
git commit -m "feat(cli/probe): probe traceroute (udp classic)

Wires lib/traceroute via the probe verb. Emits one finding per hop with
kind=probe.traceroute.hop and evidence carrying proto/mode/ttl/rtt_us.
Paris, Dublin, TCP, and ICMP modes land in a follow-on task."
```

---

## Task 10: `audit dns` — resolver hygiene

Probe a DNS resolver for:
- Open recursion (server answers a recursion-desired query for an external domain)
- `version.bind` / `version.server` CHAOS-class TXT leak
- ANY-amplification risk: ratio of `dig . ANY` response size to query size

Each becomes a finding.

**Files:**
- Create: `src/cli/audit/dns.h`, `src/cli/audit/dns.c`
- Modify: `src/cli/verbs/audit.c` to register the kind
- Modify: `src/cli/CMakeLists.txt`

- [ ] **Step 1: Implement `src/cli/audit/dns.h`**

```c
#ifndef PS_AUDIT_DNS_H
#define PS_AUDIT_DNS_H

#include "../args.h"

int ps_audit_dns_run(int argc, char **argv, const struct ps_args *opts);

#endif
```

- [ ] **Step 2: Implement `src/cli/audit/dns.c`**

```c
#include "dns.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../util/fail_on.h"
#include "finding.h"
#include "ulid.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static uint16_t g_txid = 0x1234;

static int append_name(uint8_t *buf, size_t *off, size_t cap, const char *name) {
    /* Append a DNS-encoded name (length-prefixed labels). */
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (len == 0 || len > 63) return -1;
        if (*off + len + 1 >= cap) return -1;
        buf[(*off)++] = (uint8_t)len;
        memcpy(buf + *off, p, len);
        *off += len;
        if (!dot) break;
        p = dot + 1;
    }
    if (*off + 1 >= cap) return -1;
    buf[(*off)++] = 0;
    return 0;
}

static int build_query(uint8_t *buf, size_t cap, const char *name,
                       uint16_t qtype, uint16_t qclass, int rd) {
    if (cap < 12) return -1;
    uint16_t txid = ++g_txid;
    buf[0] = (uint8_t)(txid >> 8); buf[1] = (uint8_t)(txid & 0xff);
    buf[2] = rd ? 0x01 : 0x00;     /* RD bit */
    buf[3] = 0x00;
    buf[4] = 0x00; buf[5] = 0x01;  /* QDCOUNT=1 */
    buf[6] = buf[7] = buf[8] = buf[9] = buf[10] = buf[11] = 0;
    size_t off = 12;
    if (append_name(buf, &off, cap, name) != 0) return -1;
    if (off + 4 >= cap) return -1;
    buf[off++] = (uint8_t)(qtype >> 8);  buf[off++] = (uint8_t)(qtype & 0xff);
    buf[off++] = (uint8_t)(qclass >> 8); buf[off++] = (uint8_t)(qclass & 0xff);
    return (int)off;
}

static int udp_query(const char *server, uint16_t port,
                     const uint8_t *q, size_t qlen,
                     uint8_t *resp, size_t resp_cap,
                     int timeout_ms) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in dst; memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    if (inet_pton(AF_INET, server, &dst.sin_addr) != 1) {
        close(fd); return -1;
    }
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (sendto(fd, q, qlen, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        close(fd); return -1;
    }
    ssize_t n = recv(fd, resp, resp_cap, 0);
    close(fd);
    return (int)n;
}

static int extract_txt(const uint8_t *resp, size_t n, char *out, size_t outsz) {
    /* Very narrow: find the first TXT record's first character-string. */
    if (n < 12) return -1;
    size_t pos = 12;
    int qd = (resp[4] << 8) | resp[5];
    while (qd-- > 0 && pos < n) {
        while (pos < n && resp[pos] != 0) {
            if ((resp[pos] & 0xC0) == 0xC0) { pos += 2; goto qdone; }
            pos += resp[pos] + 1;
        }
        if (pos < n) pos += 1;
qdone:  pos += 4;
    }
    /* Answers: skip name, type, class, ttl(4), rdlength(2). For TXT,
     * rdata starts with one byte length, then the characters. */
    int an = (resp[6] << 8) | resp[7];
    while (an-- > 0 && pos < n) {
        /* skip name */
        while (pos < n && resp[pos] != 0) {
            if ((resp[pos] & 0xC0) == 0xC0) { pos += 2; goto adone; }
            pos += resp[pos] + 1;
        }
        if (pos < n) pos += 1;
adone:  if (pos + 10 > n) return -1;
        uint16_t type = (resp[pos] << 8) | resp[pos+1];
        pos += 8;
        uint16_t rdlen = (resp[pos] << 8) | resp[pos+1];
        pos += 2;
        if (pos + rdlen > n) return -1;
        if (type == 16 /* TXT */) {
            uint8_t slen = resp[pos];
            if (slen > rdlen - 1) return -1;
            size_t k = slen < outsz - 1 ? slen : outsz - 1;
            memcpy(out, resp + pos + 1, k);
            out[k] = '\0';
            return 0;
        }
        pos += rdlen;
    }
    return -1;
}

int ps_audit_dns_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit dns <resolver-ip>[:port]\n");
        return 2;
    }
    /* argv[0] = "dns", argv[1] = resolver[:port] */
    char host[64] = ""; uint16_t port = 53;
    const char *colon = strrchr(argv[1], ':');
    if (colon) {
        size_t hl = (size_t)(colon - argv[1]);
        if (hl >= sizeof(host)) return 2;
        memcpy(host, argv[1], hl); host[hl] = '\0';
        port = (uint16_t)atoi(colon + 1);
    } else {
        snprintf(host, sizeof(host), "%s", argv[1]);
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    struct ps_output_opts oopts; memset(&oopts, 0, sizeof(oopts));
    switch (opts->fmt) {
        case PS_FMT_TEXT:  oopts.fmt_force = PS_OFMT_TEXT;  break;
        case PS_FMT_JSON:  oopts.fmt_force = PS_OFMT_JSON;  break;
        case PS_FMT_JSONL: oopts.fmt_force = PS_OFMT_JSONL; break;
        case PS_FMT_QUIET: oopts.fmt_force = PS_OFMT_QUIET; break;
        default:           oopts.fmt_force = 0;             break;
    }
    oopts.color = opts->no_color ? 0 : 1;
    struct ps_output out; ps_output_init(&out, &oopts);

    /* 1. version.bind CHAOS TXT */
    {
        uint8_t q[512]; int qlen = build_query(q, sizeof(q), "version.bind", 16, 3, 1);
        uint8_t r[4096];
        int n = qlen > 0 ? udp_query(host, port, q, qlen, r, sizeof(r), 1500) : -1;
        char ver[256] = "";
        if (n > 0 && extract_txt(r, (size_t)n, ver, sizeof(ver)) == 0 && ver[0]) {
            char ev[320];
            snprintf(ev, sizeof(ev), "{\"version\":\"%s\"}", ver);
            char title[320];
            snprintf(title, sizeof(title), "Resolver discloses version: %s", ver);
            struct ps_finding f;
            ps_finding_init(&f, run_id, "cli.audit.dns", self_host,
                            "dns.version_leak", PS_SEV_LOW, PS_CONF_FIRM, title);
            ps_finding_set_target_ip(&f, host, port);
            ps_finding_set_evidence_json(&f, ev);
            ps_output_emit(&out, &f);
        }
    }

    /* 2. Open-recursion check: query example.com A with RD=1; if we get an answer
     *    with ANCOUNT>0, the resolver did recursion for us. */
    {
        uint8_t q[512]; int qlen = build_query(q, sizeof(q), "example.com", 1, 1, 1);
        uint8_t r[4096];
        int n = qlen > 0 ? udp_query(host, port, q, qlen, r, sizeof(r), 2500) : -1;
        if (n >= 12) {
            int ancount = (r[6] << 8) | r[7];
            int ra      = (r[3] & 0x80) ? 1 : 0;
            if (ra && ancount > 0) {
                char ev[160];
                snprintf(ev, sizeof(ev), "{\"ra\":true,\"ancount\":%d}", ancount);
                struct ps_finding f;
                ps_finding_init(&f, run_id, "cli.audit.dns", self_host,
                                "dns.open_recursion", PS_SEV_HIGH, PS_CONF_FIRM,
                                "Resolver answers recursive queries from external clients",
                                PS_CONF_FIRM ? "" : "");
                /* fix: the call above has too many args — see note. */
                (void)f;
            }
        }
    }

    /* ANY-amplification risk: skipped in v1 narrow path — bandwidth-impactful
     * probes belong behind an explicit opt-in flag and rate cap. Captured as
     * a follow-on. */

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
```

Replace the broken open-recursion block above with this clean version (substitute the entire `{ ... }` block 2):
```c
    /* 2. Open-recursion check */
    {
        uint8_t q[512]; int qlen = build_query(q, sizeof(q), "example.com", 1, 1, 1);
        uint8_t r[4096];
        int n = qlen > 0 ? udp_query(host, port, q, qlen, r, sizeof(r), 2500) : -1;
        if (n >= 12) {
            int ancount = (r[6] << 8) | r[7];
            int ra      = (r[3] & 0x80) ? 1 : 0;
            if (ra && ancount > 0) {
                char ev[160];
                snprintf(ev, sizeof(ev), "{\"ra\":true,\"ancount\":%d}", ancount);
                struct ps_finding f;
                ps_finding_init(&f, run_id, "cli.audit.dns", self_host,
                                "dns.open_recursion", PS_SEV_HIGH, PS_CONF_FIRM,
                                "Resolver answers recursive queries from external clients");
                ps_finding_set_target_ip(&f, host, port);
                ps_finding_set_evidence_json(&f, ev);
                ps_output_emit(&out, &f);
            }
        }
    }
```

- [ ] **Step 3: Register the kind in `verbs/audit.c`**

In `/Users/billn/packetsonde/src/cli/verbs/audit.c`, add forward decl + KINDS entry:
```c
int ps_audit_dns_run(int argc, char **argv, const struct ps_args *opts);
```
```c
static const struct audit_kind KINDS[] = {
    { "tls", ps_audit_tls_run, "Audit TLS server: protocol, cipher, cert hygiene" },
    { "dns", ps_audit_dns_run, "Audit DNS resolver: version leak, open recursion" },
    { NULL, NULL, NULL }
};
```

- [ ] **Step 4: CMake + build + smoke**

In `src/cli/CMakeLists.txt`, add `audit/dns.c` to `CLI_SOURCES`.

```bash
cd /Users/billn/packetsonde/build && cmake .. && make packetsonde 2>&1 | tail -3
../build/src/cli/packetsonde audit dns 1.1.1.1
```
Expected: zero findings (Cloudflare hides version & isn't an open recursor relative to most clients), or a `dns.open_recursion` if your network sees it as such. No crash.

- [ ] **Step 5: Commit**

```bash
cd /Users/billn/packetsonde
git add src/cli/audit/dns.h src/cli/audit/dns.c src/cli/verbs/audit.c src/cli/CMakeLists.txt
git commit -m "feat(cli/audit): audit dns — version.bind + open-recursion

Hand-rolled DNS UDP query/parse (no libresolv dep). Emits:
  dns.version_leak     low    (CHAOS TXT version.bind disclosure)
  dns.open_recursion   high   (resolver answers RD queries for external names)

ANY-amplification probe deferred behind an opt-in flag (bandwidth)."
```

---

## Task 11: `discover neighbors` — read local ARP/NDP table

Reads `/proc/net/arp` on Linux, falls back to `arp -an` parsed output on macOS. Emits one finding per neighbor with kind `discover.neighbor`.

**Files:**
- Create: `src/cli/discover/neighbors.h`, `src/cli/discover/neighbors.c`
- Create: `src/cli/verbs/discover.c`
- Modify: `src/cli/dispatch.c`, `src/cli/CMakeLists.txt`

- [ ] **Step 1: Implement `src/cli/discover/neighbors.h`**

`mkdir -p src/cli/discover`
```c
#ifndef PS_DISCOVER_NEIGHBORS_H
#define PS_DISCOVER_NEIGHBORS_H

#include "../args.h"

int ps_discover_neighbors_run(int argc, char **argv, const struct ps_args *opts);

#endif
```

- [ ] **Step 2: Implement `src/cli/discover/neighbors.c`**

```c
#include "neighbors.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../util/fail_on.h"
#include "finding.h"
#include "ulid.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void emit_neighbor(struct ps_output *out, const char *run_id,
                          const char *self_host,
                          const char *ip, const char *mac, const char *iface) {
    char title[256];
    snprintf(title, sizeof(title), "%s at %s on %s", ip, mac, iface[0] ? iface : "-");
    char ev[256];
    snprintf(ev, sizeof(ev), "{\"mac\":\"%s\",\"iface\":\"%s\"}", mac, iface);
    struct ps_finding f;
    ps_finding_init(&f, run_id, "cli.discover.neighbors", self_host,
                    "discover.neighbor", PS_SEV_INFO, PS_CONF_FIRM, title);
    ps_finding_set_target_ip(&f, ip, 0);
    ps_finding_set_evidence_json(&f, ev);
    ps_output_emit(out, &f);
}

static int read_proc_net_arp(struct ps_output *out, const char *run_id, const char *self_host) {
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return -1;
    char line[512];
    fgets(line, sizeof(line), f);  /* header */
    int n = 0;
    while (fgets(line, sizeof(line), f)) {
        char ip[64], mac[32], iface[32]; int flags = 0, type = 0;
        char hw[32], mask[32];
        if (sscanf(line, "%63s %x %x %31s %31s %31s",
                   ip, &type, &flags, mac, mask, iface) >= 4) {
            if (strcmp(mac, "00:00:00:00:00:00") == 0) continue;
            emit_neighbor(out, run_id, self_host, ip, mac, iface);
            n++;
        }
    }
    fclose(f);
    return n;
}

static int read_arp_command(struct ps_output *out, const char *run_id, const char *self_host) {
    FILE *p = popen("arp -an 2>/dev/null", "r");
    if (!p) return -1;
    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), p)) {
        /* macOS format: "? (10.0.0.42) at e8:6f:38:00:00:00 on en0 ifscope [ethernet]" */
        char ip[64] = "", mac[32] = "", iface[32] = "";
        const char *lp = strchr(line, '(');
        const char *rp = lp ? strchr(lp, ')') : NULL;
        if (!lp || !rp) continue;
        size_t L = (size_t)(rp - lp - 1);
        if (L >= sizeof(ip)) continue;
        memcpy(ip, lp + 1, L); ip[L] = '\0';
        const char *at = strstr(rp, " at ");
        if (!at) continue;
        const char *m = at + 4;
        size_t mi = 0;
        while (*m && *m != ' ' && mi + 1 < sizeof(mac)) mac[mi++] = *m++;
        mac[mi] = '\0';
        const char *on = strstr(m, " on ");
        if (on) {
            const char *i = on + 4;
            size_t ii = 0;
            while (*i && *i != ' ' && ii + 1 < sizeof(iface)) iface[ii++] = *i++;
            iface[ii] = '\0';
        }
        if (mac[0] == '\0' || strcmp(mac, "(incomplete)") == 0) continue;
        emit_neighbor(out, run_id, self_host, ip, mac, iface);
        n++;
    }
    pclose(p);
    return n;
}

int ps_discover_neighbors_run(int argc, char **argv, const struct ps_args *opts) {
    (void)argc; (void)argv;

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    struct ps_output_opts oopts; memset(&oopts, 0, sizeof(oopts));
    switch (opts->fmt) {
        case PS_FMT_TEXT:  oopts.fmt_force = PS_OFMT_TEXT;  break;
        case PS_FMT_JSON:  oopts.fmt_force = PS_OFMT_JSON;  break;
        case PS_FMT_JSONL: oopts.fmt_force = PS_OFMT_JSONL; break;
        case PS_FMT_QUIET: oopts.fmt_force = PS_OFMT_QUIET; break;
        default:           oopts.fmt_force = 0;             break;
    }
    oopts.color = opts->no_color ? 0 : 1;
    struct ps_output out; ps_output_init(&out, &oopts);

    if (read_proc_net_arp(&out, run_id, self_host) < 0) {
        read_arp_command(&out, run_id, self_host);
    }

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
```

- [ ] **Step 3: Create the discover dispatcher**

Create `/Users/billn/packetsonde/src/cli/verbs/discover.c`:
```c
#include "../verbs.h"

#include <stdio.h>
#include <string.h>

int ps_discover_neighbors_run(int argc, char **argv, const struct ps_args *opts);
int ps_discover_hosts_run    (int argc, char **argv, const struct ps_args *opts);  /* Task 12 */

struct discover_kind {
    const char *name;
    int (*run)(int argc, char **argv, const struct ps_args *opts);
    const char *summary;
};

static const struct discover_kind KINDS[] = {
    { "neighbors", ps_discover_neighbors_run, "Local ARP/NDP table" },
    { "hosts",     ps_discover_hosts_run,     "ARP-sweep / connect-sweep a CIDR" },
    { NULL, NULL, NULL }
};

static void usage(void) {
    fprintf(stderr, "Usage: packetsonde discover <kind> [args...]\n\nKinds:\n");
    for (const struct discover_kind *k = KINDS; k->name; k++)
        fprintf(stderr, "  %-10s %s\n", k->name, k->summary);
}

int ps_verb_discover_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }
    for (const struct discover_kind *k = KINDS; k->name; k++) {
        if (strcmp(k->name, argv[1]) == 0) return k->run(argc - 1, argv + 1, opts);
    }
    fprintf(stderr, "discover: unknown kind '%s'\n", argv[1]);
    usage();
    return 2;
}
```

Add a weak stub for `ps_discover_hosts_run`:
```c
__attribute__((weak))
int ps_discover_hosts_run(int argc, char **argv, const struct ps_args *opts) {
    (void)argc; (void)argv; (void)opts;
    fprintf(stderr, "discover hosts: not yet implemented (Task 12)\n");
    return 2;
}
```

- [ ] **Step 4: Register + CMake**

In `src/cli/dispatch.c`, add:
```c
int  ps_verb_discover_run(int argc, char **argv, const struct ps_args *opts);
```
And in VERBS (between `audit` and `findings`):
```c
    { "discover", ps_verb_discover_run, "Local discovery: neighbors, hosts" },
```

In `src/cli/CMakeLists.txt`, add `discover/neighbors.c verbs/discover.c` to `CLI_SOURCES`.

- [ ] **Step 5: Build + smoke + commit**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make packetsonde 2>&1 | tail -3
../build/src/cli/packetsonde discover neighbors 2>&1 | head -5
```
Expected: a few neighbor findings on a normal host (router + a host or two).

```bash
cd /Users/billn/packetsonde
git add src/cli/discover/neighbors.h src/cli/discover/neighbors.c \
        src/cli/verbs/discover.c src/cli/dispatch.c src/cli/CMakeLists.txt
git commit -m "feat(cli/discover): discover neighbors

Reads /proc/net/arp on Linux, parses 'arp -an' on macOS. Emits one
finding per neighbor with discover.neighbor kind, evidence carrying
MAC and interface."
```

---

## Task 12: `scan ports` + `discover hosts` (connect sweeps)

`scan ports <target> [-p ports]` connect-scans a target or CIDR. `discover hosts <iface|cidr>` runs a small port-set probe (22, 80, 443) across a CIDR — if any answer, the host is "up." Both reuse `targets.h` + the worker pool + the rate limiter.

**Files:**
- Create: `src/cli/scan/ports.h`, `src/cli/scan/ports.c`
- Create: `src/cli/discover/hosts.h`, `src/cli/discover/hosts.c`
- Create: `src/cli/verbs/scan.c`
- Modify: `src/cli/verbs/discover.c` (drop weak stub), `src/cli/dispatch.c`, `src/cli/CMakeLists.txt`

- [ ] **Step 1: Shared connect probe helper**

The actual connect logic mirrors `probe/tcp.c`. To avoid duplication, factor a tiny helper. Create `/Users/billn/packetsonde/src/cli/probe/connect.h`:
```c
#ifndef PS_PROBE_CONNECT_H
#define PS_PROBE_CONNECT_H

#include <stdint.h>

/* Open a TCP connection with timeout_ms. Returns 0 if open and writes the
 * resolved IP into ip_out (if non-NULL). Returns -1 on refused/timeout. */
int ps_tcp_open_check(const char *host, uint16_t port, int timeout_ms,
                      char *ip_out, size_t ip_out_sz);

#endif
```

Create `/Users/billn/packetsonde/src/cli/probe/connect.c`:
```c
#include "connect.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int ps_tcp_open_check(const char *host, uint16_t port, int timeout_ms,
                      char *ip_out, size_t ip_out_sz) {
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (ip_out && ip_out_sz) {
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &sin->sin_addr, ip_out, (socklen_t)ip_out_sz);
    }
    int rc = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    close(fd);
    return rc == 0 ? 0 : -1;
}
```

In `src/cli/CMakeLists.txt`, add `probe/connect.c` to `CLI_SOURCES`.

- [ ] **Step 2: Implement `src/cli/scan/ports.h`**

```c
#ifndef PS_SCAN_PORTS_H
#define PS_SCAN_PORTS_H

#include "../args.h"

int ps_scan_ports_run(int argc, char **argv, const struct ps_args *opts);

#endif
```

- [ ] **Step 3: Implement `src/cli/scan/ports.c`**

```c
#include "ports.h"
#include "../output/output.h"
#include "../probe/connect.h"
#include "../runstate.h"
#include "../signals.h"
#include "../util/fail_on.h"
#include "../util/targets.h"
#include "../workers/limiter.h"
#include "../workers/workers.h"
#include "finding.h"
#include "ulid.h"

#include <getopt.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const uint16_t DEFAULT_PORTS[] = {
    21, 22, 23, 25, 53, 80, 110, 143, 443, 587, 993, 995,
    3306, 3389, 5432, 5900, 6379, 8080, 8443
};
static const size_t DEFAULT_PORTS_N = sizeof(DEFAULT_PORTS) / sizeof(DEFAULT_PORTS[0]);

struct scan_ctx {
    struct ps_output *out;
    struct ps_workers *W;
    const char *run_id;
    const char *self_host;
};

struct scan_item {
    struct scan_ctx *ctx;
    char     host[64];
    uint16_t port;
};

static void scan_one(void *arg) {
    struct scan_item *it = (struct scan_item *)arg;
    if (ps_workers_cancelled(it->ctx->W)) { free(it); return; }
    char ip[64] = "";
    if (ps_tcp_open_check(it->host, it->port, 2000, ip, sizeof(ip)) == 0) {
        char title[160];
        snprintf(title, sizeof(title), "Open: %s:%u", ip[0] ? ip : it->host, it->port);
        struct ps_finding f;
        ps_finding_init(&f, it->ctx->run_id, "cli.scan.ports.connect",
                        it->ctx->self_host, "scan.port.open",
                        PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        if (ip[0]) ps_finding_set_target_ip(&f, ip, it->port);
        else       ps_finding_set_target_hostname(&f, it->host, it->port);
        ps_output_emit(it->ctx->out, &f);
    }
    free(it);
}

static void usage(void) {
    fprintf(stderr,
        "Usage: packetsonde scan ports <target|cidr> [-p PORTS]\n"
        "  PORTS: comma list and dash ranges, e.g. 22,80,443,1000-2000\n");
}

int ps_scan_ports_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }

    /* argv[0] = "ports", argv[1] = target, optional -p */
    const char *target = argv[1];
    const char *ports_arg = NULL;
    optind = 2;
    int c;
    while ((c = getopt(argc, argv, "p:")) != -1) {
        if (c == 'p') ports_arg = optarg;
        else { usage(); return 2; }
    }

    struct ps_cidr cidr;
    if (ps_cidr_parse(target, &cidr) != 0) {
        fprintf(stderr, "scan ports: bad target '%s'\n", target);
        return 2;
    }

    struct ps_portset ports = {0};
    if (ports_arg) {
        if (ps_ports_parse(ports_arg, &ports) != 0) {
            fprintf(stderr, "scan ports: bad ports '%s'\n", ports_arg);
            return 2;
        }
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    struct ps_output_opts oopts; memset(&oopts, 0, sizeof(oopts));
    switch (opts->fmt) {
        case PS_FMT_TEXT:  oopts.fmt_force = PS_OFMT_TEXT;  break;
        case PS_FMT_JSON:  oopts.fmt_force = PS_OFMT_JSON;  break;
        case PS_FMT_JSONL: oopts.fmt_force = PS_OFMT_JSONL; break;
        case PS_FMT_QUIET: oopts.fmt_force = PS_OFMT_QUIET; break;
        default:           oopts.fmt_force = 0;             break;
    }
    oopts.color = opts->no_color ? 0 : 1;
    struct ps_output out; ps_output_init(&out, &oopts);

    struct ps_limiter L;
    int rate = opts->rate_pps > 0 ? opts->rate_pps : 100;
    ps_limiter_init(&L, rate);

    struct ps_workers W;
    int concur = opts->concurrency > 0 ? opts->concurrency : 16;
    ps_workers_init(&W, concur, &L);
    ps_signals_install(&W);

    struct scan_ctx ctx = { &out, &W, run_id, self_host };

    const uint16_t *plist = ports_arg ? ports.ports        : DEFAULT_PORTS;
    size_t          pcnt  = ports_arg ? ports.count        : DEFAULT_PORTS_N;

    for (uint32_t i = 0; i < cidr.count && !ps_workers_cancelled(&W); i++) {
        char host[64];
        if (ps_cidr_addr(&cidr, i, host, sizeof(host)) != 0) continue;
        for (size_t pi = 0; pi < pcnt; pi++) {
            struct scan_item *it = calloc(1, sizeof(*it));
            it->ctx = &ctx;
            snprintf(it->host, sizeof(it->host), "%s", host);
            it->port = plist[pi];
            ps_workers_submit(&W, scan_one, it);
        }
    }

    ps_workers_finish(&W);
    ps_workers_destroy(&W);
    ps_limiter_destroy(&L);
    ps_ports_destroy(&ports);

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
```

- [ ] **Step 4: Implement `src/cli/discover/hosts.{h,c}`**

`src/cli/discover/hosts.h`:
```c
#ifndef PS_DISCOVER_HOSTS_H
#define PS_DISCOVER_HOSTS_H

#include "../args.h"

int ps_discover_hosts_run(int argc, char **argv, const struct ps_args *opts);

#endif
```

`src/cli/discover/hosts.c`:
```c
#include "hosts.h"
#include "../output/output.h"
#include "../probe/connect.h"
#include "../runstate.h"
#include "../signals.h"
#include "../util/fail_on.h"
#include "../util/targets.h"
#include "../workers/limiter.h"
#include "../workers/workers.h"
#include "finding.h"
#include "ulid.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const uint16_t SWEEP_PORTS[] = { 22, 80, 443, 445 };
static const size_t SWEEP_PORTS_N = sizeof(SWEEP_PORTS) / sizeof(SWEEP_PORTS[0]);

struct host_item {
    struct ps_output *out;
    struct ps_workers *W;
    const char *run_id;
    const char *self_host;
    char  host[64];
};

static void check_host(void *arg) {
    struct host_item *it = (struct host_item *)arg;
    if (ps_workers_cancelled(it->W)) { free(it); return; }
    for (size_t i = 0; i < SWEEP_PORTS_N; i++) {
        char ip[64] = "";
        if (ps_tcp_open_check(it->host, SWEEP_PORTS[i], 600, ip, sizeof(ip)) == 0) {
            char title[160];
            snprintf(title, sizeof(title), "host up: %s (port %u)",
                     ip[0] ? ip : it->host, SWEEP_PORTS[i]);
            char ev[160];
            snprintf(ev, sizeof(ev), "{\"first_open_port\":%u}", SWEEP_PORTS[i]);
            struct ps_finding f;
            ps_finding_init(&f, it->run_id, "cli.discover.hosts", it->self_host,
                            "discover.host.up", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
            if (ip[0]) ps_finding_set_target_ip(&f, ip, 0);
            else       ps_finding_set_target_hostname(&f, it->host, 0);
            ps_finding_set_evidence_json(&f, ev);
            ps_output_emit(it->out, &f);
            break;  /* one finding per host */
        }
    }
    free(it);
}

int ps_discover_hosts_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde discover hosts <cidr>\n");
        return 2;
    }
    struct ps_cidr cidr;
    if (ps_cidr_parse(argv[1], &cidr) != 0) {
        fprintf(stderr, "discover hosts: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    struct ps_output_opts oopts; memset(&oopts, 0, sizeof(oopts));
    switch (opts->fmt) {
        case PS_FMT_TEXT:  oopts.fmt_force = PS_OFMT_TEXT;  break;
        case PS_FMT_JSON:  oopts.fmt_force = PS_OFMT_JSON;  break;
        case PS_FMT_JSONL: oopts.fmt_force = PS_OFMT_JSONL; break;
        case PS_FMT_QUIET: oopts.fmt_force = PS_OFMT_QUIET; break;
        default:           oopts.fmt_force = 0;             break;
    }
    oopts.color = opts->no_color ? 0 : 1;
    struct ps_output out; ps_output_init(&out, &oopts);

    struct ps_limiter L;
    int rate = opts->rate_pps > 0 ? opts->rate_pps : 100;
    ps_limiter_init(&L, rate);

    struct ps_workers W;
    int concur = opts->concurrency > 0 ? opts->concurrency : 32;
    ps_workers_init(&W, concur, &L);
    ps_signals_install(&W);

    for (uint32_t i = 0; i < cidr.count && !ps_workers_cancelled(&W); i++) {
        struct host_item *it = calloc(1, sizeof(*it));
        it->out = &out; it->W = &W;
        it->run_id = run_id; it->self_host = self_host;
        if (ps_cidr_addr(&cidr, i, it->host, sizeof(it->host)) != 0) { free(it); continue; }
        ps_workers_submit(&W, check_host, it);
    }

    ps_workers_finish(&W);
    ps_workers_destroy(&W);
    ps_limiter_destroy(&L);

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
```

- [ ] **Step 5: Create the `scan` verb dispatcher**

Create `/Users/billn/packetsonde/src/cli/verbs/scan.c`:
```c
#include "../verbs.h"

#include <stdio.h>
#include <string.h>

int ps_scan_ports_run(int argc, char **argv, const struct ps_args *opts);

struct scan_kind {
    const char *name;
    int (*run)(int argc, char **argv, const struct ps_args *opts);
    const char *summary;
};

static const struct scan_kind KINDS[] = {
    { "ports", ps_scan_ports_run, "Connect-scan a target or CIDR" },
    { NULL, NULL, NULL }
};

static void usage(void) {
    fprintf(stderr, "Usage: packetsonde scan <kind> [args...]\n\nKinds:\n");
    for (const struct scan_kind *k = KINDS; k->name; k++)
        fprintf(stderr, "  %-8s %s\n", k->name, k->summary);
}

int ps_verb_scan_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }
    for (const struct scan_kind *k = KINDS; k->name; k++) {
        if (strcmp(k->name, argv[1]) == 0) return k->run(argc - 1, argv + 1, opts);
    }
    fprintf(stderr, "scan: unknown kind '%s'\n", argv[1]);
    usage();
    return 2;
}
```

- [ ] **Step 6: Drop the weak `discover hosts` stub**

In `src/cli/verbs/discover.c`, remove the `__attribute__((weak)) int ps_discover_hosts_run(...) {...}` block.

- [ ] **Step 7: Register, CMake, build, smoke**

In `src/cli/dispatch.c`, add:
```c
int  ps_verb_scan_run    (int argc, char **argv, const struct ps_args *opts);
```
Update VERBS (between `audit` and `discover`):
```c
    { "scan",     ps_verb_scan_run,     "Active scan (ports)" },
```

In `src/cli/CMakeLists.txt`, add `scan/ports.c discover/hosts.c verbs/scan.c` to `CLI_SOURCES`.

```bash
cd /Users/billn/packetsonde/build && cmake .. && make packetsonde 2>&1 | tail -3
../build/src/cli/packetsonde scan ports 127.0.0.1 -p 22,80,443
../build/src/cli/packetsonde discover hosts 127.0.0.1/30
```
Expected: some "Open" findings on localhost (depending on what's listening); no crash on the /30 sweep.

- [ ] **Step 8: Commit**

```bash
cd /Users/billn/packetsonde
git add src/cli/probe/connect.h src/cli/probe/connect.c \
        src/cli/scan src/cli/discover/hosts.h src/cli/discover/hosts.c \
        src/cli/verbs/scan.c src/cli/verbs/discover.c \
        src/cli/dispatch.c src/cli/CMakeLists.txt
git commit -m "feat(cli): scan ports + discover hosts (connect sweeps)

Both verbs use the shared worker pool + token-bucket limiter + signals.
scan ports has a default 'top 19' port list and accepts -p with
comma+dash syntax. discover hosts probes 22/80/443/445 and emits one
discover.host.up finding per reachable host."
```

---

## Task 13: Verification gate + tag

- [ ] **Step 1: Clean rebuild**

```bash
cd /Users/billn/packetsonde && rm -rf build && ./build.sh native 2>&1 | tail -3
```
Expected: clean.

- [ ] **Step 2: All tests pass**

```bash
cd build && ctest --output-on-failure 2>&1 | tail -3
```
Expected: 26/26 PASS (20 from Plan 2 + 6 new: test_targets, test_findings_filter, test_agents_registry, test_fail_on, test_traceroute, test_audit_tls already exists).

- [ ] **Step 3: Behavioral smoke**

```bash
cd /Users/billn/packetsonde
./build/src/cli/packetsonde help
./build/src/cli/packetsonde --jsonl probe tcp example.com:80 | jq -c '{kind,severity}'
./build/src/cli/packetsonde --jsonl scan ports 127.0.0.1 -p 80 2>/dev/null
./build/src/cli/packetsonde --jsonl audit dns 1.1.1.1 2>/dev/null
./build/src/cli/packetsonde config path
./build/src/cli/packetsonde discover neighbors --quiet 2>&1 | head -3
echo '{"v":1,"id":"x","run_id":"r","ts":"t","source":"s","host":"h","kind":"tls.weak_cipher","severity":"high","confidence":"firm","title":"t","target":{"ip":"1.2.3.4","port":443}}' \
  | ./build/src/cli/packetsonde findings filter 'severity>=high'
```
Expected: each command produces sensible output for its kind; `findings filter` echoes the JSONL line back.

- [ ] **Step 4: Tag**

```bash
git tag -a plan-3-verb-breadth -m "Plan 3 (verb breadth) complete

- util/targets (CIDR + port-list)
- findings_util (JSONL reader + filter expressions)
- findings verb: tail + filter
- config verb: show + path
- registry/agents: TOML-lite parser for agents.toml
- --fail-on severity>=LEVEL gates exit code
- probe tcp (single TCP probe + banner)
- lib/traceroute (UDP classic)
- probe traceroute --proto udp --mode classic
- audit dns (version.bind + open-recursion)
- discover neighbors (ARP table)
- scan ports (connect sweep, CIDR-aware)
- discover hosts (port-set host sweep)

Paris/Dublin/TCP/ICMP traceroute modes deferred to follow-on."
```

Plan 3 complete. v1 verb surface is shipped.

---

## Self-review notes

- Tasks 7+8 (probe tcp + probe traceroute stub) and Tasks 11+12 (discover dispatcher + discover hosts) share the `__attribute__((weak))` stub pattern so each task commits cleanly without breaking the build. Subsequent tasks drop the stub when the real implementation lands.
- `probe traceroute` ships UDP classic only in this plan. Paris, Dublin, TCP, and ICMP modes are explicitly deferred to a follow-on plan (spec §6.3) — the verb's `usage()` message tells the user what is and isn't implemented.
- `audit dns` skips the ANY-amplification check by design — it's bandwidth-impactful and belongs behind an opt-in flag. Captured as follow-on.
- `discover hosts` uses TCP connect to common ports rather than ARP/ICMP — that avoids the privilege requirement and works on macOS without changes. ARP-sweep is a follow-on.
- `--fail-on` only implements `severity>=LEVEL` (the most common gate). Compound expressions are a follow-on.
- The `runstate.h` global is intentional and small — a struct `ps_fail_counts` populated by each verb run, consumed by main. Threading isn't a concern because verbs serialize through their own emitter.
- The agents registry parser is a deliberate subset of TOML (only `[agents.NAME]` blocks with string values). Full TOML is unnecessary for v1 and would be its own dependency.
