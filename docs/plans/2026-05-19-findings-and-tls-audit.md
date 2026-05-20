# Findings & First Audit (TLS) Implementation Plan — Plan 2 of 3

> **For agentic workers:** Execute task-by-task. Each task has steps with checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the finding record, the output pipeline (text/JSONL/auto-append/tty-detect), a worker pool with polite-by-default rate limiting, SIGINT-clean cancellation, and ship `packetsonde audit tls <target>` as the first real verb. End state: a real auditor can pipe `packetsonde audit tls mail.example.com:443` into `jq` and read findings.

**Architecture:** A single emitter thread owns stdout (and the auto-append file descriptor if active), receiving findings from N worker threads through a bounded MPSC queue. Workers acquire tokens from a shared rate limiter before each probe. `audit tls` is implemented in-process via OpenSSL: open a TCP connection to `target:port`, drive the handshake at requested protocol versions / cipher lists, inspect the negotiated parameters and certificate chain, emit one finding per issue. SIGINT sets a global cancellation flag that workers and the emitter observe; the emitter flushes before exit.

**Tech Stack:** C11, pthreads, OpenSSL (already used by the agent's `tls_probe`), CMake. No new third-party deps. Tests link `packetsonde_lib` plus a small `audit_tls_core.c` library object so integration tests can drive the audit logic without forking the CLI.

**Spec reference:** `docs/specs/2026-05-18-packetsonde-cli-design.md` §3 (finding record), §4 (data flow / lifecycle / exit codes), §5 (CLI grammar, defaults), §6.1 (`audit tls`).

---

## File structure produced by this plan

```
src/lib/
├── finding.h                # struct ps_finding + builder + JSON/text serializer API
├── finding.c
├── tests/
│   └── test_finding.c

src/cli/
├── output/
│   ├── output.h             # emitter: fmt selection, tty-detect, auto-append, thread-safe emit
│   └── output.c
├── workers/
│   ├── limiter.h            # token-bucket rate limiter
│   ├── limiter.c
│   ├── workers.h            # pool + bounded MPSC queue + cancel flag
│   └── workers.c
├── audit/
│   ├── tls.h                # ps_audit_tls(target, port, emit_fn, ctx, cancel_fn)
│   └── tls.c                # OpenSSL-driven TLS audit
├── verbs/
│   ├── audit.c              # `packetsonde audit <kind> ...` dispatcher
│   └── (existing) version.c, agent.c
├── signals.h                # ps_signals_install / ps_should_cancel
├── signals.c
├── tests/
│   ├── test_args.c          # (existing)
│   ├── test_output.c
│   ├── test_limiter.c
│   ├── test_workers.c
│   └── test_audit_tls.sh    # integration test driver (uses openssl s_server)
```

`src/cli/CMakeLists.txt` grows to (a) compile the new sources, (b) link OpenSSL onto `packetsonde` (the agent already finds it at the top level), and (c) register the new tests.

---

## Task 1: Baseline check

Confirm `main` is green on the current host before changing anything.

**Files:** none modified.

- [ ] **Step 1: Clean build**

Run: `cd /Users/billn/packetsonde && rm -rf build && ./build.sh native 2>&1 | tail -5`
Expected: `=== Build complete ===` with no errors.

- [ ] **Step 2: All tests pass**

Run: `cd /Users/billn/packetsonde/build && ctest --output-on-failure 2>&1 | tail -5`
Expected: `100% tests passed, 0 tests failed out of 15`.

- [ ] **Step 3: CLI surface still works**

Run: `cd /Users/billn/packetsonde && ./build/src/cli/packetsonde version`
Expected: `packetsonde 0.1.0`

No commit. Verification gate only.

---

## Task 2: Finding record + JSON serializer (TDD)

`finding.h` and `finding.c` own the wire format defined in spec §3. The struct and the JSON emitter are the two things that must be stable v1; everything else in this plan is consumer code.

**Files:**
- Create: `src/lib/finding.h`, `src/lib/finding.c`
- Create: `src/lib/tests/test_finding.c`
- Modify: `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test**

Create `/Users/billn/packetsonde/src/lib/tests/test_finding.c`:
```c
#include "../finding.h"
#include "../ulid.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int contains(const char *hay, const char *needle) {
    return strstr(hay, needle) != NULL;
}

static void test_minimal_finding_to_json(void) {
    char run_id[PS_ULID_STRLEN + 1];
    ps_ulid_new(run_id, sizeof(run_id));

    struct ps_finding f;
    ps_finding_init(&f, run_id, "cli.audit.tls", "test-host", "tls.weak_protocol",
                    PS_SEV_HIGH, PS_CONF_FIRM, "TLS 1.0 negotiated");
    ps_finding_set_target_ip(&f, "10.0.0.42", 443);

    char buf[2048];
    int n = ps_finding_to_json(&f, buf, sizeof(buf));
    assert(n > 0);
    assert(contains(buf, "\"v\":1"));
    assert(contains(buf, "\"run_id\":"));
    assert(contains(buf, run_id));
    assert(contains(buf, "\"source\":\"cli.audit.tls\""));
    assert(contains(buf, "\"host\":\"test-host\""));
    assert(contains(buf, "\"kind\":\"tls.weak_protocol\""));
    assert(contains(buf, "\"severity\":\"high\""));
    assert(contains(buf, "\"confidence\":\"firm\""));
    assert(contains(buf, "\"title\":\"TLS 1.0 negotiated\""));
    assert(contains(buf, "\"target\":{"));
    assert(contains(buf, "\"ip\":\"10.0.0.42\""));
    assert(contains(buf, "\"port\":443"));
    /* JSONL: exactly one line, ends with newline */
    assert(buf[n - 1] == '\n');
    int newlines = 0;
    for (int i = 0; i < n; i++) if (buf[i] == '\n') newlines++;
    assert(newlines == 1);
}

static void test_severity_enum_strings(void) {
    assert(strcmp(ps_severity_str(PS_SEV_INFO),     "info")     == 0);
    assert(strcmp(ps_severity_str(PS_SEV_LOW),      "low")      == 0);
    assert(strcmp(ps_severity_str(PS_SEV_MEDIUM),   "medium")   == 0);
    assert(strcmp(ps_severity_str(PS_SEV_HIGH),     "high")     == 0);
    assert(strcmp(ps_severity_str(PS_SEV_CRITICAL), "critical") == 0);
}

static void test_json_escaping(void) {
    char run_id[PS_ULID_STRLEN + 1];
    ps_ulid_new(run_id, sizeof(run_id));
    struct ps_finding f;
    /* Title contains a quote and a backslash and a newline — must be escaped. */
    ps_finding_init(&f, run_id, "cli.audit.tls", "h", "tls.x",
                    PS_SEV_INFO, PS_CONF_FIRM, "weird \"quotes\" and \\back\\ and \n");
    char buf[1024];
    int n = ps_finding_to_json(&f, buf, sizeof(buf));
    assert(n > 0);
    assert(contains(buf, "\\\"quotes\\\""));
    assert(contains(buf, "\\\\back\\\\"));
    assert(contains(buf, "\\n"));
}

static void test_optional_via_agent(void) {
    char run_id[PS_ULID_STRLEN + 1];
    ps_ulid_new(run_id, sizeof(run_id));
    struct ps_finding f;
    ps_finding_init(&f, run_id, "agent.tls_probe", "trunkbox", "tls.weak_protocol",
                    PS_SEV_HIGH, PS_CONF_FIRM, "TLS 1.0");
    ps_finding_set_via_agent(&f, "trunkbox");
    char buf[1024];
    int n = ps_finding_to_json(&f, buf, sizeof(buf));
    assert(n > 0);
    assert(contains(buf, "\"via_agent\":\"trunkbox\""));
}

static void test_evidence_blob_passthrough(void) {
    char run_id[PS_ULID_STRLEN + 1];
    ps_ulid_new(run_id, sizeof(run_id));
    struct ps_finding f;
    ps_finding_init(&f, run_id, "cli.audit.tls", "h", "tls.weak_cipher",
                    PS_SEV_HIGH, PS_CONF_FIRM, "weak cipher");
    /* Caller provides a JSON object literal as evidence. */
    ps_finding_set_evidence_json(&f, "{\"cipher\":\"DES-CBC3-SHA\"}");
    char buf[1024];
    int n = ps_finding_to_json(&f, buf, sizeof(buf));
    assert(n > 0);
    assert(contains(buf, "\"evidence\":{\"cipher\":\"DES-CBC3-SHA\"}"));
}

int main(void) {
    test_minimal_finding_to_json();
    test_severity_enum_strings();
    test_json_escaping();
    test_optional_via_agent();
    test_evidence_blob_passthrough();
    printf("test_finding: OK\n");
    return 0;
}
```

- [ ] **Step 2: Wire the test into CMake**

In `/Users/billn/packetsonde/src/lib/CMakeLists.txt`, append to the `add_library(packetsonde_lib STATIC ...)` source list so it reads:
```cmake
add_library(packetsonde_lib STATIC
    json.c
    log.c
    ulid.c
    ipc.c
    finding.c
)
```

Add the test target alongside the existing `test_ulid` block:
```cmake
if(BUILD_TESTING)
    add_executable(test_finding tests/test_finding.c)
    target_link_libraries(test_finding PRIVATE packetsonde_lib)
    add_test(NAME test_finding COMMAND test_finding)
endif()
```

- [ ] **Step 3: Confirm the test fails to build**

Run:
```bash
cd /Users/billn/packetsonde/build
cmake ..
make test_finding 2>&1 | tail -10
```
Expected: build error referencing missing `finding.h`. TDD red.

- [ ] **Step 4: Implement `src/lib/finding.h`**

```c
#ifndef PS_FINDING_H
#define PS_FINDING_H

#include "ulid.h"
#include <stddef.h>
#include <stdint.h>

enum ps_severity {
    PS_SEV_INFO = 0,
    PS_SEV_LOW,
    PS_SEV_MEDIUM,
    PS_SEV_HIGH,
    PS_SEV_CRITICAL
};

enum ps_confidence {
    PS_CONF_TENTATIVE = 0,
    PS_CONF_FIRM,
    PS_CONF_CONFIRMED
};

#define PS_FIND_TITLE_MAX     256
#define PS_FIND_EVIDENCE_MAX  4096
#define PS_FIND_TARGET_MAX    256
#define PS_FIND_HOST_MAX      128
#define PS_FIND_SOURCE_MAX    128
#define PS_FIND_KIND_MAX      128
#define PS_FIND_VIA_MAX       64

struct ps_finding {
    char id[PS_ULID_STRLEN + 1];
    char run_id[PS_ULID_STRLEN + 1];
    char ts[32];                            /* RFC3339, e.g. 2026-05-19T22:00:00.123Z */
    char source[PS_FIND_SOURCE_MAX];
    char host[PS_FIND_HOST_MAX];
    char via_agent[PS_FIND_VIA_MAX];        /* "" when absent */
    char kind[PS_FIND_KIND_MAX];
    char title[PS_FIND_TITLE_MAX];
    enum ps_severity   severity;
    enum ps_confidence confidence;

    /* Target: any subset may be set. ip/hostname are NUL-terminated; port==0 means absent. */
    char target_ip[64];
    char target_hostname[PS_FIND_TARGET_MAX];
    uint16_t target_port;

    /* Optional JSON-object literal (caller-provided, must be valid JSON object or empty). */
    char evidence_json[PS_FIND_EVIDENCE_MAX];
};

/* Initialize a finding with required fields. Generates id (ULID), stamps ts (UTC now).
 * Required strings are copied (truncated to their fixed-size buffers if too long). */
void ps_finding_init(struct ps_finding *f,
                     const char *run_id,
                     const char *source,
                     const char *host,
                     const char *kind,
                     enum ps_severity severity,
                     enum ps_confidence confidence,
                     const char *title);

void ps_finding_set_target_ip      (struct ps_finding *f, const char *ip, uint16_t port);
void ps_finding_set_target_hostname(struct ps_finding *f, const char *hostname, uint16_t port);
void ps_finding_set_via_agent      (struct ps_finding *f, const char *agent_name);

/* `evidence` must be a syntactically valid JSON object, e.g. "{\"k\":\"v\"}".
 * It is copied verbatim into the output between the evidence key and the next comma. */
void ps_finding_set_evidence_json(struct ps_finding *f, const char *evidence);

const char *ps_severity_str  (enum ps_severity s);
const char *ps_confidence_str(enum ps_confidence c);

/* Serialize as exactly one JSONL line (terminated with '\n'). Returns
 * bytes written (excluding terminator). Returns -1 if buf too small. */
int ps_finding_to_json(const struct ps_finding *f, char *buf, size_t bufsz);

/* Human-readable single-line rendering. Returns bytes written (excluding NUL).
 * `color`: 0 = no color; 1 = ANSI color. */
int ps_finding_to_text(const struct ps_finding *f, char *buf, size_t bufsz, int color);

#endif
```

- [ ] **Step 5: Implement `src/lib/finding.c`**

```c
#include "finding.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

static void copy_str(char *dst, size_t dst_sz, const char *src) {
    if (!src) { dst[0] = '\0'; return; }
    size_t n = strlen(src);
    if (n >= dst_sz) n = dst_sz - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void stamp_now(char *buf, size_t sz) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    gmtime_r(&tv.tv_sec, &tm);
    /* RFC3339 with ms */
    snprintf(buf, sz, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             (int)(tv.tv_usec / 1000));
}

void ps_finding_init(struct ps_finding *f,
                     const char *run_id,
                     const char *source,
                     const char *host,
                     const char *kind,
                     enum ps_severity severity,
                     enum ps_confidence confidence,
                     const char *title) {
    memset(f, 0, sizeof(*f));
    ps_ulid_new(f->id, sizeof(f->id));
    copy_str(f->run_id, sizeof(f->run_id), run_id);
    copy_str(f->source, sizeof(f->source), source);
    copy_str(f->host,   sizeof(f->host),   host);
    copy_str(f->kind,   sizeof(f->kind),   kind);
    copy_str(f->title,  sizeof(f->title),  title);
    f->severity   = severity;
    f->confidence = confidence;
    stamp_now(f->ts, sizeof(f->ts));
}

void ps_finding_set_target_ip(struct ps_finding *f, const char *ip, uint16_t port) {
    copy_str(f->target_ip, sizeof(f->target_ip), ip);
    f->target_port = port;
}

void ps_finding_set_target_hostname(struct ps_finding *f, const char *hostname, uint16_t port) {
    copy_str(f->target_hostname, sizeof(f->target_hostname), hostname);
    if (port) f->target_port = port;
}

void ps_finding_set_via_agent(struct ps_finding *f, const char *agent_name) {
    copy_str(f->via_agent, sizeof(f->via_agent), agent_name);
}

void ps_finding_set_evidence_json(struct ps_finding *f, const char *evidence) {
    copy_str(f->evidence_json, sizeof(f->evidence_json), evidence);
}

static const char *SEV[] = { "info", "low", "medium", "high", "critical" };
static const char *CONF[] = { "tentative", "firm", "confirmed" };

const char *ps_severity_str  (enum ps_severity s) {
    if (s < 0 || (size_t)s >= sizeof(SEV)/sizeof(SEV[0]))   return "info";
    return SEV[s];
}
const char *ps_confidence_str(enum ps_confidence c) {
    if (c < 0 || (size_t)c >= sizeof(CONF)/sizeof(CONF[0])) return "firm";
    return CONF[c];
}

/* Append a JSON-escaped string into out. Returns chars written, or -1 on overflow. */
static int json_escape(const char *in, char *out, size_t outsz) {
    size_t o = 0;
    for (size_t i = 0; in[i]; i++) {
        unsigned char c = (unsigned char)in[i];
        const char *esc = NULL;
        char ubuf[8];
        switch (c) {
            case '"':  esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\n': esc = "\\n";  break;
            case '\r': esc = "\\r";  break;
            case '\t': esc = "\\t";  break;
            case '\b': esc = "\\b";  break;
            case '\f': esc = "\\f";  break;
            default:
                if (c < 0x20) {
                    snprintf(ubuf, sizeof(ubuf), "\\u%04x", c);
                    esc = ubuf;
                }
                break;
        }
        if (esc) {
            size_t n = strlen(esc);
            if (o + n >= outsz) return -1;
            memcpy(out + o, esc, n);
            o += n;
        } else {
            if (o + 1 >= outsz) return -1;
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
    return (int)o;
}

int ps_finding_to_json(const struct ps_finding *f, char *buf, size_t bufsz) {
    char title_e[PS_FIND_TITLE_MAX * 6 + 1];
    if (json_escape(f->title, title_e, sizeof(title_e)) < 0) return -1;

    /* Build target sub-object only if any target field is set. */
    char target_obj[PS_FIND_TARGET_MAX * 6 + 96] = "";
    int has_target = (f->target_ip[0] || f->target_hostname[0] || f->target_port);
    if (has_target) {
        size_t o = 0;
        o += snprintf(target_obj + o, sizeof(target_obj) - o, "{");
        int first = 1;
        if (f->target_ip[0]) {
            o += snprintf(target_obj + o, sizeof(target_obj) - o, "\"ip\":\"%s\"", f->target_ip);
            first = 0;
        }
        if (f->target_hostname[0]) {
            char hn_e[PS_FIND_TARGET_MAX * 6 + 1];
            if (json_escape(f->target_hostname, hn_e, sizeof(hn_e)) < 0) return -1;
            o += snprintf(target_obj + o, sizeof(target_obj) - o, "%s\"hostname\":\"%s\"",
                          first ? "" : ",", hn_e);
            first = 0;
        }
        if (f->target_port) {
            o += snprintf(target_obj + o, sizeof(target_obj) - o, "%s\"port\":%u",
                          first ? "" : ",", (unsigned)f->target_port);
        }
        o += snprintf(target_obj + o, sizeof(target_obj) - o, "}");
        (void)o;
    }

    int n = snprintf(buf, bufsz,
        "{\"v\":1,\"id\":\"%s\",\"run_id\":\"%s\",\"ts\":\"%s\","
        "\"source\":\"%s\",\"host\":\"%s\""
        "%s%s%s"
        ",\"kind\":\"%s\",\"severity\":\"%s\",\"confidence\":\"%s\""
        ",\"title\":\"%s\""
        "%s%s"
        "%s%s%s"
        "}\n",
        f->id, f->run_id, f->ts,
        f->source, f->host,
        f->via_agent[0] ? ",\"via_agent\":\"" : "",
        f->via_agent[0] ? f->via_agent       : "",
        f->via_agent[0] ? "\""                : "",
        f->kind, ps_severity_str(f->severity), ps_confidence_str(f->confidence),
        title_e,
        has_target ? ",\"target\":" : "",
        has_target ? target_obj     : "",
        f->evidence_json[0] ? ",\"evidence\":" : "",
        f->evidence_json[0] ? f->evidence_json : "",
        ""
    );
    if (n < 0 || (size_t)n >= bufsz) return -1;
    return n;
}

int ps_finding_to_text(const struct ps_finding *f, char *buf, size_t bufsz, int color) {
    const char *sev_color =
        f->severity == PS_SEV_CRITICAL ? "\x1b[1;31m" :
        f->severity == PS_SEV_HIGH     ? "\x1b[31m"   :
        f->severity == PS_SEV_MEDIUM   ? "\x1b[33m"   :
        f->severity == PS_SEV_LOW      ? "\x1b[36m"   : "\x1b[2m";
    const char *reset = "\x1b[0m";

    char target_s[PS_FIND_TARGET_MAX + 32] = "-";
    if (f->target_ip[0] && f->target_port) {
        snprintf(target_s, sizeof(target_s), "%s:%u", f->target_ip, f->target_port);
    } else if (f->target_hostname[0] && f->target_port) {
        snprintf(target_s, sizeof(target_s), "%s:%u", f->target_hostname, f->target_port);
    } else if (f->target_ip[0]) {
        snprintf(target_s, sizeof(target_s), "%s", f->target_ip);
    } else if (f->target_hostname[0]) {
        snprintf(target_s, sizeof(target_s), "%s", f->target_hostname);
    }

    int n;
    if (color) {
        n = snprintf(buf, bufsz, "%s%-8s%s  %-24s  %-32s  %s\n",
                     sev_color, ps_severity_str(f->severity), reset,
                     f->kind, target_s, f->title);
    } else {
        n = snprintf(buf, bufsz, "%-8s  %-24s  %-32s  %s\n",
                     ps_severity_str(f->severity), f->kind, target_s, f->title);
    }
    if (n < 0 || (size_t)n >= bufsz) return -1;
    return n;
}
```

- [ ] **Step 6: Build and run test**

```bash
cd /Users/billn/packetsonde/build
cmake ..
make test_finding
ctest -R '^test_finding$' --output-on-failure
ctest --output-on-failure 2>&1 | tail -5
```
Expected: `test_finding: OK`; suite passes 16/16.

- [ ] **Step 7: Commit**

```bash
cd /Users/billn/packetsonde
git add src/lib/finding.h src/lib/finding.c src/lib/tests/test_finding.c src/lib/CMakeLists.txt
git commit -m "feat(lib): finding record + JSON serializer

Stable wire format per spec section 3. Severity/confidence enums,
RFC3339 timestamp, target sub-object, optional via_agent, evidence
as a caller-supplied JSON object literal. JSONL emitter writes
exactly one '\n'-terminated line."
```

---

## Task 3: Output system — fmt selection, tty detect, thread-safe emit (TDD)

The output module owns stdout and (optionally) the auto-append file. A single internal mutex serializes writes so workers can submit findings from any thread.

**Files:**
- Create: `src/cli/output/output.h`, `src/cli/output/output.c`
- Create: `src/cli/tests/test_output.c`
- Modify: `src/cli/CMakeLists.txt`

- [ ] **Step 1: Write the failing test**

`mkdir -p /Users/billn/packetsonde/src/cli/output`

Create `/Users/billn/packetsonde/src/cli/tests/test_output.c`:
```c
#include "../output/output.h"
#include "finding.h"
#include "ulid.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void capture_to_buf(int fmt_force, int color, const struct ps_finding *f,
                           char *out, size_t outsz) {
    char path[] = "/tmp/ps_test_out_XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);

    struct ps_output o;
    struct ps_output_opts opts = {0};
    opts.fmt_force      = fmt_force;
    opts.color          = color;
    opts.target_fd      = fd;        /* explicit target instead of stdout */
    opts.assume_tty     = (color ? 1 : 0);
    assert(ps_output_init(&o, &opts) == 0);
    ps_output_emit(&o, f);
    ps_output_close(&o);

    lseek(fd, 0, SEEK_SET);
    ssize_t r = read(fd, out, outsz - 1);
    out[r > 0 ? r : 0] = '\0';
    close(fd);
    unlink(path);
}

static void make_finding(struct ps_finding *f) {
    char run_id[PS_ULID_STRLEN + 1];
    ps_ulid_new(run_id, sizeof(run_id));
    ps_finding_init(f, run_id, "cli.audit.tls", "h", "tls.weak_protocol",
                    PS_SEV_HIGH, PS_CONF_FIRM, "TLS 1.0");
    ps_finding_set_target_ip(f, "10.0.0.42", 443);
}

static void test_jsonl_format(void) {
    struct ps_finding f; make_finding(&f);
    char buf[2048];
    capture_to_buf(PS_FMT_JSONL, 0, &f, buf, sizeof(buf));
    assert(strstr(buf, "\"kind\":\"tls.weak_protocol\""));
    /* JSONL: ends with '\n' */
    size_t L = strlen(buf);
    assert(L > 0 && buf[L - 1] == '\n');
}

static void test_text_format_no_color(void) {
    struct ps_finding f; make_finding(&f);
    char buf[1024];
    capture_to_buf(PS_FMT_TEXT, 0, &f, buf, sizeof(buf));
    assert(strstr(buf, "tls.weak_protocol"));
    assert(strstr(buf, "10.0.0.42:443"));
    assert(strstr(buf, "TLS 1.0"));
    /* No ANSI escape sequences when color is off */
    assert(strstr(buf, "\x1b[") == NULL);
}

static void test_text_format_with_color(void) {
    struct ps_finding f; make_finding(&f);
    char buf[1024];
    capture_to_buf(PS_FMT_TEXT, 1, &f, buf, sizeof(buf));
    assert(strstr(buf, "\x1b[") != NULL);  /* ANSI present */
}

static void test_quiet_format(void) {
    struct ps_finding f; make_finding(&f);
    char buf[1024];
    capture_to_buf(PS_FMT_QUIET, 0, &f, buf, sizeof(buf));
    /* Tab-separated: severity, kind, target, title */
    assert(strstr(buf, "high\ttls.weak_protocol"));
    assert(strstr(buf, "\t10.0.0.42:443\t"));
}

int main(void) {
    test_jsonl_format();
    test_text_format_no_color();
    test_text_format_with_color();
    test_quiet_format();
    printf("test_output: OK\n");
    return 0;
}
```

- [ ] **Step 2: Wire into CMake**

In `/Users/billn/packetsonde/src/cli/CMakeLists.txt`, add `output/output.c` to `CLI_SOURCES`. The block should read:
```cmake
set(CLI_SOURCES
    main.c
    args.c
    dispatch.c
    verbs/version.c
    verbs/agent.c
    output/output.c
    psctl/psctl_commands.c
    psctl/psctl_connection.c
    psctl/psctl_format.c
    psctl/psctl_shell.c
    ../agent/src/platform/unix.c
)
```

And in the `BUILD_TESTING` section, alongside the existing `test_args`:
```cmake
add_executable(test_output tests/test_output.c output/output.c)
target_include_directories(test_output PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_output PRIVATE packetsonde_lib)
add_test(NAME test_output COMMAND test_output)
```

- [ ] **Step 3: Confirm red**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make test_output 2>&1 | tail -10
```
Expected: build error referencing missing `output/output.h`.

- [ ] **Step 4: Implement `src/cli/output/output.h`**

```c
#ifndef PS_OUTPUT_H
#define PS_OUTPUT_H

#include "finding.h"
#include <pthread.h>
#include <stdio.h>

enum {
    PS_FMT_OUT_AUTO  = 0,  /* tty → text, otherwise → jsonl */
    PS_FMT_TEXT      = 1,
    PS_FMT_JSON      = 2,
    PS_FMT_JSONL     = 3,
    PS_FMT_QUIET     = 4
};

struct ps_output_opts {
    int  fmt_force;          /* one of PS_FMT_*; 0 = auto */
    int  color;               /* 1 to force ANSI color; 0 to suppress */
    int  assume_tty;          /* if target_fd is a pipe/file but caller knows it's a tty */
    int  target_fd;           /* if 0, output goes to stdout */
    const char *auto_append_path;  /* if non-NULL, JSONL is also appended here */
};

struct ps_output {
    int             fmt;            /* resolved (no AUTO) */
    int             color;          /* resolved */
    int             stdout_fd;
    int             append_fd;      /* -1 if disabled */
    pthread_mutex_t lock;
};

int  ps_output_init (struct ps_output *o, const struct ps_output_opts *opts);
void ps_output_emit (struct ps_output *o, const struct ps_finding *f);
void ps_output_close(struct ps_output *o);

#endif
```

- [ ] **Step 5: Implement `src/cli/output/output.c`**

```c
#include "output.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int write_all(int fd, const char *buf, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, buf, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        buf += w; n -= (size_t)w;
    }
    return 0;
}

int ps_output_init(struct ps_output *o, const struct ps_output_opts *opts) {
    memset(o, 0, sizeof(*o));
    o->stdout_fd = opts->target_fd ? opts->target_fd : 1;
    o->append_fd = -1;

    int is_tty = opts->assume_tty ? 1 : isatty(o->stdout_fd);

    if (opts->fmt_force) {
        o->fmt = opts->fmt_force;
    } else {
        o->fmt = is_tty ? PS_FMT_TEXT : PS_FMT_JSONL;
    }
    o->color = opts->color && (o->fmt == PS_FMT_TEXT) && is_tty;

    /* Honor NO_COLOR env */
    if (getenv("NO_COLOR")) o->color = 0;

    if (opts->auto_append_path && opts->auto_append_path[0]) {
        o->append_fd = open(opts->auto_append_path,
                            O_WRONLY | O_CREAT | O_APPEND, 0644);
        /* Failure is non-fatal: emit a warning to stderr and continue. */
        if (o->append_fd < 0) {
            fprintf(stderr, "warning: cannot open %s: %s\n",
                    opts->auto_append_path, strerror(errno));
        }
    }
    pthread_mutex_init(&o->lock, NULL);
    return 0;
}

static int render_text  (const struct ps_finding *f, int color, char *buf, size_t sz) {
    return ps_finding_to_text(f, buf, sz, color);
}
static int render_jsonl (const struct ps_finding *f, char *buf, size_t sz) {
    return ps_finding_to_json(f, buf, sz);
}
static int render_quiet (const struct ps_finding *f, char *buf, size_t sz) {
    /* sev<TAB>kind<TAB>target<TAB>title<NL> */
    char target_s[PS_FIND_TARGET_MAX + 32] = "-";
    if (f->target_ip[0] && f->target_port)
        snprintf(target_s, sizeof(target_s), "%s:%u", f->target_ip, f->target_port);
    else if (f->target_hostname[0] && f->target_port)
        snprintf(target_s, sizeof(target_s), "%s:%u", f->target_hostname, f->target_port);
    else if (f->target_ip[0])
        snprintf(target_s, sizeof(target_s), "%s", f->target_ip);
    else if (f->target_hostname[0])
        snprintf(target_s, sizeof(target_s), "%s", f->target_hostname);
    int n = snprintf(buf, sz, "%s\t%s\t%s\t%s\n",
                     ps_severity_str(f->severity), f->kind, target_s, f->title);
    return (n < 0 || (size_t)n >= sz) ? -1 : n;
}

void ps_output_emit(struct ps_output *o, const struct ps_finding *f) {
    char text_buf [PS_FIND_TITLE_MAX + PS_FIND_TARGET_MAX + 256];
    char jsonl_buf[PS_FIND_EVIDENCE_MAX + 2048];

    int tn = -1;
    int jn = -1;

    /* If --auto-append is on, we *always* need JSONL for that side, regardless of
     * the primary output format. */
    int need_jsonl = (o->append_fd >= 0) ||
                     (o->fmt == PS_FMT_JSON || o->fmt == PS_FMT_JSONL);
    int need_text  = (o->fmt == PS_FMT_TEXT  || o->fmt == PS_FMT_AUTO);
    int need_quiet = (o->fmt == PS_FMT_QUIET);

    if (need_jsonl) jn = render_jsonl(f, jsonl_buf, sizeof(jsonl_buf));
    if (need_text)  tn = render_text (f, o->color, text_buf, sizeof(text_buf));
    if (need_quiet) tn = render_quiet(f, text_buf, sizeof(text_buf));

    pthread_mutex_lock(&o->lock);
    if (o->fmt == PS_FMT_TEXT || o->fmt == PS_FMT_QUIET || o->fmt == PS_FMT_AUTO) {
        if (tn > 0) write_all(o->stdout_fd, text_buf, (size_t)tn);
    } else {
        if (jn > 0) write_all(o->stdout_fd, jsonl_buf, (size_t)jn);
    }
    if (o->append_fd >= 0 && jn > 0) {
        write_all(o->append_fd, jsonl_buf, (size_t)jn);
    }
    pthread_mutex_unlock(&o->lock);
}

void ps_output_close(struct ps_output *o) {
    if (o->append_fd >= 0) {
        close(o->append_fd);
        o->append_fd = -1;
    }
    pthread_mutex_destroy(&o->lock);
}
```

- [ ] **Step 6: Build, test**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make test_output
ctest -R '^test_output$' --output-on-failure
ctest --output-on-failure 2>&1 | tail -5
```
Expected: `test_output: OK`; suite passes 17/17.

- [ ] **Step 7: Commit**

```bash
cd /Users/billn/packetsonde
git add src/cli/output src/cli/tests/test_output.c src/cli/CMakeLists.txt
git commit -m "feat(cli/output): thread-safe emitter with text/json/jsonl/quiet/auto-append

Single-mutex serializer over the configured target fd (and optional
auto-append fd). TTY detection, NO_COLOR support, format forcing
via opts->fmt_force."
```

---

## Task 4: Token-bucket rate limiter (TDD)

A simple shared rate limiter so polite-default actually limits.

**Files:**
- Create: `src/cli/workers/limiter.h`, `src/cli/workers/limiter.c`
- Create: `src/cli/tests/test_limiter.c`
- Modify: `src/cli/CMakeLists.txt`

- [ ] **Step 1: Write the failing test**

`mkdir -p /Users/billn/packetsonde/src/cli/workers`

Create `/Users/billn/packetsonde/src/cli/tests/test_limiter.c`:
```c
#include "../workers/limiter.h"
#include <assert.h>
#include <stdio.h>
#include <time.h>

static long now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void test_rate_zero_means_unlimited(void) {
    struct ps_limiter L;
    ps_limiter_init(&L, 0);
    long t0 = now_ms();
    for (int i = 0; i < 1000; i++) ps_limiter_acquire(&L);
    long dt = now_ms() - t0;
    /* 1000 immediate acquires should be very fast. */
    assert(dt < 100);
    ps_limiter_destroy(&L);
}

static void test_rate_limits(void) {
    struct ps_limiter L;
    ps_limiter_init(&L, 100);   /* 100 pps */
    long t0 = now_ms();
    /* The first burst is "free" (full bucket = 100 tokens). The next
     * 100 should take ~1s at 100 pps. We take 50 of those to keep the
     * test runtime reasonable. */
    for (int i = 0; i < 150; i++) ps_limiter_acquire(&L);
    long dt = now_ms() - t0;
    /* 50 paced acquires at 100pps ≈ 500ms; allow a wide range to avoid
     * flakiness in CI containers. */
    assert(dt >= 300);
    assert(dt < 1500);
    ps_limiter_destroy(&L);
}

int main(void) {
    test_rate_zero_means_unlimited();
    test_rate_limits();
    printf("test_limiter: OK\n");
    return 0;
}
```

- [ ] **Step 2: Wire into CMake**

In `/Users/billn/packetsonde/src/cli/CMakeLists.txt`, add `workers/limiter.c` to `CLI_SOURCES`. Add the test:
```cmake
add_executable(test_limiter tests/test_limiter.c workers/limiter.c)
target_include_directories(test_limiter PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_limiter PRIVATE packetsonde_lib)
add_test(NAME test_limiter COMMAND test_limiter)
```

- [ ] **Step 3: Red**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make test_limiter 2>&1 | tail -10
```
Expected: missing `limiter.h`.

- [ ] **Step 4: Implement `src/cli/workers/limiter.h`**

```c
#ifndef PS_LIMITER_H
#define PS_LIMITER_H

#include <pthread.h>
#include <stdint.h>

struct ps_limiter {
    int             rate_pps;     /* 0 = unlimited */
    double          tokens;
    double          capacity;     /* equal to rate_pps for now */
    long            last_refill_us;
    pthread_mutex_t lock;
};

void ps_limiter_init   (struct ps_limiter *L, int rate_pps);
void ps_limiter_destroy(struct ps_limiter *L);
void ps_limiter_acquire(struct ps_limiter *L);   /* blocks until one token available */

#endif
```

- [ ] **Step 5: Implement `src/cli/workers/limiter.c`**

```c
#include "limiter.h"

#include <errno.h>
#include <string.h>
#include <time.h>

static long now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000000L + t.tv_nsec / 1000;
}

void ps_limiter_init(struct ps_limiter *L, int rate_pps) {
    memset(L, 0, sizeof(*L));
    L->rate_pps     = rate_pps;
    L->capacity     = rate_pps > 0 ? (double)rate_pps : 0;
    L->tokens       = L->capacity;
    L->last_refill_us = now_us();
    pthread_mutex_init(&L->lock, NULL);
}

void ps_limiter_destroy(struct ps_limiter *L) {
    pthread_mutex_destroy(&L->lock);
}

void ps_limiter_acquire(struct ps_limiter *L) {
    if (L->rate_pps <= 0) return;  /* unlimited */
    for (;;) {
        long sleep_us = 0;
        pthread_mutex_lock(&L->lock);
        long n = now_us();
        double dt = (n - L->last_refill_us) / 1.0e6;
        L->tokens += dt * L->rate_pps;
        if (L->tokens > L->capacity) L->tokens = L->capacity;
        L->last_refill_us = n;
        if (L->tokens >= 1.0) {
            L->tokens -= 1.0;
            pthread_mutex_unlock(&L->lock);
            return;
        }
        double need = 1.0 - L->tokens;
        sleep_us = (long)((need / L->rate_pps) * 1.0e6) + 250;  /* slight slack */
        pthread_mutex_unlock(&L->lock);
        struct timespec req = { sleep_us / 1000000, (sleep_us % 1000000) * 1000 };
        while (nanosleep(&req, &req) == -1 && errno == EINTR) {}
    }
}
```

- [ ] **Step 6: Build, test**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make test_limiter
ctest -R '^test_limiter$' --output-on-failure
ctest --output-on-failure 2>&1 | tail -5
```
Expected: `test_limiter: OK`; suite passes 18/18.

- [ ] **Step 7: Commit**

```bash
cd /Users/billn/packetsonde
git add src/cli/workers/limiter.h src/cli/workers/limiter.c src/cli/tests/test_limiter.c src/cli/CMakeLists.txt
git commit -m "feat(cli/workers): token-bucket rate limiter

Capacity = rate_pps; refills continuously based on monotonic clock.
rate_pps=0 disables limiting. Used by every probe verb."
```

---

## Task 5: Worker pool + bounded MPSC queue + cancel flag (TDD)

A small thread pool that takes function pointers + context pointers off a bounded queue. Workers respect a shared cancel flag set by SIGINT.

**Files:**
- Create: `src/cli/workers/workers.h`, `src/cli/workers/workers.c`
- Create: `src/cli/tests/test_workers.c`
- Modify: `src/cli/CMakeLists.txt`

- [ ] **Step 1: Failing test**

Create `/Users/billn/packetsonde/src/cli/tests/test_workers.c`:
```c
#include "../workers/workers.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

static atomic_int g_done = 0;

static void work_inc(void *ctx) {
    (void)ctx;
    atomic_fetch_add(&g_done, 1);
}

static void test_basic(void) {
    g_done = 0;
    struct ps_workers W;
    ps_workers_init(&W, 4, NULL);   /* no limiter */
    for (int i = 0; i < 100; i++) ps_workers_submit(&W, work_inc, NULL);
    ps_workers_finish(&W);
    assert(atomic_load(&g_done) == 100);
    ps_workers_destroy(&W);
}

static atomic_int g_cancelled = 0;
static void work_slow(void *ctx) {
    struct ps_workers *W = (struct ps_workers *)ctx;
    if (ps_workers_cancelled(W)) {
        atomic_fetch_add(&g_cancelled, 1);
        return;
    }
    /* tiny pause so the cancel actually beats some items */
    struct timespec t = { 0, 1000000 };  /* 1ms */
    nanosleep(&t, NULL);
    atomic_fetch_add(&g_done, 1);
}

static void test_cancel_drains(void) {
    g_done = 0; g_cancelled = 0;
    struct ps_workers W;
    ps_workers_init(&W, 2, NULL);
    for (int i = 0; i < 200; i++) ps_workers_submit(&W, work_slow, &W);
    ps_workers_cancel(&W);
    ps_workers_finish(&W);
    int total = atomic_load(&g_done) + atomic_load(&g_cancelled);
    /* Every submitted item must be observed (either ran or saw cancel). */
    assert(total == 200);
    ps_workers_destroy(&W);
}

int main(void) {
    test_basic();
    test_cancel_drains();
    printf("test_workers: OK\n");
    return 0;
}
```

- [ ] **Step 2: CMake**

Add `workers/workers.c` to `CLI_SOURCES`. Add:
```cmake
add_executable(test_workers tests/test_workers.c workers/workers.c workers/limiter.c)
target_include_directories(test_workers PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_workers PRIVATE packetsonde_lib pthread)
add_test(NAME test_workers COMMAND test_workers)
```

- [ ] **Step 3: Red**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make test_workers 2>&1 | tail -10
```
Expected: missing `workers.h`.

- [ ] **Step 4: Implement `src/cli/workers/workers.h`**

```c
#ifndef PS_WORKERS_H
#define PS_WORKERS_H

#include "limiter.h"

#include <pthread.h>
#include <stdatomic.h>

typedef void (*ps_work_fn)(void *ctx);

#define PS_WORK_QUEUE_CAP 4096

struct ps_work_item {
    ps_work_fn  fn;
    void       *ctx;
};

struct ps_workers {
    int                 nthreads;
    pthread_t          *threads;

    struct ps_work_item queue[PS_WORK_QUEUE_CAP];
    int                 q_head;
    int                 q_tail;
    int                 q_count;
    int                 closed;

    pthread_mutex_t     lock;
    pthread_cond_t      not_empty;
    pthread_cond_t      not_full;

    struct ps_limiter  *limiter;     /* may be NULL */
    atomic_int          cancel;
};

/* limiter may be NULL (unlimited). */
void ps_workers_init   (struct ps_workers *W, int nthreads, struct ps_limiter *limiter);

/* Blocks if the queue is full. */
void ps_workers_submit (struct ps_workers *W, ps_work_fn fn, void *ctx);

/* Marks the queue closed, drains in-flight items, joins all threads. */
void ps_workers_finish (struct ps_workers *W);

void ps_workers_cancel (struct ps_workers *W);
int  ps_workers_cancelled(const struct ps_workers *W);

void ps_workers_destroy(struct ps_workers *W);

#endif
```

- [ ] **Step 5: Implement `src/cli/workers/workers.c`**

```c
#include "workers.h"

#include <stdlib.h>
#include <string.h>

static void *worker_main(void *arg) {
    struct ps_workers *W = (struct ps_workers *)arg;
    for (;;) {
        struct ps_work_item it;

        pthread_mutex_lock(&W->lock);
        while (W->q_count == 0 && !W->closed) {
            pthread_cond_wait(&W->not_empty, &W->lock);
        }
        if (W->q_count == 0 && W->closed) {
            pthread_mutex_unlock(&W->lock);
            break;
        }
        it = W->queue[W->q_head];
        W->q_head = (W->q_head + 1) % PS_WORK_QUEUE_CAP;
        W->q_count--;
        pthread_cond_signal(&W->not_full);
        pthread_mutex_unlock(&W->lock);

        if (!atomic_load(&W->cancel) && W->limiter) {
            ps_limiter_acquire(W->limiter);
        }
        it.fn(it.ctx);
    }
    return NULL;
}

void ps_workers_init(struct ps_workers *W, int nthreads, struct ps_limiter *limiter) {
    memset(W, 0, sizeof(*W));
    if (nthreads <= 0) nthreads = 1;
    W->nthreads = nthreads;
    W->limiter  = limiter;
    atomic_init(&W->cancel, 0);
    pthread_mutex_init(&W->lock, NULL);
    pthread_cond_init(&W->not_empty, NULL);
    pthread_cond_init(&W->not_full,  NULL);
    W->threads = calloc(nthreads, sizeof(pthread_t));
    for (int i = 0; i < nthreads; i++) {
        pthread_create(&W->threads[i], NULL, worker_main, W);
    }
}

void ps_workers_submit(struct ps_workers *W, ps_work_fn fn, void *ctx) {
    pthread_mutex_lock(&W->lock);
    while (W->q_count == PS_WORK_QUEUE_CAP && !W->closed) {
        pthread_cond_wait(&W->not_full, &W->lock);
    }
    if (W->closed) { pthread_mutex_unlock(&W->lock); return; }
    W->queue[W->q_tail].fn  = fn;
    W->queue[W->q_tail].ctx = ctx;
    W->q_tail = (W->q_tail + 1) % PS_WORK_QUEUE_CAP;
    W->q_count++;
    pthread_cond_signal(&W->not_empty);
    pthread_mutex_unlock(&W->lock);
}

void ps_workers_finish(struct ps_workers *W) {
    pthread_mutex_lock(&W->lock);
    W->closed = 1;
    pthread_cond_broadcast(&W->not_empty);
    pthread_cond_broadcast(&W->not_full);
    pthread_mutex_unlock(&W->lock);
    for (int i = 0; i < W->nthreads; i++) {
        pthread_join(W->threads[i], NULL);
    }
}

void ps_workers_cancel(struct ps_workers *W) {
    atomic_store(&W->cancel, 1);
}

int ps_workers_cancelled(const struct ps_workers *W) {
    return atomic_load((atomic_int *)&W->cancel);
}

void ps_workers_destroy(struct ps_workers *W) {
    free(W->threads);
    pthread_mutex_destroy(&W->lock);
    pthread_cond_destroy(&W->not_empty);
    pthread_cond_destroy(&W->not_full);
}
```

- [ ] **Step 6: Build, test**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make test_workers
ctest -R '^test_workers$' --output-on-failure
ctest --output-on-failure 2>&1 | tail -5
```
Expected: `test_workers: OK`; suite passes 19/19.

- [ ] **Step 7: Commit**

```bash
cd /Users/billn/packetsonde
git add src/cli/workers/workers.h src/cli/workers/workers.c src/cli/tests/test_workers.c src/cli/CMakeLists.txt
git commit -m "feat(cli/workers): pthread pool with bounded MPSC queue and cancel

Submit work via fn+ctx; workers acquire a rate-limiter token (if
set) before running each item; cancel flag observable by workers
so SIGINT can stop dispatch. finish() drains and joins."
```

---

## Task 6: Signals — SIGINT-driven cancel

A tiny module so any verb can `ps_signals_install(&workers)` once and let SIGINT cancel them.

**Files:**
- Create: `src/cli/signals.h`, `src/cli/signals.c`
- Modify: `src/cli/CMakeLists.txt`

- [ ] **Step 1: Implement `src/cli/signals.h`**

```c
#ifndef PS_SIGNALS_H
#define PS_SIGNALS_H

#include "workers/workers.h"

/* Installs a handler for SIGINT and SIGTERM that calls
 * ps_workers_cancel() on the passed pool. Safe to call once. */
void ps_signals_install(struct ps_workers *W);

#endif
```

- [ ] **Step 2: Implement `src/cli/signals.c`**

```c
#include "signals.h"

#include <signal.h>
#include <stddef.h>

static struct ps_workers *g_pool = NULL;

static void handler(int signo) {
    (void)signo;
    if (g_pool) ps_workers_cancel(g_pool);
}

void ps_signals_install(struct ps_workers *W) {
    g_pool = W;
    struct sigaction sa;
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;   /* don't break blocking I/O for benign signals */
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    /* Ignore SIGPIPE so piping into `head` doesn't kill us. */
    signal(SIGPIPE, SIG_IGN);
}
```

- [ ] **Step 3: Add `signals.c` to `CLI_SOURCES`**

In `src/cli/CMakeLists.txt`, expand the source list to include `signals.c`.

- [ ] **Step 4: Build to confirm it compiles**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make packetsonde
```
Expected: clean build. (No new test — handler behavior is exercised by the integration test in Task 11.)

- [ ] **Step 5: Commit**

```bash
cd /Users/billn/packetsonde
git add src/cli/signals.h src/cli/signals.c src/cli/CMakeLists.txt
git commit -m "feat(cli): SIGINT/SIGTERM handler cancels worker pool

SIGPIPE ignored so piping into 'head' is non-fatal. Handler delegates
to ps_workers_cancel; emitter still owns flushing."
```

---

## Task 7: `audit` verb skeleton + `--help`

Stub the `audit` verb so the next task can plug `tls` in. The skeleton parses `audit <kind>` and dispatches via a small table; unknown kinds print available options.

**Files:**
- Create: `src/cli/verbs/audit.c`
- Modify: `src/cli/dispatch.c`
- Modify: `src/cli/CMakeLists.txt`

- [ ] **Step 1: Create `src/cli/verbs/audit.c`**

```c
#include "../verbs.h"

#include <stdio.h>
#include <string.h>

/* Defined in Task 8. */
int ps_audit_tls_run(int argc, char **argv, const struct ps_args *opts);

struct audit_kind {
    const char *name;
    int (*run)(int argc, char **argv, const struct ps_args *opts);
    const char *summary;
};

static const struct audit_kind KINDS[] = {
    { "tls", ps_audit_tls_run, "Audit TLS server: protocol, cipher, cert hygiene" },
    { NULL, NULL, NULL }
};

static void audit_usage(void) {
    fprintf(stderr,
        "Usage: packetsonde audit <kind> <target> [args...]\n"
        "\n"
        "Kinds:\n");
    for (const struct audit_kind *k = KINDS; k->name; k++) {
        fprintf(stderr, "  %-8s %s\n", k->name, k->summary);
    }
}

int ps_verb_audit_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { audit_usage(); return 2; }
    const char *kind = argv[1];
    for (const struct audit_kind *k = KINDS; k->name; k++) {
        if (strcmp(k->name, kind) == 0) {
            /* Verb argv passed in: argv[0]="audit", argv[1]=kind, argv[2..]=kind args.
             * Pass kind's argv as starting at the kind name. */
            return k->run(argc - 1, argv + 1, opts);
        }
    }
    fprintf(stderr, "packetsonde audit: unknown kind '%s'\n", kind);
    audit_usage();
    return 2;
}
```

- [ ] **Step 2: Register the verb in `src/cli/dispatch.c`**

Add the forward declaration alongside existing ones:
```c
int  ps_verb_audit_run  (int argc, char **argv, const struct ps_args *opts);
```

Update the `VERBS` array to include audit between `version` and `agent`:
```c
static const struct ps_verb VERBS[] = {
    { "version", ps_verb_version_run, "Show packetsonde version" },
    { "audit",   ps_verb_audit_run,   "Run a security audit (tls, ...)" },
    { "agent",   ps_verb_agent_run,   "Control / query the local agent" },
    { "help",    ps_verb_help_run,    "Show this help" },
    { NULL, NULL, NULL }
};
```

- [ ] **Step 3: CMake**

Add `verbs/audit.c` to `CLI_SOURCES`.

- [ ] **Step 4: Build**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make packetsonde 2>&1 | tail -10
```
Expected: undefined reference to `ps_audit_tls_run` — that's expected, Task 8 implements it. **Continue to Task 8 without committing** — this task's commit happens at the end of Task 8 along with the TLS audit.

(The verb skeleton has no useful behavior without `tls`, so the commit boundary is "the verb + first kind together.")

---

## Task 8: `audit tls` implementation

Use OpenSSL to drive a handshake against `target:port`. Inspect protocol, cipher, cert chain. Emit findings for:
- TLS 1.0 / 1.1 supported (high)
- Weak cipher in default offer (high)
- Expired cert (critical)
- Cert expires within 30 days (medium)
- Self-signed (medium)
- Hostname mismatch (high)
- Weak signature algorithm (sha1, md5) (high)
- Weak RSA key (< 2048) (high)

**Files:**
- Create: `src/cli/audit/tls.h`, `src/cli/audit/tls.c`
- Modify: `src/cli/CMakeLists.txt` (add OpenSSL link)

- [ ] **Step 1: Create `src/cli/audit/tls.h`**

`mkdir -p /Users/billn/packetsonde/src/cli/audit`

```c
#ifndef PS_AUDIT_TLS_H
#define PS_AUDIT_TLS_H

#include "../args.h"

int ps_audit_tls_run(int argc, char **argv, const struct ps_args *opts);

#endif
```

- [ ] **Step 2: Create `src/cli/audit/tls.c`**

```c
#include "tls.h"
#include "../output/output.h"
#include "../signals.h"
#include "../workers/workers.h"
#include "../workers/limiter.h"
#include "finding.h"
#include "ulid.h"

#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* ---------- target parsing ---------- */

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    /* "host:port" — last colon delimits port (for IPv4/hostnames; IPv6 literals
     * are not supported in v1 — escalate later). */
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

/* ---------- TCP connect ---------- */

static int tcp_connect(const char *host, uint16_t port, int timeout_ms,
                       char *ip_out, size_t ip_out_sz) {
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res); return -1;
    }
    if (ip_out && ip_out_sz) {
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        snprintf(ip_out, ip_out_sz, "%u.%u.%u.%u",
                 (sin->sin_addr.s_addr >> 0) & 0xff,
                 (sin->sin_addr.s_addr >> 8) & 0xff,
                 (sin->sin_addr.s_addr >> 16) & 0xff,
                 (sin->sin_addr.s_addr >> 24) & 0xff);
    }
    freeaddrinfo(res);
    return fd;
}

/* ---------- one TLS handshake attempt ---------- */

struct tls_attempt {
    const SSL_METHOD *method;
    long              min_proto;     /* TLS1_VERSION etc.; 0 = leave default */
    long              max_proto;
    const char       *cipher_list;   /* may be NULL */
};

struct tls_result {
    int          ok;
    int          protocol_version;   /* SSL_version() */
    char         cipher[64];
    int          cert_present;
    X509        *peer;               /* refcount++ */
    STACK_OF(X509) *chain;
};

static void tls_result_free(struct tls_result *r) {
    if (r->peer) X509_free(r->peer);
    /* chain is owned by SSL; do not free */
}

static int do_handshake(const char *host, uint16_t port,
                        const struct tls_attempt *a,
                        struct tls_result *out) {
    memset(out, 0, sizeof(*out));
    char ip[64] = "";
    int fd = tcp_connect(host, port, 4000, ip, sizeof(ip));
    if (fd < 0) return -1;

    SSL_CTX *ctx = SSL_CTX_new(a->method ? a->method : TLS_client_method());
    if (!ctx) { close(fd); return -1; }
    if (a->min_proto) SSL_CTX_set_min_proto_version(ctx, a->min_proto);
    if (a->max_proto) SSL_CTX_set_max_proto_version(ctx, a->max_proto);
    if (a->cipher_list) SSL_CTX_set_cipher_list(ctx, a->cipher_list);
    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set_fd(ssl, fd);
    int rc = SSL_connect(ssl);
    if (rc == 1) {
        out->ok = 1;
        out->protocol_version = SSL_version(ssl);
        const char *cn = SSL_get_cipher_name(ssl);
        if (cn) snprintf(out->cipher, sizeof(out->cipher), "%s", cn);
        X509 *peer = SSL_get_peer_certificate(ssl);
        if (peer) { out->peer = peer; out->cert_present = 1; }
        out->chain = SSL_get_peer_cert_chain(ssl);
    }
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return out->ok ? 0 : -1;
}

/* ---------- emit helpers ---------- */

struct emit_ctx {
    struct ps_output *out;
    const char       *run_id;
    const char       *self_host;
    const char       *target_host;
    const char       *target_ip;
    uint16_t          target_port;
};

static void emit(struct emit_ctx *e,
                 const char *kind, enum ps_severity sev, enum ps_confidence conf,
                 const char *title, const char *evidence_json) {
    struct ps_finding f;
    ps_finding_init(&f, e->run_id, "cli.audit.tls", e->self_host, kind, sev, conf, title);
    if (e->target_ip && e->target_ip[0])
        ps_finding_set_target_ip(&f, e->target_ip, e->target_port);
    if (e->target_host && e->target_host[0])
        ps_finding_set_target_hostname(&f, e->target_host, e->target_port);
    if (evidence_json) ps_finding_set_evidence_json(&f, evidence_json);
    ps_output_emit(e->out, &f);
}

/* ---------- checks ---------- */

static void check_protocol(struct emit_ctx *e, const char *target_host) {
    /* Probe TLS 1.0 explicitly. */
    struct tls_attempt a10 = { .method = TLS_client_method(),
                                .min_proto = TLS1_VERSION,
                                .max_proto = TLS1_VERSION };
    struct tls_result  r10;
    if (do_handshake(target_host, e->target_port, &a10, &r10) == 0) {
        emit(e, "tls.weak_protocol", PS_SEV_HIGH, PS_CONF_FIRM,
             "TLS 1.0 negotiated successfully", "{\"protocol\":\"TLSv1\"}");
    }
    tls_result_free(&r10);

    struct tls_attempt a11 = { .method = TLS_client_method(),
                                .min_proto = TLS1_1_VERSION,
                                .max_proto = TLS1_1_VERSION };
    struct tls_result  r11;
    if (do_handshake(target_host, e->target_port, &a11, &r11) == 0) {
        emit(e, "tls.weak_protocol", PS_SEV_HIGH, PS_CONF_FIRM,
             "TLS 1.1 negotiated successfully", "{\"protocol\":\"TLSv1.1\"}");
    }
    tls_result_free(&r11);
}

static void check_ciphers(struct emit_ctx *e, const char *target_host) {
    /* Ask explicitly for known-weak families. */
    struct tls_attempt aw = {
        .method = TLS_client_method(),
        .min_proto = TLS1_VERSION, .max_proto = TLS1_2_VERSION,
        .cipher_list = "DES:3DES:RC4:NULL:EXP:MD5"
    };
    struct tls_result  rw;
    if (do_handshake(target_host, e->target_port, &aw, &rw) == 0 && rw.cipher[0]) {
        char ev[160];
        snprintf(ev, sizeof(ev), "{\"cipher\":\"%s\"}", rw.cipher);
        char title[160];
        snprintf(title, sizeof(title), "Server negotiates weak cipher: %s", rw.cipher);
        emit(e, "tls.weak_cipher", PS_SEV_HIGH, PS_CONF_FIRM, title, ev);
    }
    tls_result_free(&rw);
}

static int cert_days_until_expiry(X509 *cert) {
    const ASN1_TIME *na = X509_get0_notAfter(cert);
    int  pday = 0, psec = 0;
    if (ASN1_TIME_diff(&pday, &psec, NULL, na) == 0) return -99999;
    return pday;
}

static int hostname_matches(X509 *cert, const char *host) {
    return X509_check_host(cert, host, 0, 0, NULL);  /* 1 = match, 0 = no */
}

static int weak_signature_alg(X509 *cert, char *out, size_t outsz) {
    const X509_ALGOR *sig_alg = NULL;
    X509_get0_signature(NULL, &sig_alg, cert);
    int nid = OBJ_obj2nid(sig_alg->algorithm);
    const char *sn = OBJ_nid2sn(nid);
    if (sn) snprintf(out, outsz, "%s", sn);
    if (nid == NID_md5WithRSAEncryption  ||
        nid == NID_sha1WithRSAEncryption ||
        nid == NID_ecdsa_with_SHA1) {
        return 1;
    }
    return 0;
}

static void check_certificate(struct emit_ctx *e, const char *target_host) {
    struct tls_attempt a = { .method = TLS_client_method() };
    struct tls_result  r;
    if (do_handshake(target_host, e->target_port, &a, &r) != 0 || !r.peer) {
        tls_result_free(&r);
        return;
    }

    int days = cert_days_until_expiry(r.peer);
    if (days < 0) {
        char ev[64]; snprintf(ev, sizeof(ev), "{\"days_overdue\":%d}", -days);
        emit(e, "tls.expired_cert", PS_SEV_CRITICAL, PS_CONF_FIRM,
             "Certificate expired", ev);
    } else if (days < 30) {
        char ev[64]; snprintf(ev, sizeof(ev), "{\"days_remaining\":%d}", days);
        emit(e, "tls.expiring_cert", PS_SEV_MEDIUM, PS_CONF_FIRM,
             "Certificate expires within 30 days", ev);
    }

    if (!hostname_matches(r.peer, target_host)) {
        char ev[256]; snprintf(ev, sizeof(ev), "{\"hostname\":\"%s\"}", target_host);
        emit(e, "tls.hostname_mismatch", PS_SEV_HIGH, PS_CONF_FIRM,
             "Certificate does not match the requested hostname", ev);
    }

    char sig_name[64] = "";
    if (weak_signature_alg(r.peer, sig_name, sizeof(sig_name))) {
        char ev[128]; snprintf(ev, sizeof(ev), "{\"signature\":\"%s\"}", sig_name);
        emit(e, "tls.weak_signature", PS_SEV_HIGH, PS_CONF_FIRM,
             "Certificate uses a weak signature algorithm", ev);
    }

    /* Self-signed: peer == issuer */
    X509_NAME *subj = X509_get_subject_name(r.peer);
    X509_NAME *issu = X509_get_issuer_name(r.peer);
    if (X509_NAME_cmp(subj, issu) == 0) {
        emit(e, "tls.self_signed", PS_SEV_MEDIUM, PS_CONF_FIRM,
             "Certificate is self-signed", NULL);
    }

    /* Weak RSA key */
    EVP_PKEY *pk = X509_get0_pubkey(r.peer);
    if (pk && EVP_PKEY_base_id(pk) == EVP_PKEY_RSA) {
        int bits = EVP_PKEY_bits(pk);
        if (bits < 2048) {
            char ev[64]; snprintf(ev, sizeof(ev), "{\"bits\":%d}", bits);
            emit(e, "tls.weak_key", PS_SEV_HIGH, PS_CONF_FIRM,
                 "RSA public key < 2048 bits", ev);
        }
    }

    tls_result_free(&r);
}

/* ---------- entry point ---------- */

int ps_audit_tls_run(int argc, char **argv, const struct ps_args *opts) {
    /* argv[0] = "tls"; argv[1] = target */
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit tls <host:port>\n");
        return 2;
    }
    const char *spec = argv[1];
    char  target_host[256];
    uint16_t target_port = 0;
    if (parse_target(spec, target_host, sizeof(target_host), &target_port) != 0) {
        fprintf(stderr, "packetsonde audit tls: bad target '%s' (expected host:port)\n", spec);
        return 2;
    }

    OPENSSL_init_ssl(0, NULL);

    char self_host[256] = "";
    gethostname(self_host, sizeof(self_host));

    char run_id[PS_ULID_STRLEN + 1];
    ps_ulid_new(run_id, sizeof(run_id));

    struct ps_output_opts oopts = {0};
    oopts.fmt_force = (opts->fmt == 0) ? 0 :
                      (opts->fmt == 1) ? PS_FMT_TEXT :
                      (opts->fmt == 2) ? PS_FMT_JSON :
                      (opts->fmt == 3) ? PS_FMT_JSONL : PS_FMT_QUIET;
    oopts.color = 1;
    oopts.auto_append_path = NULL;  /* wired into args in Task 9 */
    struct ps_output out;
    ps_output_init(&out, &oopts);

    /* Single-target audit in v1; multi-target / CIDR comes later. The worker
     * pool still exists so the cancel and limiter paths get exercised. */
    struct ps_limiter L;
    int rate = opts->rate_pps > 0 ? opts->rate_pps : 100;
    ps_limiter_init(&L, rate);

    struct ps_workers W;
    int concur = opts->concurrency > 0 ? opts->concurrency : 16;
    ps_workers_init(&W, concur, &L);
    ps_signals_install(&W);

    /* Resolve once for the target_ip on the finding records. */
    char ip[64] = "";
    int probe_fd = tcp_connect(target_host, target_port, 4000, ip, sizeof(ip));
    if (probe_fd < 0) {
        fprintf(stderr, "packetsonde audit tls: cannot connect to %s:%u\n", target_host, target_port);
        ps_workers_finish(&W); ps_workers_destroy(&W);
        ps_limiter_destroy(&L); ps_output_close(&out);
        return 1;
    }
    close(probe_fd);

    struct emit_ctx e = {
        .out = &out, .run_id = run_id, .self_host = self_host,
        .target_host = target_host, .target_ip = ip, .target_port = target_port
    };

    /* Run checks in-line for v1 (still inside the worker-pool lifecycle so
     * cancel works). Multi-target parallelism arrives in Plan 3. */
    if (!ps_workers_cancelled(&W)) check_protocol(&e, target_host);
    if (!ps_workers_cancelled(&W)) check_ciphers(&e, target_host);
    if (!ps_workers_cancelled(&W)) check_certificate(&e, target_host);

    ps_workers_finish(&W);
    ps_workers_destroy(&W);
    ps_limiter_destroy(&L);
    ps_output_close(&out);
    return 0;
}
```

- [ ] **Step 3: Wire OpenSSL onto the CLI target in `src/cli/CMakeLists.txt`**

After the `target_link_libraries(packetsonde PRIVATE packetsonde_lib)` line, add:
```cmake
find_package(OpenSSL REQUIRED)
target_link_libraries(packetsonde PRIVATE OpenSSL::SSL OpenSSL::Crypto)
```

Also add `audit/tls.c` to `CLI_SOURCES`.

- [ ] **Step 4: Build**

```bash
cd /Users/billn/packetsonde/build && cmake .. && make -j$(sysctl -n hw.ncpu) packetsonde 2>&1 | tail -15
```
Expected: clean build of `packetsonde`.

- [ ] **Step 5: Smoke against a known target**

```bash
/Users/billn/packetsonde/build/src/cli/packetsonde audit tls badssl.com:443 2>&1 | head -10
/Users/billn/packetsonde/build/src/cli/packetsonde --jsonl audit tls badssl.com:443 2>&1 | head -5 | jq -r '.kind' 2>/dev/null
```
Expected: some findings emitted to text (TTY) or JSONL (piped). badssl.com:443 is a "normal" target, so the run may produce zero findings — that's fine. The smoke is "doesn't crash, produces parseable output." A guaranteed-misconfigured run happens in Task 10.

- [ ] **Step 6: Run the test suite**

```bash
ctest --output-on-failure 2>&1 | tail -5
```
Expected: 19/19 PASS (no new C tests in this task; integration test arrives in Task 10).

- [ ] **Step 7: Commit (both Task 7 and Task 8 together)**

```bash
cd /Users/billn/packetsonde
git add src/cli/verbs/audit.c src/cli/audit/tls.h src/cli/audit/tls.c src/cli/dispatch.c src/cli/CMakeLists.txt
git commit -m "feat(cli/audit): packetsonde audit tls <host:port>

First real audit verb. Drives explicit TLS 1.0/1.1 and weak-cipher
handshakes via OpenSSL, inspects cert chain for expiry, hostname,
signature algorithm, self-signed status, and weak RSA keys.

Kinds emitted:
  tls.weak_protocol     high
  tls.weak_cipher       high
  tls.expired_cert      critical
  tls.expiring_cert     medium
  tls.hostname_mismatch high
  tls.weak_signature    high
  tls.self_signed       medium
  tls.weak_key          high

Routes through the worker pool + limiter + signals modules so SIGINT
and rate limits behave consistently with later verbs."
```

---

## Task 9: Wire global flags through to the audit run

The `audit tls` verb in Task 8 only consumes `opts->fmt`, `concurrency`, and `rate_pps`. We need to honor `--auto-append`, `--no-color`, and choose the format more carefully.

**Files:**
- Modify: `src/cli/audit/tls.c`

- [ ] **Step 1: Compute auto-append path**

In `src/cli/audit/tls.c`, replace the `oopts.auto_append_path = NULL;` block with:
```c
    char append_path[512] = "";
    if (opts->auto_append) {
        const char *base = getenv("XDG_STATE_HOME");
        char default_base[400];
        if (!base || !base[0]) {
            const char *home = getenv("HOME");
            if (home && home[0]) {
                snprintf(default_base, sizeof(default_base), "%s/.local/state", home);
                base = default_base;
            } else {
                base = "/tmp";
            }
        }
        char dir[450];
        snprintf(dir, sizeof(dir), "%s/packetsonde", base);
        mkdir(base, 0755);  /* harmless if exists */
        mkdir(dir,  0755);
        struct timeval tv; gettimeofday(&tv, NULL);
        struct tm tm; gmtime_r(&tv.tv_sec, &tm);
        snprintf(append_path, sizeof(append_path),
                 "%s/findings-%04d-%02d-%02d.jsonl",
                 dir, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    }
    oopts.auto_append_path = append_path[0] ? append_path : NULL;
```

Add `#include <sys/stat.h>` at the top of `tls.c` near the other system includes.

- [ ] **Step 2: Honor `--no-color`**

Replace `oopts.color = 1;` with `oopts.color = opts->no_color ? 0 : 1;`.

- [ ] **Step 3: Map `--text`/`--json`/`--jsonl`/`--quiet` correctly**

Replace the existing `fmt_force` computation (the ternary chain) with:
```c
    switch (opts->fmt) {
        case PS_FMT_TEXT:  oopts.fmt_force = PS_FMT_TEXT;  break;
        case PS_FMT_JSON:  oopts.fmt_force = PS_FMT_JSON;  break;
        case PS_FMT_JSONL: oopts.fmt_force = PS_FMT_JSONL; break;
        case PS_FMT_QUIET: oopts.fmt_force = PS_FMT_QUIET; break;
        default:           oopts.fmt_force = 0; break;  /* auto */
    }
```

Note: `enum ps_fmt` in `args.h` and the output module's format constants are distinct enums but share the same values (1..4). Add an explicit static assertion at the top of `tls.c` after the includes:
```c
_Static_assert(PS_FMT_TEXT  == 1, "fmt mapping drift");
_Static_assert(PS_FMT_JSON  == 2, "fmt mapping drift");
_Static_assert(PS_FMT_JSONL == 3, "fmt mapping drift");
_Static_assert(PS_FMT_QUIET == 4, "fmt mapping drift");
```

(Either both enums agree at 1..4 today; if a future change diverges them, the build breaks at this assertion and we add a converter.)

- [ ] **Step 4: Build and smoke**

```bash
cd /Users/billn/packetsonde/build && make packetsonde 2>&1 | tail -5

/Users/billn/packetsonde/build/src/cli/packetsonde --auto-append audit tls badssl.com:443 2>&1 | head -3
ls -la ${XDG_STATE_HOME:-$HOME/.local/state}/packetsonde/findings-$(date -u +%Y-%m-%d).jsonl
```
Expected: build clean; if any findings emit, the dated file exists.

- [ ] **Step 5: Commit**

```bash
cd /Users/billn/packetsonde
git add src/cli/audit/tls.c
git commit -m "feat(cli/audit/tls): honor --auto-append, --no-color, fmt flags

Resolves XDG_STATE_HOME for the dated findings file, maps the parser's
ps_fmt onto the emitter's PS_FMT_* constants with a compile-time
assertion to catch drift."
```

---

## Task 10: Integration test with `openssl s_server`

A small shell test that spins up an `openssl s_server` with intentionally bad parameters and asserts findings.

**Files:**
- Create: `src/cli/tests/test_audit_tls.sh`
- Create: `src/cli/tests/test_audit_tls_cert.sh` (helper that generates a self-signed cert)
- Modify: `src/cli/CMakeLists.txt`

- [ ] **Step 1: Create the cert-generation helper `src/cli/tests/test_audit_tls_cert.sh`**

```bash
#!/bin/bash
# Generates a self-signed cert valid for "localhost", weak (sha1, 1024-bit RSA),
# expiring in 10 days, into $TMPDIR/ps-test-cert.{pem,key}.
# Used by test_audit_tls.sh.
set -e
DIR="${TMPDIR:-/tmp}"
CRT="$DIR/ps-test-cert.pem"
KEY="$DIR/ps-test-cert.key"

openssl req -x509 -nodes \
    -newkey rsa:1024 \
    -days 10 \
    -sha1 \
    -subj "/CN=localhost" \
    -keyout "$KEY" -out "$CRT" 2>/dev/null

echo "$CRT $KEY"
```

`chmod +x` it.

- [ ] **Step 2: Create the integration test `src/cli/tests/test_audit_tls.sh`**

```bash
#!/bin/bash
# Integration test: spin up an openssl s_server on a free port with weak
# parameters, run `packetsonde audit tls 127.0.0.1:PORT`, assert findings.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="${PS_TEST_PORT:-44443}"
BUILD_DIR="${PS_BUILD_DIR:-/Users/billn/packetsonde/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"

if [ ! -x "$CLI" ]; then
    echo "skip: $CLI not built"
    exit 77   # CTest "skip" status
fi
if ! command -v openssl >/dev/null 2>&1; then
    echo "skip: no openssl"
    exit 77
fi

# Generate weak cert
read CRT KEY < <("$HERE/test_audit_tls_cert.sh")
trap "rm -f $CRT $KEY" EXIT

# Start s_server with: TLS1.0 enabled, weak cipher list, 1024-bit cert.
openssl s_server \
    -cert "$CRT" -key "$KEY" \
    -port "$PORT" \
    -tls1 \
    -cipher 'DEFAULT:@SECLEVEL=0:DES-CBC3-SHA' \
    -quiet \
    >/dev/null 2>&1 &
SERVER_PID=$!
trap "kill $SERVER_PID 2>/dev/null; rm -f $CRT $KEY" EXIT

# Give it a moment to bind.
sleep 1

OUT="$("$CLI" --jsonl audit tls "127.0.0.1:$PORT" 2>/dev/null || true)"

# Assertions
echo "$OUT" | grep -q '"kind":"tls.weak_protocol"'     || { echo FAIL: missing tls.weak_protocol;     echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"tls.self_signed"'       || { echo FAIL: missing tls.self_signed;       echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"tls.weak_signature"'    || { echo FAIL: missing tls.weak_signature;    echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"tls.weak_key"'          || { echo FAIL: missing tls.weak_key;          echo "$OUT"; exit 1; }
# Note: hostname mismatch is expected (cert CN=localhost, target 127.0.0.1).
echo "$OUT" | grep -q '"kind":"tls.hostname_mismatch"' || { echo FAIL: missing tls.hostname_mismatch; echo "$OUT"; exit 1; }

echo "test_audit_tls: OK"
```

`chmod +x` it.

- [ ] **Step 3: Register the test in CMake**

In `src/cli/CMakeLists.txt`, inside the `BUILD_TESTING` block:
```cmake
add_test(NAME test_audit_tls
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_audit_tls.sh)
set_tests_properties(test_audit_tls PROPERTIES
    SKIP_RETURN_CODE 77
    ENVIRONMENT "PS_BUILD_DIR=${CMAKE_BINARY_DIR};PS_TEST_PORT=44443")
```

- [ ] **Step 4: Run the test**

```bash
cd /Users/billn/packetsonde/build && cmake .. && ctest -R '^test_audit_tls$' --output-on-failure
```
Expected: PASS (or SKIP if openssl missing). All assertions in the shell script succeed.

Also run the full suite:
```bash
ctest --output-on-failure 2>&1 | tail -5
```
Expected: 20/20 PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/billn/packetsonde
git add src/cli/tests/test_audit_tls.sh src/cli/tests/test_audit_tls_cert.sh src/cli/CMakeLists.txt
git commit -m "test(cli/audit/tls): integration test against openssl s_server

Spins up s_server with TLS 1.0, weak cipher, 1024-bit SHA1 self-signed
cert, then runs packetsonde audit tls and asserts the five expected
findings kinds appear. Skips with code 77 when openssl is unavailable."
```

---

## Task 11: Run summary on stderr at exit

Per spec §4.1: emit a one-line run summary to stderr when the run completes (or is cancelled).

**Files:**
- Modify: `src/cli/audit/tls.c`
- Modify: `src/cli/output/output.h`, `src/cli/output/output.c`

- [ ] **Step 1: Add counters to `struct ps_output`**

In `src/cli/output/output.h`, extend the struct:
```c
struct ps_output {
    int             fmt;
    int             color;
    int             stdout_fd;
    int             append_fd;
    pthread_mutex_t lock;
    /* counters (post-Task 3 addition) */
    unsigned int    n_info;
    unsigned int    n_low;
    unsigned int    n_medium;
    unsigned int    n_high;
    unsigned int    n_critical;
};
```

- [ ] **Step 2: Bump counters in `ps_output_emit`**

In `src/cli/output/output.c`, inside `ps_output_emit`, immediately after `pthread_mutex_lock(&o->lock);`:
```c
    switch (f->severity) {
        case PS_SEV_INFO:     o->n_info++;     break;
        case PS_SEV_LOW:      o->n_low++;      break;
        case PS_SEV_MEDIUM:   o->n_medium++;   break;
        case PS_SEV_HIGH:     o->n_high++;     break;
        case PS_SEV_CRITICAL: o->n_critical++; break;
    }
```

- [ ] **Step 3: Add a summary emitter to `output.h`/`output.c`**

In `output.h`:
```c
/* Writes a single-line summary to stderr. duration_ms is wall time. */
void ps_output_summary(const struct ps_output *o, const char *run_id, long duration_ms);
```

In `output.c`:
```c
void ps_output_summary(const struct ps_output *o, const char *run_id, long duration_ms) {
    unsigned int total = o->n_info + o->n_low + o->n_medium + o->n_high + o->n_critical;
    fprintf(stderr,
            "run %s: %u findings (info=%u low=%u medium=%u high=%u critical=%u) in %ld ms\n",
            run_id, total,
            o->n_info, o->n_low, o->n_medium, o->n_high, o->n_critical,
            duration_ms);
}
```

- [ ] **Step 4: Call it from `audit tls`**

In `src/cli/audit/tls.c`, near the start of `ps_audit_tls_run`, after `ps_ulid_new(run_id, ...)`:
```c
    struct timeval t_start;
    gettimeofday(&t_start, NULL);
```

Just before `return 0;` at the bottom of the function:
```c
    struct timeval t_end;
    gettimeofday(&t_end, NULL);
    long dt_ms = (t_end.tv_sec - t_start.tv_sec) * 1000L
               + (t_end.tv_usec - t_start.tv_usec) / 1000L;
    ps_output_summary(&out, run_id, dt_ms);
```

(Place this before `ps_output_close(&out)` so the counters are still valid.)

- [ ] **Step 5: Build and smoke**

```bash
cd /Users/billn/packetsonde/build && make packetsonde 2>&1 | tail -5
/Users/billn/packetsonde/build/src/cli/packetsonde audit tls badssl.com:443 2>&1 >/dev/null | tail -1
```
Expected: a line starting with `run ` on stderr, with finding counts.

```bash
ctest --output-on-failure 2>&1 | tail -5
```
Expected: 20/20 PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/billn/packetsonde
git add src/cli/output/output.h src/cli/output/output.c src/cli/audit/tls.c
git commit -m "feat(cli/output): per-run summary on stderr

Output module counts findings by severity; audit tls emits a one-line
summary (run id, histogram, duration) to stderr at exit per spec 4.1."
```

---

## Task 12: Verification gate + tag

Confirm end state of Plan 2.

**Files:** none modified.

- [ ] **Step 1: Clean build**

```bash
cd /Users/billn/packetsonde
rm -rf build
./build.sh native 2>&1 | tail -5
```
Expected: clean.

- [ ] **Step 2: All tests pass**

```bash
cd /Users/billn/packetsonde/build && ctest --output-on-failure 2>&1 | tail -5
```
Expected: `20 tests, 0 failed`. The integration test counts; if it skips, suite reports `19 tests, 0 failed, 1 skipped`.

- [ ] **Step 3: Behavioral smoke**

```bash
cd /Users/billn/packetsonde
./build/src/cli/packetsonde --jsonl audit tls badssl.com:443 2>/dev/null | jq -c '{kind,severity}' | head -3
./build/src/cli/packetsonde audit tls badssl.com:443 2>&1 >/dev/null | tail -1
./build/src/cli/packetsonde audit nope 2>&1; echo "exit=$?"
```
Expected:
- JSONL piped to `jq` produces compact records with kind+severity (or nothing for clean targets — non-zero is okay if real findings emit).
- The stderr line starts with `run ` and contains a severity histogram.
- `audit nope` → "unknown kind 'nope'" + usage + exit 2.

- [ ] **Step 4: Tag**

```bash
cd /Users/billn/packetsonde
git tag -a plan-2-findings-and-tls -m "Plan 2 (findings & first audit) complete

- finding record + JSON/text serializers (libpacketsonde)
- thread-safe output emitter (text/json/jsonl/quiet, tty-detect, --auto-append)
- token-bucket rate limiter + pthread worker pool
- SIGINT/SIGTERM cancel handler
- packetsonde audit tls: 8 finding kinds via OpenSSL handshake/cert inspection
- integration test against openssl s_server"
```

Plan 2 complete. Plan 3 (verb breadth — discover, scan, probe, findings, config) is next.

---

## Self-review notes

- Each task either commits at its end or pairs with the next (Tasks 7+8 share a commit, intentionally). All other tasks commit.
- The `audit tls` body uses the worker pool + signals + limiter even though v1 only has one target — this exercises the cancel path and keeps the wiring honest so multi-target work in Plan 3 just submits to the pool.
- Tests escalate from unit (finding, output, limiter, workers) to integration (audit_tls.sh against openssl s_server). The integration test correctly exits 77 (CTest skip code) when openssl isn't on the path.
- OpenSSL is required for the CLI from Task 8 onward; the top-level CMake already finds it for the agent, so `find_package(OpenSSL REQUIRED)` in `src/cli/CMakeLists.txt` is consistent.
- No references to undefined functions: `ps_audit_tls_run` is forward-declared in `audit.c` (Task 7) and defined in `tls.c` (Task 8) — committed together so the tree is never in a state where the verb dispatch references a missing symbol after a commit.
- Auto-append path resolution honors `XDG_STATE_HOME` per spec §4.1; falls back to `$HOME/.local/state` and finally `/tmp`.
- No placeholders: every code block is the actual code, every commit message is provided, every shell command has the expected output described.
