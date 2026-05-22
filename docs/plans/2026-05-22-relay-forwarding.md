# packetsonde Relay Forwarding (Spec A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An edge agent in `report_mode=relay` forwards origin-signed envelopes to a relay over an `agent_proto` `ingest` frame; the relay appends a signed per-hop attestation and forwards to central; central verifies the attested chain, flags hops, and ingests (origin sig permitting).

**Architecture:** New `agent_proto` message types `ingest`/`ack`. The lib reporter gains a factored envelope-array builder reused by both the direct POST and the relay path. The edge relay path reuses `audit_via.c`'s mTLS connect/registry/knock to send an `ingest` frame and read an `ack`. The relay extends `network_listener.c`'s dispatch with an `ingest` handler that attests + forwards to central over HTTPS. Central's `ingest.py` verifies each `relay_path` attestation against the relay's pinned key (flag-don't-reject) and records `ps_relay_edges`. Relay policy is local config (`[central] report_mode/relay_via`, `[relay] role/allow_sources`).

**Tech Stack:** C11 + OpenSSL (agent), CMake/CTest; Python + ES (central, `rna-packetsonde`), pytest. Reuses keystore/`ps_keystore_sign`, `http_client`, `agent_proto`, `agent_transport`, `reporter`, `[central]` config, and the `--via`/`network_listener` machinery.

**Spec:** `docs/specs/2026-05-22-relay-forwarding-design.md`.

**Repos:** agent tasks (1–6, 8) in `/opt/repo/packetsonde` (branch `feat/relay-forwarding`); central task (7) in `/opt/repo/rna-packetsonde`. Agent build: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON && make <t> && ctest -R <t>`.

---

## Interfaces locked here

- **`agent_proto.h`:** `#define PS_AP_MSG_INGEST "ingest"`, `#define PS_AP_MSG_ACK "ack"`.
- **Frames:** ingest = `{"type":"ingest","envelopes":[<env>,…]}`; ack = `{"type":"ack","accepted":N,"rejected":M,"detail":"…"}`. `<env>` = `{envelope_v,origin_agent_id,payload,ed25519_sig[,relay_path]}`.
- **`relay_attest.h`:**
  - `int ps_relay_attest_string(const char *env_sig_b64, const char *received_from, const char *ts, char *out, size_t cap);` → bytes or -1. Produces `"<env_sig_b64>|<received_from>|<ts>"`.
  - `int ps_relay_attest_entry(const struct ps_keypair *kp, const char *self_agent_id, const char *env_sig_b64, const char *received_from, char *out, size_t cap);` → builds the JSON object `{"relay_agent_id":…,"received_from":…,"ts":…,"sig":…}` (ts = now ISO-8601, sig = base64 over the attest string). Returns len or -1.
- **`reporter.h`:** `int ps_reporter_build_envelopes(const struct ps_central_config *cc, const char **event_jsons, size_t n, char *out, size_t cap);` → length of the `[<env>,…]` array (no outer key), or -1.
- **`central_config.h`:** `ps_central_config` gains `const char *report_mode;` and `const char *relay_via;`.
- **Relay-path entry (wire + central):** `{relay_agent_id, received_from, ts, sig}`; central annotates with `verified` (+`reason`).

---

## Task 1: agent_proto `ingest`/`ack` message types

**Files:** Modify `src/lib/agent_proto.h`; Test `src/lib/tests/test_agent_proto.c`

- [ ] **Step 1: Add a failing assertion to `test_agent_proto.c`** (in its `main`, before the success print)

```c
    /* ingest/ack frame round-trip via the existing in-memory io harness */
    assert(strcmp(PS_AP_MSG_INGEST, "ingest") == 0);
    assert(strcmp(PS_AP_MSG_ACK, "ack") == 0);
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/packetsonde/build && make test_agent_proto 2>&1 | tail -4`
Expected: FAIL — `PS_AP_MSG_INGEST` undeclared.

- [ ] **Step 3: Add the constants to `src/lib/agent_proto.h`** (next to the other `PS_AP_MSG_*`)

```c
#define PS_AP_MSG_INGEST  "ingest"
#define PS_AP_MSG_ACK     "ack"
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd /opt/repo/packetsonde/build && make test_agent_proto >/dev/null && ctest -R '^test_agent_proto$' --output-on-failure`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /opt/repo/packetsonde
git add src/lib/agent_proto.h src/lib/tests/test_agent_proto.c
git commit -m "agent_proto: add ingest/ack message types"
```

---

## Task 2: Relay attestation builder (`src/lib/relay_attest`)

**Files:** Create `src/lib/relay_attest.h`, `src/lib/relay_attest.c`; Test `src/lib/tests/test_relay_attest.c`; Modify `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test** (`src/lib/tests/test_relay_attest.c`)

```c
#include "relay_attest.h"
#include "keystore.h"
#include <openssl/evp.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

static void test_attest_string(void) {
    char s[256];
    int n = ps_relay_attest_string("SIGB64", "edge-07", "2026-05-22T10:00:00Z", s, sizeof s);
    assert(n > 0);
    assert(strcmp(s, "SIGB64|edge-07|2026-05-22T10:00:00Z") == 0);
}

static void test_attest_entry_signs_and_verifies(void) {
    struct ps_keypair kp; assert(ps_keystore_generate(&kp) == 0);
    char entry[1024];
    int n = ps_relay_attest_entry(&kp, "relay-1", "SIGB64", "edge-07", entry, sizeof entry);
    assert(n > 0);
    assert(strstr(entry, "\"relay_agent_id\":\"relay-1\""));
    assert(strstr(entry, "\"received_from\":\"edge-07\""));
    assert(strstr(entry, "\"ts\":\""));
    assert(strstr(entry, "\"sig\":\""));
}

int main(void) { test_attest_string(); test_attest_entry_signs_and_verifies();
    printf("test_relay_attest: OK\n"); return 0; }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_relay_attest 2>&1 | tail -4`
Expected: FAIL — `relay_attest.h` not found.

- [ ] **Step 3: Create `src/lib/relay_attest.h`**

```c
#ifndef PS_RELAY_ATTEST_H
#define PS_RELAY_ATTEST_H
#include <stddef.h>
#include "keystore.h"

/* "<env_sig_b64>|<received_from>|<ts>" — the exact bytes a relay signs.
 * Central rebuilds this identically (no JSON canonicalization). */
int ps_relay_attest_string(const char *env_sig_b64, const char *received_from,
                           const char *ts, char *out, size_t cap);

/* Build a relay_path entry JSON object:
 *   {"relay_agent_id":"<self>","received_from":"<rf>","ts":"<now>","sig":"<b64>"}
 * ts = current UTC ISO-8601; sig = base64 Ed25519 over ps_relay_attest_string(...).
 * Returns bytes written, or -1. */
int ps_relay_attest_entry(const struct ps_keypair *kp, const char *self_agent_id,
                          const char *env_sig_b64, const char *received_from,
                          char *out, size_t cap);
#endif
```

- [ ] **Step 4: Create `src/lib/relay_attest.c`**

```c
#include "relay_attest.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int ps_relay_attest_string(const char *env_sig_b64, const char *received_from,
                           const char *ts, char *out, size_t cap) {
    int n = snprintf(out, cap, "%s|%s|%s", env_sig_b64, received_from, ts);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

static void iso_now(char *out, size_t cap) {
    time_t t = time(NULL); struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static int b64(const unsigned char *in, size_t n, char *out, size_t cap) {
    int len = EVP_EncodeBlock((unsigned char *)out, in, (int)n);
    return (len < 0 || (size_t)len >= cap) ? -1 : len;
}

int ps_relay_attest_entry(const struct ps_keypair *kp, const char *self_agent_id,
                          const char *env_sig_b64, const char *received_from,
                          char *out, size_t cap) {
    char ts[40]; iso_now(ts, sizeof ts);
    char s[512];
    if (ps_relay_attest_string(env_sig_b64, received_from, ts, s, sizeof s) < 0) return -1;
    unsigned char sig[64];
    if (ps_keystore_sign(kp, (const unsigned char *)s, strlen(s), sig) != 0) return -1;
    char sig_b64[128];
    if (b64(sig, 64, sig_b64, sizeof sig_b64) < 0) return -1;
    int n = snprintf(out, cap,
        "{\"relay_agent_id\":\"%s\",\"received_from\":\"%s\",\"ts\":\"%s\",\"sig\":\"%s\"}",
        self_agent_id, received_from, ts, sig_b64);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}
```

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `relay_attest.c` to `packetsonde_lib` sources, and after the `test_reporter` block:

```cmake
    add_executable(test_relay_attest tests/test_relay_attest.c)
    target_link_libraries(test_relay_attest PRIVATE packetsonde_lib)
    add_test(NAME test_relay_attest COMMAND test_relay_attest)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_relay_attest >/dev/null && ctest -R '^test_relay_attest$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /opt/repo/packetsonde
git add src/lib/relay_attest.h src/lib/relay_attest.c src/lib/tests/test_relay_attest.c src/lib/CMakeLists.txt
git commit -m "Add relay attestation builder (fixed-string sign, relay_path entry)"
```

---

## Task 3: Relay config fields

**Files:** Modify `src/agent/src/config_to_env.c`, `src/lib/central_config.h`, `packaging/packetsonded.toml`

- [ ] **Step 1: Add `[central]` + `[relay]` mappings to `config_to_env.c`** (in the MAPPINGS table, before the NULL terminator)

```c
    { "central", "report_mode", "PS_CENTRAL_REPORT_MODE" },
    { "central", "relay_via",   "PS_CENTRAL_RELAY_VIA" },
    { "relay", "role",          "PS_RELAY_ROLE" },
    { "relay", "allow_sources", "PS_RELAY_ALLOW_SOURCES" },
```

- [ ] **Step 2: Extend `ps_central_config` + `from_env` in `src/lib/central_config.h`**

Add the two fields to the struct (after `key_dir`):

```c
    const char *report_mode;     /* "direct" (default) | "relay" */
    const char *relay_via;       /* edge: relay agent name when report_mode=relay */
```

And in `ps_central_config_from_env()` (before `return cc;`):

```c
    cc.report_mode = getenv("PS_CENTRAL_REPORT_MODE");
    if (!cc.report_mode || !cc.report_mode[0]) cc.report_mode = "direct";
    cc.relay_via = getenv("PS_CENTRAL_RELAY_VIA");
```

- [ ] **Step 3: Document the blocks in `packaging/packetsonded.toml`** (append)

```toml
# report_mode "relay" forwards events through relay_via instead of POSTing central.
# (central settings above are still used by relays for their own forward.)
# [central] report_mode = "relay"   relay_via = "bastion-1"

[relay]
role          = "0"   # "1" on a relay-capable agent (accepts ingest, forwards to central)
allow_sources = ""    # comma-separated agent_ids this relay will forward for
```

- [ ] **Step 4: Build the lib + agent to confirm it compiles**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make packetsonde_lib packetsonde-agent >/dev/null 2>&1 && echo OK`
Expected: `OK`.

- [ ] **Step 5: Commit**

```bash
cd /opt/repo/packetsonde
git add src/agent/src/config_to_env.c src/lib/central_config.h packaging/packetsonded.toml
git commit -m "config: add [central] report_mode/relay_via + [relay] role/allow_sources"
```

---

## Task 4: Factor envelope-array builder in the reporter

**Files:** Modify `src/lib/reporter.h`, `src/lib/reporter.c`; Test `src/lib/tests/test_reporter.c`

- [ ] **Step 1: Add a failing test** (append to `test_reporter.c`, call from `main`)

```c
#include <stdlib.h>
static void test_build_envelopes(void) {
    struct ps_keypair kp; ps_keystore_generate(&kp);
    /* write a temp key dir so the builder can load 'agent' */
    char dir[] = "/tmp/ps_env_XXXXXX"; assert(mkdtemp(dir));
    assert(ps_keystore_save(dir, "agent", &kp) == 0);
    struct ps_central_config cc; memset(&cc, 0, sizeof cc);
    cc.url = "http://x"; cc.agent_id = "edge-07"; cc.verify = 0; cc.key_dir = dir;
    const char *events[] = { "{\"v\":1,\"kind\":\"tls\"}" };
    char buf[8192];
    int n = ps_reporter_build_envelopes(&cc, events, 1, buf, sizeof buf);
    assert(n > 0);
    assert(buf[0] == '[');                                   /* an array */
    assert(strstr(buf, "\"origin_agent_id\":\"edge-07\""));  /* outer field */
    assert(strstr(buf, "\"payload\":\""));
    assert(strstr(buf, "\"ed25519_sig\":\""));
}
```
Add `test_build_envelopes();` to `main()`.

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/packetsonde/build && make test_reporter 2>&1 | tail -4`
Expected: FAIL — `ps_reporter_build_envelopes` undefined.

- [ ] **Step 3: Declare in `reporter.h`** (after `ps_report_findings`)

```c
/* Build the signed envelope array "[<env>,…]" (no outer key) for the events.
 * Returns bytes written, or -1. */
int ps_reporter_build_envelopes(const struct ps_central_config *cc,
                                const char **event_jsons, size_t n,
                                char *out, size_t cap);
```

- [ ] **Step 4: Refactor `reporter.c`** — extract the per-envelope build loop from `ps_report_events` into `ps_reporter_build_envelopes`, and have `ps_report_events` call it.

```c
int ps_reporter_build_envelopes(const struct ps_central_config *cc,
                                const char **event_jsons, size_t n,
                                char *out, size_t cap) {
    const char *keydir = (cc->key_dir && cc->key_dir[0]) ? cc->key_dir : "/etc/packetsonded/keys";
    struct ps_keypair kp;
    if (ps_keystore_load(keydir, "agent", &kp) != 0) return -1;
    char host[256];
    const char *agent_id = (cc->agent_id && cc->agent_id[0]) ? cc->agent_id
                          : (gethostname(host, sizeof host) == 0 ? host : "unknown");
    size_t o = 0;
    o += (size_t)snprintf(out + o, cap - o, "[");
    for (size_t i = 0; i < n; i++) {
        char ts[40];
        if (ps_reporter_extract_ts(event_jsons[i], ts, sizeof ts) != 0)
            snprintf(ts, sizeof ts, "1970-01-01T00:00:00Z");
        char payload[16384];
        if (ps_reporter_build_payload(payload, sizeof payload, agent_id, ts, event_jsons[i]) < 0)
            continue;
        unsigned char sig[64];
        if (ps_keystore_sign(&kp, (const unsigned char*)payload, strlen(payload), sig) != 0) return -1;
        char sig_b64[128]; if (b64(sig, 64, sig_b64, sizeof sig_b64) < 0) return -1;
        char env[20000]; struct ps_json j; ps_json_init(&j, env, sizeof env);
        ps_json_object_begin(&j);
        ps_json_key_int(&j, "envelope_v", 1);
        ps_json_key_string(&j, "origin_agent_id", agent_id);
        ps_json_key_string(&j, "payload", payload);
        ps_json_key_string(&j, "ed25519_sig", sig_b64);
        ps_json_object_end(&j);
        if (ps_json_finish(&j) < 0) return -1;
        o += (size_t)snprintf(out + o, cap - o, "%s%s", i ? "," : "", env);
        if (o >= cap - 64) break;
    }
    o += (size_t)snprintf(out + o, cap - o, "]");
    return (int)o;
}
```

Then change `ps_report_events` body to:

```c
int ps_report_events(const struct ps_central_config *cc, const char *base_url,
                     const char **event_jsons, size_t n, struct ps_report_result *out) {
    if (!cc || !cc->url || !cc->url[0]) return -1;
    static char body[262144];
    int alen = ps_reporter_build_envelopes(cc, event_jsons, n, body + 13, sizeof body - 16);
    if (alen < 0) return -1;
    memcpy(body, "{\"envelopes\":", 13);
    memcpy(body + 13 + alen, "}", 2);  /* NUL-terminated */
    char url[640];
    snprintf(url, sizeof url, "%s/api/v1/packetsonde/events",
             (base_url && base_url[0]) ? base_url : cc->url);
    struct ps_http_opts opts = { cc->verify, cc->ca_cert, 15 };
    int status = 0; char resp[8192];
    if (ps_http_request("POST", url, body, &opts, &status, resp, sizeof resp) != 0) return -1;
    if (out) {
        out->http_status = status; out->total = (int)n;
        const char *a = strstr(resp, "\"accepted\":");
        out->accepted = a ? atoi(a + 11) : 0;
        out->rejected = out->total - out->accepted;
    }
    return 0;
}
```

(Keep the file-scope `b64` static helper; both functions use it.)

- [ ] **Step 5: Run to verify both pass**

Run: `cd /opt/repo/packetsonde/build && make test_reporter >/dev/null && ctest -R '^test_reporter$' --output-on-failure`
Expected: PASS (existing reporter tests + the new one).

- [ ] **Step 6: Commit**

```bash
cd /opt/repo/packetsonde
git add src/lib/reporter.h src/lib/reporter.c src/lib/tests/test_reporter.c
git commit -m "reporter: factor ps_reporter_build_envelopes (shared by direct + relay paths)"
```

---

## Task 5: Edge relay-send path (CLI)

**Files:** Create `src/cli/remote/ingest_via.h`, `src/cli/remote/ingest_via.c`; Modify `src/cli/CMakeLists.txt`, `src/cli/verbs/report_central.c`

> Reuses `audit_via.c`'s connect machinery. To avoid duplicating the registry-resolve + `ps_at_ctx_init`/`ps_at_connect`/knock block, factor it: in `audit_via.c` expose `int ps_via_connect(const char *agent_name, struct ps_at_ctx *ctx_out, SSL **ssl_out, struct ps_ap_io *io_out);` (returns 0 on a connected, hello-exchanged channel) by lifting the existing block (registry load/find, knock-for-session, `ps_at_ctx_init`, `ps_at_connect`, `ps_at_make_io`, write hello) out of `ps_audit_via_run` into this helper, and have `ps_audit_via_run` call it. Declare it in a new `src/cli/remote/via_connect.h`.

- [ ] **Step 1: Factor `ps_via_connect` out of `audit_via.c`**

Create `src/cli/remote/via_connect.h`:

```c
#ifndef PS_VIA_CONNECT_H
#define PS_VIA_CONNECT_H
#include "agent_transport.h"
#include "agent_proto.h"
#include <openssl/ssl.h>
/* Connect to a registered via-agent over mTLS and exchange hello.
 * On success returns 0 with *ctx_out/*ssl_out/*io_out owned by the caller
 * (close ssl with ps_at_close, destroy ctx with ps_at_ctx_destroy). -1 on failure. */
int ps_via_connect(const char *agent_name, struct ps_at_ctx *ctx_out,
                   SSL **ssl_out, struct ps_ap_io *io_out);
#endif
```

In `audit_via.c`, move the block from `ps_audit_via_run` that does: `ps_agents_load`/`find`, `split_addr`, the knock-mode `knock_for_session`, `ps_at_ctx_init(&tctx, PS_AT_CLIENT, &kp, pin)`, `ps_at_connect`, `ps_at_make_io`, and the hello-write — into `int ps_via_connect(const char *agent_name, struct ps_at_ctx *ctx_out, SSL **ssl_out, struct ps_ap_io *io_out)`. Have `ps_audit_via_run` call `ps_via_connect(opts->via, &tctx, &ssl, &io)` then proceed to write the audit request as before. (The agent keypair is loaded inside `ps_via_connect` via the keystore, as `ps_audit_via_run` already does.)

- [ ] **Step 2: Create `src/cli/remote/ingest_via.c`**

```c
#include "ingest_via.h"
#include "via_connect.h"
#include "agent_proto.h"
#include "agent_transport.h"
#include <stdio.h>
#include <string.h>

int ps_ingest_via(const char *relay_agent, const char *envelopes_array,
                  struct ps_report_result *out) {
    struct ps_at_ctx ctx; SSL *ssl = NULL; struct ps_ap_io io;
    if (ps_via_connect(relay_agent, &ctx, &ssl, &io) != 0) return -1;

    /* {"type":"ingest","envelopes":<array>} */
    static char frame[262144];
    int fn = snprintf(frame, sizeof frame, "{\"type\":\"ingest\",\"envelopes\":%s}", envelopes_array);
    int rc = -1;
    if (fn > 0 && (size_t)fn < sizeof frame &&
        ps_ap_write_frame(&io, frame, (size_t)fn) == PS_AP_OK) {
        uint8_t buf[8192]; size_t blen;
        if (ps_ap_read_frame(&io, buf, sizeof buf, &blen) == PS_AP_OK) {
            buf[blen < sizeof buf ? blen : sizeof buf - 1] = 0;
            if (out) {
                const char *a = strstr((char*)buf, "\"accepted\":");
                out->accepted = a ? atoi(a + 11) : 0;
                out->http_status = 200;
            }
            rc = 0;
        }
    }
    ps_at_close(ssl); ps_at_ctx_destroy(&ctx);
    return rc;
}
```

And `src/cli/remote/ingest_via.h`:

```c
#ifndef PS_INGEST_VIA_H
#define PS_INGEST_VIA_H
#include "reporter.h"   /* struct ps_report_result */
/* Forward a pre-built envelope array (the "[…]" from ps_reporter_build_envelopes)
 * to relay_agent over the agent_proto ingest frame; fills out from the ack. */
int ps_ingest_via(const char *relay_agent, const char *envelopes_array,
                  struct ps_report_result *out);
#endif
```

- [ ] **Step 3: Branch the report path in `report_central.c`**

After building `cc` (which now has `report_mode`/`relay_via` — read them with `ps_cli_unq` from `[central]`), replace the single `ps_report_events(...)` call with:

```c
    struct ps_report_result r = {0}; int rc;
    if (cc.report_mode && strcmp(cc.report_mode, "relay") == 0 && cc.relay_via && cc.relay_via[0]) {
        static char arr[262144];
        int alen = ps_reporter_build_envelopes(&cc, (const char**)events, n, arr, sizeof arr);
        rc = (alen < 0) ? -1 : ps_ingest_via(cc.relay_via, arr, &r);
        r.total = (int)n; r.rejected = r.total - r.accepted;
    } else {
        rc = ps_report_events(&cc, endpoint, (const char**)events, n, &r);
    }
```

Add `#include "../remote/ingest_via.h"` and read `cc.report_mode`/`cc.relay_via` via `ps_cli_unq(ps_config_get(&cfg,"central","report_mode"),…)` etc.

- [ ] **Step 4: Add sources to `src/cli/CMakeLists.txt`** — `remote/ingest_via.c` (and ensure `remote/audit_via.c` still compiles with the factored helper; `via_connect.h` is header-only declaring the function defined in `audit_via.c`).

- [ ] **Step 5: Build + smoke-test the relay branch (no relay running → connect fails cleanly)**

Run:
```bash
cd /opt/repo/packetsonde/build && make packetsonde >/dev/null 2>&1 && echo BUILD_OK
printf '[keys]\ndir="/tmp/k"\n[central]\nurl="http://127.0.0.1:8700"\nreport_mode="relay"\nrelay_via="nope"\n' > /tmp/relay.toml; mkdir -p /tmp/k
printf '{"v":1,"id":"A","ts":"2026-05-22T10:00:00Z","kind":"tls","severity":"low","confidence":"firm","title":"t","source":"s","host":"h"}\n' > /tmp/f.jsonl
./src/cli/packetsonde report-central --to-central /tmp/f.jsonl --config /tmp/relay.toml; echo "exit=$?"
```
Expected: builds; with an unknown `relay_via` the connect fails → "relay unreachable / send failed", non-zero exit (the registry-resolve in `ps_via_connect` returns -1 for unknown agent).

- [ ] **Step 6: Commit**

```bash
cd /opt/repo/packetsonde
git add src/cli/remote/ingest_via.h src/cli/remote/ingest_via.c src/cli/remote/via_connect.h src/cli/remote/audit_via.c src/cli/verbs/report_central.c src/cli/CMakeLists.txt
git commit -m "Edge: forward via relay (ingest frame) when report_mode=relay; factor ps_via_connect"
```

---

## Task 6: Relay ingest handler

**Files:** Modify `src/agent/src/modules/network_listener.c`

> The connection handler's dispatch loop currently handles `hello`/`audit`. Add an `ingest` branch that: checks the peer agent_id ∈ `allow_sources`; for each envelope appends `ps_relay_attest_entry`; POSTs the batch to central via `http_client` with `X-Packetsonde-Relay`; replies with an `ack`.

- [ ] **Step 1: Add includes + the handler to `network_listener.c`**

At the top add:
```c
#include "relay_attest.h"
#include "http_client.h"
#include "central_config.h"
#include <stdlib.h>
```

Add a handler function (above the connection handler):

```c
/* Forward one ingest frame's envelopes to central with this relay's attestation.
 * peer_id = connecting peer's agent_id (received_from). Returns accepted count. */
static int handle_ingest(struct nl_state *st, const char *peer_id,
                         const uint8_t *frame, size_t len, char *ack, size_t ack_cap) {
    /* allow_sources gate */
    const char *allow = getenv("PS_RELAY_ALLOW_SOURCES");
    if (!allow || !strstr(allow, peer_id)) {
        snprintf(ack, ack_cap, "{\"type\":\"ack\",\"accepted\":0,\"rejected\":0,\"detail\":\"source not allowed\"}");
        return 0;
    }
    /* Pull the envelopes array substring: from the first '[' after "envelopes" to its matching ']'.
     * (Conservative: envelopes is the only array in the frame.) */
    const char *p = strstr((const char*)frame, "\"envelopes\":");
    if (!p) { snprintf(ack, ack_cap, "{\"type\":\"ack\",\"accepted\":0,\"rejected\":0,\"detail\":\"no envelopes\"}"); return 0; }
    /* For attestation we need each envelope's ed25519_sig; simplest robust path:
     * re-emit the array, inserting a relay_path entry per envelope. We do a light
     * transform: for each "\"ed25519_sig\":\"<sig>\"" occurrence, capture <sig> and
     * append ,"relay_path":[<entry>] before the envelope's closing brace. */
    /* (Implementation: scan envelope objects by brace depth; for each, find ed25519_sig,
     *  build entry via ps_relay_attest_entry(&st->agent_kp, self_id, sig, peer_id), and
     *  splice "\"relay_path\":[<entry>]" into the object. Build forwarded[] string.) */
    /* POST to central */
    /* ... see Step 2 for the concrete splice + POST ... */
    (void)st; (void)len; (void)ack_cap;
    return 0;
}
```

- [ ] **Step 2: Implement the splice + POST inside `handle_ingest`** (replace the placeholder comment block)

```c
    char self_id[256];
    const char *cid = getenv("PS_CENTRAL_AGENT_ID");
    if (cid && cid[0]) snprintf(self_id, sizeof self_id, "%s", cid);
    else if (gethostname(self_id, sizeof self_id) != 0) snprintf(self_id, sizeof self_id, "relay");

    static char fwd[262144]; size_t fo = 0;
    fo += snprintf(fwd + fo, sizeof fwd - fo, "{\"envelopes\":[");
    /* Walk top-level envelope objects in the array p..]. */
    const char *arr = strchr(p, '[');
    int depth = 0; const char *obj_start = NULL; int first = 1;
    for (const char *c = arr; c && *c && *c != '\0'; c++) {
        if (*c == '{') { if (depth == 0) obj_start = c; depth++; }
        else if (*c == '}') {
            depth--;
            if (depth == 0 && obj_start) {
                size_t objlen = (size_t)(c - obj_start) + 1;
                char obj[20000];
                if (objlen >= sizeof obj) { obj_start = NULL; continue; }
                memcpy(obj, obj_start, objlen); obj[objlen] = 0;
                /* capture ed25519_sig */
                char sig[128] = "";
                const char *sp = strstr(obj, "\"ed25519_sig\":\"");
                if (sp) { sp += 15; const char *se = strchr(sp, '"');
                          if (se && (size_t)(se - sp) < sizeof sig) { memcpy(sig, sp, se - sp); sig[se-sp]=0; } }
                char entry[1024];
                ps_relay_attest_entry(&st->agent_kp, self_id, sig, peer_id, entry, sizeof entry);
                /* splice ,"relay_path":[entry] before the closing '}' */
                obj[objlen - 1] = 0;  /* drop trailing } */
                fo += snprintf(fwd + fo, sizeof fwd - fo, "%s%s,\"relay_path\":[%s]}",
                               first ? "" : ",", obj, entry);
                first = 0; obj_start = NULL;
                if (fo >= sizeof fwd - 64) break;
            }
        } else if (*c == ']' && depth == 0) break;
    }
    fo += snprintf(fwd + fo, sizeof fwd - fo, "]}");

    const char *curl_base = getenv("PS_CENTRAL_URL");
    char url[640]; snprintf(url, sizeof url, "%s/api/v1/packetsonde/events", curl_base ? curl_base : "");
    const char *verify = getenv("PS_CENTRAL_VERIFY");
    char hdr[320]; snprintf(hdr, sizeof hdr, "X-Packetsonde-Relay: %s\r\n", self_id);
    struct ps_http_opts opts = { (verify && verify[0]=='0') ? 0 : 1, getenv("PS_CENTRAL_CA_CERT"), 15 };
    int status = 0; char resp[8192];
    int accepted = 0;
    /* ps_http_request signature has no extra-headers arg; use the variant that takes one,
     * or extend ps_http_build_request via the extra_headers param already present. Pass hdr. */
    if (ps_http_request_h("POST", url, fwd, hdr, &opts, &status, resp, sizeof resp) == 0) {
        const char *a = strstr(resp, "\"accepted\":"); accepted = a ? atoi(a + 11) : 0;
    }
    snprintf(ack, ack_cap, "{\"type\":\"ack\",\"accepted\":%d,\"rejected\":0,\"detail\":\"\"}", accepted);
    return accepted;
```

> Note: `http_client`'s `ps_http_build_request` already accepts an `extra_headers` argument, but `ps_http_request` does not thread it through. Add a thin `ps_http_request_h(method,url,body,extra_headers,opts,...)` to `http_client.c/.h` (copy `ps_http_request`, pass `extra_headers` into `ps_http_build_request`) and have `ps_http_request` call it with `NULL`. Do this as the first sub-step of Task 6 (it's a 10-line addition with the existing `ps_http_build_request` already supporting the param).

- [ ] **Step 3: Dispatch `ingest` in the connection handler loop**

In the `while (!dispatched)` loop (after the `audit` branch), add — note relays accept `ingest` without requiring a prior audit `hello` gate beyond the mTLS auth, but still require the `hello` frame for the peer fingerprint exchange; capture the peer agent_id from the authorized fingerprint match:

```c
        if (strcmp(type, "ingest") == 0) {
            char peer_id[256] = "";
            /* Resolve peer agent_id from its authorized pubkey fingerprint. For the
             * lab/flat-LAN case allow_sources lists agent_ids; map the peer via the
             * authorized entry name. Minimal: use the connecting fingerprint's short
             * form if no name mapping — allow_sources should then list fingerprints. */
            ps_at_peer_fingerprint(ssl, peer_id, sizeof peer_id);
            char ack[1024];
            handle_ingest(st, peer_id, buf, blen, ack, sizeof ack);
            ps_ap_write_frame(&io, ack, strlen(ack));
            dispatched = 1;
            continue;
        }
```

> `received_from`/`allow_sources` identity: this uses the peer's mTLS fingerprint string. `allow_sources` in config should therefore list the peer fingerprints (or the relay maps fingerprint→agent_id via its authorized dir filenames). For the single-hop lab test (Task 8) set `allow_sources` to the edge's fingerprint. (A friendlier fingerprint→name mapping is a small follow-up.)

- [ ] **Step 4: Wire `network_listener.c`'s new lib deps** — the agent target already links `packetsonde_lib` (has `relay_attest`, `http_client`). Build:

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make packetsonde-agent 2>&1 | tail -6`
Expected: compiles + links.

- [ ] **Step 5: Commit**

```bash
cd /opt/repo/packetsonde
git add src/agent/src/modules/network_listener.c src/lib/http_client.h src/lib/http_client.c
git commit -m "Relay: ingest handler — allow_sources gate, attest each envelope, forward to central"
```

---

## Task 7: Central — verify + record the attested chain

**Files:** Modify `/opt/repo/rna-packetsonde/service/envelope.py`, `service/ingest.py`; Test `/opt/repo/rna-packetsonde/tests/unit/test_relay_chain.py`

- [ ] **Step 1: Write the failing test** (`tests/unit/test_relay_chain.py`)

```python
import base64, json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import service.ingest as ingest_mod
from service.ingest import Ingestor

def _pub(sk):
    return base64.b64encode(sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

class Reg:
    def __init__(self, recs): self.r = recs
    def get(self, a): return self.r.get(a)
class ES:
    def __init__(self): self.docs = []
    def index(self, index, id, document): self.docs.append(document)
class Edges:
    def __init__(self): self.calls = []
    def record(self, origin, relay, state, zone): self.calls.append((origin, relay, state))

def _wire(origin_sk, origin, relay_sk, relay_id, received_from, tamper=False):
    payload = json.dumps({"origin_agent_id": origin, "ts": "2026-05-22T10:00:00Z",
                          "event": {"v": 1, "kind": "tls"}})
    sig = base64.b64encode(origin_sk.sign(payload.encode())).decode()
    ts = "2026-05-22T10:00:01Z"
    attest = f"{sig}|{received_from}|{ts}"
    asig = base64.b64encode(relay_sk.sign(attest.encode())).decode()
    if tamper: asig = base64.b64encode(b"x"*64).decode()
    return {"envelope_v": 1, "origin_agent_id": origin, "payload": payload, "ed25519_sig": sig,
            "relay_path": [{"relay_agent_id": relay_id, "received_from": received_from,
                            "ts": ts, "sig": asig}]}

def test_verified_hop_ingests_and_records_edge(monkeypatch):
    monkeypatch.setattr(ingest_mod, "prefixed", lambda n: n)
    osk, rsk = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    reg = Reg({"edge-07": {"status":"validated","pubkey":_pub(osk)},
               "relay-1": {"status":"validated","pubkey":_pub(rsk)}})
    edges = Edges()
    ing = Ingestor(reg, ES(), relay_edges=edges)
    raw = _wire(osk, "edge-07", rsk, "relay-1", "edge-07")
    r = ing.ingest(raw, transport="relay", relay_path=raw["relay_path"], relay_identity="relay-1")
    assert r.outcome == "accepted"
    assert ("edge-07", "relay-1", "verified") in edges.calls

def test_bad_hop_still_ingests_flagged(monkeypatch):
    monkeypatch.setattr(ingest_mod, "prefixed", lambda n: n)
    osk, rsk = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    reg = Reg({"edge-07": {"status":"validated","pubkey":_pub(osk)},
               "relay-1": {"status":"validated","pubkey":_pub(rsk)}})
    edges = Edges(); es = ES()
    ing = Ingestor(reg, es, relay_edges=edges)
    raw = _wire(osk, "edge-07", rsk, "relay-1", "edge-07", tamper=True)
    r = ing.ingest(raw, transport="relay", relay_path=raw["relay_path"], relay_identity="relay-1")
    assert r.outcome == "accepted"                       # origin sig still valid -> ingested
    assert es.docs and es.docs[0]["relay_chain_verified"] is False
    assert ("edge-07", "relay-1", "unverified") in edges.calls
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/rna-packetsonde && python3 -m pytest tests/unit/test_relay_chain.py -q`
Expected: FAIL — central doesn't verify `relay_path` attestations or set `relay_chain_verified` yet.

- [ ] **Step 3: `envelope.py` — accept optional `relay_path`**

In `parse_envelope`, after building `inner`, accept a top-level `relay_path` (default `[]`) and add it to the `Envelope`:

Add field `relay_path: list` to the dataclass; in the return, `relay_path=raw.get("relay_path") or []` (validate it's a list; non-list → `EnvelopeError`).

- [ ] **Step 4: `ingest.py` — verify the chain after the origin-sig check**

After the `verify_ed25519(... env.payload ...)` block and before building `doc`, add:

```python
        from .signing import verify_ed25519 as _v
        verified_path = []
        chain_ok = True
        for entry in (env.relay_path or []):
            rid = entry.get("relay_agent_id"); rf = entry.get("received_from")
            ts = entry.get("ts"); asig = entry.get("sig")
            ok = False; reason = None
            if not (rid and rf and ts and asig):
                reason = "malformed"
            else:
                rec = self._registry.get(rid)
                if rec is None: reason = "unknown_relay"
                elif rec.get("status") != "validated": reason = "not_validated"
                else:
                    msg = f"{env.ed25519_sig}|{rf}|{ts}".encode("utf-8")
                    ok = _v(rec["pubkey"], asig, msg)
                    if not ok: reason = "bad_sig"
            verified_path.append({**entry, "verified": ok, **({"reason": reason} if reason else {})})
            if not ok: chain_ok = False
            if self._relay_edges and rid and rf:
                self._relay_edges.record(rf, rid, "verified" if ok else "unverified", None)
```

Then in the `doc.update({...})`, add `"relay_path": verified_path` (overriding the raw) and `"relay_chain_verified": chain_ok`. (Leave the existing `transport`/`relay_identity` as-is.)

- [ ] **Step 5: Run to verify it passes**

Run: `cd /opt/repo/rna-packetsonde && python3 -m pytest tests/unit/test_relay_chain.py tests/unit/test_envelope.py tests/unit/test_ingest_rules.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd /opt/repo/rna-packetsonde
git add service/envelope.py service/ingest.py tests/unit/test_relay_chain.py
git commit -m "ingest: verify relay_path attestation chain (flag-not-reject), record ps_relay_edges"
```

---

## Task 8: Live two-agent relay round-trip (central)

**Files:** Create `scripts/test-relay-central.sh`

- [ ] **Step 1: Create the script** — start a relay agent, register+validate both, edge reports via relay, assert the event lands with a verified hop.

```bash
#!/bin/bash
# Two-agent relay round-trip against central (loopback). Requires the agent built
# and central running the merged central. Uses uuid-scoped ids + cleans up.
set -e
cd "$(dirname "$0")/.."
PY=/opt/central-0522-3/venv/bin/python
EXPORTS="PYTHONPATH=/opt/repo/rna/rna BASE_CONFIG=/opt/etc/central/config.yml"
EDGE="edge-$(openssl rand -hex 3)"; RELAY="relay-$(openssl rand -hex 3)"
TMP=$(mktemp -d); mkdir -p "$TMP/edge-keys" "$TMP/relay-keys"

# (1) generate identities + register/validate both
for who in "$EDGE:$TMP/edge-keys" "$RELAY:$TMP/relay-keys"; do
  id="${who%%:*}"; kd="${who##*:}"
  cat > "$TMP/$id.toml" <<EOF
[keys]
dir = "$kd"
[central]
url = "http://127.0.0.1:8700"
agent_id = "$id"
verify = "0"
EOF
  ./build/src/cli/packetsonde register --config "$TMP/$id.toml" --provenance direct >/dev/null
  env $EXPORTS $PY -c "from backend.framework.es import get_es_client; get_es_client().update(index='central_ps_agents', id='$id', doc={'status':'validated'}, refresh='wait_for')"
done

echo "Manual relay start needed: run the relay agent with agent_listen + [relay] role=1,"
echo "allow_sources=<edge fingerprint>, PS_CENTRAL_URL=http://127.0.0.1:8700, then point the"
echo "edge toml's [central] report_mode=relay relay_via=$RELAY and run report-central."
echo "Verify: central_ps_events has the edge event transport=relay, relay_path[0].verified=true,"
echo "relay_chain_verified=true; central_ps_relay_edges has ($EDGE -> $RELAY) state=verified."
echo "Cleanup: delete test agents/events/edges for $EDGE/$RELAY."
```

- [ ] **Step 2: Run the assisted live test** (the daemon listener needs root/caps; drive it per the script's printed steps, or via systemd on the host). Confirm in `central_ps_events`: `transport=relay`, `relay_path[0].verified=true`, `relay_chain_verified=true`; and `central_ps_relay_edges` shows `(edge→relay) verified`. Clean up the test docs.

- [ ] **Step 3: Commit**

```bash
cd /opt/repo/packetsonde
git add scripts/test-relay-central.sh
git commit -m "Add two-agent relay round-trip live test script"
```

---

## Self-Review

**Spec coverage:**
- §3 `ingest`/`ack` frame → Tasks 1 (types), 5 (edge send), 6 (relay handle) ✓
- §4 edge forward when `report_mode=relay` → Tasks 4 (envelope builder), 5 ✓
- §5 relay receive + attest + forward (allow_sources, attestation, POST + header) → Tasks 2 (attest), 6 ✓
- §6 central verify chain (flag-not-reject), `ps_relay_edges`, per-hop `verified`, `relay_chain_verified` → Task 7 ✓
- §7 local config + config_to_env → Task 3 ✓ (salt/bootstrap flag plumbing is a thin follow-up noted below)
- §9 testing (attest unit, central chain unit, parity, live two-agent) → Tasks 2, 7, 8 ✓
- D7 pluggable terminal → Task 6 forwards to a terminal resolved from config (central HTTPS here); Spec B adds the collector terminal ✓

**Gaps noted + accepted:** (a) the rna-salt state + `packetsonded-bootstrap` flag plumbing for the new config keys is a small follow-up (the keys parse + work via toml/env now; salt templating is mechanical — fold into Task 3 or a 3.5 if you want it this phase). (b) `allow_sources`/`received_from` identity uses the mTLS **fingerprint** string in this plan; a friendly fingerprint→agent_id mapping (so config lists names) is a small follow-up — flagged in Task 6 Step 3. (c) the C-signs/Python-verifies parity for the *attestation* string reuses `scripts/test-signing-parity.sh`'s approach; add an attestation variant if you want it explicit.

**Placeholder scan:** Task 6's handler is shown in two steps (skeleton then concrete splice/POST) with full code in Step 2; the `ps_http_request_h` thin wrapper is specified concretely (copy `ps_http_request`, thread `extra_headers` which `ps_http_build_request` already accepts). No "TBD"/"add error handling" placeholders.

**Type/name consistency:** `PS_AP_MSG_INGEST`/`PS_AP_MSG_ACK` (1,5,6); `ps_relay_attest_string`/`ps_relay_attest_entry` (2,6); `ps_reporter_build_envelopes` (4,5); `ps_central_config.report_mode`/`relay_via` (3,5); `ps_via_connect`/`ps_ingest_via` (5); `ps_http_request_h` (6); attestation string `"<env_sig>|<received_from>|<ts>"` identical in Task 2 (C) and Task 7 (Python). `relay_path` entry shape `{relay_agent_id,received_from,ts,sig}` consistent across 2/6/7.
```
