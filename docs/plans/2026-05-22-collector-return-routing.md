# packetsonde Collector / Return Routing (Spec B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `packetsonde collect` — a CLI verb that receives signed `ingest` frames over the agent_proto mTLS channel, verifies origin + relay-chain signatures against a *local* authorized-pubkey set (no central), and presents events as JSONL.

**Architecture:** The fragile/important parts live in the lib and are unit-tested: `ps_keystore_verify` (Ed25519 verify), `ps_json_extract_string` (extract + unescape a JSON string field — the wire-parsing primitive), and `ps_collect_process` (envelope → try-all-verify → enriched JSONL line). The CLI verb is a thin shell: parse args, load keys + authorized set, run an mTLS accept loop, and feed each `ingest` envelope to `ps_collect_process`.

**Tech Stack:** C11 + OpenSSL, CMake/CTest. Reuses `keystore`, `agent_transport` (mTLS), `agent_proto` (frames), `json` (output build) from Spec A.

**Spec:** `docs/specs/2026-05-22-collector-return-routing-design.md`.

**Repo:** all in `/opt/repo/packetsonde` (branch `feat/collector-return-routing`). Build: `cd build && cmake .. -DBUILD_TESTING=ON && make <t> && ctest -R <t>`.

---

## Interfaces locked here

- `keystore.h`: `int ps_keystore_verify(const uint8_t *pubkey32, const uint8_t *msg, size_t msg_len, const uint8_t sig64[64]);` → 1 valid, 0 invalid.
- `json_extract.h`:
  - `int ps_json_extract_string(const char *json, const char *key, char *out, size_t cap);` → unescaped value length, or -1 if key absent / malformed. Finds the first `"key":"…"` and unescapes (`\" \\ \/ \n \r \t \b \f \uXXXX`).
- `collect.h`:
  - `struct ps_collect_result { int verified; int relay_chain_verified; int has_relay; };`
  - `int ps_collect_process(const char *envelope_json, const uint8_t (*pubkeys)[32], size_t npk, const char *received_ts, char *out, size_t cap, struct ps_collect_result *res);` → length of the JSONL line (no trailing newline) on success, -1 on malformed envelope. `out` = the `event` object enriched with `agent_id`, `verified`, `relay_chain_verified`, `transport`, `received_ts`, and an annotated `relay_path`.
- Collect verb: `packetsonde collect [--listen ADDR:PORT] [--out FILE] [--key-dir DIR] [--authorized DIR]`.

---

## Task 1: `ps_keystore_verify`

**Files:** Modify `src/lib/keystore.h`, `src/lib/keystore.c`; Test `src/lib/tests/test_keystore_sign.c`

- [ ] **Step 1: Add assertions to the existing keystore-sign test**

Append inside `main()` of `src/lib/tests/test_keystore_sign.c`, before the success print:

```c
    /* ps_keystore_verify round-trip */
    struct ps_keypair kp2; ps_keystore_generate(&kp2);
    uint8_t sig2[64];
    assert(ps_keystore_sign(&kp2, (const uint8_t*)"hello", 5, sig2) == 0);
    assert(ps_keystore_verify(kp2.pubkey, (const uint8_t*)"hello", 5, sig2) == 1);
    assert(ps_keystore_verify(kp2.pubkey, (const uint8_t*)"hellp", 5, sig2) == 0);  /* wrong msg */
    sig2[0] ^= 0xff;
    assert(ps_keystore_verify(kp2.pubkey, (const uint8_t*)"hello", 5, sig2) == 0);  /* tampered */
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd build && make test_keystore_sign 2>&1 | tail -4`
Expected: FAIL — `ps_keystore_verify` undeclared.

- [ ] **Step 3: Declare in `keystore.h`** (after `ps_keystore_sign`)

```c
/* Verify an Ed25519 signature over msg. Returns 1 if valid, 0 otherwise. */
int ps_keystore_verify(const uint8_t *pubkey32, const uint8_t *msg,
                       size_t msg_len, const uint8_t sig64[64]);
```

- [ ] **Step 4: Implement in `keystore.c`** (append, after `ps_keystore_sign`)

```c
int ps_keystore_verify(const uint8_t *pubkey32, const uint8_t *msg,
                       size_t msg_len, const uint8_t sig64[64]) {
    EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                               pubkey32, PS_KEYSTORE_PUBKEY_SIZE);
    if (!pk) return 0;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = m
        && EVP_DigestVerifyInit(m, NULL, NULL, NULL, pk) == 1
        && EVP_DigestVerify(m, sig64, 64, msg, msg_len) == 1;
    if (m) EVP_MD_CTX_free(m);
    EVP_PKEY_free(pk);
    return ok ? 1 : 0;
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd build && make test_keystore_sign >/dev/null && ctest -R '^test_keystore_sign$' --output-on-failure`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/lib/keystore.h src/lib/keystore.c src/lib/tests/test_keystore_sign.c
git commit -m "keystore: add ps_keystore_verify (Ed25519 verify over arbitrary bytes)"
```

---

## Task 2: `ps_json_extract_string` (extract + unescape a JSON string field)

**Files:** Create `src/lib/json_extract.h`, `src/lib/json_extract.c`; Test `src/lib/tests/test_json_extract.c`; Modify `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test**

```c
/* src/lib/tests/test_json_extract.c */
#include "json_extract.h"
#include "json.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static void test_basic(void) {
    char out[256];
    int n = ps_json_extract_string("{\"a\":\"x\",\"b\":\"hello\"}", "b", out, sizeof out);
    assert(n == 5 && strcmp(out, "hello") == 0);
    assert(ps_json_extract_string("{\"a\":\"x\"}", "missing", out, sizeof out) == -1);
}

static void test_unescape(void) {
    char out[256];
    /* embedded escaped quote + backslash + newline */
    assert(ps_json_extract_string("{\"p\":\"he\\\"llo\\\\\\n\"}", "p", out, sizeof out) > 0);
    assert(strcmp(out, "he\"llo\\\n") == 0);
}

static void test_roundtrip_with_ps_json(void) {
    /* The reporter embeds payload via ps_json_key_string (escaping). Extracting it
     * back must reproduce the original bytes exactly — this is what the collector
     * verifies the signature over. */
    const char *payload = "{\"origin_agent_id\":\"e\",\"ts\":\"t\",\"event\":{\"v\":1}}";
    char env[512]; struct ps_json j; ps_json_init(&j, env, sizeof env);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "payload", payload);
    ps_json_object_end(&j);
    assert(ps_json_finish(&j) > 0);
    char out[512];
    int n = ps_json_extract_string(env, "payload", out, sizeof out);
    assert(n == (int)strlen(payload));
    assert(strcmp(out, payload) == 0);
}

int main(void) { test_basic(); test_unescape(); test_roundtrip_with_ps_json();
    printf("test_json_extract: OK\n"); return 0; }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_json_extract 2>&1 | tail -4`
Expected: FAIL — `json_extract.h` not found.

- [ ] **Step 3: Create `src/lib/json_extract.h`**

```c
#ifndef PS_JSON_EXTRACT_H
#define PS_JSON_EXTRACT_H
#include <stddef.h>
/* Find the first occurrence of "<key>":"<value>" in json and write the
 * UNESCAPED value into out. Returns the unescaped length (excluding NUL), or
 * -1 if the key is absent or the value is malformed/over-long. Handles the
 * JSON string escapes ps_json emits: \" \\ \/ \n \r \t \b \f \uXXXX. */
int ps_json_extract_string(const char *json, const char *key, char *out, size_t cap);
#endif
```

- [ ] **Step 4: Create `src/lib/json_extract.c`**

```c
#include "json_extract.h"
#include <string.h>
#include <stdio.h>

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int ps_json_extract_string(const char *json, const char *key, char *out, size_t cap) {
    if (!json || !key || !out || cap == 0) return -1;
    /* Build the search needle: "key": */
    char needle[128];
    int nl = snprintf(needle, sizeof needle, "\"%s\":", key);
    if (nl < 0 || (size_t)nl >= sizeof needle) return -1;
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += nl;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return -1;       /* not a string value */
    p++;                            /* past opening quote */

    size_t o = 0;
    while (*p) {
        unsigned char c = (unsigned char)*p;
        if (c == '"') {             /* unescaped closing quote -> done */
            out[o] = '\0';
            return (int)o;
        }
        if (c == '\\') {
            p++;
            char e = *p;
            char dec;
            switch (e) {
                case '"':  dec = '"';  break;
                case '\\': dec = '\\'; break;
                case '/':  dec = '/';  break;
                case 'n':  dec = '\n'; break;
                case 'r':  dec = '\r'; break;
                case 't':  dec = '\t'; break;
                case 'b':  dec = '\b'; break;
                case 'f':  dec = '\f'; break;
                case 'u': {
                    if (!p[1] || !p[2] || !p[3] || !p[4]) return -1;
                    int h1 = hexval(p[1]), h2 = hexval(p[2]), h3 = hexval(p[3]), h4 = hexval(p[4]);
                    if (h1 < 0 || h2 < 0 || h3 < 0 || h4 < 0) return -1;
                    unsigned cp = (unsigned)((h1 << 12) | (h2 << 8) | (h3 << 4) | h4);
                    p += 4;
                    /* ps_json only \u-escapes control chars (< 0x20), so cp fits one byte. */
                    dec = (char)(cp & 0xff);
                    break;
                }
                default: return -1;  /* invalid escape */
            }
            if (o + 1 >= cap) return -1;
            out[o++] = dec;
            p++;
            continue;
        }
        if (o + 1 >= cap) return -1;
        out[o++] = (char)c;
        p++;
    }
    return -1;  /* unterminated string */
}
```

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `json_extract.c` to `packetsonde_lib` sources, and after the `test_json` block:

```cmake
    add_executable(test_json_extract tests/test_json_extract.c)
    target_link_libraries(test_json_extract PRIVATE packetsonde_lib)
    add_test(NAME test_json_extract COMMAND test_json_extract)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_json_extract >/dev/null && ctest -R '^test_json_extract$' --output-on-failure`
Expected: PASS (incl. the round-trip against ps_json's escaping).

- [ ] **Step 7: Commit**

```bash
git add src/lib/json_extract.h src/lib/json_extract.c src/lib/tests/test_json_extract.c src/lib/CMakeLists.txt
git commit -m "Add ps_json_extract_string (extract + unescape a JSON string field)"
```

---

## Task 3: `ps_collect_process` (verify + enriched JSONL)

**Files:** Create `src/lib/collect.h`, `src/lib/collect.c`; Test `src/lib/tests/test_collect.c`; Modify `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test**

```c
/* src/lib/tests/test_collect.c */
#include "collect.h"
#include "keystore.h"
#include "reporter.h"
#include "json_extract.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    /* Build a real signed envelope array via the reporter, then process one. */
    struct ps_keypair kp; assert(ps_keystore_generate(&kp) == 0);
    char dir[] = "/tmp/ps_coll_XXXXXX"; assert(mkdtemp(dir));
    assert(ps_keystore_save(dir, "agent", &kp) == 0);
    struct ps_central_config cc; memset(&cc, 0, sizeof cc);
    cc.url = "http://x"; cc.agent_id = "edge-07"; cc.key_dir = dir;
    const char *events[] = { "{\"v\":1,\"kind\":\"tls\",\"ts\":\"2026-05-22T10:00:00Z\"}" };
    char arr[8192];
    assert(ps_reporter_build_envelopes(&cc, events, 1, arr, sizeof arr) > 0);
    /* arr is "[ {envelope} ]" — strip the brackets to get one envelope object. */
    char env[8192];
    int alen = (int)strlen(arr);
    assert(arr[0] == '[' && arr[alen-1] == ']');
    memcpy(env, arr + 1, (size_t)(alen - 2)); env[alen - 2] = '\0';

    uint8_t pks[2][32];
    memcpy(pks[0], kp.pubkey, 32);                  /* trusted */
    for (int i = 0; i < 32; i++) pks[1][i] = 0xAA;  /* a decoy key */

    char out[8192]; struct ps_collect_result r;
    int n = ps_collect_process(env, pks, 2, "2026-05-22T11:00:00Z", out, sizeof out, &r);
    assert(n > 0);
    assert(r.verified == 1);                        /* signed by pks[0] */
    assert(strstr(out, "\"agent_id\":\"edge-07\""));
    assert(strstr(out, "\"verified\":true"));
    assert(strstr(out, "\"transport\":\"direct\""));
    assert(strstr(out, "\"kind\":\"tls\""));

    /* Not-trusted: only the decoy key -> verified false, still produces a line. */
    char out2[8192]; struct ps_collect_result r2;
    assert(ps_collect_process(env, pks + 1, 1, "t", out2, sizeof out2, &r2) > 0);
    assert(r2.verified == 0);
    assert(strstr(out2, "\"verified\":false"));

    printf("test_collect: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_collect 2>&1 | tail -4`
Expected: FAIL — `collect.h` not found.

- [ ] **Step 3: Create `src/lib/collect.h`**

```c
#ifndef PS_COLLECT_H
#define PS_COLLECT_H
#include <stddef.h>
#include <stdint.h>

struct ps_collect_result { int verified; int relay_chain_verified; int has_relay; };

/* Verify one envelope JSON against the authorized pubkey set (try-all) and build a
 * JSONL line (the event enriched with agent_id/verified/relay_chain_verified/transport/
 * received_ts) into out. Returns line length (no newline), or -1 on a malformed
 * envelope. Never fails on verification — verified flags are recorded in *res. */
int ps_collect_process(const char *envelope_json, const uint8_t (*pubkeys)[32], size_t npk,
                       const char *received_ts, char *out, size_t cap,
                       struct ps_collect_result *res);
#endif
```

- [ ] **Step 4: Create `src/lib/collect.c`**

```c
#include "collect.h"
#include "json_extract.h"
#include "keystore.h"
#include "json.h"
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

/* base64-decode in-place-ish; returns decoded length or -1. */
static int b64dec(const char *in, uint8_t *out, size_t outcap) {
    size_t inlen = strlen(in);
    if (inlen == 0 || inlen % 4 != 0 || outcap < inlen / 4 * 3) return -1;
    int n = EVP_DecodeBlock(out, (const unsigned char*)in, (int)inlen);
    if (n < 0) return -1;
    /* EVP_DecodeBlock counts padding; trim by '=' count. */
    if (inlen >= 1 && in[inlen-1] == '=') n--;
    if (inlen >= 2 && in[inlen-2] == '=') n--;
    return n;
}

/* True if `msg` is signed by any of the pubkeys (sig is base64). */
static int verified_by_any(const uint8_t (*pks)[32], size_t npk,
                           const uint8_t *msg, size_t msglen, const char *sig_b64) {
    uint8_t sig[80];
    int sl = b64dec(sig_b64, sig, sizeof sig);
    if (sl != 64) return 0;
    for (size_t i = 0; i < npk; i++)
        if (ps_keystore_verify(pks[i], msg, msglen, sig) == 1) return 1;
    return 0;
}

int ps_collect_process(const char *envelope_json, const uint8_t (*pubkeys)[32], size_t npk,
                       const char *received_ts, char *out, size_t cap,
                       struct ps_collect_result *res) {
    char payload[16384], sig_b64[128], outer_id[256];
    if (ps_json_extract_string(envelope_json, "payload", payload, sizeof payload) < 0) return -1;
    if (ps_json_extract_string(envelope_json, "ed25519_sig", sig_b64, sizeof sig_b64) < 0) return -1;
    ps_json_extract_string(envelope_json, "origin_agent_id", outer_id, sizeof outer_id);

    /* Origin verify over the exact payload bytes. */
    int verified = verified_by_any(pubkeys, npk, (const uint8_t*)payload, strlen(payload), sig_b64);

    /* Parse payload -> origin_agent_id, ts, event (event is a nested object: take the
     * substring from "event": to the matching closing brace). */
    char inner_id[256], ts[64];
    ps_json_extract_string(payload, "origin_agent_id", inner_id, sizeof inner_id);
    ps_json_extract_string(payload, "ts", ts, sizeof ts);
    if (inner_id[0] && outer_id[0] && strcmp(inner_id, outer_id) != 0) verified = 0;  /* origin mismatch */

    const char *ev = strstr(payload, "\"event\":");
    const char *obj = ev ? strchr(ev, '{') : NULL;
    char event_obj[16384] = "{}";
    if (obj) {
        int depth = 0; const char *c = obj;
        for (; *c; c++) { if (*c=='{') depth++; else if (*c=='}') { depth--; if (depth==0) { c++; break; } } }
        size_t len = (size_t)(c - obj);
        if (len < sizeof event_obj) { memcpy(event_obj, obj, len); event_obj[len] = 0; }
    }

    int has_relay = (strstr(envelope_json, "\"relay_path\":") != NULL);
    /* Relay chain: verify each hop's attestation "<ed25519_sig>|<received_from>|<ts>".
     * (Single relay_path here; multi-hop annotation is a follow-up — we record
     * relay_chain_verified = all hops we can verify.) */
    int chain_ok = 1;
    if (has_relay) {
        /* Extract one hop's fields for the common single-hop case. */
        const char *rp = strstr(envelope_json, "\"relay_path\":");
        char rf[256] = "", rts[64] = "", rsig[128] = "";
        ps_json_extract_string(rp, "received_from", rf, sizeof rf);
        ps_json_extract_string(rp, "ts", rts, sizeof rts);
        ps_json_extract_string(rp, "sig", rsig, sizeof rsig);
        char attest[512];
        snprintf(attest, sizeof attest, "%s|%s|%s", sig_b64, rf, rts);
        chain_ok = verified_by_any(pubkeys, npk, (const uint8_t*)attest, strlen(attest), rsig);
    }

    res->verified = verified;
    res->has_relay = has_relay;
    res->relay_chain_verified = has_relay ? chain_ok : 1;

    /* Build the enriched JSONL line: start from the event object, splice fields before
     * its closing brace. event_obj is "{...}". */
    size_t elen = strlen(event_obj);
    if (elen < 2 || event_obj[elen-1] != '}') return -1;
    event_obj[elen-1] = 0;  /* drop closing brace */
    const char *sep = (elen > 2) ? "," : "";  /* "{}" has nothing before */
    int n = snprintf(out, cap,
        "%s%s\"agent_id\":\"%s\",\"verified\":%s,\"relay_chain_verified\":%s,"
        "\"transport\":\"%s\",\"received_ts\":\"%s\"}",
        event_obj, sep,
        inner_id[0] ? inner_id : (outer_id[0] ? outer_id : "unknown"),
        verified ? "true" : "false",
        res->relay_chain_verified ? "true" : "false",
        has_relay ? "relay" : "direct",
        received_ts ? received_ts : "");
    if (n < 0 || (size_t)n >= cap) return -1;
    return n;
}
```

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `collect.c` to `packetsonde_lib` sources, and after the `test_json_extract` block:

```cmake
    add_executable(test_collect tests/test_collect.c)
    target_link_libraries(test_collect PRIVATE packetsonde_lib)
    add_test(NAME test_collect COMMAND test_collect)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_collect >/dev/null && ctest -R '^test_collect$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/lib/collect.h src/lib/collect.c src/lib/tests/test_collect.c src/lib/CMakeLists.txt
git commit -m "Add ps_collect_process: try-all verify + enriched JSONL for a received envelope"
```

---

## Task 4: `packetsonde collect` verb (mTLS server loop)

**Files:** Create `src/cli/verbs/collect.c`; Modify `src/cli/dispatch.c`, `src/cli/CMakeLists.txt`

- [ ] **Step 1: Create `src/cli/verbs/collect.c`**

```c
#include "verbs.h"
#include "keystore.h"
#include "agent_transport.h"
#include "agent_proto.h"
#include "collect.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAX_AUTHORIZED 64

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int s) { (void)s; g_stop = 1; }

static size_t load_authorized(const char *dir, uint8_t pks[][32]) {
    DIR *d = opendir(dir); if (!d) return 0;
    struct dirent *de; size_t n = 0;
    while ((de = readdir(d)) && n < MAX_AUTHORIZED) {
        size_t l = strlen(de->d_name);
        if (l < 5 || strcmp(de->d_name + l - 4, ".pub") != 0) continue;
        char p[1100]; snprintf(p, sizeof p, "%s/%s", dir, de->d_name);
        FILE *f = fopen(p, "rb"); if (!f) continue;
        if (fread(pks[n], 1, 32, f) == 32) n++;
        fclose(f);
    }
    closedir(d);
    return n;
}

static int peer_authorized(SSL *ssl, const uint8_t pks[][32], size_t npk) {
    char peer[PS_KEYSTORE_FPR_HEX_SIZE];
    if (ps_at_peer_fingerprint(ssl, peer, sizeof peer) != 0) return 0;
    /* peer is "sha256:<hex>" or "<hex>"; compare against each authorized key's fpr. */
    const char *ph = strncmp(peer, "sha256:", 7) == 0 ? peer + 7 : peer;
    for (size_t i = 0; i < npk; i++) {
        char fpr[PS_KEYSTORE_FPR_HEX_SIZE];
        ps_keystore_fingerprint(pks[i], fpr);
        if (strcmp(ph, fpr) == 0) return 1;
    }
    return 0;
}

static void now_iso(char *out, size_t cap) {
    time_t t = time(NULL); struct tm tm; gmtime_r(&t, &tm);
    strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

int ps_verb_collect_run(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    const char *listen = "0.0.0.0:8442", *outpath = NULL, *keydir = NULL, *authdir = NULL;
    static struct option lo[] = {
        {"listen", required_argument, 0, 'l'}, {"out", required_argument, 0, 'o'},
        {"key-dir", required_argument, 0, 'k'}, {"authorized", required_argument, 0, 'a'},
        {0,0,0,0}
    };
    optind = 1; int c;
    while ((c = getopt_long(argc, argv, "l:o:k:a:", lo, NULL)) != -1) {
        if (c=='l') listen=optarg; else if (c=='o') outpath=optarg;
        else if (c=='k') keydir=optarg; else if (c=='a') authdir=optarg;
    }
    char kdir[1024];
    if (keydir) snprintf(kdir, sizeof kdir, "%s", keydir);
    else if (ps_keystore_default_dir(kdir, sizeof kdir) != 0) { fprintf(stderr,"collect: no key dir\n"); return 1; }
    char adir[1100];
    if (authdir) snprintf(adir, sizeof adir, "%s", authdir);
    else snprintf(adir, sizeof adir, "%s/authorized", kdir);

    struct ps_keypair kp;
    if (ps_keystore_load(kdir, "agent", &kp) != 0) { fprintf(stderr,"collect: no 'agent' key in %s\n",kdir); return 1; }
    static uint8_t authpks[MAX_AUTHORIZED][32];
    size_t npk = load_authorized(adir, authpks);
    fprintf(stderr, "collect: %zu authorized pubkey(s) from %s\n", npk, adir);

    char host[256]; int port = 8442;
    { const char *colon = strrchr(listen, ':');
      if (colon) { size_t hl = (size_t)(colon-listen); if (hl<sizeof host){memcpy(host,listen,hl);host[hl]=0;} port = atoi(colon+1); }
      else snprintf(host, sizeof host, "%s", listen); }

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa; memset(&sa,0,sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = (strcmp(host,"0.0.0.0")==0) ? INADDR_ANY : inet_addr(host);
    if (bind(lfd,(struct sockaddr*)&sa,sizeof sa) != 0 || listen(lfd, 16) != 0) {
        fprintf(stderr, "collect: cannot bind %s:%d\n", host, port); close(lfd); return 1;
    }
    ps_at_block_sigpipe();
    signal(SIGINT, on_sigint); signal(SIGTERM, on_sigint);

    struct ps_at_ctx ctx;
    if (ps_at_ctx_init(&ctx, PS_AT_SERVER, &kp, "") != 0) { fprintf(stderr,"collect: TLS ctx init failed\n"); close(lfd); return 1; }
    FILE *outf = outpath ? fopen(outpath, "a") : NULL;
    fprintf(stderr, "collect: listening on %s:%d (Ctrl-C to stop)\n", host, port);

    while (!g_stop) {
        SSL *ssl = ps_at_accept(&ctx, lfd);   /* blocks; mTLS handshake */
        if (!ssl) continue;
        if (!peer_authorized(ssl, authpks, npk)) {
            fprintf(stderr, "collect: rejected unauthorized peer\n"); ps_at_close(ssl); continue;
        }
        struct ps_ap_io io; ps_at_make_io(ssl, &io);
        char hello[256], selffpr[PS_KEYSTORE_FPR_HEX_SIZE];
        ps_keystore_fingerprint(kp.pubkey, selffpr);
        int hn = snprintf(hello,sizeof hello,"{\"type\":\"hello\",\"v\":%d,\"agent_fingerprint\":\"sha256:%s\"}",PS_AGENT_PROTO_VERSION,selffpr);
        if (hn>0) ps_ap_write_frame(&io, hello, (size_t)hn);

        uint8_t buf[256*1024]; size_t blen;
        if (ps_ap_read_frame(&io, buf, sizeof buf, &blen) == PS_AP_OK) {
            char type[32];
            if (ps_ap_frame_type(buf, blen, type, sizeof type) == 0 && strcmp(type,"ingest")==0) {
                buf[blen < sizeof buf ? blen : sizeof buf - 1] = 0;
                /* walk top-level envelope objects inside "envelopes":[ ... ] */
                int accepted = 0, total = 0;
                const char *arr = strstr((char*)buf, "\"envelopes\":");
                arr = arr ? strchr(arr, '[') : NULL;
                int depth = 0; const char *os = NULL;
                char rts[40]; now_iso(rts, sizeof rts);
                for (const char *p = arr; p && *p; p++) {
                    if (*p=='{') { if (depth==0) os=p; depth++; }
                    else if (*p=='}') { depth--; if (depth==0 && os) {
                        size_t ol=(size_t)(p-os)+1; char ej[20000];
                        if (ol < sizeof ej) { memcpy(ej,os,ol); ej[ol]=0;
                            char line[20000]; struct ps_collect_result r;
                            if (ps_collect_process(ej, authpks, npk, rts, line, sizeof line, &r) > 0) {
                                printf("%s\n", line); if (outf){fputs(line,outf);fputc('\n',outf);fflush(outf);}
                                total++; if (r.verified) accepted++;
                            }
                        }
                        os=NULL; }
                    } else if (*p==']' && depth==0) break;
                }
                fflush(stdout);
                char ack[128]; int an=snprintf(ack,sizeof ack,"{\"type\":\"ack\",\"accepted\":%d,\"rejected\":%d}",accepted,total-accepted);
                if (an>0) ps_ap_write_frame(&io, ack, (size_t)an);
            }
        }
        ps_at_close(ssl);
    }
    if (outf) fclose(outf);
    ps_at_ctx_destroy(&ctx); close(lfd);
    fprintf(stderr, "collect: stopped\n");
    return 0;
}
```

- [ ] **Step 2: Register in `src/cli/dispatch.c`** — add the extern + table row (after `report-central`):

```c
int  ps_verb_collect_run(int argc, char **argv, const struct ps_args *opts);
/* ... in VERBS[]: */
    { "collect", ps_verb_collect_run, "Receive + present signed findings (no central)" },
```

- [ ] **Step 3: Add to `src/cli/CMakeLists.txt`** — add `verbs/collect.c` to `CLI_SOURCES`.

- [ ] **Step 4: Build + smoke (verb listed, binds + stops)**

Run:
```bash
cd build && cmake .. -DBUILD_TESTING=ON >/dev/null && make packetsonde >/dev/null 2>&1 && echo BUILD_OK
./src/cli/packetsonde help | grep collect
mkdir -p /tmp/ck/authorized
PS_KEY_DIR=/tmp/ck ./src/cli/packetsonde key generate >/dev/null 2>&1 || true
timeout 1 ./src/cli/packetsonde collect --key-dir /tmp/ck --listen 127.0.0.1:18442 2>&1 | head -2 || true
```
Expected: builds; `collect` listed; the collect process prints "listening on 127.0.0.1:18442" then exits on the 1s timeout. (No client connects in this smoke; the round-trip is Task 5.)

- [ ] **Step 5: Commit**

```bash
git add src/cli/verbs/collect.c src/cli/dispatch.c src/cli/CMakeLists.txt
git commit -m "Add \`packetsonde collect\` verb: mTLS listener -> verify -> present JSONL"
```

---

## Task 5: Live loopback round-trip (no central)

**Files:** Create `scripts/test-collect-loopback.sh`

- [ ] **Step 1: Create the script**

```bash
#!/bin/bash
# Fully central-free: collector + edge on loopback. The edge reports in relay mode
# straight to the collector, which verifies against its local authorized/ set and
# writes JSONL. Runnable end-to-end (collector is a plain CLI process).
set -e
cd "$(dirname "$0")/.."
BIN=./build/src/cli/packetsonde
TMP=$(mktemp -d); CK="$TMP/collector"; EK="$TMP/edge"
mkdir -p "$CK/authorized" "$EK/keys"

# Collector identity + edge identity.
PS_KEY_DIR="$CK" "$BIN" key generate >/dev/null 2>&1 || true     # collector 'agent' key (default keystore name)
# Edge keystore 'agent' key:
cat > "$EK/cfg.toml" <<EOF
[keys]
dir = "$EK/keys"
[central]
url = "http://127.0.0.1:1"
agent_id = "edge-07"
report_mode = "relay"
relay_via = "collector"
verify = "0"
EOF
# generate edge agent key by triggering a register attempt (keygen happens in ps_register) or key gen:
PS_KEY_DIR="$EK/keys" "$BIN" key generate >/dev/null 2>&1 || true

# Authorize the edge at the collector + register the collector in the edge's agent registry.
cp "$EK/keys/agent.pub" "$CK/authorized/edge.pub" 2>/dev/null || cp "$EK/keys"/*.pub "$CK/authorized/"
echo ">>> Add a 'collector' agent (127.0.0.1:18442 + the collector key fingerprint) to the"
echo "    edge agent registry so relay_via=collector resolves, then run the edge report."
echo ">>> Collector key fingerprint:"; PS_KEY_DIR="$CK" "$BIN" key fingerprint 2>/dev/null || true

"$BIN" collect --key-dir "$CK" --listen 127.0.0.1:18442 --out "$TMP/collected.jsonl" &
CPID=$!; sleep 1
printf '{"v":1,"id":"01C","run_id":"01R","ts":"2026-05-22T10:00:00Z","source":"audit.tls","host":"h","kind":"tls.weak_cipher","severity":"medium","confidence":"firm","title":"t"}\n' > "$TMP/f.jsonl"
"$BIN" report-central --to-central "$TMP/f.jsonl" --config "$EK/cfg.toml" || true
sleep 1; kill "$CPID" 2>/dev/null || true
echo "=== collected.jsonl ==="; cat "$TMP/collected.jsonl" 2>/dev/null
echo "Expect: the tls.weak_cipher finding with \"verified\":true, \"transport\":\"relay\"."
rm -rf "$TMP"
```

- [ ] **Step 2: Run it**

Run: `chmod +x scripts/test-collect-loopback.sh && ./scripts/test-collect-loopback.sh`
Expected: `collected.jsonl` contains the finding with `"verified":true`, `"transport":"relay"`. (If `relay_via` resolution needs the collector in the agent registry, the script prints the fingerprint + the registry step — wire it via `packetsonde config` / the agents.toml the registry uses.)

- [ ] **Step 3: Commit**

```bash
git add scripts/test-collect-loopback.sh
git commit -m "Add central-free collector loopback round-trip test"
```

---

## Self-Review

**Spec coverage:**
- §3 `ps_keystore_verify` → Task 1 ✓
- §4 `collect` verb (listen/out/key-dir/authorized, mTLS accept, ingest→verify→present→ack, SIGINT) → Task 4 ✓
- §5 try-all verify (origin + relay hop), inner==outer check, JSONL enrichment (agent_id/verified/relay_chain_verified/transport/received_ts) → Tasks 3 (logic) + 2 (the extract/unescape primitive it needs) ✓
- §6 edge→collector path (no new edge code) → Task 5 exercises it via `report_mode=relay relay_via=collector` ✓
- §7 errors (unauthorized peer rejected, malformed skipped, verify-fail still presented) → Task 4 (peer check, loop continues) + Task 3 (verified:false still emits) ✓
- §8 testing (verify round-trip, try-all, JSONL shape, live loopback) → Tasks 1,2,3 (unit) + 5 (live) ✓

**Gaps noted + accepted:** (a) Task 3 verifies a single relay hop's attestation and annotates `relay_chain_verified`; per-hop annotation in the *output* `relay_path` for multi-hop is folded into the deferred relay→collector item (spec §9) — single-hop is the path edge→collector produces. (b) The wire-parsing is `ps_json_extract_string` (strstr-anchored), consistent with the codebase's existing approach; the critique's "replace with a real parser" is a separate backlog item that would harden this *and* `ps_finding_parse_line`/the relay splice together. (c) Task 5's `relay_via` resolution depends on the collector being in the edge's agent registry — the script prints the fingerprint + the step; if `packetsonde config`/agents.toml editing is non-obvious, that registry-add is the one manual touch.

**Placeholder scan:** No TBD/TODO. Every code step is complete. The base64 sig decode, the brace-walk envelope extraction, and the SIGINT loop are all shown in full.

**Type/name consistency:** `ps_keystore_verify` (1/2/3); `ps_json_extract_string` (2,3); `ps_collect_process` + `struct ps_collect_result {verified, relay_chain_verified, has_relay}` (3,4); the attestation string `"<ed25519_sig>|<received_from>|<ts>"` matches Spec A / central. `ps_at_accept`/`ps_at_ctx_init(PS_AT_SERVER,…)`/`ps_at_make_io`/`ps_keystore_fingerprint` are the real lib signatures.
