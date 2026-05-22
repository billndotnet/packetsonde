# packetsonde Event Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A validated agent signs findings into envelopes and POSTs them to central `/events`, where they land in `ps_events` attributed to the agent's pinned key — using sign-over-transmitted-bytes so there is no cross-language canonical-JSON parity to maintain.

**Architecture:** The envelope carries the signed region as an opaque `payload` *string*; central verifies the Ed25519 signature over the exact received `payload` bytes, then parses it (no re-canonicalization). The agent builds the payload (`{"origin_agent_id","ts","event"}`) with plain `snprintf` (order/escaping irrelevant), signs it with the keystore `agent` key, and embeds it as an escaped string in the envelope JSON. A reusable C reporter (`src/lib/reporter`) does event→payload→sign→POST; two CLI surfaces feed it (`report --to-central`, `audit --report`). The only central change is the verify site + envelope parse.

**Tech Stack:** C11 + OpenSSL (agent), CMake/CTest; Python + Elasticsearch (central, `rna-packetsonde`), pytest. Reuses `http_client`, `keystore`, `finding`, `[central]` config from the merged registration work.

**Spec:** `docs/specs/2026-05-22-event-reporting-design.md`.

**Two repos:** central tasks (1–2) are in `/opt/repo/rna-packetsonde`; agent tasks (3–8) in `/opt/repo/packetsonde`. Build agent with `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON && make <target> && ctest -R <name>`. Central tests: `cd /opt/repo/rna-packetsonde && python -m pytest tests/...` (the module's conftest stubs the framework; no live ES needed for envelope/ingest unit tests).

---

## Interfaces locked here (names must match across tasks)

- **Envelope wire shape** (one element of `envelopes[]`):
  `{ "envelope_v":1, "origin_agent_id":"<id>", "payload":"<json string>", "ed25519_sig":"<base64>" }`
  where `payload` (the signed bytes) decodes to `{"origin_agent_id":"<id>","ts":"<iso>","event":{…}}`.
- **`src/lib/keystore.h`:** `int ps_keystore_sign(const struct ps_keypair *kp, const uint8_t *msg, size_t msg_len, uint8_t sig64[64]);` → 0 ok, -1 fail.
- **`src/lib/reporter.h`:**
  - `struct ps_report_result { int accepted; int rejected; int total; int http_status; };`
  - `int ps_report_events(const struct ps_central_config *cc, const char *base_url, const char **event_jsons, size_t n, struct ps_report_result *out);` → 0 on completed HTTP exchange, -1 transport/local error. `base_url` NULL → use `cc->url`.
  - `int ps_report_findings(const struct ps_central_config *cc, const char *base_url, const struct ps_finding *findings, size_t n, struct ps_report_result *out);`

---

## Task 1: Central — envelope accepts `payload` string

**Files:**
- Modify: `/opt/repo/rna-packetsonde/service/envelope.py`
- Test: `/opt/repo/rna-packetsonde/tests/test_envelope.py` (create if absent)

- [ ] **Step 1: Write the failing test**

```python
# /opt/repo/rna-packetsonde/tests/test_envelope.py
import json
import pytest
from service.envelope import parse_envelope, EnvelopeError

def _wire(origin="edge-07", ts="2026-05-22T10:00:00Z", event=None, payload=None):
    event = {"v": 1, "kind": "tls"} if event is None else event
    if payload is None:
        payload = json.dumps({"origin_agent_id": origin, "ts": ts, "event": event})
    return {"envelope_v": 1, "origin_agent_id": origin, "payload": payload, "ed25519_sig": "QQ=="}

def test_parse_extracts_payload_and_parsed_fields():
    env = parse_envelope(_wire())
    assert env.payload == json.dumps(
        {"origin_agent_id": "edge-07", "ts": "2026-05-22T10:00:00Z", "event": {"v": 1, "kind": "tls"}})
    assert env.origin_agent_id == "edge-07"
    assert env.ts == "2026-05-22T10:00:00Z"
    assert env.event == {"v": 1, "kind": "tls"}

def test_missing_payload_rejected():
    raw = _wire(); del raw["payload"]
    with pytest.raises(EnvelopeError):
        parse_envelope(raw)

def test_inner_outer_origin_mismatch_rejected():
    bad_payload = json.dumps({"origin_agent_id": "OTHER", "ts": "2026-05-22T10:00:00Z", "event": {"v": 1}})
    with pytest.raises(EnvelopeError):
        parse_envelope(_wire(payload=bad_payload))

def test_payload_not_json_rejected():
    with pytest.raises(EnvelopeError):
        parse_envelope(_wire(payload="not json"))
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/rna-packetsonde && python -m pytest tests/test_envelope.py -q`
Expected: FAIL — current `parse_envelope` requires `event`/`ts` top-level, has no `payload`, and `Envelope` has no `payload` field.

- [ ] **Step 3: Rewrite `service/envelope.py`**

```python
"""Signed-envelope parsing for sign-over-transmitted-bytes.

The signed region is the literal `payload` string the agent serialized and signed:
{"origin_agent_id","ts","event"}. Central verifies the Ed25519 signature over the
exact received payload bytes (see ingest), then trusts the parsed payload. No
re-canonicalization — the agent and central never need byte-identical JSON
serializers.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


class EnvelopeError(ValueError):
    """Raised when an envelope is structurally invalid."""


@dataclass(frozen=True)
class Envelope:
    envelope_v: int
    origin_agent_id: str
    ts: str
    ed25519_sig: str
    event: dict[str, Any]
    payload: str  # the exact signed bytes (UTF-8 text), verified as-is


_REQUIRED = ("origin_agent_id", "payload", "ed25519_sig")


def parse_envelope(raw: dict) -> Envelope:
    if not isinstance(raw, dict):
        raise EnvelopeError("envelope must be an object")
    for field in _REQUIRED:
        if field not in raw or raw[field] in (None, ""):
            raise EnvelopeError(f"missing required field: {field}")
    if not isinstance(raw["origin_agent_id"], str):
        raise EnvelopeError("origin_agent_id must be a string")
    if not isinstance(raw["payload"], str):
        raise EnvelopeError("payload must be a string")

    try:
        inner = json.loads(raw["payload"])
    except (ValueError, TypeError):
        raise EnvelopeError("payload is not valid JSON")
    if not isinstance(inner, dict):
        raise EnvelopeError("payload must decode to an object")
    if not isinstance(inner.get("event"), dict):
        raise EnvelopeError("payload.event must be an object")
    if inner.get("origin_agent_id") != raw["origin_agent_id"]:
        raise EnvelopeError("payload.origin_agent_id must match outer origin_agent_id")

    return Envelope(
        envelope_v=int(raw.get("envelope_v", 1)),
        origin_agent_id=raw["origin_agent_id"],
        ts=str(inner.get("ts", "")),
        ed25519_sig=str(raw["ed25519_sig"]),
        event=inner["event"],
        payload=raw["payload"],
    )
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd /opt/repo/rna-packetsonde && python -m pytest tests/test_envelope.py -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
cd /opt/repo/rna-packetsonde
git add service/envelope.py tests/test_envelope.py
git commit -m "envelope: accept signed payload string; bind inner==outer origin_agent_id"
```

---

## Task 2: Central — verify over payload bytes (ingest)

**Files:**
- Modify: `/opt/repo/rna-packetsonde/service/ingest.py`
- Test: `/opt/repo/rna-packetsonde/tests/test_ingest_verify.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# /opt/repo/rna-packetsonde/tests/test_ingest_verify.py
import base64, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from service.ingest import Ingestor

class _Reg:
    def __init__(self, pub_b64): self._pub = pub_b64
    def get(self, agent_id):
        return {"status": "validated", "pubkey": self._pub} if agent_id == "edge-07" else None

class _ES:
    def __init__(self): self.docs = []
    def index(self, index, id, document): self.docs.append((index, id, document))

def _signed_wire(sk, origin="edge-07"):
    payload = json.dumps({"origin_agent_id": origin, "ts": "2026-05-22T10:00:00Z",
                          "event": {"v": 1, "kind": "tls", "title": "x"}})
    sig = base64.b64encode(sk.sign(payload.encode("utf-8"))).decode()
    return {"envelope_v": 1, "origin_agent_id": origin, "payload": payload, "ed25519_sig": sig}

def _pub_b64(sk):
    from cryptography.hazmat.primitives import serialization
    raw = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()

def test_valid_payload_signature_accepted():
    sk = Ed25519PrivateKey.generate()
    ing = Ingestor(_Reg(_pub_b64(sk)), _ES())
    r = ing.ingest(_signed_wire(sk), transport="direct", relay_path=None, relay_identity=None)
    assert r.status == "accepted"

def test_tampered_payload_rejected():
    sk = Ed25519PrivateKey.generate()
    wire = _signed_wire(sk)
    wire["payload"] = wire["payload"].replace('"tls"', '"ssh"')  # changed after signing
    ing = Ingestor(_Reg(_pub_b64(sk)), _ES())
    r = ing.ingest(wire, transport="direct", relay_path=None, relay_identity=None)
    assert r.status == "rejected_bad_sig"
```

(`IngestResult` exposes `.status`; confirm by reading the top of `service/ingest.py`. If the field differs, match it in the asserts.)

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/rna-packetsonde && python -m pytest tests/test_ingest_verify.py -q`
Expected: FAIL — ingest still calls `canonical_signed_bytes(env)`, which no longer exists/imports, or verifies the wrong bytes.

- [ ] **Step 3: Edit `service/ingest.py`**

Change the import line that brings in `canonical_signed_bytes` to drop it:

```python
from .envelope import EnvelopeError, parse_envelope
```

Replace the verification call:

```python
        if not verify_ed25519(
            record["pubkey"], env.ed25519_sig, env.payload.encode("utf-8")
        ):
            return IngestResult("rejected_bad_sig")
```

(Everything below — `skew_ms`, `doc_id` from the sig, `doc = dict(env.event)` + `agent_id`/`ts`/`received_ts`/`transport`/`relay_path`/`relay_identity`, the index call, drift — is unchanged.)

- [ ] **Step 4: Run to verify it passes**

Run: `cd /opt/repo/rna-packetsonde && python -m pytest tests/test_ingest_verify.py tests/test_envelope.py -q`
Expected: PASS.

- [ ] **Step 5: Run the module's existing suite to catch fallout**

Run: `cd /opt/repo/rna-packetsonde && python -m pytest tests/ -q -k "envelope or ingest or events"`
Expected: PASS, or update any old test still constructing the pre-`payload` envelope shape to the new shape.

- [ ] **Step 6: Commit**

```bash
cd /opt/repo/rna-packetsonde
git add service/ingest.py tests/test_ingest_verify.py
git commit -m "ingest: verify Ed25519 over transmitted payload bytes (no re-canonicalization)"
```

---

## Task 3: Agent — `ps_keystore_sign`

**Files:**
- Modify: `/opt/repo/packetsonde/src/lib/keystore.h`, `/opt/repo/packetsonde/src/lib/keystore.c`
- Test: `/opt/repo/packetsonde/src/lib/tests/test_keystore_sign.c` (create) + `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test**

```c
/* src/lib/tests/test_keystore_sign.c */
#include "keystore.h"
#include <openssl/evp.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    struct ps_keypair kp;
    assert(ps_keystore_generate(&kp) == 0);

    const char *msg = "{\"origin_agent_id\":\"edge-07\",\"ts\":\"t\",\"event\":{}}";
    uint8_t sig[64];
    assert(ps_keystore_sign(&kp, (const uint8_t*)msg, strlen(msg), sig) == 0);

    /* Verify with OpenSSL directly against the public key. */
    EVP_PKEY *pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                                kp.pubkey, PS_KEYSTORE_PUBKEY_SIZE);
    assert(pub);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    assert(EVP_DigestVerifyInit(m, NULL, NULL, NULL, pub) == 1);
    assert(EVP_DigestVerify(m, sig, 64, (const uint8_t*)msg, strlen(msg)) == 1);

    /* A flipped byte must fail. */
    sig[0] ^= 0xff;
    EVP_MD_CTX *m2 = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(m2, NULL, NULL, NULL, pub);
    assert(EVP_DigestVerify(m2, sig, 64, (const uint8_t*)msg, strlen(msg)) != 1);

    EVP_MD_CTX_free(m); EVP_MD_CTX_free(m2); EVP_PKEY_free(pub);
    printf("test_keystore_sign: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_keystore_sign 2>&1 | tail -5`
Expected: FAIL — `ps_keystore_sign` undeclared.

- [ ] **Step 3: Declare in `keystore.h`** (after `ps_keystore_load`):

```c
/* Ed25519-sign msg with kp's secret key. sig64 receives the 64-byte signature.
 * Returns 0 on success, -1 on any OpenSSL failure. */
int ps_keystore_sign(const struct ps_keypair *kp, const uint8_t *msg,
                     size_t msg_len, uint8_t sig64[64]);
```

- [ ] **Step 4: Implement in `keystore.c`** (append; mirrors discovery.c's one-shot signer):

```c
#include <openssl/evp.h>

int ps_keystore_sign(const struct ps_keypair *kp, const uint8_t *msg,
                     size_t msg_len, uint8_t sig64[64]) {
    EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                kp->seckey, PS_KEYSTORE_SECKEY_SIZE);
    if (!pk) return -1;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    size_t sl = 64;
    int ok = m
        && EVP_DigestSignInit(m, NULL, NULL, NULL, pk) == 1
        && EVP_DigestSign(m, sig64, &sl, msg, msg_len) == 1
        && sl == 64;
    if (m) EVP_MD_CTX_free(m);
    EVP_PKEY_free(pk);
    return ok ? 0 : -1;
}
```

(Ensure `keystore.c` includes `<openssl/evp.h>` once — add the include at the top if not already present rather than mid-file.)

- [ ] **Step 5: Wire the test in `src/lib/CMakeLists.txt`** (after the `test_registration` block):

```cmake
    add_executable(test_keystore_sign tests/test_keystore_sign.c)
    target_link_libraries(test_keystore_sign PRIVATE packetsonde_lib)
    add_test(NAME test_keystore_sign COMMAND test_keystore_sign)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_keystore_sign >/dev/null && ctest -R '^test_keystore_sign$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /opt/repo/packetsonde
git add src/lib/keystore.h src/lib/keystore.c src/lib/tests/test_keystore_sign.c src/lib/CMakeLists.txt
git commit -m "keystore: add ps_keystore_sign (Ed25519 one-shot over arbitrary bytes)"
```

---

## Task 4: Agent — reporter library

**Files:**
- Create: `/opt/repo/packetsonde/src/lib/reporter.h`, `/opt/repo/packetsonde/src/lib/reporter.c`
- Test: `/opt/repo/packetsonde/src/lib/tests/test_reporter.c` + `src/lib/CMakeLists.txt`

- [ ] **Step 1: Write the failing test** (covers the two pure builders; the POST is exercised live in Task 8)

```c
/* src/lib/tests/test_reporter.c */
#include "reporter.h"
#include "keystore.h"
#include <openssl/evp.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

/* Internal helpers exposed for testing (declared in reporter.h under PS_REPORTER_TESTING). */
int ps_reporter_build_payload(char *buf, size_t cap, const char *agent_id,
                              const char *ts, const char *event_json);
int ps_reporter_extract_ts(const char *event_json, char *out, size_t cap);

static void test_extract_ts(void) {
    char ts[32];
    assert(ps_reporter_extract_ts("{\"v\":1,\"id\":\"A\",\"ts\":\"2026-05-22T10:00:00Z\",\"kind\":\"tls\"}", ts, sizeof ts) == 0);
    assert(strcmp(ts, "2026-05-22T10:00:00Z") == 0);
}

static void test_build_payload(void) {
    char p[512];
    int n = ps_reporter_build_payload(p, sizeof p, "edge-07", "2026-05-22T10:00:00Z",
                                      "{\"v\":1,\"kind\":\"tls\"}");
    assert(n > 0);
    /* exact bytes; central will verify these */
    assert(strcmp(p, "{\"origin_agent_id\":\"edge-07\",\"ts\":\"2026-05-22T10:00:00Z\",\"event\":{\"v\":1,\"kind\":\"tls\"}}") == 0);
}

static void test_payload_signs_and_verifies(void) {
    struct ps_keypair kp; assert(ps_keystore_generate(&kp) == 0);
    char p[512];
    ps_reporter_build_payload(p, sizeof p, "edge-07", "t", "{\"v\":1}");
    uint8_t sig[64];
    assert(ps_keystore_sign(&kp, (const uint8_t*)p, strlen(p), sig) == 0);
    EVP_PKEY *pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, kp.pubkey, 32);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(m, NULL, NULL, NULL, pub);
    assert(EVP_DigestVerify(m, sig, 64, (const uint8_t*)p, strlen(p)) == 1);
    EVP_MD_CTX_free(m); EVP_PKEY_free(pub);
}

int main(void) {
    test_extract_ts(); test_build_payload(); test_payload_signs_and_verifies();
    printf("test_reporter: OK\n");
    return 0;
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_reporter 2>&1 | tail -5`
Expected: FAIL — `reporter.h` not found.

- [ ] **Step 3: Create `src/lib/reporter.h`**

```c
#ifndef PS_REPORTER_H
#define PS_REPORTER_H
#include <stddef.h>
#include "central_config.h"
#include "finding.h"

struct ps_report_result { int accepted; int rejected; int total; int http_status; };

/* Sign + POST raw event-JSON strings to central as one {envelopes:[…]} batch.
 * base_url NULL -> cc->url. Returns 0 on a completed HTTP exchange (inspect out),
 * -1 on transport/local error. */
int ps_report_events(const struct ps_central_config *cc, const char *base_url,
                     const char **event_jsons, size_t n, struct ps_report_result *out);

/* Serialize findings to event JSON, then ps_report_events. */
int ps_report_findings(const struct ps_central_config *cc, const char *base_url,
                       const struct ps_finding *findings, size_t n,
                       struct ps_report_result *out);

/* Exposed for unit tests. */
int ps_reporter_build_payload(char *buf, size_t cap, const char *agent_id,
                              const char *ts, const char *event_json);
int ps_reporter_extract_ts(const char *event_json, char *out, size_t cap);
#endif
```

- [ ] **Step 4: Create `src/lib/reporter.c`**

```c
#include "reporter.h"
#include "http_client.h"
#include "keystore.h"
#include "json.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int ps_reporter_extract_ts(const char *event_json, char *out, size_t cap) {
    const char *k = strstr(event_json, "\"ts\":\"");
    if (!k) return -1;
    k += 6;
    const char *end = strchr(k, '"');
    if (!end) return -1;
    size_t len = (size_t)(end - k);
    if (len >= cap) len = cap - 1;
    memcpy(out, k, len); out[len] = 0;
    return 0;
}

int ps_reporter_build_payload(char *buf, size_t cap, const char *agent_id,
                              const char *ts, const char *event_json) {
    /* Order/escaping irrelevant — central verifies these exact bytes, then parses.
     * agent_id/ts are controlled (ids + ISO timestamps); event_json is embedded raw. */
    int n = snprintf(buf, cap,
        "{\"origin_agent_id\":\"%s\",\"ts\":\"%s\",\"event\":%s}",
        agent_id, ts, event_json);
    if (n < 0 || (size_t)n >= cap) return -1;
    return n;
}

static int b64(const uint8_t *in, size_t n, char *out, size_t cap) {
    int len = EVP_EncodeBlock((unsigned char *)out, in, (int)n);
    return (len < 0 || (size_t)len >= cap) ? -1 : len;
}

int ps_report_events(const struct ps_central_config *cc, const char *base_url,
                     const char **event_jsons, size_t n, struct ps_report_result *out) {
    if (!cc || !cc->url || !cc->url[0]) return -1;
    const char *keydir = (cc->key_dir && cc->key_dir[0]) ? cc->key_dir : "/etc/packetsonded/keys";
    struct ps_keypair kp;
    if (ps_keystore_load(keydir, "agent", &kp) != 0) return -1;

    char host[256];
    const char *agent_id = (cc->agent_id && cc->agent_id[0]) ? cc->agent_id
                          : (gethostname(host, sizeof host) == 0 ? host : "unknown");

    /* Assemble {"envelopes":[ {…}, … ]} by hand: payload is embedded as an escaped
     * string via ps_json so we get correct JSON-string quoting. */
    static char body[262144];   /* 256 KiB batch cap */
    size_t bo = 0;
    bo += (size_t)snprintf(body + bo, sizeof body - bo, "{\"envelopes\":[");
    for (size_t i = 0; i < n; i++) {
        char ts[40];
        if (ps_reporter_extract_ts(event_jsons[i], ts, sizeof ts) != 0)
            snprintf(ts, sizeof ts, "1970-01-01T00:00:00Z");
        char payload[16384];
        if (ps_reporter_build_payload(payload, sizeof payload, agent_id, ts, event_jsons[i]) < 0)
            continue;
        uint8_t sig[64];
        if (ps_keystore_sign(&kp, (const uint8_t*)payload, strlen(payload), sig) != 0) return -1;
        char sig_b64[128];
        if (b64(sig, 64, sig_b64, sizeof sig_b64) < 0) return -1;

        /* one envelope object via ps_json (escapes payload + sig correctly) */
        char env[20000]; struct ps_json j; ps_json_init(&j, env, sizeof env);
        ps_json_object_begin(&j);
        ps_json_key_int(&j, "envelope_v", 1);
        ps_json_key_string(&j, "origin_agent_id", agent_id);
        ps_json_key_string(&j, "payload", payload);
        ps_json_key_string(&j, "ed25519_sig", sig_b64);
        ps_json_object_end(&j);
        if (ps_json_finish(&j) < 0) return -1;

        bo += (size_t)snprintf(body + bo, sizeof body - bo, "%s%s", i ? "," : "", env);
        if (bo >= sizeof body - 64) break;  /* batch full; caller can chunk */
    }
    bo += (size_t)snprintf(body + bo, sizeof body - bo, "]}");

    char url[640];
    snprintf(url, sizeof url, "%s/api/v1/packetsonde/events",
             (base_url && base_url[0]) ? base_url : cc->url);
    struct ps_http_opts opts = { cc->verify, cc->ca_cert, 15 };
    int status = 0; char resp[8192];
    if (ps_http_request("POST", url, body, &opts, &status, resp, sizeof resp) != 0) return -1;

    if (out) {
        out->http_status = status;
        out->total = (int)n;
        /* central returns {"accepted":N,...}; pull the integer if present */
        const char *a = strstr(resp, "\"accepted\":");
        out->accepted = a ? atoi(a + 11) : 0;
        out->rejected = out->total - out->accepted;
    }
    return 0;
}

int ps_report_findings(const struct ps_central_config *cc, const char *base_url,
                       const struct ps_finding *findings, size_t n,
                       struct ps_report_result *out) {
    /* Serialize each finding to its event JSON, then report. */
    const char **events = calloc(n, sizeof(char*));
    char *blob = malloc(n * 8192);
    if (!events || !blob) { free(events); free(blob); return -1; }
    size_t ok = 0;
    for (size_t i = 0; i < n; i++) {
        char *slot = blob + i * 8192;
        int len = ps_finding_to_json(&findings[i], slot, 8192);
        if (len < 0) continue;
        if (len > 0 && slot[len-1] == '\n') slot[len-1] = 0;  /* drop trailing newline */
        events[ok++] = slot;
    }
    int rc = ps_report_events(cc, base_url, events, ok, out);
    free(events); free(blob);
    return rc;
}
```

(Add `#include <stdlib.h>` for `calloc`/`malloc`/`atoi`.)

- [ ] **Step 5: Wire into `src/lib/CMakeLists.txt`** — add `reporter.c` to the `packetsonde_lib` sources, and after the `test_keystore_sign` block:

```cmake
    add_executable(test_reporter tests/test_reporter.c)
    target_link_libraries(test_reporter PRIVATE packetsonde_lib)
    add_test(NAME test_reporter COMMAND test_reporter)
```

- [ ] **Step 6: Run to verify it passes**

Run: `cd /opt/repo/packetsonde/build && cmake .. -DBUILD_TESTING=ON >/dev/null && make test_reporter >/dev/null && ctest -R '^test_reporter$' --output-on-failure`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd /opt/repo/packetsonde
git add src/lib/reporter.h src/lib/reporter.c src/lib/tests/test_reporter.c src/lib/CMakeLists.txt
git commit -m "Add reporter lib: event->payload->sign->POST /events (batch envelopes)"
```

---

## Task 5: Agent — `packetsonde report --to-central` verb

**Files:**
- Create: `/opt/repo/packetsonde/src/cli/verbs/report_central.c`
- Modify: `/opt/repo/packetsonde/src/cli/dispatch.c`, `/opt/repo/packetsonde/src/cli/CMakeLists.txt`

> Note: a `report` verb already exists (Markdown report from JSONL). To avoid colliding, this adds a **new** verb `report-central` (kebab) wired as its own dispatch entry. Reuse the `unq()` quote-stripping idiom from `verbs/register.c` for `[central]` values.

- [ ] **Step 1: Create `src/cli/verbs/report_central.c`**

```c
#include "verbs.h"
#include "config.h"
#include "central_config.h"
#include "reporter.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

static const char *unq(const char *v, char *buf, size_t cap) {
    if (!v) return NULL;
    size_t n = strlen(v);
    if (n >= 2 && v[0] == '"' && v[n-1] == '"') {
        size_t inner = n - 2; if (inner >= cap) inner = cap - 1;
        memcpy(buf, v + 1, inner); buf[inner] = 0;
    } else snprintf(buf, cap, "%s", v);
    return buf;
}

int ps_verb_report_central_run(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    const char *cfg_path = "/etc/packetsonded/packetsonded.toml";
    const char *jsonl = NULL, *endpoint = NULL;
    static struct option lo[] = {
        {"config", required_argument, 0, 'c'},
        {"to-central", required_argument, 0, 't'},
        {"endpoint", required_argument, 0, 'e'},
        {0,0,0,0}
    };
    optind = 1; int c;
    while ((c = getopt_long(argc, argv, "c:t:e:", lo, NULL)) != -1) {
        if (c == 'c') cfg_path = optarg;
        else if (c == 't') jsonl = optarg;
        else if (c == 'e') endpoint = optarg;
    }
    if (!jsonl) { fprintf(stderr, "usage: packetsonde report-central --to-central <findings.jsonl>\n"); return 2; }

    struct ps_config cfg;
    if (ps_config_parse_file(&cfg, cfg_path) != 0) { fprintf(stderr, "report-central: cannot read %s\n", cfg_path); return 1; }
    char ub_url[512], ub_id[256], ub_ca[512], ub_kd[512];
    struct ps_central_config cc;
    cc.url = unq(ps_config_get(&cfg,"central","url"), ub_url, sizeof ub_url);
    cc.agent_id = unq(ps_config_get(&cfg,"central","agent_id"), ub_id, sizeof ub_id);
    cc.deployment_mode = NULL;
    const char *v = ps_config_get(&cfg,"central","verify");
    cc.verify = (v && strstr(v,"0")) ? 0 : 1;
    cc.ca_cert = unq(ps_config_get(&cfg,"central","ca_cert"), ub_ca, sizeof ub_ca);
    cc.checkin_seconds = 60;
    cc.key_dir = unq(ps_config_get(&cfg,"keys","dir"), ub_kd, sizeof ub_kd);

    FILE *f = fopen(jsonl, "r");
    if (!f) { fprintf(stderr, "report-central: cannot open %s\n", jsonl); ps_config_free(&cfg); return 1; }

    /* Collect event lines (each JSONL line is already the event object). */
    char **events = NULL; size_t n = 0, capn = 0;
    char line[16384];
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] != '{') continue;
        if (n == capn) { capn = capn ? capn*2 : 64; events = realloc(events, capn*sizeof(char*)); }
        events[n++] = strdup(line);
    }
    fclose(f);

    struct ps_report_result r = {0};
    int rc = ps_report_events(&cc, endpoint, (const char**)events, n, &r);
    for (size_t i = 0; i < n; i++) free(events[i]);
    free(events);
    ps_config_free(&cfg);

    if (rc != 0) { fprintf(stderr, "report-central: central unreachable / send failed\n"); return 2; }
    printf("reported: accepted %d / rejected %d of %d (HTTP %d)\n", r.accepted, r.rejected, r.total, r.http_status);
    return r.rejected == 0 ? 0 : 3;
}
```

- [ ] **Step 2: Register in `src/cli/dispatch.c`** — add the extern (next to `ps_verb_register_run`) and a table row (after `register`):

```c
int  ps_verb_report_central_run(int argc, char **argv, const struct ps_args *opts);
/* ... in VERBS[]: */
    { "report-central", ps_verb_report_central_run, "Report findings JSONL to central /events" },
```

- [ ] **Step 3: Add to `src/cli/CMakeLists.txt`** — add `verbs/report_central.c` to `CLI_SOURCES` (next to `verbs/register.c`).

- [ ] **Step 4: Build + smoke-test (missing-url path)**

Run:
```bash
cd /opt/repo/packetsonde/build && make packetsonde >/dev/null 2>&1
./src/cli/packetsonde help | grep report-central
printf '{"v":1,"id":"A","run_id":"R","ts":"2026-05-22T10:00:00Z","source":"audit.tls","host":"h","kind":"tls.weak","severity":"medium","confidence":"firm","title":"t"}\n' > /tmp/f.jsonl
printf '[keys]\ndir="/tmp/k"\n[central]\nurl=""\n' > /tmp/empty.toml; mkdir -p /tmp/k
./src/cli/packetsonde report-central --to-central /tmp/f.jsonl --config /tmp/empty.toml; echo "exit=$?"
```
Expected: verb listed; with empty url the reporter returns -1 → "central unreachable / send failed", exit 2.

- [ ] **Step 5: Commit**

```bash
cd /opt/repo/packetsonde
git add src/cli/verbs/report_central.c src/cli/dispatch.c src/cli/CMakeLists.txt
git commit -m "Add `packetsonde report-central --to-central` verb"
```

---

## Task 6: Agent — `audit … --report` flag

**Files:**
- Modify: `/opt/repo/packetsonde/src/cli/verbs/audit.c`

> Read `verbs/audit.c` first to find where it has the full set of findings in memory (the loop/array it prints or writes to JSONL). Add a `--report` flag that, after that point, calls the reporter with those findings.

- [ ] **Step 1: Add the flag + reporting call in `audit.c`**

Add to audit's option parsing a `--report` boolean (`int report_to_central = 0;` set when the flag is seen — match audit.c's existing getopt/option style). Near the top add:

```c
#include "central_config.h"
#include "reporter.h"
#include "config.h"
```

After the audit has produced its findings array (call it `findings`, count `nf` — match the actual names in audit.c), add:

```c
    if (report_to_central) {
        struct ps_config cfg;
        if (ps_config_parse_file(&cfg, "/etc/packetsonded/packetsonded.toml") == 0) {
            char ub_url[512], ub_id[256], ub_ca[512], ub_kd[512];
            struct ps_central_config cc;
            cc.url = unq(ps_config_get(&cfg,"central","url"), ub_url, sizeof ub_url);   /* unq: copy register.c's helper or move it to a shared header */
            cc.agent_id = unq(ps_config_get(&cfg,"central","agent_id"), ub_id, sizeof ub_id);
            cc.deployment_mode = NULL;
            const char *v = ps_config_get(&cfg,"central","verify");
            cc.verify = (v && strstr(v,"0")) ? 0 : 1;
            cc.ca_cert = unq(ps_config_get(&cfg,"central","ca_cert"), ub_ca, sizeof ub_ca);
            cc.checkin_seconds = 60;
            cc.key_dir = unq(ps_config_get(&cfg,"keys","dir"), ub_kd, sizeof ub_kd);
            struct ps_report_result rr = {0};
            if (ps_report_findings(&cc, NULL, findings, (size_t)nf, &rr) == 0)
                fprintf(stderr, "reported to central: accepted %d / rejected %d of %d\n", rr.accepted, rr.rejected, rr.total);
            else
                fprintf(stderr, "report to central failed (central unreachable / not configured)\n");
            ps_config_free(&cfg);
        }
    }
```

To avoid duplicating `unq()` three times (register.c, report_central.c, audit.c), move it once into a tiny shared header `src/cli/cli_config_util.h` as a `static inline` and include it in all three. Do that move as part of this step (create the header with the `unq` body from Task 5 Step 1, and replace the local copies with the include).

- [ ] **Step 2: Build + smoke-test**

Run:
```bash
cd /opt/repo/packetsonde/build && make packetsonde >/dev/null 2>&1 && echo BUILD_OK
./src/cli/packetsonde audit --help 2>&1 | grep -i report || echo "(flag present in audit usage)"
```
Expected: builds; `--report` accepted by the audit verb (a full audit run is exercised live in Task 8).

- [ ] **Step 3: Commit**

```bash
cd /opt/repo/packetsonde
git add src/cli/verbs/audit.c src/cli/cli_config_util.h src/cli/verbs/register.c src/cli/verbs/report_central.c
git commit -m "audit: --report sends findings to central; share unq() config helper"
```

---

## Task 7: Cross-language signing parity test

**Files:**
- Create: `/opt/repo/packetsonde/scripts/test-signing-parity.sh`

- [ ] **Step 1: Create the script** (C signs a payload; Python verifies with the same key — the proof that the agent's signatures are acceptable to central)

```bash
#!/bin/bash
# Prove the agent's Ed25519 signature over a payload verifies in Python (central's
# verify path), with NO canonicalization. Uses a tiny C harness built ad hoc.
set -e
cd "$(dirname "$0")/.."
cat > /tmp/sign_harness.c <<'EOF'
#include "keystore.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
static void b64(const unsigned char*in,int n,char*out){ EVP_EncodeBlock((unsigned char*)out,in,n); }
int main(void){
  struct ps_keypair kp; ps_keystore_generate(&kp);
  const char *payload="{\"origin_agent_id\":\"edge-07\",\"ts\":\"t\",\"event\":{\"v\":1,\"kind\":\"tls\"}}";
  unsigned char sig[64]; ps_keystore_sign(&kp,(const unsigned char*)payload,strlen(payload),sig);
  char sigb[128],pubb[128]; b64(sig,64,sigb); b64(kp.pubkey,32,pubb);
  printf("%s\n%s\n%s\n", pubb, sigb, payload);
  return 0;
}
EOF
cc /tmp/sign_harness.c -Isrc/lib build/src/lib/libpacketsonde_lib.a -lssl -lcrypto -o /tmp/sign_harness
/tmp/sign_harness > /tmp/parity.txt
python3 - <<'PY'
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
lines=open("/tmp/parity.txt").read().splitlines()
pub=base64.b64decode(lines[0]); sig=base64.b64decode(lines[1]); payload=lines[2].encode()
Ed25519PublicKey.from_public_bytes(pub).verify(sig, payload)  # raises on failure
print("PARITY OK: C signature verified by Python over raw payload bytes")
PY
```

- [ ] **Step 2: Run it**

Run: `cd /opt/repo/packetsonde && chmod +x scripts/test-signing-parity.sh && ./scripts/test-signing-parity.sh`
Expected: `PARITY OK: C signature verified by Python over raw payload bytes`. (Requires `python3` with the `cryptography` package — present in the rna venvs; use `/opt/central-0522-2/venv/bin/python` if the system python lacks it.)

- [ ] **Step 3: Commit**

```bash
cd /opt/repo/packetsonde
git add scripts/test-signing-parity.sh
git commit -m "Add C-signs/Python-verifies signing parity test"
```

---

## Task 8: Live integration against central

**Files:** none (manual verification)

- [ ] **Step 1: Register + validate a throwaway agent, report a finding**

```bash
cd /opt/repo/packetsonde
AID="report-test-$(openssl rand -hex 4)"; rm -rf /tmp/rt; mkdir -p /tmp/rt/keys
printf '[keys]\ndir = "/tmp/rt/keys"\n[central]\nurl = "http://127.0.0.1:8700"\nagent_id = "%s"\nverify = "0"\n' "$AID" > /tmp/rt/cfg.toml
# enroll
./build/src/cli/packetsonde register --config /tmp/rt/cfg.toml --provenance direct
# validate it (set status=validated in central_ps_agents)
PYTHONPATH=/opt/repo/rna/rna BASE_CONFIG=/opt/etc/central/config.yml /opt/central-0522-2/venv/bin/python -c "
from backend.framework.es import get_es_client
es=get_es_client(); es.update(index='central_ps_agents', id='$AID', doc={'status':'validated'}, refresh='wait_for')
print('validated $AID')"
# report a fixture finding
printf '{"v":1,"id":"01J","run_id":"01R","ts":"2026-05-22T10:00:00Z","source":"audit.tls","host":"h1","kind":"tls.weak_cipher","severity":"medium","confidence":"firm","title":"weak cipher","target":{"ip":"10.0.0.5","port":443}}\n' > /tmp/rt/find.jsonl
./build/src/cli/packetsonde report-central --to-central /tmp/rt/find.jsonl --config /tmp/rt/cfg.toml
```
Expected: `reported: accepted 1 / rejected 0 of 1 (HTTP 200)`.

- [ ] **Step 2: Confirm the event landed + cleanup**

```bash
PYTHONPATH=/opt/repo/rna/rna BASE_CONFIG=/opt/etc/central/config.yml /opt/central-0522-2/venv/bin/python -c "
from backend.framework.es import get_es_client
es=get_es_client(); es.indices.refresh(index='central_ps_events')
h=es.search(index='central_ps_events', query={'term':{'agent_id':'$AID'}})['hits']['hits']
print('events for $AID:', len(h), h[0]['_source'].get('kind') if h else '-')
for i in ('central_ps_events',): pass
es.options(ignore_status=[404]).delete(index='central_ps_agents', id='$AID')
import sys
for d in h: es.options(ignore_status=[404]).delete(index='central_ps_events', id=d['_id'])
print('cleaned up')"
```
Expected: `events for <AID>: 1 tls.weak_cipher` then `cleaned up`. (A pre-validation report would return `rejected_not_validated` — the message guiding the operator to validate first.)

---

## Self-Review

**Spec coverage:**
- §3 envelope (payload string) → Task 1 ✓
- §4 central verify-over-bytes + origin match → Tasks 1 (origin match) + 2 (verify) ✓
- §5 event from `ps_finding` (reuse `ps_finding_to_json`, central sets `agent_id`) → Task 4 (`ps_report_findings` strips `\n`; central adds `agent_id`, already in ingest) ✓
- §6 reporter lib (`ps_report_events`/`ps_report_findings`, payload build, sign, batch POST, parse result) → Tasks 3 (sign) + 4 ✓
- §7 CLI (`report --to-central`, `audit --report`, `[central]` read, `--endpoint`/ingest_endpoint) → Tasks 5 + 6 ✓ (config `GET /config` policy fetch is honored via `--endpoint`/`base_url`; full `GET /config` auto-fetch is a thin add — see note below)
- §8 trust (inner sig, origin bind, dedup, send-only) → Tasks 1–2 + 4 ✓
- §9 errors (counts, exit codes, unreachable, malformed line skipped) → Tasks 4–5 ✓
- §10 testing (payload/sign unit, central verify unit, **C/Python parity**, live) → Tasks 3,4 (unit) + 7 (parity) + 8 (live) ✓

**Gap noted + accepted:** §7's automatic `GET /config` fetch to read `ingest_endpoint`/`report_mode` is represented by the `--endpoint`/`base_url` override rather than an auto-fetch, to keep the phase tight; auto-fetch + `report_mode=relay` warn-and-fallback is a 1-task follow-on once relay exists (the relay phase needs `/config` anyway). If you want the auto-fetch now, add a Task 5.5 that GETs `/config`, parses `reporting_policy.ingest_endpoint`/`report_mode`, and passes the endpoint through. Flag this in review.

**Placeholder scan:** No TBD/TODO. Task 6 references audit.c's `findings`/`nf` names with an explicit instruction to match the file's actual identifiers (integration into unread code, with the concrete shape given). Task 5 note explains the `report-central` name choice (avoids the existing `report` verb).

**Type/name consistency:** `ps_keystore_sign` (Tasks 3,4,7); `ps_report_events`/`ps_report_findings`/`ps_report_result`/`ps_reporter_build_payload`/`ps_reporter_extract_ts` (Task 4, used in 5,6,7); envelope wire shape (`envelope_v`/`origin_agent_id`/`payload`/`ed25519_sig`) consistent across Tasks 1,2 (central) and 4 (agent); central `Envelope.payload` + `env.payload.encode()` (Tasks 1,2).
