# packetsonde — Event Reporting (direct, CLI-driven) — Design Spec

**Date:** 2026-05-22
**Status:** Draft, pending review
**Components:** `packetsonde` C agent (reporter lib + CLI verbs) **and** a small change
to the central `rna-packetsonde` envelope/ingest code.
**Builds on:** the agent registration + identity work merged 2026-05-22 (keystore
`agent` Ed25519 key, `http_client`, `[central]` config) and the central ingest spine
(`/events`, `ps_events`, registry validation gate) already deployed.

---

## 1. Purpose & scope

Make a validated agent able to **report findings to central**: take a `ps_finding`,
wrap it in a signed envelope, POST it to `/events`, and have it land in the
`ps_events` index — provably originating from the agent whose public key central
pinned at registration.

This phase is deliberately bounded:

- **In scope:** the signing model, the envelope shape, the central verification
  change, a reusable C reporter, and CLI surfaces that feed it
  (`packetsonde report --to-central` and `packetsonde audit … --report`).
- **Out of scope (each its own later spec):** the relay/forwarding plane (agents
  forwarding other agents' envelopes over `agent_proto` mTLS); the daemon emitting
  its own events continuously (flow anomalies, neighbor changes); durable on-disk
  spooling for offline resilience; key rotation. These are noted in §10.

The reason for the CLI-first source: findings are produced by the CLI audit path
(`src/cli/audit/*.c`) today; the daemon does not emit `ps_finding`s yet. The
*reporting mechanism* (finding → envelope → sign → POST) is the reusable, valuable
piece, so we build it as a library and wire it to the source that actually exists.
The daemon adopts the same library later, once it has event sources.

---

## 2. Decisions captured (from brainstorming)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Sign-over-transmitted-bytes.** The agent signs the exact bytes it transmits; central verifies those received bytes, then parses. No re-canonicalization on either side. | A C agent reproducing Python's recursive `json.dumps(sort_keys=True, …)` byte-for-byte (key order, escaping, number formatting) over a nested `event` is fragile and a perennial source of "valid signature rejected" bugs. Signing the wire bytes removes the entire problem class. |
| D2 | **Direct transport only this phase.** Agent POSTs envelopes straight to central `/events`, honoring `report_mode=direct` + `ingest_endpoint` from `GET /config`. `report_mode=relay` is parsed but warns and falls back to direct. | The relay plane (inbound forwarding, `relay_edges`, allow-sources) is a large, separable chunk. Central already accepts relayed ingest when we build it. |
| D3 | **CLI-driven source via a reusable reporter lib.** `src/lib/reporter` does finding→envelope→sign→POST; CLI verbs feed it. Daemon reuses later. | Findings come from the CLI audit path today; the library is source-agnostic. |
| D4 | **One identity.** Signing uses the existing keystore `agent` Ed25519 key — the same key central pinned at registration. | Unified identity; central already has the pubkey to verify against. |

No backward-compatibility constraint: no agents report yet, so changing the envelope
contract (D1) breaks nothing deployed.

---

## 3. The envelope (new shape)

The wire object the agent POSTs (inside an `envelopes[]` array):

```json
{
  "envelope_v": 1,
  "origin_agent_id": "edge-07",
  "payload": "{\"origin_agent_id\":\"edge-07\",\"ts\":\"2026-05-22T10:00:00Z\",\"event\":{ … }}",
  "ed25519_sig": "<base64 Ed25519 signature over the UTF-8 bytes of payload>"
}
```

Field semantics:

- **`envelope_v`** — integer envelope-format version. `1` for this design.
- **`origin_agent_id`** (outer) — **untrusted routing hint.** Central uses it only to
  look up the candidate pinned public key. It is *not* trusted for attribution; the
  signed `payload` is authoritative.
- **`payload`** — a **string**: the exact JSON text the agent serialized for
  `{origin_agent_id, ts, event}`. This is the signed region. Central treats it as
  opaque bytes for verification, then parses it. Because central verifies the literal
  received bytes, the agent may serialize this however it likes (its own `ps_json`
  output) — key order, whitespace, and escaping are irrelevant to validity, as long
  as the bytes the agent signed are the bytes it sends.
- **`ed25519_sig`** — base64 of the 64-byte Ed25519 signature over
  `payload`'s UTF-8 bytes, using the agent's keystore `agent` secret key.

The parsed `payload` object:

```json
{
  "origin_agent_id": "edge-07",
  "ts": "2026-05-22T10:00:00Z",
  "event": { /* see §5 */ }
}
```

---

## 4. Central change (`rna-packetsonde`)

Today `service/envelope.py` defines `canonical_signed_bytes(env)` by **re-serializing**
the parsed dict with `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)`,
and `service/ingest.py` verifies the signature against that re-serialized form. We
change this to verify over the transmitted bytes.

Concretely:

1. **`parse_envelope(raw)`** accepts the new shape: requires `payload` (string) and
   `ed25519_sig`; reads outer `origin_agent_id` and `envelope_v`. It parses
   `payload` (a JSON string) into `{origin_agent_id, ts, event}` and keeps **both**
   the raw `payload` string (for verification) and the parsed dict (for indexing).
2. **Verification** uses `payload.encode("utf-8")` as the message — the exact received
   bytes — instead of `canonical_signed_bytes(...)`. `canonical_signed_bytes` is
   removed (or kept only as dead code to delete) since nothing should re-canonicalize.
3. **Identity binding:** after a successful signature check against the key pinned for
   the outer `origin_agent_id`, central asserts `parsed_payload.origin_agent_id ==
   outer.origin_agent_id`; mismatch → `rejected_bad_sig` (the signature is over a
   payload claiming a different origin). This prevents using agent A's outer id to
   smuggle agent B's signed payload.
4. **Everything else is unchanged:** registry lookup, the `status == "validated"`
   gate, dedup via a doc id derived from the signature, `skew_ms` computation,
   indexing into `ps_events`. The relay parameters (`transport`, `relay_path`,
   `relay_identity`) on `Ingestor.ingest(...)` stay; direct ingest passes
   `transport="direct"`, no relay path.
5. **Tests:** update `rna-packetsonde` envelope/ingest unit tests for the new shape —
   a sign/verify round-trip over `payload` bytes, the `origin_agent_id`-match
   rejection, and the existing reject reasons (`rejected_unsigned`,
   `rejected_unknown_agent`, `rejected_not_validated`, `rejected_bad_sig`).

The `/events` API handler (`api/events.py`) is unchanged in shape: it still takes
`{envelopes:[…]}` and returns `{accepted, total, results:[…]}` with a per-envelope
status string.

---

## 5. The `event` object (from `ps_finding`)

`src/lib/finding.c:ps_finding_to_json()` already serializes a finding. We reuse it and
extend the produced object to match what `ps_events` indexes. The `event` carries:

| Field | Source | ps_events mapping |
|-------|--------|-------------------|
| `v` | constant `1` (event schema version) | `v` (integer) |
| `id` | `finding.id` (ULID) | `id` (keyword) |
| `run_id` | `finding.run_id` | `run_id` (keyword) |
| `ts` | `finding.ts` | `ts` (date) — also the envelope `ts` |
| `source` | `finding.source` | `source` (keyword) |
| `host` | `finding.host` | `host` (keyword) |
| `via_agent` | `finding.via_agent` (may be empty) | `via_agent` (keyword) |
| `kind` | `finding.kind` | `kind` (keyword) |
| `severity` | `finding.severity` (enum→string) | `severity` (keyword) |
| `confidence` | `finding.confidence` (enum→string) | `confidence` (keyword) |
| `title` | `finding.title` (escaped) | `title` (text) |
| `target` | nested `{ip, hostname, port}` | `target.*` |
| `evidence` | `finding.evidence_json` embedded as a nested JSON object (raw, when present) | `evidence` (object) |

Note `agent_id` in `ps_events` comes from the **envelope's** authenticated
`origin_agent_id` (central sets it during ingest), **not** from the event body — so
the agent does not put `agent_id` in `event`; central attributes it from the verified
identity. (`received_ts` and `skew_ms` are also set centrally.)

If `ps_finding_to_json` does not already emit `v` and the exact field set above, we
extend it (or add a thin `ps_finding_to_event_json` wrapper) — a small, tested change
in `src/lib/finding.c`. `evidence` is embedded as the raw object the module produced;
because of D1 this needs no canonicalization.

---

## 6. The reporter library (`src/lib/reporter.{c,h}`)

A single, focused unit. Public surface:

```c
struct ps_report_result { int accepted; int rejected; int total; int http_status; };

/* Sign + POST a batch of findings to central as one {envelopes:[…]} request.
 * cc supplies url/agent_id/verify/ca_cert/key_dir (the [central] settings).
 * Returns 0 on a completed HTTP exchange (inspect result for accept/reject
 * counts); -1 on transport failure or local error (no key, etc.). */
int ps_report_findings(const struct ps_central_config *cc,
                       const struct ps_finding *findings, size_t n,
                       struct ps_report_result *out);
```

Internal steps, per finding:

1. Build the `event` JSON (§5) into a buffer.
2. Build the `payload` string: `{"origin_agent_id":"<id>","ts":"<finding.ts>","event":<event>}`
   using `ps_json` (order/escaping free per D1). `origin_agent_id` = resolved agent id
   (`cc->agent_id` or hostname, same resolution as registration); `ts` = the finding's
   timestamp.
3. Load the keystore `agent` secret key (from `cc->key_dir`) and Ed25519-sign the
   `payload` bytes; base64 the 64-byte signature.
4. Append `{envelope_v:1, origin_agent_id, payload, ed25519_sig}` to the `envelopes[]`
   array being assembled.

Then one `ps_http_request("POST", "<base>/api/v1/packetsonde/events", body, …)` with
`{envelopes:[…]}`, where `<base>` is the `ingest_endpoint` from `GET /config` if set,
else `cc->url`. Parse central's `{accepted, total, results}` into `ps_report_result`.

Batching: all findings in the call go in one POST (central's `/events` is built for
batches). For very large inputs the CLI may chunk (e.g., 200 envelopes/POST) — a simple
loop over `ps_report_findings`; the library itself reports per-batch.

Signing primitives reuse the same Ed25519 the keystore/discovery already use
(OpenSSL `EVP_PKEY` Ed25519, or the existing helper `discovery.c`/`keystore.c` sign
path). We add a `ps_keystore_sign(keypair, msg, len, sig_out)` if one is not already
exposed — small, with a sign/verify round-trip test.

---

## 7. CLI surface

Two entry points, both reading `[central]` from `packetsonded.toml` exactly as the
`register` verb does (with the same quote-stripping — `ps_config` preserves wrapping
quotes for direct readers):

1. **`packetsonde report --to-central <findings.jsonl> [--config PATH] [--endpoint URL]`**
   Reads a findings JSONL file (the format `packetsonde audit`/`findings` already
   emit — one finding object per line), parses each line into a `ps_finding`, and
   calls the reporter. Prints `reported: accepted N / rejected M` and per-reason
   counts; exit non-zero if the POST failed or any envelope was rejected (so cron/CI
   can detect problems).

2. **`packetsonde audit … --report`**
   A flag on the existing `audit` verb: after the audit produces its findings
   in-memory, pass them straight to the reporter (no intermediate file). Audit
   output to stdout/JSONL is unchanged; `--report` is additive.

`GET /config` handling (both paths): optionally fetch
`<base>/api/v1/packetsonde/config` to read the agent's `reporting_policy`. If
`report_mode == "relay"`, log a clear warning ("relay reporting not yet supported;
sending direct") and proceed directly. If `ingest_endpoint` is set, use it as the POST
base. `--endpoint` on the CLI overrides everything (operator escape hatch). If
`GET /config` fails or is absent, default to direct against `cc->url` — config fetch is
an optimization, never a hard dependency.

---

## 8. Trust & security model

- Attribution rests entirely on the **inner Ed25519 signature** over `payload`,
  verified against the key central pinned when the agent was validated. An unvalidated
  or unknown agent's envelopes are rejected at ingest (already enforced).
- The outer `origin_agent_id` is an untrusted lookup hint; the signed-payload
  `origin_agent_id` must match it (§4.3), so an attacker cannot replay agent B's signed
  payload under agent A's routing id.
- Dedup on the signature makes redelivery idempotent (no duplicate `ps_events`).
- TLS to central uses the same `verify`/`ca_cert` options as registration (`http://`
  allowed for dev like psdev; `https://` + verify in prod).
- The agent only ever *sends*; it exposes no new listening surface. (The relay role,
  which *does* accept inbound, is the deferred next phase.)

---

## 9. Error handling

- **Transport failure** (central unreachable, TLS failure): `ps_report_findings`
  returns -1; the CLI prints the error and exits non-zero. No spooling this phase —
  findings are not lost from the source JSONL (it still exists), but in-memory
  `audit --report` findings that fail to send are reported as failed (operator can
  re-run `report --to-central` on the saved JSONL). Offline spool is a deferred item.
- **Per-envelope rejection** (central returns `results` with non-`accepted` statuses):
  surfaced as counts + reasons; exit non-zero if any rejected. A `rejected_not_validated`
  is the common first-run case (agent registered but not yet validated by an engineer)
  — the message tells the operator to validate the agent in the admin UI.
- **Malformed finding line** in `report --to-central`: skipped with a warning + counted;
  does not abort the batch.
- Response body is read with a bounded buffer (reuse `http_client`'s cap).

---

## 10. Testing

**Unit (C, no network):**
- `reporter`: `payload` assembly for a known finding (assert it parses + contains the
  expected fields); Ed25519 **sign-in-C / verify-in-C** round-trip over the payload
  bytes (proves the signing primitive); `event`-from-finding field set (incl. nested
  `target`, embedded `evidence`).
- `finding`: the extended `to_json`/`to_event_json` emits `v` + the §5 fields.

**Unit (central, `rna-packetsonde`):**
- New `parse_envelope` accepts the `payload`-string shape; verify-over-bytes succeeds
  for a correctly signed payload and fails for a tampered one; `origin_agent_id`
  mismatch → `rejected_bad_sig`; the existing reject reasons still hold.

**Cross-language parity (the important one):**
- A test where C signs a `payload` and Python (`verify_ed25519`) verifies it with the
  same key — confirming the agent's signature is acceptable to central *without*
  canonicalization. (Can be a scripted test: C tool emits `{payload, sig, pubkey}`;
  a small Python check verifies.)

**Integration (live psdev):**
- Register + **validate** a throwaway agent (set `status=validated` via the admin path
  or directly), then `packetsonde audit … --report` (or `report --to-central` on a
  fixture JSONL) against psdev → assert the finding appears in `psdev_ps_events` with
  `agent_id` = the agent, correct `kind`/`severity`/`target`. UUID-scoped test ids +
  cleanup, per the project's real-infrastructure testing rule.

---

## 11. Deferred (future specs)

- **Relay/forwarding plane:** edge agents in `report_mode=relay` send envelopes to a
  relay over `agent_proto` mTLS; relay-capable agents enforce `relay_allow_sources`
  and forward to `/events` with `relay_path`/`relay_identity`. Central already ingests
  these.
- **Daemon-emitted events:** define and wire the daemon's own event sources (flow
  anomalies, neighbor/discovery changes, `--via` audit results) into the same reporter.
- **Offline spool:** durable on-disk queue + retry/backoff for intermittently-connected
  agents (at-least-once delivery across restarts; dedup already handled by signature).
- **Key rotation:** checksum-gated rotation of the agent identity, with central
  re-pinning.
