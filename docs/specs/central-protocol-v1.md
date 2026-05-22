# packetsonde Central Protocol — v1

The wire contract between a packetsonde agent and a **central collector**. This is
deliberately implementation-independent: `rna-packetsonde` is the reference collector,
but any service that speaks this contract is a valid sink. JSONL / `--auto-append`
remains the baseline output format; **central is an optional second sink** that adds
signed delivery + a queryable index. Nothing in the toolkit requires a central.

**Status:** v1, as implemented through the relay-forwarding phase (2026-05-22).
**Transport:** HTTPS (or HTTP for dev) for direct agent→central; the `agent_proto` mTLS
`ingest` frame for relayed delivery (§6). All endpoints are under
`{base}/api/v1/packetsonde`.

---

## 1. Identity & trust model

- Each agent has one **Ed25519** keypair (the keystore `agent` key). Its public key is
  sent at registration; central pins it. The same key signs event envelopes and (for
  relays) hop attestations.
- **Public key** is transmitted base64 (raw 32-byte key). **Fingerprint** = SHA-256 of
  the 32-byte pubkey, lowercase hex.
- **Trust = the inner Ed25519 signature + the engineer-validation gate, never the
  transport.** An agent is `pending` after registration and must be moved to
  `validated` by an operator before its events are stored. Transport (direct vs relayed)
  does not affect attribution.

---

## 2. `POST /register`

Unauthenticated by design — it creates a `pending` record that an operator validates.
(Collectors SHOULD rate-limit by source IP; the request carries `ip_address`.)

Request body (JSON):

| field | type | notes |
|-------|------|-------|
| `agent_id` | string | stable identity (hostname or operator-assigned) |
| `pubkey` | string | base64 of the raw 32-byte Ed25519 public key |
| `binary_checksum` | string | hex SHA-256 of the running agent binary |
| `deployment_mode` | string | `host` \| `proxy` \| `trunk` \| `bridge` |
| `provenance` | string | `direct` (self-enroll) \| `salt` (config-mgmt) |
| `ip_address` | string | self-detected primary IPv4 (advisory) |

Response `201`: `{ "agent_id": "<id>", "status": "pending" }`. Re-registration of an
existing id is idempotent.

---

## 3. `POST /checkin`

Liveness + status. Sent periodically once registered.

| field | type | notes |
|-------|------|-------|
| `agent_id` | string | |
| `uptime_seconds` | integer | |
| `config_version` | string | `"none"` if unmanaged |
| `agent_version` | string | build version |
| `key_rotation_status` | string | `"none"` (rotation is a future contract addition) |

Response `200`: `{ "ok": true }`. Drives the collector's online/offline view.

---

## 4. The event envelope (sign-over-transmitted-bytes)

The unit of telemetry. **The signature is computed over the exact `payload` bytes the
agent transmits; the collector verifies those received bytes and then parses them.**
There is no canonicalization — agent and collector never need byte-identical JSON
serializers. **Forwarders MUST treat `payload` and `ed25519_sig` as opaque; any
re-encoding breaks the signature.**

Envelope object:

```json
{
  "envelope_v": 1,
  "origin_agent_id": "edge-07",
  "payload": "{\"origin_agent_id\":\"edge-07\",\"ts\":\"2026-05-22T10:00:00Z\",\"event\":{…}}",
  "ed25519_sig": "<base64 sig over payload's UTF-8 bytes>",
  "relay_path": [ … ]            // optional; present only for relayed delivery (§6)
}
```

- `origin_agent_id` (outer) is an **untrusted routing hint** — used only to look up the
  candidate pinned key. The signed `payload` is authoritative.
- `payload` is a **string** that decodes to `{ "origin_agent_id", "ts", "event" }`. The
  collector MUST require `payload.origin_agent_id == outer origin_agent_id`.
- `ed25519_sig` = base64 Ed25519 signature over `payload`'s UTF-8 bytes, by the origin
  agent's key.

### 4.1 The `event` object

The finding, as produced by `ps_finding_to_json`. The collector sets `agent_id` from the
**verified** identity (not from the event body), plus `received_ts` / `skew_ms`.

| field | type | |
|-------|------|--|
| `v` | int | event schema version (`1`) |
| `id`, `run_id` | string | ULIDs |
| `ts` | string | ISO-8601; also the envelope `ts` |
| `source`, `host` | string | |
| `via_agent` | string | optional |
| `kind` | string | e.g. `tls.weak_cipher` |
| `severity`, `confidence` | string | |
| `title` | string | |
| `target` | object | `{ ip?, hostname?, port? }` |
| `evidence` | object | module-specific; opaque to the contract |

---

## 5. `POST /events`

Ingest a batch.

Request: `{ "envelopes": [ <envelope>, … ] }`.
Optional header `X-Packetsonde-Relay: <agent_id>` set by a forwarding relay (§6).

Response `200`:
```json
{ "accepted": 1, "total": 1, "results": [ { "outcome": "accepted", "doc_id": "…" } ] }
```

Per-envelope `outcome` values:

| outcome | meaning |
|---------|---------|
| `accepted` | inner sig valid, origin `validated`, stored (idempotent on the sig) |
| `rejected_unsigned` | structurally invalid / missing required fields |
| `rejected_unknown_agent` | `origin_agent_id` not in the registry |
| `rejected_not_validated` | origin agent is `pending` (operator hasn't validated it) |
| `rejected_bad_sig` | signature does not verify over `payload`, or inner≠outer origin |

Dedup: the stored doc id is derived from `ed25519_sig`, so redelivery is idempotent.

---

## 6. Relayed delivery + chain-of-custody

An agent that cannot (or should not) reach central directly forwards its **unmodified**
envelopes to a relay over the `agent_proto` mTLS channel as an `ingest` frame:

```
{ "type": "ingest", "envelopes": [ <envelope>, … ] }      relay replies:
{ "type": "ack", "accepted": N, "rejected": M, "detail": "" }
```

Each relay **appends a signed attestation** to the envelope's `relay_path` (it never
touches `payload`/`ed25519_sig`):

```json
{ "relay_agent_id": "relay-1", "received_from": "edge-07",
  "ts": "2026-05-22T10:00:01Z", "sig": "<base64>" }
```

- The attestation `sig` is Ed25519 over the **fixed string**
  `"<envelope.ed25519_sig>|<received_from>|<ts>"` (no JSON — same parity-safe rule as
  §4). `received_from` is the immediate upstream sender's `agent_id`.
- The relay then POSTs the (now `relay_path`-bearing) envelopes to central `/events`
  with `X-Packetsonde-Relay: <relay_agent_id>`.

### 6.1 Collector verification of the chain (flag, don't reject)

For each `relay_path` entry, the collector rebuilds the fixed string and verifies the
`sig` against that relay's pinned key. It stamps each hop `verified: true|false` (with a
`reason` of `unknown_relay` / `not_validated` / `bad_sig` / `malformed` when false),
records the `(received_from → relay_agent_id, state)` edge, and sets
`relay_chain_verified` on the event. **A bad/unverified hop never drops the event** —
ingestion is governed solely by the inner origin signature + the origin `validated`
gate. The relay chain is forensic metadata, not the trust root.

---

## 7. `GET /config`

Returns the agent's central-authored reporting policy (when central authors it; the
agent may also be configured entirely locally — see the agent's `[central]`/`[relay]`
config):

```json
{ "reporting_policy": { "report_mode": "direct|relay", "relay_via": "<agent>|null",
                        "relay_role": false, "relay_allow_sources": [],
                        "ingest_endpoint": "<url>|null" } }
```

ACL-isolated edges that cannot reach central use **local** config for policy instead of
this endpoint.

---

## 8. Implementing a third-party collector

A minimal v1 collector needs: a registry of `agent_id → {pubkey, status}` with an
operator path to set `validated`; `POST /register` / `/checkin` / `/events`; Ed25519
verification over the received `payload` bytes (and over the `relay_path` attestation
strings); and a store/index for accepted events. It does **not** need to match any
particular JSON serialization — only to verify the exact transmitted bytes. The agent
points at it via `[central].url`; any endpoint speaking this contract works.

---

## Versioning

`envelope_v` and `event.v` are `1`. Additive fields are non-breaking. Changes that alter
what bytes are signed, or the `/events` accept/reject semantics, bump the protocol
version and this document.
