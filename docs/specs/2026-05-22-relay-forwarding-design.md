# packetsonde — Relay Forwarding to Central (signed chain-of-custody) — Design Spec

**Date:** 2026-05-22
**Status:** Draft, pending review
**Components:** `packetsonde` C agent (edge forward + relay receive/forward) **and** a
change to central `rna-packetsonde` `ingest.py` to verify + record the attested chain.
**Builds on:** the merged registration (keystore identity, `[central]` config,
`packetsonded-bootstrap`, rna-salt state), reporting (`reporter` lib, `ps_keystore_sign`,
sign-over-bytes envelope), and the existing `agent_proto` mTLS channel + `--via`.

**This is Spec A of a two-part routing plane.** Spec B (collector-mode agent /
return-routing to end users with no central) is the immediate follow-on and reuses this
spec's `ingest` frame and per-hop attestation verbatim. **A explicitly keeps the chain
*terminal* pluggable** so B can slot a collector terminal in beside the central terminal
with no rework. B is out of scope here (§9).

---

## 1. Purpose & scope

Let an edge agent that cannot (or should not) reach central directly forward its signed
event envelopes through a **relay** agent, with a **cryptographic chain-of-custody**:
every relay hop appends a signed attestation, and central verifies each hop against that
relay's pinned key. This realizes `report_mode=relay` from the reporting phase (where it
currently warns and falls back to direct).

- **In scope:** a new `agent_proto` `ingest` frame; the edge forwarding path
  (`report_mode=relay` → send to `relay_via` instead of POSTing central); the relay
  receive/attest/forward path (`relay_role` agent accepts `ingest`, appends a signed
  attestation, forwards to central); the central change to verify + record the attested
  `relay_path`; local relay config (`[central] report_mode/relay_via`, `[relay]
  role/allow_sources`) distributed via salt/bootstrap.
- **Terminal abstraction (for B):** the relay forwards toward a *terminal*. In this spec
  the only terminal is **central over HTTPS**. The forwarding code routes to a terminal
  resolved from config; Spec B adds a **collector-agent** terminal (an `ingest` frame to
  a collector that presents locally) without changing the edge or attestation logic.
- **Out of scope:** collector mode / return routing (Spec B); `GET /config` auto-fetch
  (policy is local config here); daemon-emitted events; offline spool; key rotation.

Trust model carried over: the **inner origin Ed25519 signature** over the payload is the
attribution root and is never modified by relays. The relay chain is **chain-of-custody
metadata** — verified and recorded, but a bad/unverified hop **flags** the hop rather
than dropping the event (see §5).

---

## 2. Decisions captured (from brainstorming)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Edge→relay transport is a new `agent_proto` **`ingest` frame** over the existing mTLS channel (`ps_at_connect`, as `--via` does). | Reuses the knock-capable, SPKI-pinned channel; relays keep their stealth posture (no new socket type); consistent with `--via`. |
| D2 | Each relay appends a **signed per-hop attestation** to `relay_path`: `{relay_agent_id, received_from, ts, sig}`. | True cryptographic chain-of-custody (design-review requirement); multi-hop-capable. |
| D3 | The attestation signature is over a **fixed string** `"<envelope.ed25519_sig>|<received_from>|<ts>"`, not JSON. | Avoids the C↔Python canonicalization-parity problem (same lesson as the origin signature). |
| D4 | Central **flags, doesn't reject**: ingest if inner origin sig valid + origin validated; stamp each hop `verified`/`unverified`; record `ps_relay_edges`. | Origin sig is the trust root; custody is audit metadata; a misconfigured relay must not silently drop telemetry. Matches the flat-LAN tolerant philosophy. |
| D5 | Relay policy is **local config** (`packetsonded.toml`), salt/pillar-distributed. No `GET /config`. | ACL-isolated edges can't reach central to pull policy; fits the central-authors-→-salt-distributes vision. |
| D6 | **Single-hop is implemented + tested** (edge→relay→central); multi-hop is data-model-ready (each relay appends; a relay that is itself `report_mode=relay` forwards to its own `relay_via`). | Bound the testing surface; multi-hop falls out of the same code by construction. |
| D7 | The chain **terminal is pluggable** (central HTTPS now; collector-agent in Spec B). | Lets B reuse this without rework. |

---

## 3. The `ingest` agent_proto frame

Add a message type to `agent_proto` (alongside `hello`/`audit`/`finding`/…):

```
PS_AP_MSG_INGEST  "ingest"   edge|relay -> relay : carries envelopes to forward
PS_AP_MSG_ACK     "ack"      relay -> sender     : forwarding result
```

- **`ingest` frame body:** `{"type":"ingest","envelopes":[ <envelope>, … ]}` where each
  `<envelope>` is exactly the reporting-phase shape
  `{envelope_v, origin_agent_id, payload, ed25519_sig}` plus an optional existing
  `relay_path` (present when this is a multi-hop forward; absent on the first edge→relay
  hop).
- **`ack` frame body:** `{"type":"ack","accepted":N,"rejected":M,"detail":"…"}` —
  the relay's summary of what its terminal (central) returned, relayed back to the sender
  so the edge's `report-central`/`audit --report` can report counts as today.

Frame size obeys the existing `PS_AGENT_FRAME_MAX` (1 MiB); a batch that would exceed it
is chunked by the sender (the reporter already loops/chunks).

---

## 4. Edge forwarding path (`report_mode=relay`)

The reporter (`src/lib/reporter.c`) currently always POSTs central. We add terminal
resolution:

1. Read `[central].report_mode` + `[central].relay_via` from config (already parsed by
   the CLI verbs; thread `report_mode`/`relay_via` into `ps_central_config`).
2. If `report_mode == "direct"` (default): unchanged — POST central `/events`.
3. If `report_mode == "relay"`: open the mTLS channel to `relay_via`
   (`ps_at_connect`, reusing the `--via`/`agent_transport` setup + the agent's keystore
   identity for the client cert), send one `ingest` frame with the `{envelopes:[…]}`
   batch, read the `ack`, map it into `ps_report_result`. No HTTPS to central from the
   edge. The envelopes are unchanged (origin-signed); the edge does **not** add a
   `relay_path` entry (only relays attest).

`relay_via` is an agent name resolved exactly as `--via` resolves agent names (the agent
registry / authorized peers the channel already uses).

---

## 5. Relay receive + attest + forward path (`relay_role`)

The relay's inbound `agent_listen` server (`src/agent/src/modules/network_listener.c`)
today dispatches `audit` frames. We add an `ingest` handler:

1. **Source authorization.** Identify the connecting peer via the mTLS SPKI fingerprint
   (`ps_at_peer_fingerprint`) → its agent identity. The peer is already constrained by
   the channel's `authorized_dir` (pinned pubkeys allowed to connect). Additionally,
   require the peer's agent_id ∈ `[relay].allow_sources`; otherwise reply with an `ack`
   of `{"accepted":0,"rejected":N,"detail":"source not allowed"}` and forward nothing.
2. **Attest each envelope.** Compute `received_from` = the connecting peer's agent_id
   (the immediate sender). Build the attestation string
   `s = "<envelope.ed25519_sig>|<received_from>|<ts>"` (ISO-8601 `ts` = now), sign it
   with the relay's keystore `agent` key (`ps_keystore_sign`), base64 the 64-byte sig,
   and **append** `{ "relay_agent_id": <self>, "received_from": <received_from>,
   "ts": <ts>, "sig": <b64> }` to the envelope's `relay_path` (creating the list if
   absent). Existing `relay_path` entries (multi-hop) are preserved and prepended-to.
3. **Forward to the terminal.** The terminal is resolved from the relay's own config:
   - `report_mode != "relay"` (the common relay-to-central case): POST the (now
     attestation-bearing) envelopes to central `/events` over HTTPS (`http_client`,
     using the relay's `[central]` url/verify/ca_cert) with header
     `X-Packetsonde-Relay: <self agent_id>`.
   - `report_mode == "relay"` (a relay that is itself an edge → multi-hop): send an
     `ingest` frame to *its* `relay_via` (the same edge path in §4). Each hop appends its
     own attestation. *(Data-model-ready; single-hop is the tested path — D6.)*
4. **Ack.** Relay central's `{accepted, rejected}` (or the next hop's `ack`) back to the
   sender as an `ack` frame.

The relay never inspects or alters `payload` or the origin `ed25519_sig`; it only appends
to `relay_path`.

---

## 6. Central change — verify + record the attested chain

In `rna-packetsonde` `service/ingest.py`, after the existing inner-origin-sig check
(unchanged) and before/at indexing:

1. For each entry in `env`'s `relay_path` (a list of attestation objects):
   - Rebuild `s = "<env.ed25519_sig>|<entry.received_from>|<entry.ts>"`.
   - Look up the relay's pinned pubkey via `registry.get(entry.relay_agent_id)`.
   - `verified = (record exists and status == "validated" and
     verify_ed25519(record["pubkey"], entry.sig, s.encode("utf-8")))`.
   - Annotate the entry with `verified: true|false` (and `reason` when false:
     `unknown_relay` / `not_validated` / `bad_sig` / `malformed`).
   - Record the edge in `ps_relay_edges`: `RelayEdges.record(origin=entry.received_from,
     relay=entry.relay_agent_id, state=("verified" if verified else "unverified"),
     zone=<ipam zone or None>)`.
2. Store the verified-annotated `relay_path` on the event document, plus a summary
   `relay_chain_verified: bool` (true iff all hops verified). `transport` stays `"relay"`
   when `relay_path`/the header is present (existing logic).
3. **Ingestion is unchanged in its accept/reject decision**: governed solely by the inner
   origin signature + origin `validated` gate. Relay-chain health never rejects (D4). A
   structurally malformed `relay_path` entry (missing fields) → that entry
   `verified:false, reason:malformed`, event still ingested.

`parse_envelope` accepts an optional top-level `relay_path` list (each entry an object
with `relay_agent_id`, `received_from`, `ts`, `sig`); absent/empty for direct events.
The `X-Packetsonde-Relay` header remains the immediate-sender hint and should match the
last `relay_path` entry's `relay_agent_id` (logged if mismatched; not fatal).

---

## 7. Config (local, salt-distributed)

`packetsonded.toml`:

```toml
[central]
url             = "https://central:8700"   # used by direct agents AND relays' own forward
report_mode     = "direct"                  # "relay" on an edge that forwards via a relay
relay_via       = ""                        # edge: the relay agent name to forward through

[relay]
role            = "0"                        # "1" on a relay-capable agent
allow_sources   = ""                         # relay: comma-separated agent_ids it will relay for
```

- Edge: `report_mode="relay"`, `relay_via="bastion-1"`.
- Relay: `role="1"`, `allow_sources="edge-07,edge-09"`, plus its own `[central].url` for
  the forward.
- `config_to_env` mappings added (`PS_CENTRAL_REPORT_MODE`, `PS_CENTRAL_RELAY_VIA`,
  `PS_RELAY_ROLE`, `PS_RELAY_ALLOW_SOURCES`); `central_config.h`/the CLI readers gain the
  fields (with the same quote-stripping). The rna-salt state template +
  `packetsonded-bootstrap` gain `--report-mode/--relay-via/--relay-role/--allow-sources`
  flags and pillar keys.

---

## 8. Error handling

- **Edge can't reach relay** (mTLS connect fails): `ps_report_*` returns -1; the CLI
  prints "relay unreachable" and exits non-zero (no spool — deferred). The source JSONL
  still exists for a re-run.
- **Relay can't reach central**: the relay replies with an `ack` of
  `{"accepted":0,"rejected":N,"detail":"relay->central failed"}`; the edge surfaces it.
- **Source not in `allow_sources`**: `ack` with `detail:"source not allowed"`, nothing
  forwarded; the relay logs the rejected peer.
- **Unverified hop at central**: event ingested, hop flagged (§6) — never an error to the
  edge.
- All frames bounded by `PS_AGENT_FRAME_MAX`; oversize → existing `PS_AP_ERR_OVERSIZE`.

---

## 9. Testing

**Unit (agent, C):**
- `agent_proto`: encode/parse an `ingest` frame and an `ack` frame (round-trip).
- Attestation: build the fixed string for known inputs; `ps_keystore_sign` over it +
  verify in C; assert the appended `relay_path` entry shape.
- `allow_sources`: a parser/check accepts an allowed agent_id and rejects others.

**Unit (central, Python):**
- `parse_envelope` accepts optional `relay_path`; chain verify stamps `verified:true` for
  a correctly-signed hop, `verified:false` (+ reason) for a tampered sig / unknown relay /
  not-validated relay; event still ingested in all those cases; `ps_relay_edges.record`
  called per hop with the right state.

**Cross-language parity:** C builds + signs an attestation string; Python
`verify_ed25519` verifies it against the relay's pubkey (the same proof we did for the
origin signature) — confirms relay attestations verify at central with no canonicalization.

**Live (psdev, two-agent loopback):**
- Start one `packetsonded` as a **relay** (`agent_listen` enabled, `[relay] role=1`,
  `allow_sources` includes the edge); register + validate both the relay and the edge in
  `psdev_ps_agents`.
- Configure the edge `report_mode=relay`, `relay_via=<relay>`; run
  `packetsonde report-central` (or `audit --report`).
- Assert: the event lands in `psdev_ps_events` with `transport="relay"`, a `relay_path`
  whose single hop is `verified:true`, `relay_chain_verified:true`; and
  `psdev_ps_relay_edges` shows the `edge→relay` edge in state `verified`. UUID-scoped ids
  + cleanup per the project's real-infra testing rule.

---

## 10. Deferred (Spec B + later)

- **Spec B — collector-mode agent / return routing:** a `collect`/receive terminal that
  accepts `ingest` frames, verifies the origin sig + the relay attestation chain against a
  **local** authorized-pubkey store (no central registry), and presents findings
  (JSONL/stdout/local store); the destination abstraction so a `relay_via` chain can
  terminate at a collector `agent_id` instead of central. Reuses this spec's `ingest`
  frame + attestation + verify logic.
- `GET /config` auto-fetch; daemon-emitted events; offline spool; key rotation;
  multi-hop *testing* (the code path is built but only single-hop is validated here).
