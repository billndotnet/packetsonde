# packetsonde — Collector / Return Routing (Spec B) — Design Spec

**Date:** 2026-05-22
**Status:** Draft, pending review
**Component:** `packetsonde` C agent — a new `collect` CLI verb + one lib primitive.
**Builds on:** the relay-forwarding phase (Spec A): the `agent_proto` `ingest`/`ack`
frame, the signed `relay_path` attestation, `ps_keystore_sign`, the sign-over-bytes
envelope, and `agent_transport` mTLS. Consumes the central protocol contract
(`docs/specs/central-protocol-v1.md`) but needs **no central**.

This is Spec B of the two-part routing plane (Spec A = relay→central). It makes a
`relay_via` chain able to **terminate at a user** instead of central, so deployments
with no collection service still get signed findings delivered to a person.

---

## 1. Purpose & scope

An operator/analyst runs `packetsonde collect` on their own box. Agents that can reach
it forward their origin-signed envelopes (the Spec A `ingest` frame); the collector
**verifies them against a local authorized-pubkey set** (no central registry) and
**presents** them as JSONL. JSONL/`--auto-append` remains the baseline output format;
the collector is simply a *receiving* sink for signed, relayed delivery.

- **In scope:** a public `ps_keystore_verify`; the `packetsonde collect` verb (mTLS
  listener → accept `ingest` → local verify → present JSONL → `ack`); the local
  try-all-authorized-pubkeys trust model; the edge→collector-direct path (which needs
  **no new edge/relay code** — an edge already sends `ingest` frames to `relay_via`).
- **Out of scope (deferred):** a relay *forwarding* to a collector (multi-hop chain
  ending at a collector) — reuses this collector + the Spec A terminal seam; per-key
  ACLs (`authorized/<fpr>.toml`), subscription/source-side filtering, retention/ring
  buffer — the larger "passive findings bus" items from the 2026-05-22 critique; a
  persistent daemon collect-role (this is a foreground CLI verb).

**Trust model:** an envelope is trusted iff its origin signature (over the exact
`payload` bytes) verifies against **some** pubkey in the collector's local
`authorized/` set — i.e. "signed by a key the operator trusts." The claimed
`origin_agent_id` is recorded but advisory (not key-bound; that's the deferred
agent_id→key-map option). Relay-hop attestations are verified the same way. Nothing is
dropped: every received event is presented, flagged `verified`/`unverified`. This
mirrors central's flag-not-reject philosophy and the existing `authorized/` pubkey-set
model.

---

## 2. Decisions captured (from brainstorming)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | The collector is a **foreground CLI verb** `packetsonde collect`, not a daemon role. | The operator runs it ad-hoc; their box isn't a stealth field agent, so a standing listener is fine; matches "run packetsonde in collect mode." |
| D2 | Local trust = **try-all authorized pubkeys, present-flagged**. | `authorized/` is a pubkey set with no agent_id binding; trying all avoids a local registry, fits small/home-lab fleets, and keeps full visibility (flag, don't drop). |
| D3 | Add a public **`ps_keystore_verify`** (counterpart to `ps_keystore_sign`). | The Ed25519 verify is currently static in `discovery.c`; the collector needs verify-over-arbitrary-bytes for the origin sig and each attestation. |
| D4 | Presentation = **JSONL** to stdout (+ optional `--out` append). | Reuses the baseline format; composes with `--auto-append`/`findings`. |
| D5 | **edge→collector direct** is the scope; **relay→collector deferred**. | The edge already sends `ingest` to `relay_via`; pointing it at a collector works with zero new code. Relay→collector reuses this collector + the terminal seam later. |

---

## 3. `ps_keystore_verify` (lib)

```c
/* Verify an Ed25519 signature over msg. Returns 1 if valid, 0 otherwise. */
int ps_keystore_verify(const uint8_t *pubkey32, const uint8_t *msg, size_t msg_len,
                       const uint8_t sig64[64]);
```

Implementation mirrors `discovery.c`'s static `ed25519_verify` (one-shot
`EVP_DigestVerify` with `EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, …)`). Lives in
`keystore.{c,h}` beside `ps_keystore_sign`. (Optionally `discovery.c` is later refactored
to call it; not required here.)

---

## 4. The `packetsonde collect` verb

```
packetsonde collect [--listen ADDR:PORT] [--out FILE] [--key-dir DIR] [--authorized DIR]
```

Defaults: `--listen 0.0.0.0:8442` (the agent_listen port), `--key-dir` = keystore
default, `--authorized` = `<key-dir>/authorized`, `--out` absent (stdout only).

Flow:
1. Load the collector's own keypair (`agent` in `--key-dir`) for the mTLS server identity,
   and load the **authorized pubkey set** from `--authorized` (raw 32-byte `*.pub` files,
   the existing format).
2. `ps_at_ctx_init(PS_AT_SERVER, …)`, bind + listen on `--listen`, then an accept loop:
   for each connection, `ps_at_accept_fd` (mTLS; the peer's pinned fingerprint must be in
   the authorized set — the same gate the agent listener uses), send a `hello`, then read
   frames.
3. On an `ingest` frame: parse the `{envelopes:[…]}`, verify + present each (§5), reply
   with an `ack` (`{accepted, rejected}` counts), close.
4. Ctrl-C / SIGINT cleanly stops the loop.

The verb builds a focused server loop using `ps_at` + `agent_proto` directly (it does
**not** pull in the daemon's module system); it reuses the lib primitives
(`ps_keystore_*`, `ps_at_*`, `ps_ap_*`, the authorized-load idiom).

---

## 5. Per-envelope verify + present (try-all)

For each envelope `{envelope_v, origin_agent_id, payload, ed25519_sig, relay_path?}`:

1. **Origin:** `verified = any(ps_keystore_verify(pk, payload_bytes, sig) for pk in authorized)`.
2. **Relay chain:** for each `relay_path` entry, rebuild `"<ed25519_sig>|<received_from>|<ts>"`
   and `verified_hop = any(ps_keystore_verify(pk, attest_bytes, hop_sig) for pk in authorized)`;
   `relay_chain_verified = all hops verified`.
3. **Parse** `payload` → `{origin_agent_id, ts, event}`; require inner==outer
   `origin_agent_id` (mismatch ⇒ `verified=false`, `reason:"origin_mismatch"`).
4. **Emit** one JSONL line: the `event` object enriched with:
   `agent_id` (claimed origin), `verified` (bool), `relay_chain_verified` (bool),
   `relay_path` (each hop annotated `verified`), `received_ts` (collector's now),
   `transport` (`"relay"` if `relay_path` present else `"direct"`). Written to stdout and,
   if `--out`, appended to the file.

`accepted` in the `ack` = count whose origin `verified` is true; `rejected` = the rest
(but all are still presented locally — `ack` counts are advisory feedback to the sender).

---

## 6. Edge→collector path (no new edge/relay code)

To send to a collector, an edge uses the **existing** Spec A relay path:
- Edge config: `[central] report_mode = "relay"`, `relay_via = "<collector-name>"`.
- The collector must be in the edge's CLI agent registry (name → address + key
  fingerprint), exactly like any `--via` target, so `ps_via_connect` can reach it.
- The edge's pubkey must be in the collector's `--authorized` dir.

The edge's `ps_ingest_via` already opens the mTLS channel to `relay_via` and sends the
`ingest` frame; the collector receives, verifies, presents, and `ack`s. **No central is
contacted anywhere in this path.** (A direct agent could also be pointed here; the point
is the chain terminus is a user's `collect` process.)

---

## 7. Error handling

- **Unauthorized peer:** rejected at the mTLS layer (fingerprint not in authorized set) —
  connection closed, logged. Same gate as the agent listener.
- **Malformed `ingest`/envelope:** logged + skipped; the loop continues (one bad frame
  doesn't kill the collector).
- **Verify failure / origin mismatch:** the event is still presented, flagged
  `verified:false` (+ `reason`); never silently dropped.
- **`--out` write failure:** logged; stdout emission still happens.
- Bounded frame reads (`PS_AGENT_FRAME_MAX`); bounded per-event buffers.

---

## 8. Testing

**Unit (C):**
- `ps_keystore_verify`: sign in C with one key → verify true; tampered sig / wrong key →
  false (round-trip with `ps_keystore_sign`).
- Try-all verifier: a payload signed by key K verifies against a set containing K
  (true) and against a set without K (false); the relay-attestation string is rebuilt +
  verified identically.
- JSONL enrichment: a known envelope produces a line with the expected
  `verified`/`relay_chain_verified`/`agent_id`/`transport` fields.

**Live (loopback, fully central-free — runnable here):**
- Generate two keypairs (collector + edge). Put the edge's pubkey in the collector's
  `authorized/`; register the collector in the edge's agent registry (127.0.0.1:PORT +
  the collector's fingerprint).
- Start `packetsonde collect --listen 127.0.0.1:PORT --out /tmp/collected.jsonl` in the
  background.
- Run the edge: `report-central --to-central <fixture.jsonl> --config <edge cfg with
  report_mode=relay relay_via=collector>`.
- Assert `/tmp/collected.jsonl` contains the finding with `verified:true`,
  `transport:"relay"`. Because the collector is a plain CLI process (no privileged
  daemon, no central), this runs end-to-end in-session.

---

## 9. Deferred (future)

- **Relay→collector** multi-hop terminal: a relay forwarding to a collector instead of
  central (terminal=collector config + ingest-forward), so `edge→relay→collector` works.
- **Per-key ACLs** (`authorized/<fpr>.toml` with allowed kinds/verbs), **subscription /
  source-side filtering** (push the predicate to the agent), **retention/ring buffer**
  for knock-then-listen — the "passive findings bus" items from the critique.
- A **persistent daemon collect-role** (this spec is a foreground CLI verb).
- An **agent_id→pubkey local map** (key-bound attribution, vs the try-all advisory model).
