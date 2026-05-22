# packetsonded — Agent Registration + Deployment — Design Spec

**Date:** 2026-05-22
**Status:** Draft, pending review
**Component:** `packetsonded` (C agent) + packaging/deploy glue. Central counterpart
(`rna-packetsonde`) registry/ingest is already built and deployed.

---

## 1. Scope & posture

Get a packetsonded agent **enrolled, validated, and checking in** so it appears as a
live, trusted member in central's Fleet view — plus the **deployment glue** to put it
on a host (manual/off-fleet and salt-fleet). This builds on what the agent already has:
the `keystore` + `key` CLI (Ed25519), mTLS `agent_transport`, signed discovery, the
daemon (config/modules/split-priv), and multi-platform packaging (deb/freebsd/brew/
systemd/launchd + `packetsonded.toml` + bootstrap).

**Explicitly out of this spec (next phase):** event *reporting* (signing findings into
the `v:1` envelope and sending to `/events`, directly or relayed), config-driven
reporting-policy application (`GET /config` → `report_mode`/`relay_via`), and key
rotation. This spec stops at "registered + validated + checking in."

**Central contract (already shipped in rna-packetsonde, this spec consumes it):**
- `POST /api/v1/packetsonde/register` →
  `{agent_id, pubkey, binary_checksum, deployment_mode, provenance, ip_address}`
  → `201 {agent_id, status:"pending"}`. Engineer validates `pending → validated` in
  the admin UI. Unauthenticated by design (the validation gate is the trust step).
- `POST /api/v1/packetsonde/checkin` →
  `{agent_id, uptime_seconds, config_version, agent_version, key_rotation_status}`
  → `200 {ok:true}`; writes `ps_health` (drives online/offline in Fleet).

---

## 2. Decisions captured

| # | Decision |
|---|---|
| D1 | Agent→central HTTP uses a **hand-rolled HTTP/1.1 client over the OpenSSL the agent already links** — no libcurl, stays a lean single binary. |
| D2 | Registration is **one idempotent routine, two triggers**: daemon self-enroll on first boot (`provenance=direct`) + a `packetsonde register` CLI verb for salt/postinst (`provenance=salt`). |
| D3 | **One Ed25519 identity** (keystore `agent` key) underpins discovery, mTLS, and central registration; the pubkey sent at `/register` is exactly what central pins for future envelope validation. |
| D4 | Central config is a new **`[central]`** block in `packetsonded.toml`; TLS trust mirrors the framework's `ES_VERIFY_CERTS` pattern (`verify` bool + optional `ca_cert`; `http://` allowed for dev). |
| D5 | **Two deployment paths**: `packetsonded-bootstrap` script (manual/off-fleet/home-lab) + an rna-salt state templated from pillar (fleet). Both build on existing packaging. |
| D6 | `agent_id` defaults to the hostname (overridable). `ip_address` reuses discovery's existing auto primary-v4 detection. |

---

## 3. Components

### 3.1 `src/lib/http_client.{c,h}` — minimal HTTPS client
- `ps_http_post_json(url, body, headers, opts) -> ps_http_resp` and `ps_http_get(url, opts)`.
- Parses `url` (`http://host:port/path` or `https://...`). For `https`, opens TLS via
  the OpenSSL primitives already used by `agent_transport`; for `http`, plain socket.
- TLS verification from `opts`: `verify` (default true) checks the chain; `ca_cert`
  pins an internal CA file; `verify=false` skips (dev / self-signed). No SPKI pin here
  (central is a server cert behind HAProxy, unlike the agent's mTLS peer pins).
- HTTP/1.1 with explicit `Content-Length`, `Connection: close`, bounded response read
  (cap, e.g. 64 KiB), per-request timeout. Returns status code + body. Never blocks
  the daemon's main loop indefinitely.
- One focused unit: parse URL, connect (+TLS), write request, read+parse response.

### 3.2 `src/lib/registration.{c,h}` — the enrollment routine
`ps_register(cfg, provenance, force) -> ps_reg_result`:
1. If `registered` marker present and `!force` → no-op (return `already_registered`).
2. Ensure identity: if keystore `agent` key absent, generate it (existing keystore API).
3. Compute `binary_checksum` = `sha256` of the running executable (`/proc/self/exe` on
   Linux; `argv[0]`/`KERN_PROC_PATHNAME` fallback on BSD/macOS), hex-encoded.
4. Resolve `agent_id` (config or hostname) and `ip_address` (discovery's auto v4).
5. Build JSON `{agent_id, pubkey(base64), binary_checksum, deployment_mode,
   provenance, ip_address}` and `POST /register` via `http_client`.
6. On `201` → write the `registered` marker (`/etc/packetsonded/registered`, recording
   agent_id + status + ts). On error → return error (caller logs; daemon retries with
   backoff on next boot; CLI exits non-zero).

### 3.3 `packetsonde register` verb — `src/cli/verbs/register.c`
- Flags: `--provenance {salt|direct}` (default `salt` for the CLI path), `--force`,
  `--config <path>`. Loads config, calls `ps_register(...)`, prints outcome, exit code
  reflects success/pending/error. Invoked by salt/postinst.

### 3.4 `packetsonded` boot self-enroll — `main.c`
- After config load + key setup, if `[central].url` is set and no `registered` marker:
  call `ps_register(cfg, "direct", force=false)`. Log result; failure is non-fatal
  (the agent keeps running its other modules; retries enrollment next boot).

### 3.5 Checkin loop (daemon)
- A periodic task (interval from config, default 60 s) that `POST /checkin`s
  `{agent_id, uptime_seconds, config_version (from marker/none), agent_version
  (build_config.h), key_rotation_status ("none" for now)}`.
- Single-flight; bounded; failures logged and retried next tick. Runs only once
  registered (marker present). This is what makes the agent show **online** in Fleet.

---

## 4. Config — `[central]` block

```toml
[central]
# Central rna-packetsonde base URL. http:// for dev (e.g. central :8700),
# https:// in production (via HAProxy).
url             = "https://central.example.net"
# Stable identity for this agent in the registry. Defaults to the hostname.
agent_id        = ""            # empty -> hostname
deployment_mode = "host"        # host | proxy | trunk | bridge
# TLS trust (mirrors framework ES_VERIFY_CERTS):
verify          = "1"           # 0 to skip (dev / self-signed)
ca_cert         = ""            # optional: pin an internal CA file
checkin_seconds = "60"
```
Parsed in `config.c` / surfaced through `config_to_env.c` like the other sections
(`PS_CENTRAL_URL`, `PS_CENTRAL_AGENT_ID`, …), so launch-time env overrides win.

---

## 5. Deployment methods

### 5.1 `packetsonded-bootstrap` (manual / off-fleet / home-lab)
Extend `packaging/bootstrap`. Usage:
```
packetsonded-bootstrap --central https://central:port --mode host \
    [--agent-id NAME] [--ca-cert FILE | --insecure] [--relay-via AGENT]
```
Steps: write the `[central]` block into `packetsonded.toml`, ensure the keystore
`agent` key (gen if absent), run `packetsonde register --provenance direct`, then
enable/start the service (systemd/launchd/rc per platform). Idempotent.

### 5.2 rna-salt state + pillar (fleet)
A salt state (lives in **rna-salt**, not the agent repo) that:
1. Installs the platform package (deb/freebsd) at the pinned version.
2. Templates `packetsonded.toml` `[central]` from pillar
   (`packetsonde:central_url`, `:deployment_mode`, per-minion `agent_id`).
3. Runs `packetsonde register --provenance salt`.
Both paths converge on a `pending` `ps_agents` record → engineer validates.

---

## 6. Identity & trust boundary

- The agent's **Ed25519 keystore `agent` key** is its single identity. Its public key
  is sent at `/register`; central pins it (`ps_agents.pubkey`) and will verify future
  signed envelopes against it. The same key already backs discovery signing and the
  mTLS self-signed cert (identity == pubkey).
- `binary_checksum` (sha256 of the running binary) is recorded at registration; central
  can later gate key rotation on checksum match (rotation is out of this spec).
- `/register` is unauthenticated; the **engineer validation gate** (`pending →
  validated`) is the trust-establishing step. A bogus self-enrollment sits harmless in
  `pending` until a human approves it — and unvalidated agents' events are rejected at
  ingest (already enforced centrally).

---

## 7. Error handling

- HTTP/TLS failures (unreachable central, cert mismatch): logged via the agent's
  logger; **non-fatal** — the daemon keeps running and retries enrollment/checkin on
  the next boot/tick with simple backoff. The CLI verb exits non-zero so salt sees it.
- `409`/duplicate (already registered with same id): treated as success (idempotent).
- Response body capped; malformed JSON tolerated (status code is authoritative).
- Bootstrap script is re-runnable; a present `registered` marker short-circuits
  re-registration unless `--force`.

---

## 8. Testing

**Unit (no network):**
- `http_client`: request-line + header framing for POST/GET; response status/body
  parse; `Content-Length` handling; truncation at cap; URL parse (http/https/port/path).
- `registration`: JSON payload build (fields + base64 pubkey); marker write/skip
  idempotency; `force` override; sha256 self-hash against a fixture file.
- config: `[central]` parse + env override precedence.

**Integration (against live central central):**
- `packetsonde register --provenance direct --config <test cfg pointing at central>` →
  assert `201`, then query central `ps_agents` for the `pending` record (correct pubkey,
  checksum, deployment_mode, provenance). Then flip to `validated` (admin path) and run
  one `/checkin` → assert `ps_health` shows the agent. UUID-scoped test agent_id +
  cleanup, per the project's real-infra testing rule.

---

## 9. Deferred (next spec)

Event **reporting**: agent produces findings (flow/anomaly), wraps them in the `v:1`
signed envelope, and delivers to `/events` directly or via an `agent_proto` relay; the
`GET /config` reporting-policy fetch + application (`report_mode`/`relay_via`/
`ingest_endpoint`); relay/bastion forwarding; key rotation (checksum-gated). These
depend on this spec's enrollment + identity being in place.
