# kernelsonde — splitting the local detect track into its own agent

**Date:** 2026-06-26
**Status:** Approved, pending implementation plan

## Goal

Extract the Linux host behavioral-detection track (the `[detect]` feature:
fanotify file/exec/socket observation, declared-policy overwatch, learned
per-exe baselines, capture sessions, file provenance) out of the
`packetsonded` network agent into a new, independently deployable daemon
**`kernelsonded`**. Both binaries live in the same repository and share
`src/lib`.

The split serves three goals equally: **capability isolation** (confine
`CAP_SYS_ADMIN` + `CAP_DAC_READ_SEARCH` to a separate daemon),
**independent deployability** (run network observation, host detection, or
both per host), and **clean separation for growth** (host sensing is a
distinct concern from cross-platform network audit and will grow its own
sensors, e.g. USB observation).

Non-goals: changing detect behavior or output formats; a separate
`kernelsonde` CLI; a separate git repo; cross-platform detect (it stays
Linux-only); auto-migration of running detect state.

## Decisions (resolved during brainstorming)

- Same repo, new binaries on the shared `src/lib`. Detect code moves to a
  new `src/kernel/`.
- The detect CLI verbs (`watch`, `inspect`, `baseline`, `sandbox-suggest`)
  stay in the single `packetsonde` CLI; they target the kernelsonded socket.
- `kernelsonded` gets its **own** privilege-separated worker
  (`kernelsonde-priv`) carrying the fanotify capabilities.
- Packaging: **one** `packetsonde` `.deb` shipping both daemons as **two
  systemd units, both disabled**.
- `kernelsonded` enrolls with central as its **own** Ed25519 agent identity.
- No central-protocol change (no agent "role" tag — central simply sees two
  agents per host).
- Config keeps the `[detect]` section name, in the new `kernelsonded.toml`.

## Architecture

### What moves to `src/kernel/`

From `src/agent/`:

- `fan_monitor.c`, `proc_enrich.c`, `sock_snapshot.c`
- `activity_ring.c`, `baseline_store.c`, `capture_session.c`
- `capture/` (`capture_handle.c`, `protocol_demux.c`)
- `modules/baseline_monitor.{c,h}`, `modules/policy_overwatch.{c,h}`
- the fanotify/proc/sock half of `priv_worker.c` (see "Privilege split")

A new `src/kernel/main.c` is the `kernelsonded` entry point: fork priv
worker → drop privileges → build the activity ring → start the consumers →
run the IPC server and central checkin.

### What stays in `src/agent/` (`packetsonded`)

Everything network/passive: flow tracking, interface monitor, all the
control-plane listeners, TLS fingerprinting, discovery, `--via` mTLS remote
audit, relay, central checkin. `packetsonded` no longer references the
detect track and **no longer needs** `CAP_SYS_ADMIN`/`CAP_DAC_READ_SEARCH`.

### Shared code promoted to `src/lib`

Currently in `src/agent/` but needed by both daemons after the split — move
to `src/lib` (or a shared static lib both link):

- config parser (`config.c`), `config_to_env.c`
- Ed25519 identity / key handling
- `central_checkin.c` (enrollment + reporting)
- IPC framing: `ipc_server.c`, `priv_client.c`
- `iso8601.c`, logging

`packetsonde_lib` is already the shared target; these files join it. The
CLI, `packetsonded`, and `kernelsonded` all link it.

### Privilege split

Today `priv_worker.c` does **both** pcap (raw sockets / `NET_RAW`) and
fanotify (`SYS_ADMIN`/`DAC_READ_SEARCH`), and `fan_monitor.c`/`proc_enrich.c`/
`sock_snapshot.c` are compiled into both `packetsonde-agent` and
`packetsonde-priv`. After the split:

- `packetsonde-priv` keeps **only** the pcap/raw-socket path.
- `kernelsonde-priv` (new) gets the fanotify/proc/sock path.
- The priv-worker IPC protocol/framing is shared (in `src/lib`); each worker
  implements only its own opcodes.

## Runtime model

| Aspect | `packetsonded` | `kernelsonded` |
|---|---|---|
| Caps (ambient) | `CAP_NET_RAW`, `CAP_NET_ADMIN` | `CAP_SYS_ADMIN`, `CAP_DAC_READ_SEARCH` |
| Service user | `packetsonded` | `kernelsonded` |
| Config | `/etc/packetsonded/packetsonded.toml` | `/etc/kernelsonded/kernelsonded.toml` |
| Keys | `/etc/packetsonded/keys` | `/etc/kernelsonded/keys` |
| Runtime socket | `/run/packetsonde/agent.sock` | `/run/kernelsonde/agent.sock` |
| State | `/var/lib/packetsonde` | `/var/lib/kernelsonde` |
| Unit | `packetsonded.service` | `kernelsonded.service` |

- `kernelsonded.service` carries the fanotify caps (the comment block already
  documenting them in `packaging/packetsonded.service` moves here) plus
  `RuntimeDirectory=kernelsonde`, `StateDirectory=kernelsonde`, and the same
  `ProtectSystem=strict`/`NoNewPrivileges`/etc. hardening.
- `packetsonded.service` drops the detect-caps comment and keeps only the
  network caps.
- Config: `kernelsonded.toml` carries the existing `[detect]` keys verbatim
  (`enabled`, `watch_paths`, `suppress_paths`, `max_depth`, `max_events_ps`,
  `sink`, `policy_*`, `baseline_*`, `provenance_*`, `learn_state_dir`). The
  state/sink defaults change from `/var/lib/packetsonde` to
  `/var/lib/kernelsonde`. `packetsonded` warns-and-ignores a stale `[detect]`
  block if present.

## CLI integration

One `packetsonde` CLI talks to both daemons:

- `watch`, `inspect`, `baseline`, `sandbox-suggest` default their IPC target
  to `/run/kernelsonde/agent.sock`.
- All other agent verbs default to `/run/packetsonde/agent.sock`.
- A single override (`--socket PATH`, or `PS_AGENT_SOCKET`) applies to
  whichever verb is running, for non-default deployments.

The CLI `key`/`register` verbs can manage the kernelsonded identity via the
existing `PS_KEY_DIR` mechanism pointed at `/etc/kernelsonded/keys`.

## Central integration

`kernelsonded` uses central-protocol-v1 unchanged. It enrolls as its own
agent (own key, own `register → pending → operator-validated` gate) and ships
`detect.*` findings (including `detect.file_provenance`) directly. On a host
running both daemons, central sees two independent agents; the operator
validates each. No protocol fields are added.

## Packaging & migration

- The existing single `packetsonde` `.deb` now also builds and ships
  `kernelsonded` + `kernelsonde-priv`, the `kernelsonded.service` unit
  (installed **disabled**, like `packetsonded.service`), and the
  `/etc/kernelsonded/` config + keys tree.
- debhelper still produces one binary package. `debian/rules` generates both
  units (the existing `sed` ExecStart-rewrite pattern extends to
  `kernelsonded.service`) and installs both with `--no-enable --no-start`.
- `debian/packetsonde.postinst` creates **both** system users
  (`packetsonded`, `kernelsonded`) and chowns each key dir; the prerm stops
  **both** units on removal (extend the existing explicit stop).
- Migration (lab, light): on a host that ran `packetsonded` with `[detect]`,
  the operator moves the `[detect]` block into `kernelsonded.toml`, enables
  `kernelsonded`, and enrolls it. Documented in `docs/build.md` and the salt
  pillar split (ties into the fleet-deploy plan). No automatic migration of
  learned-baseline state; operators re-point `baseline_state_dir` or copy it.

## Testing

- **Unit tests move with the code**: `test_baseline_store`,
  `test_baseline_monitor`, `test_capture_session`, and any other detect
  tests retarget to the `kernel` sources / shared lib. They must still build
  and pass under a Debug build (ctest; recall the Release/NDEBUG assert
  caveat).
- **`packetsonded` builds without the detect sources** — verify the network
  agent compiles and links with the detect track removed.
- **Live LXD-chamber acceptance** (Ubuntu 24.04, the disposable-chamber
  method): build the `.deb`; install; enable `kernelsonded` only; confirm
  fanotify capture works, `packetsonded` has no `CAP_SYS_ADMIN`
  (capability isolation holds), the CLI detect verbs reach
  `/run/kernelsonde/agent.sock`, and `kernelsonded` enrolls independently.
  Then enable both and confirm two distinct agents at central.

## Build version

Per the single-source policy, bump `PS_VERSION_STR` (patch) for the build
that introduces `kernelsonded`, and keep `debian/changelog` in lockstep
(the `build-deb.sh` guard enforces it).
