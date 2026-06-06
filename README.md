# packetsonde

A CLI-first network infrastructure and security auditing toolkit.

`packetsonde` is the auditor's command-line tool; `packetsonded` is its long-running observation agent. The CLI runs active campaigns (audit TLS / HTTP / DNS / SSH and 20+ other services, scan ports, traceroute, probe TCP); the agent runs passive, continuous observation (flow tracking, neighbor discovery, L2/L3 control-plane listeners) and — on Linux — host process/file/socket behavioral monitoring.

Findings come back as **JSONL on stdout** — pipeable to `jq`, `vector`, splunk-forwarders, anything that reads a line.

---

## Documentation

- **Use case guides** — deployment shapes packetsonde fits:
    - [Trunk probe](docs/guides/trunk-probe.md) — dot1q-attached, multi-VLAN visibility behind ACLs
    - [Service-dependency test point](docs/guides/service-dependency.md) — continuous validation that a host can reach its dependencies
    - [Passive bridge appliance](docs/guides/bridge-appliance.md) — small in-line device with wifi management
- **Building** — [docs/build.md](docs/build.md): per-platform build, install layout, the single-source build version + dev-push bump policy
- **Deploying a fleet** — [packaging/salt/README.md](packaging/salt/README.md): SaltStack state, staged rollout, enrollment
- **Extending** — [Writing audit plugins](docs/guides/writing-audit-plugins.md): single-file C plugins discovered via `dlopen` at runtime; ship custom audits without recompiling `packetsonde`. Example: `examples/audit-plugin/audit-vnc.c`.
- **Reference** — [central protocol v1](docs/specs/central-protocol-v1.md) (agent↔central wire contract), [whitepaper](docs/specs/whitepaper.md) (architecture and principles)

## Status

Actively developed. Milestone history in [CHANGELOG.md](CHANGELOG.md); current build version reported by `packetsonde version`.

### CLI verbs

| Verb | What it does |
|-----------:|---|
| `audit`    | 26 services: `tls`, `dns`, `http`, `ssh`, `smb`, `telnet`, `ftp`, `redis`, `ntp`, `memcached`, `elasticsearch`, `smtp`, `mysql`, `postgresql`, `ldap`, `imap`, `pop3`, `snmp`, `rdp`, `mssql`, `kafka`, `vnc`, `haproxy`, `proxmox`, `nginx`, `opnsense` |
| `scan`     | `ports` — connect-scan a target or CIDR (TCP / UDP) |
| `discover` | `neighbors` (local ARP/NDP), `hosts` (port-set sweep), `agents` (signed broadcast for remote `packetsonded`) |
| `probe`    | `tcp` (single connect + banner), `traceroute` (UDP / TCP / ICMP; classic / Paris / Dublin; streams hops live with `--max-gap` early-stop and optional `--ptr` reverse-DNS) |
| `recipe`   | `run` / `sign` / `verify` / `info` — author and run signed declarative audit recipes (pushed JIT to a remote agent over `--via`) |
| `findings` | `tail` / `filter` / `stats` — read, filter, or aggregate JSONL records from a file or stdin |
| `report`   | Generate a Markdown engagement report from JSONL findings |
| `collect`  | Receive + present signed findings from a remote agent, central-free |
| `watch`    | Tail the agent's process/file/socket activity records (JSONL) |
| `inspect`  | Live mtr-style dashboard of one process's fanotify profile (`--pid N` or `--exe PATH`): files / network dests / spawned procs with baseline verdicts; `--stream` emits the `profile.v1` keyframe/delta feed |
| `baseline` | Manage learned per-executable behavioral baselines (`list` / `approve` / `deny` for file paths, network dests, spawn parents) |
| `sandbox-suggest` | Emit a suggested systemd sandbox stanza from learned per-unit activity |
| `key`      | `generate` / `list` / `fingerprint` / `revoke` — Ed25519 identity for discovery, `--via`, and enrollment |
| `register` | Enroll this host with central management (lands a `pending` agent for operator validation) |
| `report-central` | Ship findings JSONL to central |
| `config`   | `show`, `path` — inspect resolved configuration |
| `agent`    | Control / query the local `packetsonded` |
| `version`, `help` | Standard |

### The agent (`packetsonded`)

Long-running passive observation, plus an opt-in remote-audit channel:

- **Passive control-plane listeners** — DHCP, DNS, CDP, LLDP, STP, OSPF, VRRP, SSDP, NetBIOS, MLD, ARP/NDP neighbors, broadcast, and a honeypot listener. Zero injected traffic; it watches what the segment already carries.
- **Flow tracking + interface monitor** — connection/flow accounting and live capture-interface state, with dynamic capture-interface selection.
- **TLS fingerprinting** — JA3 / JA3S / JA4 / JA4S / JA4X computed from observed handshakes.
- **`--via <agent>`** — the CLI dispatches audits to a remote agent over a TLS 1.3 mTLS channel (identity == Ed25519 pubkey, no PKI). Single- and multi-hop (`CLI → bunker → trunkbox`), with an optional knock-then-listen stealth mode (no idle listening socket between signed knocks).
- **Central integration** — Ed25519 enrollment (`register` → `pending` → operator-validated trust gate), batched observation reporting, and relay forwarding so deep-segment agents reach central through an edge hop.

### Process-level detection track (Linux)

A layered, post-exploitation behavioral sensor for the host the agent runs on:

1. **Collection** — `fanotify` in a privilege-separated worker captures process/file/socket activity, enriched from `/proc` with an ancestry walk to the owning service/session. View it live as raw events with `packetsonde watch --follow`, or as an aggregated per-process dashboard with `packetsonde inspect --pid N | --exe PATH` (files / dests / spawned procs with baseline verdicts; `--stream` emits the `profile.v1` keyframe/delta feed).
2. **Declared-policy overwatch** — compares observed activity against the unit's own `systemd` sandbox directives (`ProtectSystem`, `ReadOnlyPaths`, exec-from-writable, …) and flags violations. A `learn` mode accumulates per-unit envelopes; `packetsonde sandbox-suggest <unit>` turns them into a tightened sandbox stanza.
3. **Learned per-exe baseline** — a hybrid learn/enforce allowlist keyed by executable across three signals: **file paths**, **network destinations**, and **spawn parents**. Novel activity becomes a candidate; an operator `approve`s it into the baseline or `deny`s it (denied → anomaly) via the `baseline` verb.

All three run together off a multi-consumer activity ring and are off by default (`[detect]` config block).

When provenance is enabled (`detect_provenance_enabled` pillar / `[detect]
provenance_enabled`), suspicious writes/execs (droppers to `/tmp`, persistence
writes, execs from transient dirs) are reported to central as
`detect.file_provenance` findings answering "who wrote this, and from where?".

## Quick start

```bash
# Install build deps (Ubuntu/Debian, RHEL/Fedora, FreeBSD/OPNsense
# detected automatically; macOS prints the brew command).
sudo ./bootstrap.sh

# Build agent + CLI
./build.sh

# Audit a TLS service, JSONL piped to jq
./build/src/cli/packetsonde --jsonl audit tls mail.example.com:443 | jq -c '{kind,severity,title}'

# Security-header audit on an HTTP service
./build/src/cli/packetsonde audit http https://example.com

# SSH server banner + version check
./build/src/cli/packetsonde audit ssh github.com

# Port scan a /28 with a custom port list
./build/src/cli/packetsonde scan ports 10.0.0.0/28 -p 22,80,443,8080

# Traceroute, streaming hops as findings (modes: classic, paris, dublin)
./build/src/cli/packetsonde --jsonl probe traceroute 1.1.1.1 --mode paris

# Local ARP table
./build/src/cli/packetsonde discover neighbors

# CI/cron: exit 3 if any high-severity finding emitted
./build/src/cli/packetsonde --fail-on severity>=high audit tls $TARGET
```

## Output

Default: text on a TTY, JSONL when piped. Override with `--text`, `--json`, `--jsonl`, `--quiet`. Persist runs with `--auto-append` (writes JSONL to `$XDG_STATE_HOME/packetsonde/findings-YYYY-MM-DD.jsonl`).

Every finding carries `v: 1` and a stable schema (kind, severity, target, evidence, host, optional via_agent); the wire format is committed to stability. The agent↔central contract is in [docs/specs/central-protocol-v1.md](docs/specs/central-protocol-v1.md).

Example finding:

```json
{"v":1,"id":"01KS22Q97P...","run_id":"01KS22Q8AK...","ts":"2026-05-20T06:56:11.510Z",
 "source":"cli.audit.tls","host":"auditbox","kind":"tls.weak_protocol",
 "severity":"high","confidence":"firm",
 "title":"TLS 1.0 negotiated successfully",
 "target":{"ip":"10.0.0.42","hostname":"mail.example.com","port":443},
 "evidence":{"protocol":"TLSv1"}}
```

## Architecture

```
                 ┌──────────────────────────┐
   stdout ◄──    │  packetsonde (CLI)       │
                 │  verbs/* → audit/scan/.. │
                 │  workers + emitter       │
                 └────┬──────────────┬──────┘
                      │              │
              local raw          --via <name>
        (cap_net_raw/sudo)       (mTLS, knock-then-listen,
                      │           single- or multi-hop)
                      ▼              ▼
                  kernel       ┌────────────────┐      enroll / observations / relay
                               │ packetsonded   │ ───────────────────────────► central
                               │ on remote host │
                               └────────────────┘
```

The agent is positioned in topologically-advantaged places — see the [use case guides](docs/guides/) for the deployment shapes.

## Security & trust model

packetsonde is a network-auditing tool — by definition it exercises capabilities that could be misused — so the trust model is explicit and the design is overt by construction. This section is the orientation for a security reviewer; the wire-level contract is in [central-protocol-v1](docs/specs/central-protocol-v1.md) and the rationale in the [whitepaper](docs/specs/whitepaper.md) §7.

### Cryptographic identity — Ed25519, no PKI

Every CLI and agent has an **Ed25519 keypair**, not an X.509 certificate. There is no CA, no chain, no expiry to manage. A peer *is* its public key; you refer to it by its `sha256:` fingerprint.

```bash
packetsonde key generate --name auditor      # 32-byte .pub / .sec in the keystore
packetsonde key fingerprint auditor          # sha256:d607af8a...  (the stable identity)
packetsonde key list / key revoke <name>
```

Keys live in the per-user keystore (`$PS_KEY_DIR`, default `~/.config/packetsonde/keys`); secret keys are 32-byte Ed25519 seeds and never leave the host. This one identity is reused for the three trust decisions below.

### Authenticated transport — pinned-key mTLS

The `--via <agent>` channel is **TLS 1.3 with mutual authentication**, but identity is the pinned Ed25519 public key rather than a PKI-issued cert (an SSH-style static-key model). The CLI pins the agent's fingerprint in `agents.toml`; the agent authorizes client pubkeys it will accept. Neither side trusts a peer it hasn't been told about (optional trust-on-first-use exists for prototyping only).

```toml
[agents.trunkbox]
address = "10.20.0.9:7443"
key_fingerprint = "sha256:1f3c…"     # connection aborts if the peer key doesn't match
```

Multi-hop (`CLI → bunker → trunkbox`) chains these pinned channels. An optional **knock-then-listen** mode keeps the agent with *no idle listening socket* between signed knocks, shrinking its attack surface to zero when not in use.

### Authorization gates — explicit operator consent

Two human-in-the-loop gates bound what an authenticated peer can do:

- **Agent side:** a client pubkey must be present in the agent's authorized-clients set before any `--via` request is honored. Authentication (who you are) and authorization (what you're allowed) are separate steps.
- **Central side:** `packetsonde register` lands an agent in a **`pending`** state. An operator must validate and promote it before central ingests its findings or the agent appears in the fleet. Enrollment is not auto-trust.

### Signed declarative recipes — no offensive logic at rest on the agent

Active audit logic is authored and signed on the **auditor's** machine, pushed to the agent just-in-time over the already-authenticated `--via` channel, executed, and discarded on disconnect. **An agent imaged at rest contains audit *primitives* (connect / send / recv / match / TLS-probe opcodes) but no offensive scripts** — a load-bearing property for trunk probes and bridge appliances in environments that face legal or evidentiary scrutiny.

A recipe is wrapped in a signed envelope. The signature is **Ed25519 over the 72-byte tuple**:

```
recipe_sha256 (32)  ‖  author_pub (32)  ‖  signed_at_ms (8, big-endian)
```

so the signature binds the exact recipe bytes, the signing identity, and the signing time together — a tampered recipe, a swapped author key, or a replayed-with-different-time envelope all fail verification.

```bash
packetsonde recipe sign   --key auditor -o tls.signed.json recipes/tls-posture.json
packetsonde recipe verify tls.signed.json     # signature: VALID + author fingerprint + signed_at
packetsonde recipe info   tls.signed.json     # name, version, step/probe budgets, author, signed_at
```

Verification is deliberately **two decisions, kept separate**: (1) *is the signature cryptographically valid* over those bytes (`recipe verify`), and (2) *is `author_pub` an identity I trust* (a keystore lookup the operator controls). A valid signature from an unknown author is reported, not silently honored. Recipes are also **budgeted** — caps on steps, receive bytes, targets, wall-clock, and TLS handshakes per run are part of the signed document, so an authorized recipe still can't run unbounded.

### Privilege boundary

The boundary the toolkit defends is *between the auditor and the network*, not between the auditor and the tool.

- The **CLI is unprivileged** by default. Raw-socket modes refuse to run without `cap_net_raw` (or `sudo`) and say so explicitly — no silent privilege escalation.
- The **agent is split-privilege**: an unprivileged main process directs a small privileged worker that holds the raw socket / packet-capture / `fanotify` capabilities, containing the blast radius of the component that has to be privileged.

### Forensic posture — overt by design

- **The finding stream is its own audit trail.** Every record carries the producing host, timestamp, run identifier, and (when applicable) the `via_agent` it was produced through.
- **No covert operation.** No fragmented scans, no timing obfuscation, no source-address spoofing. Operators who need covert capability use a different tool — this is by design, not omission.
- **Polite by default.** The default profile (100 pps, 16 concurrency) is structurally unlikely to trip an IDS or cause an outage; flooding is a deliberate opt-in.
- **No secrets at rest in source or findings.** Identity is key-based; findings are observations, not credentials.

## Build requirements

- C11 compiler (clang or gcc)
- CMake 3.20+
- OpenSSL — `audit tls`, `audit http` for HTTPS, mTLS for the agent network protocol
- pthreads
- libedit — used by the `packetsonde agent shell` REPL
    - macOS: shipped (no install needed)
    - Debian/Ubuntu: `apt install libedit-dev`
    - RHEL/Fedora: `dnf install libedit-devel`
- Optional: libpcap (passive capture), hiredis (Redis bridge) — agent only
    - Debian/Ubuntu: `apt install libpcap-dev libhiredis-dev`
    - RHEL/Fedora: `dnf install libpcap-devel hiredis-devel`

The process-level detection track (`fanotify`) is Linux-only; the rest builds and runs on macOS, Linux, and FreeBSD / OPNsense. See [docs/build.md](docs/build.md).

## License

PolyForm Noncommercial 1.0.0, modified to exclude government use. See `LICENSE`. Personal, educational, research, and charitable use are permitted; commercial and government use are not granted under this license. Contact the licensor for a separate license if you need to use this software for any non-permitted purpose.

## Project layout

```
src/
├── lib/      # libpacketsonde — finding record, JSON, ULID, IPC, traceroute core,
│             #   baseline set/decide, dest match, relay attestation
├── agent/    # packetsonded daemon — passive listeners, flow tracker, iface monitor,
│             #   process-collection worker, policy overwatch, learned baseline
└── cli/      # packetsonde (this binary)
    ├── verbs/         # one file per verb
    ├── audit/         # 26 audit kinds (also built as dlopen plugins)
    ├── scan/          # active scans (tcp/udp ports)
    ├── discover/      # neighbors, hosts, agents
    ├── probe/         # single-target probes + traceroute
    ├── remote/        # --via channel (audit/ingest over mTLS)
    ├── recipe/        # signed declarative recipe runner
    ├── findings_util/ # JSONL reader + filter
    ├── output/        # text/json/jsonl emitter
    ├── workers/       # pthread pool + rate limiter
    └── registry/      # agents.toml parser

docs/
├── guides/   # use case guides + plugin authoring
├── build.md  # build + version policy
└── specs/    # durable reference docs (central-protocol-v1, whitepaper, viz-notes)

packaging/    # salt state (fleet deploy), systemd unit, bootstrap installers
```

> Design specs and per-phase implementation plans are kept **local** (untracked) as development scaffolding — they're not part of the published tree.
