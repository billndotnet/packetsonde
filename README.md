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
| `probe`    | `tcp` (single connect + banner), `traceroute` (UDP / TCP / ICMP; classic / Paris / Dublin) |
| `recipe`   | Run / manage signed declarative audit recipes (pushed JIT to a remote agent over `--via`) |
| `findings` | `tail` / `filter` / `stats` — read, filter, or aggregate JSONL records from a file or stdin |
| `report`   | Generate a Markdown engagement report from JSONL findings |
| `collect`  | Receive + present signed findings from a remote agent, central-free |
| `watch`    | Tail the agent's process/file/socket activity records (JSONL) |
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

1. **Collection** — `fanotify` in a privilege-separated worker captures process/file/socket activity, enriched from `/proc` with an ancestry walk to the owning service/session. View it live with `packetsonde watch --follow`.
2. **Declared-policy overwatch** — compares observed activity against the unit's own `systemd` sandbox directives (`ProtectSystem`, `ReadOnlyPaths`, exec-from-writable, …) and flags violations. A `learn` mode accumulates per-unit envelopes; `packetsonde sandbox-suggest <unit>` turns them into a tightened sandbox stanza.
3. **Learned per-exe baseline** — a hybrid learn/enforce allowlist keyed by executable across three signals: **file paths**, **network destinations**, and **spawn parents**. Novel activity becomes a candidate; an operator `approve`s it into the baseline or `deny`s it (denied → anomaly) via the `baseline` verb.

All three run together off a multi-consumer activity ring and are off by default (`[detect]` config block).

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
