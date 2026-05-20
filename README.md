# packetsonde

A CLI-first network infrastructure and security auditing toolkit.

`packetsonde` is the auditor's command-line tool; `packetsonded` is its long-running observation agent. The CLI runs active campaigns (audit TLS / HTTP / DNS / SSH, scan ports, traceroute, probe TCP); the agent runs passive, continuous observation (flow tracking, neighbor discovery, listeners for DHCP/DNS/LLDP/CDP/STP/...).

Findings come back as **JSONL on stdout** — pipeable to `jq`, `vector`, splunk-forwarders, anything that reads a line.

---

## Documentation

- **Use case guides** — three deployment shapes packetsonde fits:
    - [Trunk probe](docs/guides/trunk-probe.md) — dot1q-attached, multi-VLAN visibility behind ACLs
    - [Service-dependency test point](docs/guides/service-dependency.md) — continuous validation that a host can reach its dependencies
    - [Passive bridge appliance](docs/guides/bridge-appliance.md) — small in-line device with wifi management
- **Extending** — [Writing audit plugins](docs/guides/writing-audit-plugins.md): single-file C plugins discovered via `dlopen` at runtime; ship custom audits without recompiling `packetsonde`. Example: `examples/audit-plugin/audit-vnc.c`.
- [Design spec](docs/specs/2026-05-18-packetsonde-cli-design.md) — finding wire format, verb grammar, defaults, follow-ons
- [Whitepaper](docs/specs/whitepaper.md) — the project's architecture and principles
- [Agent network protocol brainstorm](docs/specs/agent-network-protocol-brainstorm.md) — open design questions for the `--via <agent>` work
- [Visualization notes](docs/specs/viz-notes.md) — discipline file for the deferred viz redesign

## Status

v1.1.

| Verb       | What it does |
|-----------:|---|
| `audit`    | `tls`, `dns`, `http`, `ssh`, `smb`, `telnet`, `ftp`, `redis`, `ntp`, `memcached`, `elasticsearch`, `smtp`, `mysql`, `postgresql` |
| `scan`     | `ports` — connect-scan a target or CIDR |
| `discover` | `neighbors` (local ARP/NDP), `hosts` (port-set sweep of a CIDR) |
| `probe`    | `tcp` (single connect + banner), `traceroute` (UDP classic / Paris / Dublin) |
| `findings` | `tail` / `filter` / `stats` — read, filter, or aggregate JSONL records from a file or stdin |
| `report`   | Generate a Markdown engagement report from JSONL findings |
| `config`   | `show`, `path` — inspect resolved configuration |
| `agent`    | Control / query the local `packetsonded` |
| `version`, `help` | Standard |

## Quick start

```bash
# Build
./build.sh native

# Audit a TLS service, JSONL piped to jq
./build/src/cli/packetsonde --jsonl audit tls mail.example.com:443 | jq -c '{kind,severity,title}'

# Security-header audit on an HTTP service
./build/src/cli/packetsonde audit http https://example.com

# SSH server banner + version check
./build/src/cli/packetsonde audit ssh github.com

# Port scan a /28 with a custom port list
./build/src/cli/packetsonde scan ports 10.0.0.0/28 -p 22,80,443,8080

# Traceroute, streaming hops as findings (modes: classic, paris, dublin)
./build/src/cli/packetsonde --jsonl probe traceroute 1.1.1.1
./build/src/cli/packetsonde --jsonl probe traceroute 1.1.1.1 --mode paris
./build/src/cli/packetsonde --jsonl probe traceroute 1.1.1.1 --mode dublin

# Local ARP table
./build/src/cli/packetsonde discover neighbors

# CI/cron: exit 3 if any high-severity finding emitted
./build/src/cli/packetsonde --fail-on severity>=high audit tls $TARGET
```

## Output

Default: text on a TTY, JSONL when piped. Override with `--text`, `--json`, `--jsonl`, `--quiet`. Persist runs with `--auto-append` (writes JSONL to `$XDG_STATE_HOME/packetsonde/findings-YYYY-MM-DD.jsonl`).

Every finding carries `v: 1` and a stable schema (kind, severity, target, evidence, host, optional via_agent). The wire format is documented in `docs/specs/2026-05-18-packetsonde-cli-design.md` §3 and committed to stability.

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
        (cap_net_raw/sudo)       (network, follow-on)
                      │              │
                      ▼              ▼
                  kernel       ┌────────────────┐
                               │ packetsonded   │
                               │ on remote host │
                               └────────────────┘
```

The agent is positioned in topologically-advantaged places — see the [use case guides](docs/guides/) for the three deployment shapes.

## Build requirements

- C11 compiler (clang or gcc)
- CMake 3.20+
- OpenSSL (system) — `audit tls`, `audit http` for HTTPS
- pthreads
- Optional: libpcap, hiredis (for agent passive modules)

macOS additionally needs libedit for the agent shell.

## License

PolyForm Noncommercial 1.0.0. See `LICENSE`. Personal, educational, research, charitable, and government use are permitted; commercial use is not granted under this license.

## Project layout

```
src/
├── lib/      # libpacketsonde — finding record, JSON, ULID, IPC, traceroute core
├── agent/    # packetsonded daemon (passive observation, modules)
└── cli/      # packetsonde (this binary)
    ├── verbs/         # one file per verb
    ├── audit/         # tls, dns, http, ssh
    ├── scan/          # active scans
    ├── discover/      # local discovery
    ├── probe/         # single-target probes
    ├── findings_util/ # JSONL reader + filter
    ├── output/        # text/json/jsonl emitter
    ├── workers/       # pthread pool + rate limiter
    └── registry/      # agents.toml parser

docs/
├── guides/   # use case guides (trunk, service-dependency, bridge)
├── specs/    # design specs (cli-design, agent-network-protocol-brainstorm, viz-notes)
└── plans/    # implementation plans (one per phase)
```

## Roadmap

See `docs/specs/2026-05-18-packetsonde-cli-design.md` §8 for the full follow-on list. Near-term priorities:

1. **Agent network protocol** — unlocks `--via <agent>` for remote-segment audits. Brainstorm memo at `docs/specs/agent-network-protocol-brainstorm.md`.
2. **TCP / ICMP traceroute modes** (Paris/Dublin landed for UDP).
3. **GeoIP + ASN + JA3/JA3S/JA4 enrichment lifts.**
4. **Recipe framework** — declarative audit logic that lives client-side, signed and pushed JIT, agent stays a primitive-runner with zero offensive content at rest.
