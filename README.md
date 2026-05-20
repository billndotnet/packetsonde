# packetsonde

A CLI-first network infrastructure and security auditing toolkit.

`packetsonde` is the auditor's command-line tool; `packetsonded` is its long-running observation agent. The CLI runs active campaigns (audit TLS, scan ports, traceroute, probe DNS); the agent runs passive, continuous observation (flow tracking, neighbor discovery, listeners for DHCP/DNS/LLDP/CDP/STP/...).

Findings come back as **JSONL on stdout** — pipeable to `jq`, `vector`, splunk-forwarders, anything that reads a line.

## Status

v1 shipped. Verb surface:

| Verb       | What it does |
|-----------:|---|
| `audit`    | TLS hygiene (`tls`), DNS resolver posture (`dns`) |
| `scan`     | Connect-scan ports across a target or CIDR |
| `discover` | Local ARP/NDP table (`neighbors`), host sweep across a CIDR (`hosts`) |
| `probe`    | Single TCP probe (`tcp`), traceroute (`traceroute` — UDP classic in v1) |
| `findings` | Tail / filter JSONL finding records |
| `config`   | Show resolved configuration |
| `agent`    | Control / query the local `packetsonded` |
| `version`, `help` | Standard |

## Quick start

```bash
# Build
./build.sh native

# Audit a TLS service, JSONL piped to jq
./build/src/cli/packetsonde --jsonl audit tls mail.example.com:443 | jq -c '{kind,severity,title}'

# Port scan a /28 with a custom port list
./build/src/cli/packetsonde scan ports 10.0.0.0/28 -p 22,80,443,8080

# Traceroute, streaming hops as findings
./build/src/cli/packetsonde --jsonl probe traceroute 1.1.1.1

# Local ARP table
./build/src/cli/packetsonde discover neighbors

# CI/cron: exit 3 if any high-severity finding emitted
./build/src/cli/packetsonde --fail-on severity>=high audit tls $TARGET
```

## Output

Default: text on a TTY, JSONL when piped. Override with `--text`, `--json`, `--jsonl`, `--quiet`. Persist runs with `--auto-append` (writes JSONL to `~/.local/state/packetsonde/findings-YYYY-MM-DD.jsonl`).

Finding wire format documented in `docs/specs/2026-05-18-packetsonde-cli-design.md` §3. Schema-versioned at `v: 1` and committed to stability.

## Architecture in one diagram

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

The agent is positioned in topologically-advantaged places: dot1q trunk for multi-VLAN visibility, in-line bridge for tap-style observation, or co-located with a service consumer to validate upstream dependencies.

## Build requirements

- C11 compiler (clang or gcc)
- CMake 3.20+
- OpenSSL (system)
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
    ├── audit/         # audit kinds (tls, dns)
    ├── scan/          # active scans
    ├── discover/      # local discovery
    ├── probe/         # single-target probes
    ├── findings_util/ # JSONL reader + filter
    ├── output/        # text/json/jsonl emitter
    ├── workers/       # pthread pool + rate limiter
    └── registry/      # agents.toml parser

docs/
├── specs/    # design specs (cli-design, agent-network-protocol-brainstorm)
└── plans/    # implementation plans (one per phase)
```

## Roadmap

See `docs/specs/2026-05-18-packetsonde-cli-design.md` §8 for the follow-on list. Near-term priorities:

1. Agent network protocol — unlocks `--via <agent>` for remote-segment audits. Brainstorm memo at `docs/specs/agent-network-protocol-brainstorm.md`.
2. Paris / Dublin / TCP / ICMP traceroute modes.
3. GeoIP + ASN + JA3/JA3S/JA4 enrichment lifts.
4. Recipe framework — declarative audit logic that lives client-side, signed and pushed JIT, agent stays a primitive-runner with zero offensive content at rest.

## Not a 3D visualizer (anymore)

The repo briefly included a UE5-based visualization frontend (per the original whitepaper in `docs/specs/whitepaper.md`). That work is archived locally and paused; the project's focus is the CLI toolkit until the data and operational story are mature enough to inform a better visualization design.
