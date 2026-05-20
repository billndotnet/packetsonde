# packetsonde CLI — Design Spec

**Date:** 2026-05-18
**Status:** Draft, pending review

---

## 1. Scope & posture

`packetsonde` is the top-level CLI of a network infrastructure and security auditing tool suite. In v1 it does two things:

1. **Discovery & inventory** — what hosts/services are present, what they run.
2. **Posture & misconfig hunting** — what is wrong: TLS hygiene, exposed services, rogue DHCP/DNS, weak protocols.

Compliance-style reports (querying/aggregating findings into deliverables) are a **downstream consumer** of the same JSONL record stream produced by v1; they are not built in v1 and not designed against, but the data model is held stable so a `report` verb can be added later as a renderer rather than a rewrite.

### 1.1 Agent deployment models (informs requirements)

The `packetsonded` agent runs in several topologically-advantaged positions:

1. **Trunk probe** — dot1q-attached host, multi-VLAN visibility behind ACLs.
2. **Service-dependency test point** — agent co-located with a service consumer, generating flows/probes to validate upstream dependencies.
3. **Passive bridge appliance** — two NICs in-line, third (wifi) for auditor access; flow generation + tap-style observation.

The CLI runs **local** work directly (on the auditor's host) and **remote** work via named agents (`--via <name>`). The remote case depends on the network-accessible agent protocol (SSH-like, key-authenticated), which is **out of v1** but whose existence shapes the CLI's design (named agent registry, `via_agent` finding field).

### 1.2 Agent/CLI split

| | Agent (`packetsonded`) | CLI (`packetsonde`) |
|---|---|---|
| Lifecycle | Long-running daemon | One-shot invocation per command |
| Posture | Passive, continuous, module-driven observation | Active, campaign-shaped probing |
| Privilege | Runs privileged where deployed; split-priv worker already exists | Unprivileged by default; raw modes opt-in via cap/sudo |
| Coupling | Neither requires the other to function | |
| Shared | Wire format of findings (JSONL); future network protocol for `--via`; `libpacketsonde` (static) | |

---

## 2. Architecture

### 2.1 Language & toolchain

C, same as the existing agent. Driven by long-term coherence: the agent will grow SSH-like network-accessible auth with key-based authentication, and operating two crypto stacks (one C agent, one Go/Rust CLI) would multiply maintenance and bug surface. A whole-suite move to Rust is a separate, larger decision; until taken, C across the board is the homogeneous choice.

### 2.2 Repo layout (post-rename)

The current `agent/` directory is renamed `src/agent/` and joined by `src/cli/` and `src/lib/`.

```
packetsonde/
├── src/
│   ├── agent/          # formerly agent/src — packetsonded daemon
│   │   ├── capture/
│   │   ├── modules/    # passive listeners (dns, dhcp, lldp, ...)
│   │   ├── platform/
│   │   ├── priv_*.c    # split-priv worker (unchanged)
│   │   └── main.c
│   ├── cli/            # new — packetsonde CLI
│   │   ├── verbs/      # one file per verb: audit.c, scan.c, discover.c,
│   │   │               #   probe.c, findings.c, agent.c, config.c
│   │   ├── audit/      # audit kind implementations: tls.c, dns.c, ...
│   │   ├── scan/       # port_connect.c, port_syn.c (raw, stubbed in v1)
│   │   ├── probe/      # tcp.c, traceroute.c (drives lib/traceroute.c)
│   │   ├── output/     # text renderer, json/jsonl emitter, color, tty detect
│   │   ├── workers.c   # pthread pool + work queue + token-bucket limiter
│   │   └── main.c
│   └── lib/            # libpacketsonde — shared between agent + cli
│       ├── finding.c   # finding record builder + emitter (the wire format)
│       ├── json.c      # moved from agent/src
│       ├── log.c       # moved
│       ├── ipc.c       # UNIX socket client (CLI → local agent)
│       ├── traceroute.c # protocol- and mode-parameterized traceroute core
│       ├── net.c       # (follow-on) network client for --via + key auth
│       └── ulid.c      # finding/run id generation
├── docs/
├── build.sh
└── CMakeLists.txt      # top-level; pulls in src/lib, src/agent, src/cli
```

`psctl` (currently `agent/src/psctl/`) is **folded into the new CLI** as the `agent` verb and retired as a standalone binary.

### 2.3 Runtime topology

```
              ┌──────────────────────────────┐
   stdout ◄── │  packetsonde (CLI)           │
              │   verbs/* → audit/scan/probe │
              │   workers (pthread pool)     │
              │   libpacketsonde (findings)  │
              └────┬────────────────────┬────┘
                   │                    │
        local raw  │                    │  --via <name>
        (cap_net_raw / sudo)            │  (network, key-auth, follow-on)
                   │                    │
                   ▼                    ▼
               kernel              ┌─────────────────┐
                                   │ packetsonded    │
                                   │ on remote host  │
                                   │ (privileged)    │
                                   └─────────────────┘
```

### 2.4 Process model in the CLI

- One main thread parses args, sets up output, dispatches to a verb.
- Verbs may spawn N workers from a pool sized by `--concurrency` (default 16).
- Each worker produces zero or more `finding` records → posted to a **single emitter thread** → written to stdout in text/JSONL. The single emitter is the load-bearing invariant that prevents interleaved output corruption.
- A token-bucket rate limiter is shared across all workers in a run; defaults are conservative (polite profile).
- SIGINT → workers finish in-flight probe → emitter flushes → exit 130. No half-written JSON lines.

### 2.5 Privilege handling (v1)

v1 drops a clear, structured error if a verb needs raw and the binary lacks the capability. No setuid helper. Where raw is needed, `cap_net_raw` on the binary or `sudo` are the documented paths. A future split-priv helper (mirroring the agent's `priv_worker`) is a follow-on.

### 2.6 Agent registry

`~/.config/packetsonde/agents.toml` (XDG). Each entry: name, address (or `local` for UNIX socket), key fingerprint, optional tags/segment metadata. v1 supports only `local`; the network transport is follow-on and the registry schema **reserves the fields** for it now so config files survive the transition.

---

## 3. Finding record (the wire format)

### 3.1 Schema (v1)

```json
{
  "v": 1,
  "id": "01HXYZ...",            // ULID, stable per finding
  "run_id": "01HXYZ...",        // groups findings from one CLI invocation
  "ts": "2026-05-18T14:22:31.142Z",
  "source": "cli.audit.tls",    // who produced it
  "host": "auditbox-01",        // where packetsonde ran
  "via_agent": "trunkbox",      // optional; only present when --via was used
  "kind": "tls.weak_cipher",    // dotted, open string taxonomy
  "target": {
    "ip": "10.0.0.42",
    "port": 443,
    "hostname": "mail.example.com"
  },
  "severity": "high",           // info|low|medium|high|critical
  "confidence": "firm",         // tentative|firm|confirmed
  "title": "TLS server negotiates 3DES",
  "evidence": { /* kind-specific blob */ },
  "tags": ["pci", "external"],
  "refs": ["CVE-2016-2183"]
}
```

### 3.2 Field rules

- `v` is the schema version. **v1 is the first stable contract**; field renames in v1 are not allowed once the CLI is released.
- `kind` is an **open string** taxonomy (operators register their own; no central registry). Convention: lowercase dotted, lowest-level identifier most specific. Documented kinds live in `docs/finding-kinds.md` (to be created).
- `source` is `cli.<verb>.<kind>` for CLI-produced findings and `agent.<module>` for agent-produced findings.
- `host` is the OS hostname of the process that produced the finding. With `--via`, `host` reflects the **agent's** host and `via_agent` carries the registry name.
- `severity` and `confidence` are closed enums; unknown values are rejected by the builder.
- Errors are **not** findings (see §4.4).

### 3.3 Source tagging convention

| Pattern | Example |
|---|---|
| `cli.audit.<kind>` | `cli.audit.tls`, `cli.audit.dns` |
| `cli.scan.<kind>` | `cli.scan.ports.connect`, `cli.scan.ports.syn` |
| `cli.probe.<kind>` | `cli.probe.tcp`, `cli.probe.traceroute` |
| `agent.<module>` | `agent.dhcp_listener`, `agent.lldp_listener` |

---

## 4. Data flow & finding lifecycle

### 4.1 Per-invocation flow

1. `main` parses global flags, generates `run_id` (ULID), dispatches to verb.
2. Verb resolves its target set (CIDR expansion, hostname resolution, file input) → list of work items.
3. Verb pushes work items onto the pool; workers run probe logic.
4. Each finding goes through `lib/finding.c`: assigned `id` (ULID), stamped with `run_id`, `ts`, `source`, `host`, optional `via_agent`, then handed to the emitter.
5. Emitter renders:
   - TTY → text/color table.
   - non-TTY → JSONL.
   - `--json` forces JSON; `--jsonl` forces JSONL; `--text` forces text.
6. If `--auto-append`, emitter also tees JSONL to `${XDG_STATE_HOME:-~/.local/state}/packetsonde/findings-YYYY-MM-DD.jsonl` (append-only, line-buffered). Useful for cron / store-and-forward.
7. On exit, summary line to **stderr**: `run <id>: <n> findings (<severity histogram>) in <duration>`.

### 4.2 Cancellation

SIGINT → workers stop dequeuing, finish in-flight probe (bounded by per-probe timeout) → emitter flushes → exit 130. The single-emitter invariant guarantees no half-written JSON lines on cancel.

### 4.3 Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean run |
| 1 | Operational error (couldn't bind, couldn't resolve target, config error) |
| 2 | Usage error (bad flags, unknown verb) |
| 3 | Partial — some targets unreachable but the run otherwise completed |
| 130 | Interrupted (SIGINT) |

Findings themselves do **not** affect exit code. A `--fail-on severity>=high` flag flips this for CI/cron use and is in v1.

### 4.4 Errors vs findings

- **Finding** = a result of the audit. Goes to stdout.
- **Error** = a failure to *perform* the audit (timeout, unreachable, permission denied, DNS lookup failed). Goes to stderr as a structured log line (`level=warn ts=… msg=… target=…`).

This is the load-bearing distinction that keeps the JSONL stream parseable.

---

## 5. CLI grammar

Verb-first, shallow tree. Examples:

```
packetsonde audit tls mail.example.com:443
packetsonde audit dns 8.8.8.8
packetsonde scan ports 10.0.0.0/24 -p 1-1024
packetsonde discover hosts en0
packetsonde discover neighbors
packetsonde probe tcp 10.0.0.42:443
packetsonde probe traceroute 1.1.1.1
packetsonde probe traceroute 1.1.1.1 --proto tcp --port 443 --mode paris
packetsonde probe traceroute 1.1.1.1 --proto udp --mode dublin
packetsonde agent status
packetsonde agent modules
packetsonde findings tail ~/.local/state/packetsonde/findings-2026-05-18.jsonl
packetsonde version
```

### 5.1 Global flags

| Flag | Purpose |
|---|---|
| `--json` | Force JSON output |
| `--jsonl` | Force JSONL output (default when stdout is not a TTY) |
| `--text` | Force text output (default when stdout is a TTY) |
| `--no-color` | Suppress color (also honors `NO_COLOR` env var) |
| `--quiet` | Tab-separated minimal output for scripting |
| `--concurrency N` | Worker pool size (default 16) |
| `--rate PPS` | Token-bucket rate cap |
| `--profile {polite,normal,aggressive}` | Preset bundle for concurrency + rate (default `polite`) |
| `--via <name>` | Dispatch to a named agent (v1: only `local`) |
| `--auto-append` | Tee JSONL to dated state file |
| `--fail-on <expr>` | Exit non-zero if findings match (e.g. `severity>=high`) |
| `--config <path>` | Override config file location |
| `-h`, `--help`, `--version` | Standard |

### 5.2 Defaults

- Polite profile: concurrency 16, rate 100 pps, per-probe timeout 2s, exponential backoff on ICMP unreachable.
- Text output on TTY, JSONL otherwise.
- No automatic persistence; `--auto-append` is opt-in.

---

## 6. v1 verb set

### 6.1 In scope

| Verb | Subcommand | Notes |
|---|---|---|
| `discover` | `hosts <iface\|cidr>` | ARP sweep + reverse DNS. Connect-only; reads neighbor table. |
| `discover` | `neighbors` | Local ARP/NDP table; if agent running, pull richer LLDP/CDP/STP. |
| `scan` | `ports <target> [-p ports]` | Connect-scan only in v1. `--syn` documented but errors with "requires raw / cap_net_raw" stub. |
| `audit` | `tls <target:port>` | Cert chain, expiry, SAN match, protocol versions (TLS 1.0/1.1 flagged), weak ciphers, weak sig algs. |
| `audit` | `dns <resolver>` | Open resolver check, version.bind leak, DNSSEC validation, ANY-amplification check. |
| `probe` | `tcp <target:port>` | TCP probe, banner grab, latency. |
| `probe` | `traceroute <target>` | Protocol- and mode-parameterized (see §6.3). |
| `agent` | `status`, `modules`, `enable`, `disable`, `hosts`, `host <ip>`, `stats`, `listen` | Folded-in `psctl` surface. |
| `findings` | `tail [path]`, `filter <expr>` | Read JSONL file/stream; pretty-print or filter. |
| `config` | `show`, `path` | Inspect resolved config. |
| `version`, `help` | | |

### 6.2 Explicitly out of v1 (follow-on)

- `--via <remote>` network transport (depends on agent network protocol).
- SYN scan / raw-ICMP traceroute (privilege story documented; code stubbed).
- `report` verb (waits for real finding volume).
- `probe dependency` (multi-target service-dependency validation).
- Additional `audit` kinds: `dhcp` rogue, `smb`, `http`, `snmp`, `ntp`, `mdns`, `ssdp` leak, etc. Each is one new file in `src/cli/audit/`.
- Run manifest (`--manifest <path>`).
- setuid/cap helper for raw work without sudo.

### 6.3 `probe traceroute` — protocol × mode matrix

Single verb with orthogonal flags:

```
packetsonde probe traceroute <target> \
    [--proto udp|tcp|icmp] \
    [--mode classic|paris|dublin] \
    [--port N]
```

Defaults: `--proto udp --mode classic`.

| Mode | Behavior | Flow-tuple treatment |
|---|---|---|
| `classic` | Increment dst port (UDP) / sequence (TCP) per probe | Varies — may traverse different ECMP paths |
| `paris` | Hold flow tuple constant across TTL probes | Same path across all hops (load-balancer-stable) |
| `dublin` | Enumerate ECMP paths by varying the flow-id deliberately | Path **set**; NAT-aware (detects translations) |

| Proto | Privilege (Linux) | Privilege (macOS) |
|---|---|---|
| `udp` | Unprivileged (uses `IP_TTL` + `IP_RECVERR`) | Unprivileged |
| `tcp` | Unprivileged (same trick on connecting socket) | Likely requires raw — portability caveat |
| `icmp` | Requires `cap_net_raw` / sudo | Requires sudo |

All variants land in `lib/traceroute.c` parameterized by `(proto, mode)`. Findings carry hop sequence, RTTs, and (for Dublin) path set + NAT observations in `evidence`. `kind` is `cli.probe.traceroute` for all; `proto` and `mode` are inside `evidence` for report grouping.

### 6.4 Definition of done

- `packetsonde audit tls mail.example.com:443` produces text findings on TTY, JSONL when piped.
- `packetsonde discover hosts en0` finds local hosts.
- `packetsonde scan ports 10.0.0.1 -p 1-1024` works without sudo.
- `packetsonde probe traceroute 1.1.1.1` works without sudo on Linux.
- `packetsonde probe traceroute 1.1.1.1 --proto tcp --port 443 --mode paris` works without sudo on Linux.
- `packetsonde probe traceroute 1.1.1.1 --proto udp --mode dublin` reports a path set.
- `--auto-append` writes a dated file and survives across runs.
- `packetsonde agent status` replaces `psctl`'s same-named call; old `psctl` binary is removed from build output.
- SIGINT mid-scan: clean exit 130, no partial JSON lines.
- Old `agent/` build artifacts gone; `build.sh` builds both `packetsonded` and `packetsonde` from the new tree.

---

## 7. Testing & verification

### 7.1 Unit tests

- `finding.c`: record build/emit, field validation, ULID monotonicity, JSON escaping.
- `json.c`: round-trip, encoding edge cases (extend existing).
- `traceroute.c`: probe-packet construction for each (proto, mode) pair; ICMP time-exceeded parsing; Paris/Dublin flow-tuple invariant assertions.
- `workers.c`: pool lifecycle, token-bucket behavior, SIGINT cancellation path.
- `output/`: tty-detection branching, JSONL framing, color suppression with `--no-color` / `NO_COLOR`, `--auto-append` path resolution.
- Arg parser: every verb's flag matrix, error messages, exit codes.

### 7.2 Integration tests

- TLS audit against a local `openssl s_server` configured with known-bad parameters (TLS 1.0, weak ciphers, expired cert). Assert specific finding kinds appear.
- Port connect-scan against a test harness that opens/closes ports in known patterns.
- Traceroute against `127.0.0.1` (one hop) — sanity check on the receive loop and emitter.
- `findings tail` / `findings filter` on a fixture JSONL file.

### 7.3 Manual verification checklist

- `packetsonde version` on macOS and Linux.
- `packetsonde audit tls badssl.com:443` interactive (text) and piped to `jq` (JSONL).
- `packetsonde scan ports 127.0.0.1 -p 1-1024` finishes in < 5s, no false positives.
- `packetsonde probe traceroute 1.1.1.1` and `--proto tcp --port 443 --mode paris` both work unprivileged on Linux.
- `--auto-append` writes the dated file and survives across runs.
- `packetsonde agent status` against a running `packetsonded`.
- SIGINT mid-scan exits cleanly, exit 130.
- `psctl` is gone from the build output.

### 7.4 Lessons baked in

- **Single emitter thread.** Prevents the interleaved-JSON-lines bug naive parallel scanners produce.
- **Findings-to-stdout, errors-to-stderr.** Keeps JSONL parseable when probes are failing.
- **Polite default.** Avoids the "scan knocked over their phone system" failure mode on customer networks.
- **Privilege story explicit from day one.** No "we'll figure out raw sockets later" debt.
- **Rename in its own commit.** `agent/` → `src/agent/` before any new CLI code lands, so git history of the agent files survives cleanly.
- **Schema version field on findings.** v1 is the first stable contract; renames after release are not allowed.

---

## 8. Open items & follow-ons (post-v1)

These are *not* in v1, but listed so the design accommodates them.

1. **Network-accessible agent protocol.** SSH-like, key-authenticated transport over TCP/TLS. Unlocks `--via <name>`. Requires choosing a TLS/crypto library (OpenSSL vs mbedTLS vs libsodium + minimal TLS). The CLI's agent registry and finding `via_agent` field reserve the surface.
2. **Compliance reports (`report` verb).** Queries the JSONL corpus, renders Markdown/JSON/SARIF.
3. **SYN scan + raw ICMP traceroute.** Documented behind a sudo/cap requirement; implementations stubbed in v1.
4. **`probe dependency`.** Multi-host service-reachability validation; particularly suited to deployment model #2 (service-dependency test point).
5. **More audit kinds.** `dhcp` rogue, `smb`, `http`, `snmp`, `ntp`, `mdns`, `ssdp` leak — each a new file under `src/cli/audit/`.
6. **setuid/cap helper.** A small split-priv helper mirroring the agent's `priv_worker` so raw work doesn't require `sudo packetsonde`.
7. **Run manifest.** `--manifest <path>` writes one JSON object describing the run; useful for cron / store-and-forward.
8. **TLS/crypto library selection.** Deferred to follow-on #1; choice will be shared between agent (for the network protocol) and CLI (for `audit tls`'s own client connections — v1 may use OpenSSL or LibreSSL pragmatically and converge later).
9. **Enrichment & interop lifts** (small, additive — fold into post-v1 plans, ranked by ROI):
   - **GeoIP + ASN tagging** on flows/findings via libmaxminddb (pmacct-style).
   - **JA3 / JA3S / JA4 TLS client/server fingerprints** in the agent's `tls_probe` module and the CLI's `audit tls` finding evidence (Suricata-style — narrow algorithmic lift, not the IDS engine).
   - **Longest-prefix aggregation** knob on `discover hosts` (e.g. `--aggregate /24`).
   - **FQDN reverse-resolve cache** for flow findings.
   - **IPFIX export** sibling to the existing NetFlow v5/v9 exporter.
   - **sFlow ingest** on agent (for upstream-switch flow data on the bridge / trunk deployment models).
   - **eve.json interop**: ensure finding records can be imported from / exported to Suricata's eve.json schema; influences §3 field choices.
10. **Passive BGP / BMP peer** for AS-path / next-hop / community enrichment of every flow. pmacct's signature feature, large enough to warrant its own spec when prioritized.

11. **Recipe framework / proxied-scan model.** Audit and probe logic become declarative **recipes** (YAML/TOML, version-pinned, signed) that live in the **client's** recipe library — never on the agent at rest. The CLI compiles a recipe into a sequence of primitive operations, signs it, and pushes it to the agent for execution; the agent streams findings back tagged with `recipe_sha256` and discards the plan on disconnect. The agent exposes only a small set of typed primitives (`tcp_connect/send/recv/set_ttl`, `udp_*`, `tls_handshake`, `dns_query`, `arp_request`, `icmp_echo`, `match`, `extract`, `emit_finding`) plus a tiny non-Turing-complete expression layer. The recipe language is intentionally not code (cf. NSE/Lua, Metasploit/Ruby).

    **Properties this gains:**
    - **Zero offensive content at rest on the agent.** Forensic and compliance posture improves significantly for trunk/bridge/handheld deployments. An imaged agent is a primitive-runner, not an attack toolkit.
    - **Recipes are config, not code.** New TLS CVE → new recipe → no agent rebuild or redeploy. Auditors maintain their own libraries in normal source control.
    - **Reproducibility / evidentiary chain.** Every finding carries the recipe hash that produced it. "What was run on this engagement?" is answered by a git tag.
    - **Eats its own tail.** Once stable, v1 verbs (`audit tls`, `audit dns`, `scan ports`) get reimplemented as `packetsonde play <recipe-set>` over the same primitives — the in-process implementations become recipe-driven, the engine pays for itself.

    **Sequencing:** This is a v3/v4 effort. v1 (current Plans 1-3) builds verbs in-process in the CLI. v2 builds the **agent network protocol** that lets `--via` transport real work — the protocol design must reserve room for typed primitives, signed plan transport, finding back-channel, and recipe-hash tagging in finding evidence. v3 builds the recipe compiler in the CLI + primitive interpreter in the agent + signing/registry. v4 ports v1 verbs to recipes. Capturing the architectural intent here means v2's protocol design can avoid lock-in even though the recipe runtime isn't built yet.

---

## 9. Out of scope (explicit non-goals)

- No GUI of any kind in this scope.
- No plugin/scripting language for custom audit modules. New modules are C files in `src/cli/audit/` and recompiled.
- No live-stream output sink beyond stdout (users compose with `tee`, `vector`, `splunk-forwarder`, etc.).
- No central finding database. JSONL is the format; users pick their sink ("ability, not philosophy").
