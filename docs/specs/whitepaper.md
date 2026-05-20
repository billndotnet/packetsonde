# packetsonde — Whitepaper

**Version:** 1.0 (toolkit-era)
**Date:** 2026-05-20
**License:** PolyForm Noncommercial 1.0.0

---

## 1. Introduction

packetsonde is a network infrastructure and security auditing toolkit built around a single principle: the auditor's intelligence lives in the client, not in the sensor. A long-running agent observes; a command-line tool drives campaigns. They meet at a stable wire format and communicate through composable Unix-tool conventions.

The toolkit is shaped by three observations about the state of auditing software in 2026:

1. **The strong open-source primitives are scattered.** Zeek excels at passive observation; nuclei at template-driven active checks; testssl.sh at TLS depth; pmacct at flow data and BGP enrichment; Suricata at stateful inspection. Each is excellent in its niche. None of them speak a common record format, so stitching them into a coherent posture story requires building glue.

2. **The strong commercial products are SaaS-first and GUI-first.** runZero, Forescout, Lansweeper, Censys give you good asset/posture data but inside walled gardens with their own query languages and dashboards. They don't compose with the rest of an operator's tooling.

3. **The auditor's deployment story is underserved.** Tools assume "you can reach the targets from where you ran the tool." Real engagements don't work that way. The trunk port behind an ACL, the in-line bridge between two segments, the test point co-located with a service consumer — these are the positions auditors actually need to operate from, and most tools punt on getting there.

packetsonde occupies the empty quadrant: open-source, unix-toolchain-native, blended active/passive, with a deployment model that names the positions where auditors actually work.

## 2. Architecture

The toolkit has two binaries and one library.

```
                ┌───────────────────────────┐
   stdout ◄──   │  packetsonde (CLI)        │
                │  verbs/* → audit/scan/..  │
                │  workers + emitter        │
                └────┬──────────────────┬───┘
                     │                  │
             local raw                  --via <name>
        (cap_net_raw/sudo)              (network protocol; follow-on)
                     │                  │
                     ▼                  ▼
                 kernel            ┌──────────────────┐
                                   │ packetsonded     │
                                   │ on remote host   │
                                   │ (passive observ.)│
                                   └──────────────────┘

                 libpacketsonde
                 ───────────────
                 finding record · JSON · log
                 ULID · IPC · traceroute core
```

**`packetsonde`** (the CLI) is the auditor's instrument. Each invocation is a one-shot campaign: connect, probe, emit findings, exit. Verbs (`audit`, `scan`, `discover`, `probe`, `findings`, `config`, `agent`) cover the active-campaign surface. The CLI is unprivileged by default; raw-socket work requires `cap_net_raw` or `sudo`.

**`packetsonded`** (the agent) is the persistent observer. It runs continuously in a network position the auditor cares about. Its modules listen for DHCP, DNS, LLDP, CDP, STP, MLD, OSPF, VRRP, SSDP, NetBIOS, neighbor solicitations, and broadcast traffic; track flows; export NetFlow; honeypot; probe. The agent has a split-privilege design: an unprivileged main process directs a small privileged worker that holds the raw socket and packet-capture capabilities.

**`libpacketsonde`** is the static library both binaries link. It owns the finding record (the wire format), JSON serialization, the IPC client used by the CLI to talk to a local agent, a ULID generator, and the protocol-and-mode-parameterized traceroute core. By living in the shared library, these primitives behave identically whether you observe locally or via the agent.

The CLI and agent are loosely coupled. The CLI can audit a network without an agent running; the agent can observe a network without a CLI ever connecting. They meet, when they meet, through one of two channels: the existing local UNIX-socket IPC, or (forthcoming) a network protocol that carries CLI requests to a remote agent and findings back.

## 3. The finding record

Every observation the toolkit emits — passive or active, agent or CLI — is a **finding record**. The record is the API.

```json
{
  "v": 1,
  "id": "01KS22Q97P2PWD0GP33AC1XYPQ",
  "run_id": "01KS22Q8AKANWNJJVZNZ1HGAM9",
  "ts": "2026-05-20T06:56:11.510Z",
  "source": "cli.audit.tls",
  "host": "auditbox-01",
  "via_agent": "trunkbox",
  "kind": "tls.weak_protocol",
  "severity": "high",
  "confidence": "firm",
  "title": "TLS 1.0 negotiated successfully",
  "target": { "ip": "10.0.0.42", "hostname": "mail.example.com", "port": 443 },
  "evidence": { "protocol": "TLSv1" },
  "tags": [],
  "refs": []
}
```

A few decisions in this schema matter beyond their syntactic surface:

**`v: 1` is the first stable contract.** The version field exists before any consumer code; once the record is in the wild, downstream pipelines depend on field stability. Schema changes that would break parsers will increment `v`. Field renames at v1 are not permitted.

**`id` and `run_id` are ULIDs.** Lexicographic sort = chronological sort. Findings from a single CLI invocation share a `run_id`, making cross-finding correlation trivial without joining on timestamps.

**`source` is dotted and open.** `cli.audit.tls`, `cli.scan.ports.connect`, `agent.dns_listener`. No central registry — modules invent their own source strings, documented by convention. This trades discoverability for plugin-friendliness, and was deliberate: an auditor who writes their own kind shouldn't have to amend a central enum.

**`host` is the box that produced the finding.** When `via_agent` is present, `host` is the agent's hostname and `via_agent` names the registry entry the CLI used to reach it. Findings always self-describe their origin.

**`evidence` is a caller-supplied JSON object literal.** No schema enforced on the inner shape. Each `kind` documents what it puts there. This is what lets new audit kinds ship without coordinating with downstream consumers — a new `kind` is also a new evidence shape, opt-in.

**Errors are not findings.** A TLS handshake that times out is operational noise; it goes to stderr as a structured log line. A TLS handshake that *succeeds* at TLS 1.0 is a finding. This is the load-bearing distinction that keeps the JSONL stream parseable when probes are failing en masse.

**Severity drives `--fail-on`.** Five closed-enum severities: `info`, `low`, `medium`, `high`, `critical`. The CLI's `--fail-on severity>=high` flag makes exit code 3 for cron/CI gating without requiring downstream parsing.

## 4. The CLI

`packetsonde` is verb-first: `packetsonde <verb> <args>`. Verbs settled in v1.1:

| Verb | Subcommands |
|---|---|
| `audit` | `tls`, `dns`, `http`, `ssh` — campaign-shaped posture checks |
| `scan` | `ports` — connect-scan of a target or CIDR |
| `discover` | `neighbors` (local ARP/NDP), `hosts` (port-sweep across CIDR) |
| `probe` | `tcp` (single connect + banner), `traceroute` (UDP classic in v1.1; Paris/Dublin/TCP/ICMP follow-on) |
| `findings` | `tail`, `filter` — read/filter JSONL records |
| `config` | `show`, `path` |
| `agent` | Local agent control (folded-in `psctl` surface) |
| `version`, `help` | Standard |

### Output: ability, not philosophy

The CLI emits JSONL to stdout. That is the entirety of the persistence story.

It does not maintain its own database. It does not require a server. It does not bundle a query language. Auditors pipe findings into the tool they already run — `jq`, `vector`, `fluent-bit`, `splunk-forwarder`, `tee >> file.jsonl`, anything that reads a line. The CLI's job is to produce well-formed records; storage and analysis are the user's choice.

On a TTY, findings pretty-print with optional ANSI color. When stdout is a pipe, JSONL is the default. `--text`, `--json`, `--jsonl`, `--quiet` force a format. `--auto-append` additionally tees JSONL to a dated file under `$XDG_STATE_HOME/packetsonde/` for store-and-forward use cases (CI, cron).

Output is thread-safe through a single emitter mutex. With multi-worker scans, no JSONL line is ever interleaved. SIGINT cancels in-flight work cleanly — workers finish the probe they started, the emitter flushes, and the run exits without leaving partial records.

### Concurrency and politeness

Active verbs (`scan`, `discover hosts`, multi-target `audit`) run a small pthread worker pool with a shared token-bucket rate limiter. The default profile is **polite**: 16 concurrent workers, 100 packets per second, 2-second per-probe timeout. The auditor on a customer network rarely wants to be the cause of an unrelated outage; this default makes a runaway scan structurally hard.

Rates are user-overridable (`--rate`, `--concurrency`, `--profile`). Defaults compose: a `discover hosts /24` of 256 addresses with default concurrency and the default rate completes in roughly 30 seconds and produces no spike.

### Exit codes

```
0   Clean run
1   Operational error (could not bind, could not resolve target)
2   Usage error (bad flags, unknown verb)
3   Findings matched --fail-on expression
130 SIGINT
```

Findings themselves never affect exit code unless `--fail-on` is set. This decoupling matters for CI: a clean run that successfully reports five `tls.weak_cipher` findings is still a successful run. The auditor opts into making findings affect exit by adding `--fail-on severity>=<level>`.

## 5. The agent

`packetsonded` runs continuously. Its job is to observe a network position and produce findings about what it sees.

**Capture layer.** libpcap-driven, with a small platform abstraction. The agent binds to one or more interfaces in promiscuous mode and feeds raw frames into a protocol demultiplexer.

**Modules.** Each module is a self-contained C file that registers callbacks for specific protocols. v1 ships:

- DHCP listener — DHCP offers, ACKs, and (importantly) rogue-DHCP detection
- DNS listener — DNS responses, including version.bind disclosures
- LLDP / CDP listeners — switch neighbor discovery, port descriptions, system names
- STP listener — bridge IDs, root bridge changes (rogue-switch detection)
- MLD listener — IPv6 multicast group membership
- Neighbor listener — ARP and NDP, MAC↔IP bindings
- NetBIOS / SSDP / mDNS — local service discovery announcements
- OSPF / VRRP listeners — routing protocol presence (often unauthenticated in misconfigured networks)
- Broadcast listener — generic catch-all for noisy broadcast traffic
- Honeypot listener — open ports that record connection attempts
- Flow tracker — bidirectional flow accounting with NetFlow v5/v9 export

**Privilege model.** The agent uses a split-privilege design: the main process runs as an unprivileged user and directs a small privileged worker over a UNIX socket. The worker holds the raw socket and packet-capture capabilities; the main process holds the IPC server and module state. A compromise of the main process gets you a configured listener; it does not get you arbitrary raw packet injection. The privileged worker speaks only the documented protocol over the IPC channel.

**IPC.** Local CLIs talk to the agent over a UNIX socket (`/tmp/packetsonde-agent.sock` by default). The protocol is line-oriented JSON: channel + payload framed by length, with subscribe/unsubscribe and request/response primitives. `packetsonde agent listen` opens a streaming subscription; `packetsonde agent hosts` is a single request/response.

### Deployment models

The agent is designed to be positioned in places auditors actually need observation. Three deployment shapes are first-class in the design:

**Trunk probe.** Agent host plugged into a switch port configured as a dot1q trunk. Subinterfaces per VLAN expose the agent to each segment as a normal L3 host. Useful for auditing networks behind ACLs the auditor's laptop can't traverse. See `docs/guides/trunk-probe.md`.

**Service-dependency test point.** Agent co-located with a real service consumer. From the same network coordinates, the agent (or a CLI-on-cron) continuously validates that the consumer's documented dependencies are reachable, healthy, and behaving as expected. Catches path-specific failures invisible to external monitors. See `docs/guides/service-dependency.md`.

**Passive bridge appliance.** Small portable host with two wired NICs joined into a transparent L2 bridge, plus a wifi interface for management. Sits between two network segments without modifying topology and without holding an IP on the inspected segments. Auditor connects only via wifi. See `docs/guides/bridge-appliance.md`.

The three share a wire format, an authentication story (key fingerprints in `agents.toml`), and the principle that the agent does not maintain state about *what the auditor is allowed to do* — it does what an authenticated CLI requests, logged, with explicit primitives.

## 6. Operational model

### JSONL is the contract

A finding emitted by `cli.audit.tls` on the auditor's laptop has the same shape as one emitted by `agent.dns_listener` on a bridge appliance two networks away. Downstream tooling consumes findings without caring which produced them. The pipeline pattern that emerges in practice:

```
agent / cli --auto-append--> /var/log/packetsonde/*.jsonl
            -- vector -->     central JSONL store
            -- alert rule --> "tls.expired_cert in last 5 min"
```

The collector is `vector` or any line-shipper. The store is whatever the operator already runs. The alerter is whatever has access to that store. No piece is bundled with the toolkit; every piece is a commodity.

### Configuration

`~/.config/packetsonde/agents.toml` (or `$XDG_CONFIG_HOME` equivalent) holds the named agent registry. v1.1 supports only `local`; remote-agent entries are reserved for the network-protocol follow-on:

```toml
[agents.local]
address = "/tmp/packetsonde-agent.sock"

[agents.trunkbox]
address = "trunkbox.lan:8855"
key_fingerprint = "SHA256:..."
tags = "vlan-trunk"
```

The CLI's `--via <name>` targets one of these. `--via local` is implicit when no `--via` is given.

### Privilege boundary

The boundary the toolkit cares about is *between the auditor and the network*, not between the auditor and the tool. The CLI is unprivileged. Raw-socket modes refuse to run without explicit capability, with a clear error pointing the operator at `cap_net_raw` or `sudo`. The agent is privileged on the network side; that's its job, and its split-privilege design contains the blast radius.

For active probing of segments the auditor can't reach from their laptop, the path is `--via <remote-agent>` once the network protocol lands. Until then, the operator SSHes to the agent host and runs the CLI locally there.

## 7. Security and forensic posture

A network-auditing tool is, by definition, exercising capabilities that could be misused. The toolkit's design accommodates this honestly:

**Forensic clarity.** Every finding records the host that produced it, the time, the run identifier, and (when applicable) the agent through which it was produced. A finding stream is its own audit trail.

**No covert operation.** The CLI does not attempt evasion — no fragmented scans, no timing obfuscation, no spoofed source addresses. An auditor using packetsonde is operating overtly, which matches the engagement model packetsonde targets. Operators who need covert capability use a different tool; this is by design, not omission.

**Agent at-rest content.** In v1, the agent's modules contain the logic for what it observes. Module C code is compiled into the binary. The forthcoming **recipe framework** (see §9) will move *active audit logic* off the agent entirely — recipes live in the auditor's client, get signed and pushed to the agent for execution, and are discarded on disconnect. An agent imaged at rest will contain primitives but no offensive scripts. For deployment models that face legal or evidentiary scrutiny (trunk probes in customer environments, bridge appliances on shared infrastructure), this is a load-bearing property.

**Authentication.** v1.1 supports only local IPC, where filesystem permissions on the socket are the access boundary. The follow-on network protocol will use a static-key, SSH-style trust model: agents and CLIs identify each other by public-key fingerprint pinned in `agents.toml` / `authorized_clients`, with optional trust-on-first-use for prototyping deployments. Design memo: `docs/specs/agent-network-protocol-brainstorm.md`.

**Polite-by-default rate limiting.** The CLI's default profile (100 pps, 16 concurrency) is structurally polite. An auditor who wants to flood opts in deliberately. Tools whose defaults trigger IDS rules are tools that get blamed for outages they didn't cause; we declined that risk.

## 8. Comparison with adjacent tools

packetsonde is intentionally adjacent to several mature tools rather than positioned against any of them. Brief mapping:

| Category | Adjacent tool | How packetsonde differs |
|---|---|---|
| Passive observation | Zeek | Smaller scope, common record format with active side, deployment-model-aware |
| Active templates | nuclei | C, not Go; recipe framework intends to ship logic from client side |
| TLS depth | testssl.sh | Same record format as the rest of the toolkit; same `--via` story |
| Active asset discovery | runZero | Open-source; CLI-first; no SaaS |
| Flow / netflow | pmacct | Inherits agent's existing flow tracker; no BGP enrichment yet (follow-on) |
| IDS | Suricata | Out of scope. packetsonde does not inspect at line rate or alert in real time |

The shape that packetsonde occupies — "Zeek + nuclei + testssl.sh stitched together with a deployment model and a common record format" — is not occupied by any single tool we know of as of 2026.

## 9. Roadmap

### Near-term

1. **Agent network protocol.** Carries CLI requests to a remote agent and findings back; unlocks `--via <agent>` and multi-agent fan-out. Pre-brainstorm design memo at `docs/specs/agent-network-protocol-brainstorm.md`. Anchor decisions: transport (Noise vs mTLS), identity model (TOFU vs pinned), wire format (length-prefixed JSON, reusing local IPC).

2. **Traceroute mode expansion.** Paris and Dublin (load-balancer-stable / ECMP-enumerating) variants for UDP; TCP-traceroute (per-mode) for firewall-traversal cases; ICMP traceroute behind a privilege opt-in.

3. **Enrichment lifts.** GeoIP + ASN via libmaxminddb; JA3 / JA3S / JA4 TLS fingerprints; FQDN reverse-resolve cache; longest-prefix aggregation; IPFIX as a sibling to NetFlow v5/v9. All additive, none coupled.

### Medium-term

4. **Recipe framework.** Audit and probe logic become **declarative recipes** (YAML/TOML, version-pinned, signed) that live in the auditor's client library. The CLI compiles a recipe into a sequence of primitive operations, signs it, pushes it to the agent for execution. The agent runs only typed primitives — `tcp_connect`, `tls_handshake`, `dns_query`, `arp_request`, `match`, `extract`, `emit_finding` — and discards the plan on disconnect. Every finding carries the recipe SHA-256 that produced it.

   The properties this enables:
   - Zero offensive content at rest on the agent. Improves forensic and compliance posture significantly.
   - Recipes versioned in normal source control; "what was run on this engagement" is answered by a git tag.
   - New audit knowledge ships as a new recipe, not a new agent build. No redeploy for new CVE response.
   - v1 verbs (`audit tls`, `audit dns`, etc.) get reimplemented as recipe sets over the same primitives. The framework pays for itself once.

   This is a v3/v4 effort. The agent network protocol (above) must reserve room for signed plan transport, recipe-hash tagging in evidence, and a typed primitive set.

5. **Passive BGP / BMP peer.** Tag every flow with AS-path, next-hop, communities. pmacct's signature feature. Its own spec when prioritized.


## 10. Design principles

The toolkit consistently makes these choices, and they're worth naming:

**Stable wire format over flexible internal API.** Internal interfaces change. Finding records don't.

**Records, not events.** A finding is an immutable, self-describing record with a stable identity. It is not an event in a stream the consumer is expected to materialize into something. The persistence model is whatever the operator wants; the format does not assume.

**Errors to stderr, findings to stdout.** Mixing these breaks pipelines. The discipline is non-negotiable.

**Polite default, loud opt-in.** Defaults that can't cause outages on a customer network. Loud behavior requires deliberate action.

**Composability over completeness.** No bundled database. No bundled query language. No bundled GUI. Each of these has competent commodity solutions; packetsonde adds value by being good at producing well-formed records, not by reinventing storage.

**Auditor's perspective on the agent.** The agent is the auditor's instrument, not a centrally-managed sensor. It runs in positions the auditor configures and does work the auditor requests. Future iterations push this further with the recipe framework.

**One bad commit shouldn't end the project.** Schema versioning, single emitter mutex, SIGINT discipline, polite defaults — these are precautions against the kind of mistake that becomes a permanent embarrassment in the wild.

## 11. License and scope

**License.** PolyForm Noncommercial 1.0.0. Permits personal, educational, research, charitable, and government use. Commercial use is not granted under this license.

**Explicit non-goals.**
- Not an IDS. No line-rate inspection, no real-time alerting framework.
- Not a SIEM. Records go to stdout; downstream tooling is the user's choice.
- Not a covert tool. The CLI does not implement evasion techniques.
- Not a GUI. The CLI is the interface.
- Not a plugin runtime in v1. New audit knowledge ships as C files; the recipe framework (v3/v4) replaces this with declarative recipes.
