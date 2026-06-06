# Changelog

All notable changes to packetsonde. Format roughly follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added — TLS fingerprints
- **JA4 (client) + JA4S (server)** (FoxIO 2023) emitted alongside the existing JA3 / JA3S / JA4X in `tls.metadata` evidence. JA4 surfaces real TLS version via `supported_versions`, drops GREASE, sorts ciphers and extensions for stability under Chrome-style extension shuffling, and includes signature_algorithms in original order. Pure parser on the already-captured `client_hello` / `server_hello` — no new deps, no probe behavior changes.

### Added — process-level detection track (Linux)
Layered, post-exploitation behavioral sensor for the agent's host. Off by default (`[detect]`).
- **Collection primitives** — `fanotify` in the privilege-separated worker captures process/file/socket activity, enriched from `/proc` with an ancestry walk to the owning service/session, fanned out over a multi-consumer activity ring. New `packetsonde watch [--follow]` tails the JSONL records.
- **Declared-policy overwatch** — brain-side module compares observed activity to each unit's own `systemd` sandbox directives and flags violations; `learn` mode accumulates per-unit envelopes and `packetsonde sandbox-suggest <unit>` synthesizes a tightened sandbox stanza.
- **Learned per-exe baseline** — hybrid learn/enforce allowlist keyed by executable across three signals: file paths, network destinations, and spawn parents. Novel → candidate → operator `approve`/`deny` via the new `baseline` verb (denied → anomaly).

### Added — fleet + central integration
- **Agent registration/enrollment** — Ed25519 keystore identity, `[central]` config, `packetsonde register` (lands a `pending` agent for operator validation).
- **Observation reporting** — agent ships queued passive findings to central in bounded batches.
- **Relay forwarding** — deep-segment agents reach central through an edge hop (signed, chain-verified ingest).
- **Collector / return-routing** — `packetsonde collect` receives + presents signed findings central-free.
- **Interface monitor + dynamic capture interface** — live capture-interface state and selection.

### Added — recipe framework
- Signed declarative audit recipes that live client-side and are pushed JIT to a remote agent over the `--via` channel; the agent stays a primitive-runner with no offensive content at rest.
- **Schema-2 TLS-aware engine** — `tls_upgrade` / `tls_enum` opcodes, string-list bindings with match-any (`any ~ regex` / `any_in`), cipher peeling, and a `max_tls_probes` budget, so a recipe can classify TLS posture (enumerate offered protocols/ciphers, inspect the leaf cert) rather than only banner-grab.
- **Schema negotiation** — the agent advertises its `max_recipe_schema` in the hello; the CLI declines to push a recipe an older agent can't execute.
- **Authoring verbs** — `recipe sign` wraps canonical recipe JSON in an Ed25519-signed envelope (signature over `recipe_sha256 ‖ author_pub ‖ signed_at_ms`); `recipe verify` checks the signature and re-parses the inner recipe (signature validity and author *trust* are reported separately); `recipe info` summarizes name / version / budgets and, for envelopes, the author fingerprint and signing time.

### Added — reactive traceroute
- **Streaming + early-stop** — `probe traceroute` emits each hop the instant it resolves (no more waiting for the whole walk) and stops on destination-reached or after `--max-gap` consecutive dead hops (default 5), so a dark-tail host no longer walks all 30 TTLs (~24s → seconds). The core is refactored to a per-hop callback; `ps_traceroute_run` stays a thin back-compat wrapper.
- **`--ptr`** — reverse-DNS for hop IPs with a per-IP positive+negative cache (background resolver thread, bounded grace before each hop is emitted).

### Added — live process inspection (`inspect`)
- **`packetsonde inspect` (`--pid N` | `--exe PATH`)** — an mtr-style live dashboard of one process's fanotify profile: files / network destinations / spawned processes with learned-baseline verdicts (covered / novel / anomaly), plus a header of event rates, ancestry, cgroup/MAC, and live sockets. `--pid` follows the process and its live subtree.
- **`profile.v1` stream** — model-first design: the dashboard is renderer #0 of a versioned keyframe+delta stream (game-engine replication shape); `--stream` emits the feed for pipes / a future 3D client. Round-trippable and desync-safe.

### Fixed
- **traceroute arg ordering + `*`-hop target** — the target may now appear before, after, or interleaved with options (POSIX getopt does not permute, so options before the target were silently dropped and the target itself could be parsed as an option); a second positional is rejected. A no-reply `*` hop no longer displays the trace destination as its own target — the destination moves to the `traced` evidence field.
- **Recipe envelope parser buffer overflow** — `EVP_DecodeBlock` decodes in 3-byte groups, so the 44-char `author_pub` base64 wrote 33 bytes into the 32-byte field, corrupting the adjacent `signed_at_ms`. Timestamps ending in a zero low byte survived (masking the bug); others made freshly-signed envelopes verify as INVALID. Now decoded via sized temporaries with an exact-length copy; regression-locked with an odd-timestamp signing test.

### Packaging
- **`[detect]` config stub** — the salt-rendered `packetsonded.toml` now ships a pillar-driven `[detect]` block (off by default; set `packetsonde:detect_enabled "1"` to enable) so the activity sink that `inspect` / `watch` read is configurable, and the state creates `/var/lib/packetsonde` for it.

### Added — audit kinds
- `haproxy`, `proxmox`, `nginx`, `opnsense` — `audit` now covers 26 services.

### Build
- Single-source build version (`PS_VERSION_STR` in the root CMake drives CLI + agent + priv worker); dev-push policy bumps the patch value per fleet build so a binary swap is verifiable. See `docs/build.md`.

## [v1.6] — 2026-05-20

### Added — agent network protocol
Closes the `--via <agent>` follow-on. End-to-end mTLS channel for remote-segment audits; reuses the Ed25519 keystore from v1.5 discovery so identity and trust model are unified across the project.

- **`src/lib/agent_proto.{h,c}`** — transport-independent wire framing. `uint32_t length || JSON{...}` per frame, 1 MiB ceiling, canonical message types: `hello`, `audit`, `finding`, `log`, `error`, `bye`. Conservative top-level `type` scanner so the dispatch path doesn't pay for a full JSON parse on every frame.
- **`src/lib/agent_transport.{h,c}`** — TLS 1.3 mTLS with Ed25519 self-signed certs. Identity == pubkey, no PKI, no CA, no chain validation. Built-in verify callback accepts the chain unconditionally; the real check is a post-handshake SHA-256 of the peer's `SubjectPublicKeyInfo` compared to a pinned fingerprint. `SSL` wrapped in the `ps_ap_io` abstraction so framing code works over both plain fds (tests) and TLS sessions.
- **CLI `--via <agent>`** — when set, `packetsonde audit ...` dispatches to a remote agent instead of the local audit modules. Resolves the agent from `agents.toml` (`key_fingerprint` pin required), opens the mTLS channel, sends `hello` + `audit`, streams `finding` frames back with a `via_agent` field spliced in.
- **agent `network_listener` module** — operator opt-in (`PS_AGENT_LISTEN_MODE=persistent|knock|both`). Accept loop, pthread per session (capped via `PS_AGENT_MAX_CLIENTS`, default 64). On valid audit request, forks `packetsonde --jsonl audit ...` as a subprocess and pipes each JSONL line out as a `finding` frame. Audit-side crashes can't take down the agent.
- **Knock-then-listen stealth mode** — bit 0 of the existing discovery probe flags = `PS_DISCOVERY_FLAG_REQUEST_SESSION`. The discovery_listener calls a cross-module hook into network_listener to bind a fresh ephemeral TCP socket for one accept; the discovery reply advertises that port. Between knocks the agent has no listening socket at all — port scans return nothing distinguishable from a quiet host. CLI side: `knock = "true"` + optional `broadcast = "..."` in `agents.toml`.
- **End-to-end test (`test_via_e2e`)** — drives a real `packetsonde --via testagent audit ssh` against a `test_network_listener_driver` that hosts the agent module, with a Python mock SSH server as the audit target. Asserts `ssh.metadata`, `ssh.old_version`, and `via_agent` all appear in the finding stream.

### Tags
- `v1.6`

## [v1.5] — 2026-05-20

### Added — audit kinds
Three new audit kinds; `audit` verb now covers 21 services.

- **`audit rdp`** — RDP exposure + NLA detection on TCP/3389. Speaks the X.224 / TPKT handshake, sends an `RDP_NEG_REQ` advertising RDP / TLS / HYBRID / HYBRID_EX, parses the `RDP_NEG_RSP`. Emits `rdp.metadata` (info), `rdp.exposed` (medium), and `rdp.no_nla` (high) when the server selects plain RDP or TLS-only — the BlueKeep-class exposure where pre-auth code lives on the listener.
- **`audit mssql`** — Microsoft SQL Server pre-login probe on TCP/1433. TDS Pre-Login packet, parses version + encryption posture. Emits `mssql.metadata` (info), `mssql.no_encryption` (high, encryption=OFF/NOT_SUPPORTED), `mssql.old_version` (medium, major < 13 / pre-SQL Server 2016).
- **`audit kafka`** — Kafka broker reachability + unauthenticated cluster-metadata disclosure on TCP/9092. ApiVersions v0 + Metadata v1; if the broker returns cluster metadata without SASL/ACL gating, that's the common "open kafka" exposure. Emits `kafka.metadata` (info) and `kafka.unauthenticated` (high).

All three include integration tests with mock servers.

### Added — `audit tls` enrichments
- **JA3 + JA3S fingerprints** in `tls.metadata`. Captures the raw `ClientHello` and `ServerHello` via `SSL_CTX_set_msg_callback`, computes canonical fingerprint strings + MD5s, drops them into the evidence as `ja3` / `ja3_str` / `ja3s` / `ja3s_str`. GREASE values (RFC 8701) stripped so fingerprints are stable across probes. JA3 lets defenders recognise packetsonde traffic; JA3S groups hosts by TLS-stack fingerprint behind LBs / WAFs / CDNs.

### Added — agent discovery
End-to-end zero-listener discovery for `packetsonded` instances on remote subnets. Companion brainstorm at `docs/specs/agent-discovery-brainstorm.md`.

- **`src/lib/discovery.{h,c}`** — 144-byte signed probe / 136-byte signed reply wire format (reply strictly < probe = no amplification). Ed25519 sign/verify via OpenSSL, bounded replay LRU (4096 entries, `(pubkey,nonce)` keyed).
- **`src/lib/keystore.{h,c}`** — Ed25519 keypair generate/save/load, SHA-256 fingerprint helper. Raw 32-byte pub + 32-byte seed on disk (seed mode 0600).
- **`packetsonde key {generate,list,fingerprint,revoke}`** — CLI key management. Keys live under `$PS_KEY_DIR` (defaults to `$XDG_CONFIG_HOME/packetsonde/keys`). Revocation prints the line the operator pastes into agents.
- **`packetsonde discover agents <cidr|broadcast>`** — signed broadcast probe + listen window; emits `discovery.agent` (info) per validated reply with `agent_pub_fingerprint`, `listen_ip`, `listen_port` in evidence. CLI flags: `--wait`, `--key`, `--max-skew`, `--cover-port`. Bad signatures, expired timestamps, replays, and unauthorized pubkeys are silent drops.
- **`packetsonded` discovery_listener module** — pcap consumer inspects every captured broadcast packet for the PSDP magic, validates probe, replies via plain DGRAM unicast back to the probe's source IP:port. No listening socket is ever bound — the agent is invisible to port scans. Env config: `PS_DISCOVERY_ENABLED`, `PS_KEY_DIR`, `PS_DISCOVERY_AGENT_KEY`, `PS_DISCOVERY_AUTHORIZED_DIR`, `PS_DISCOVERY_LISTEN_IP`, `PS_DISCOVERY_LISTEN_PORT`, `PS_DISCOVERY_MAX_SKEW_MS_CAP`. Default off; operator opts in.

### Added — flow export compatibility
NetFlow exporter brought up to maximum-compatibility for off-the-shelf collectors (Kentik, nfdump/nfcapd, ntopng, Logstash, Elastic, Splunk Stream, Wireshark).

- **NetFlow v9 templates** now include `FIRST_SWITCHED(22)` + `LAST_SWITCHED(21)` — collectors get true flow start/end times instead of falling back to packet arrival time.
- **IPFIX (RFC 7011) export** added as a third supported version (`version = 10`). 16-byte header with absolute `exportTime`, Template Set ID 2, 64-bit `octetTotalCount`(85) / `packetTotalCount`(86) (no 32-bit wrap at high rates), `flowStartMilliseconds`(152) / `flowEndMilliseconds`(153) as absolute uint64 ms since epoch. Field IDs 1-31 share IANA numbers with NetFlow v9 so dual-protocol collectors see consistent semantics.
- **Operator-configurable export target** via env: `PS_NETFLOW_COLLECTOR` (`host[:port]`, default `127.0.0.1:2055`), `PS_NETFLOW_VERSION` (`5|9|10`, default 9), `PS_NETFLOW_SOURCE_ID`.

sFlow is intentionally not implemented — sample-based protocol mismatches our aggregate-flow data model.

### Tags
- `v1.5`

## [v1.4] — 2026-05-20

### Added
- **`probe traceroute --proto tcp`** — TCP-connect traceroute. Non-blocking `connect()` per TTL, `select()` over both the TCP fd and the ICMP listener — whichever fires first decides the hop. Intermediate routers appear via ICMP TTL exceeded; destination is reached when SO_ERROR comes back as 0 (open) or ECONNREFUSED (closed). Default target port 80 (override with `--port`). All three modes wired up (classic / paris / dublin); Paris binds src_port for a stable ECMP tuple, Dublin walks N flows with different src_ports. Cuts through stateful firewalls that drop UDP-traceroute payloads.
- **`probe traceroute --proto icmp`** — ICMP-echo traceroute. SOCK_DGRAM/IPPROTO_ICMP (unprivileged on macOS and on Linux when `ping_group_range` admits the user). Hand-built ICMP echo request, walks TTLs, reads TTL-exceeded (type 11) and echo-reply (type 0) responses on the same socket. The `--mode` flag is accepted for grammar parity but ICMP has only one flow tuple in practice.
- **`audit snmp`** — SNMP v1/v2c default-community detection on UDP/161. Hand-built BER GetRequest for sysDescr.0 with candidate communities `public` then `private`, v2c then v1. A valid GetResponse with matching request-id means the community is accepted. Emits `snmp.metadata` (info, with version + sysDescr) and `snmp.default_community` (high). Integration test included (mock SNMP responder).
- **`audit ldap`** — anonymous-bind detection. Sends a v3 LDAP BindRequest with empty credentials, parses the BindResponse resultCode. Emits `ldap.metadata` (info), `ldap.anonymous_bind` (medium, server accepts anon bind), `ldap.plaintext` (low, port 389 not 636/LDAPS).
- **`audit imap`** — IMAP banner + CAPABILITY parse. Emits `imap.metadata` (info, with `starttls` and `logindisabled` flags), `imap.no_starttls` (medium, port 143 without STARTTLS), `imap.plaintext_login` (high, port 143 allows LOGIN without STARTTLS + no LOGINDISABLED).
- **`audit pop3`** — POP3 banner + CAPA parse. Emits `pop3.metadata` (info), `pop3.no_stls` (medium, port 110 without STLS).
- **`scan udp <target|cidr> [-p PORTS]`** — UDP scanner. Uses connected-UDP sockets so closed ports surface as `ECONNREFUSED` via kernel-handled ICMP port-unreachable (no raw socket required). Per-port protocol-aware probes elicit responses from common UDP services: DNS (port 53, mDNS 5353), NTP (123), SNMP (161, community "public"), SSDP (1900), NetBIOS Name Service (137). Unknown ports get a single null byte. Default port list covers 53/67/69/123/137/161/500/514/1900/5353/11211. Emits `scan.udp.open` (info, with `response_bytes` and `preview_hex` in evidence) for ports that respond with payload. Silent ports (open|filtered) and closed ports do not emit — keeps the JSONL stream signal-dense.

Read the local-vs-remote behavior carefully: a kernel that doesn't return ICMP unreachable to the scanner (most cloud/firewalled setups) makes closed and silent indistinguishable, which is inherent to unprivileged UDP scanning. Raw-socket UDP scanning (Paris-style with manual ICMP receive) is a follow-on.

### Integration test coverage
Mock servers via Python + FIFO readiness sync are now the template for audit integration tests. New: `test_audit_ssh`, `test_audit_imap`, `test_audit_pop3`, `test_audit_snmp`. 29/29 tests pass.

### License
PolyForm Noncommercial 1.0.0 is now modified to exclude government use. Government / state-affiliated use is treated as commercial use; charitable, educational, research, and personal use remain permitted.

### Tags
- `v1.4`

## [v1.3] — 2026-05-20

### Added — pluggable audit ABI
The `audit` verb is now extensible without recompiling the CLI. Each audit kind is a single C file that exports `struct ps_audit_module` and compiles to a `.so` / `.dylib`. A loader scans `$PS_AUDITS_DIR` / `~/.config/packetsonde/audits/` / system paths at first call, dedupes by name, and lets user plugins shadow built-ins. All 14 existing audit kinds were converted to this ABI; each is statically linked into the binary AND built as a loadable plugin under `build/src/cli/audit/`.

- `src/lib/audit_module.h` — stable ABI (struct ps_audit_module, struct ps_audit_api, PS_AUDIT_ABI_VERSION).
- `src/cli/audit_loader.{h,c}` — dlopen + directory scan.
- Dispatcher (`src/cli/verbs/audit.c`) now owns output-emitter setup, format selection, snapshot, and close — was ~25 lines of boilerplate duplicated across every audit module.
- `docs/guides/writing-audit-plugins.md` — operator guide for shipping custom audits.
- `examples/audit-plugin/audit-vnc.c` — working ~100-line external plugin example with macOS/Linux build script.

### Added — new verb
- **`packetsonde report [path]`** — reads JSONL findings from a file or stdin, sorts by (severity descending, host, kind), and writes a Markdown deliverable grouped under severity headings with per-host subsections. Each finding renders with target, source, timestamp, and evidence. Closes the "compliance reports" follow-on from the v1 spec.

### Added — audit kinds
Three more audit kinds; `audit` verb now covers 14 services total.

- **`audit smtp`** — reads banner, sends EHLO, parses capability advertisement. Emits `smtp.metadata` (info) and `smtp.no_starttls` (medium, when STARTTLS is missing on port 25 or 587). Open-relay test deferred behind a future opt-in flag.
- **`audit mysql`** — reads MySQL/MariaDB initial handshake (sent on connect). Emits `mysql.metadata`, `mysql.old_version` (medium, < 8.0 — 5.x is EOL), `mysql.reachable` (low, posture marker).
- **`audit postgresql`** — sends SSLRequest, reads the single-byte response. Emits `postgresql.metadata`, `postgresql.no_ssl` (high, server refuses SSL), `postgresql.reachable` (low).

### Tags
- `v1.3`

## [v1.2] — 2026-05-20

### Added — traceroute modes
- **`probe traceroute --mode paris`** — holds the UDP flow tuple constant across every TTL probe so every hop traverses the same ECMP-balanced path.
- **`probe traceroute --mode dublin`** — enumerates ECMP alternative paths by walking multiple Paris-style flows with different source ports (`--flow-count N`, default 8). Deduplicates hops by (ttl, addr).

### Added — audit kinds
Seven new audit kinds; `audit` verb now covers 11 services total.

- **`audit smb`** — SMB1 detection via a minimal NEGOTIATE PROTOCOL request offering only the NT LM 0.12 dialect. Emits `smb.metadata` (info) and `smb.smb1_enabled` (high — EternalBlue / WannaCry surface).
- **`audit telnet`** — Telnet exposure detection. Plaintext + deprecated; reaching the port is itself the finding. Emits `telnet.exposed` (high) with the captured banner.
- **`audit ftp`** — FTP banner + anonymous-login probe. Emits `ftp.metadata` (info), `ftp.plaintext_exposed` (medium), and `ftp.anonymous_allowed` (high) when `USER anonymous` succeeds.
- **`audit redis`** — Redis NOAUTH detection. Sends `INFO`; if the server replies with data (instead of `-NOAUTH`), emits `redis.noauth` (critical) and `redis.metadata` (info) with version, mode, OS extracted from the INFO payload.
- **`audit ntp`** — NTP service reachability (mode-3) + monlist amplification probe (mode-7 REQ_MON_GETLIST_1, CVE-2013-5211). Emits `ntp.metadata`, `ntp.monlist_amplification` (critical, with computed amplification factor), `ntp.mode7_enabled` (low) when mode-7 is present but the specific request is rejected.
- **`audit memcached`** — sends `version\r\n` on TCP/11211. Emits `memcached.metadata` and `memcached.noauth_exposed` (critical) — memcached's text protocol has no authentication.
- **`audit elasticsearch`** — HTTP GET `/` on port 9200, parses cluster_name + version. Emits `elasticsearch.metadata` and `elasticsearch.unauthenticated` (critical) when the cluster API is reachable without auth.

### Added — findings tooling
- **`findings stats [path]`** — reads JSONL findings from a file or stdin and prints aggregate counts by severity, kind, source, and host. Sorted descending. Useful for "what does today look like" review of an `--auto-append` file.

### Tags
- `v1.2`

## [v1.1] — 2026-05-20

### Fixed
- `audit tls` now reliably detects TLS 1.0/1.1 servers and weak ciphers on hosts where the system OpenSSL policy would otherwise prevent the probe handshakes (`OPENSSL_INIT_NO_LOAD_CONFIG` + `SECLEVEL=0` + permissive cipher list on probe contexts). Integration test re-enabled assertions for `tls.weak_protocol` and `tls.weak_cipher` (now 7 kinds asserted, was 5).

### Added
- **`audit http`** — security-header hygiene against HTTP/HTTPS targets. Emits: `http.metadata`, `http.missing_hsts` / `http.weak_hsts` (HTTPS), `http.missing_xcto`, `http.missing_frame_protection`, `http.missing_csp`, `http.missing_referrer_policy`, `http.server_version_leak`.
- **`audit ssh`** — SSH server banner audit. Emits: `ssh.metadata`, `ssh.old_version` (OpenSSH < 7.4).
- **`tls.metadata`** info finding emitted by `audit tls`. Captures full TLS posture as evidence: protocol, cipher, subject CN, issuer CN, notBefore, notAfter, cert SHA-256, SANs (DNS + IP). Gives auditors "what does this server look like" alongside "what's wrong."
- `docs/specs/agent-network-protocol-brainstorm.md` — pre-brainstorm design questions for follow-on #1 (10 questions across transport, identity, wire format, session model, with leans and tradeoffs).
- `README.md`, `docs/specs/viz-notes.md`, this changelog.

### Notes
- Audit verb now covers 4 kinds: `tls`, `dns`, `http`, `ssh`.
- 25/25 tests pass.

## [v1.0] — 2026-05-20

Initial release of the CLI toolkit. Three phased plans landed:

### Plan 1 — CLI foundation
- Repo restructure: `agent/` → `src/agent/`, sibling `src/lib/` and `src/cli/`.
- `libpacketsonde` (`json`, `log`, `ipc`, `ulid`) shared between agent and CLI.
- `packetsonde` skeleton: arg parser, verb dispatch table, `version` verb.
- `packetsonde agent <subcmd>` folds in the former `psctl` handlers; `psctl` binary retired.
- PolyForm Noncommercial 1.0.0 license.

### Plan 2 — Findings & first audit
- Finding record + JSON/text serializers (`v: 1` stable wire format).
- Thread-safe output emitter (text / JSON / JSONL / quiet, TTY auto-detection, `--auto-append`).
- Token-bucket rate limiter + pthread worker pool + bounded MPSC queue.
- SIGINT/SIGTERM cancel handler.
- `audit tls` via OpenSSL — 8 finding kinds across protocol, cipher, and certificate hygiene.
- Integration test against `openssl s_server`.
- Per-run summary on stderr (severity histogram + duration).

### Plan 3 — Verb breadth
- `util/targets` — CIDR + port-list parsers.
- `findings tail` / `findings filter` (JSONL stream processing with filter expressions).
- `config show` / `config path` + `agents.toml` registry parser.
- `--fail-on severity>=LEVEL` gates exit code (3 = matching findings present).
- `probe tcp` — single TCP probe with RTT + banner.
- `lib/traceroute` core (UDP classic).
- `probe traceroute --proto udp --mode classic`.
- `audit dns` — version.bind leak + open-recursion detection.
- `discover neighbors` — local ARP/NDP table.
- `scan ports` — connect-scan with CIDR + port-list.
- `discover hosts` — port-set host sweep.

### Tags
- `plan-1-foundation`, `plan-2-findings-and-tls`, `plan-3-verb-breadth`, `v1.0`
