# Changelog

All notable changes to packetsonde. Format roughly follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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
