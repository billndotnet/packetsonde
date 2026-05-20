# Changelog

All notable changes to packetsonde. Format roughly follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- **`probe traceroute --mode paris`** — holds the UDP flow tuple constant across every TTL probe so every hop traverses the same ECMP-balanced path.
- **`probe traceroute --mode dublin`** — enumerates ECMP alternative paths by walking multiple Paris-style flows with different source ports (`--flow-count N`, default 8). Deduplicates hops by (ttl, addr).
- **`audit smb`** — SMB1 detection via a minimal NEGOTIATE PROTOCOL request offering only the NT LM 0.12 dialect. Emits `smb.metadata` (info) and `smb.smb1_enabled` (high — EternalBlue / WannaCry surface).
- **`audit telnet`** — Telnet exposure detection. Plaintext + deprecated; reaching the port is itself the finding. Emits `telnet.exposed` (high) with the captured banner.
- **`audit ftp`** — FTP banner + anonymous-login probe. Emits `ftp.metadata` (info), `ftp.plaintext_exposed` (medium), and `ftp.anonymous_allowed` (high) when `USER anonymous` succeeds.
- **`audit redis`** — Redis NOAUTH detection. Sends `INFO`; if the server replies with data (instead of `-NOAUTH`), emits `redis.noauth` (critical) and `redis.metadata` (info) with version, mode, OS extracted from the INFO payload.
- **`findings stats [path]`** — reads JSONL findings from a file or stdin and prints aggregate counts by severity, kind, source, and host. Sorted descending. Useful for "what does today look like" review of an `--auto-append` file.
- **`audit ntp`** — NTP service reachability (mode-3) + monlist amplification probe (mode-7 REQ_MON_GETLIST_1, CVE-2013-5211). Emits `ntp.metadata`, `ntp.monlist_amplification` (critical, with computed amplification factor), `ntp.mode7_enabled` (low) when mode-7 is present but the specific request is rejected.
- **`audit memcached`** — sends `version\r\n` on TCP/11211. Emits `memcached.metadata` and `memcached.noauth_exposed` (critical) — memcached's text protocol has no authentication.
- **`audit elasticsearch`** — HTTP GET `/` on port 9200, parses cluster_name + version. Emits `elasticsearch.metadata` and `elasticsearch.unauthenticated` (critical) when the cluster API is reachable without auth.

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
