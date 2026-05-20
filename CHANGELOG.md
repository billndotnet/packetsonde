# Changelog

All notable changes to packetsonde. Format roughly follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Fixed
- `audit tls` now reliably detects TLS 1.0/1.1 servers and weak ciphers on hosts where the system OpenSSL policy would otherwise prevent the probe handshakes (`OPENSSL_INIT_NO_LOAD_CONFIG` + `SECLEVEL=0` + permissive cipher list on probe contexts). Integration test now exercises all 7 finding kinds.

### Added
- `docs/specs/agent-network-protocol-brainstorm.md` — pre-brainstorm design questions for follow-on #1.
- `README.md`, `docs/specs/viz-notes.md`, this changelog.

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

### Removed
- UE5 3D visualization frontend (`Source/`, `Content/`, `Config/`, `assets/`, `packetsonde.uproject`, `start.sh`) and the UE-era plan docs. Archived locally; paused until toolkit maturity informs a better visualization design.

### Tags
- `plan-1-foundation`, `plan-2-findings-and-tls`, `plan-3-verb-breadth`
