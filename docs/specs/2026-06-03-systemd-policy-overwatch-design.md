# packetsonde — systemd Policy Overwatch + Sandbox Learning — Design Spec

**Date:** 2026-06-03
**Status:** Draft, pending review
**Component:** `packetsonde` C agent — a new brain-side module `policy_overwatch` (consumes
the SP1 activity ring), a `src/lib` systemd-policy model + sandbox synthesizer, and a
`packetsonde sandbox-suggest` CLI verb.

**This is SP2 of the process-level detection track (req-sync §4).** It is the first
*scoring* track: it consumes the activity records that SP1
(`docs/specs/2026-06-03-process-collection-primitives-design.md`, merged) produces and
turns them into security findings — without any learning period — by comparing observed
access against the host's own **declared** systemd sandbox. It also adds an inverse
**learning** mode that derives a *recommended* sandbox from observed nominal behavior in
dev/staging. SP3 (learned statistical baseline) and the AppArmor/SELinux policy sources
are out of scope (§12).

---

## 1. Purpose & scope

Two modes over one shared pipeline, both consuming the SP1 activity ring:

- **Overwatch** (prod): for each observed access, resolve the process's systemd unit and
  ask "would this unit's *declared* sandbox have blocked this?" If yes — and we observed
  it anyway — the declared control is not actually in force. Emit a finding. (The §4
  "declared-policy" baseline source.)
- **Learn** (dev/staging): accumulate each unit's observed-nominal access into an
  envelope, and synthesize on demand (`sandbox-suggest <unit>`) the minimal systemd
  sandboxing stanza that would permit exactly that behavior. (The §4 "passive learning →
  human curates" path, scoped to systemd config.)

Together they form a **dev→prod loop**: learn the envelope in staging → review/curate the
suggested stanza → apply it as a drop-in → run prod in overwatch to verify it stays
effective.

- **In scope:** the shared ring-consumer module + `cgroup`→unit resolution + record
  parsing; the `systemd_policy` model (`systemctl show` → derived filesystem + exec
  policy); overwatch evaluation + dedup + findings; the learn-mode envelope accumulator +
  persistence + `sandbox_synth` synthesizer + `sandbox-suggest` verb; `[detect]
  policy_mode` config.
- **Out of scope (§12):** AppArmor/SELinux sources; network/socket directives;
  `NoNewPrivileges` uid-escalation (the SP1 record lacks ancestor uids); auto-writing
  drop-ins or central-reporting of suggestions (we chose CLI-on-demand); SP3 statistical
  baselines / write-then-exec temporal correlation.

**The core inference (why overwatch is high-signal):** if a unit's sandbox were
*enforced*, the denied `open()` fails and SP1 never sees it (no fd → no fanotify event).
So observing the access *at all* means the declared control isn't in force — a stale
`daemon-reload`, an unsupported directive, or an escaped sandbox. Units with *no*
restrictive directives produce *zero* findings, so the detector is naturally low-noise.

---

## 2. Decisions captured (from brainstorming)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Policy source is **systemd unit sandboxing only** for v1. | `systemctl show` yields effective, drop-in-merged values as text; maps directly onto the `cgroup`→unit the SP1 record already carries; no profile-grammar parsing. AppArmor/SELinux deferred. |
| D2 | Evaluate **filesystem read/write sandboxing + exec hardening**. | FS directives map tightly onto SP1's `{path, event}`. Exec adds the post-exploitation signal (React2Shell/EternalRed shape). |
| D3 | A **dedicated tick-driven ring consumer** (new module), not inline dispatch. | The SP1 activity ring currently has no consumer — it was built for this. Async drain keeps policy lookups (`systemctl show`) off the priv-IPC path. |
| D4 | **Two config-gated modes** (`overwatch`/`learn`) over a **shared core**. | Learn is the inverse of overwatch on the same data; they share the consumer, parser, unit resolution, and policy model. |
| D5 | Overwatch **flags-and-reports** (findings → central via the existing `publish` pipeline); learn is **CLI-rendered on demand** (no files auto-written, no central traffic). | Findings are flagged anomalies meant to go upstream (principle 7). Learn output is a *proposal* for human curation — most conservative delivery. |
| D6 | Learn persists per-unit envelopes to a **state file**; the CLI reads it. | Mirrors the SP1 sink/`watch` split; works even when the agent isn't running; no new IPC. |
| D7 | The synthesizer uses **threshold rollup + annotation** for path generalization. | Durable-but-tight: ≥N files under a dir → the dir rule; one-offs stay exact; each entry annotated so the human curator can tighten. |
| D8 | Overwatch is **conservative** (under-flag over false-positive). | `ReadWritePaths` exceptions, symlink/bind-mount resolution, and systemd's path semantics make over-flagging easy; only flag clear violations. |

---

## 3. Architecture & placement

A new agent module `policy_overwatch` (registered like `iface_monitor`), tick-driven,
running unprivileged in the brain. It needs no privilege: the activity records arrive
post-IPC, and `systemctl show` works unprivileged for the properties we read.

```
                                                 ┌─ overwatch: policy_eval(record, policy) → VIOLATION
 SP1 activity ring ──ps_act_ring_drain(tick)──▶  │     → dedup → ps_finding → ctx->publish → central
   │                                             │
   └ parse JSON (path,event,cgroup,uid,mac,exe) ─┤
                       │                          └─ learn: unit_envelope.add(record) → flush state file
              cgroup → unit (basename)                  ↑ (queried later, offline)
                       │                          packetsonde sandbox-suggest <unit>:
              systemd_policy.get(unit) ──cache miss──▶ systemctl show → derive   read state → sandbox_synth → stanza
```

Mode is selected by `[detect] policy_mode`. In `off` (default) the module does not
register / the tick is a no-op. The shared steps (drain, parse, unit-resolve) run in both
non-off modes; only the terminal stage differs.

---

## 4. Shared core

### 4.1 Ring consumer (module tick)
`policy_overwatch` registers with the module framework. Each throttled tick (⚙️ ~1s) it
calls `ps_act_ring_drain` to pull up to a batch of activity-record JSON strings, and
processes each. The ring (cap 256, drop-oldest) buffers between ticks; under sustained
load the oldest records drop (acceptable — overwatch is a sampling detector, learn
accumulates sets so a dropped duplicate is harmless).

### 4.2 Record parse
Each ring item is an SP1 activity-record JSON. Use the existing JSON field extractor
(`src/lib/json_extract`, the one behind `test_json_extract`) to pull: `event`, `path`,
`process.cgroup`, `process.uid`, `process.comm`, `process.exe`, `process.mac.label`,
`process.mac.mode`. (Re-parsing the JSON we serialized in SP1 is acceptable; the brain
only has the bytes that crossed the IPC. A future optimization could hand the brain the
struct directly.)

### 4.3 `cgroup` → unit
The record's `process.cgroup` is a path like `/system.slice/smbd.service` or
`/system.slice/system-getty.slice/getty@tty1.service`. The unit is the **last path
segment ending in a known unit suffix** (`.service`, `.socket`, `.mount`, `.scope`).
Records whose cgroup yields no unit (user sessions, non-unit cgroups, empty cgroup) →
**skipped** (no declared policy to check, nothing to learn against a unit).

### 4.4 `systemd_policy` model — `unit → derived policy`
**File:** `src/lib/systemd_policy.{c,h}`.

- **Acquisition (thin I/O wrapper):** on a cache miss, run
  `systemctl show <unit> -p FragmentPath -p ProtectSystem -p ProtectHome -p ReadWritePaths
  -p ReadOnlyPaths -p InaccessiblePaths -p TemporaryFileSystem -p PrivateTmp
  -p MemoryDenyWriteExecute` via `popen` (the agent already shells out in
  `network_listener`). Parse the `key=value` lines.
- **Derivation (pure, unit-tested):** turn the directive values into a
  `struct ps_unit_policy`:
  - `deny_write[]` / `deny_read[]` path-prefix sets and `writable[]` (the
    `ReadWritePaths`) — derived per the systemd semantics in §5.1.
  - flags: `protect_system` (no/yes/full/strict), `protect_home` (no/read-only/tmpfs),
    `private_tmp`, `mdwe` (MemoryDenyWriteExecute).
  - `is_unit` / `known` (false → "no policy", cached as a skip sentinel).
- **Cache:** per-unit, ⚙️ TTL 300s (units' policy only changes on `daemon-reload` +
  restart; TTL is the v1 invalidation). Bounded; LRU/drop-oldest on capacity.

---

## 5. Overwatch mode

### 5.1 `policy_eval` (pure) — `(policy, path, op) → ALLOWED | VIOLATION{directive}`
**File:** `src/lib/policy_eval.{c,h}`. Op is derived from the record `event`: `open`
without write intent → read; a write event → write; `exec` → an exec (also a read of the
binary). Semantics modeled (conservative):

- **`ProtectSystem=`**: `yes` → `/usr`,`/boot`,`/efi` read-only; `full` → + `/etc`;
  `strict` → the **whole filesystem** read-only **except** `ReadWritePaths`,
  `TemporaryFileSystem`, and the API mounts. A **write** to a protected path not in
  `writable[]` → `VIOLATION{ProtectSystem}`.
- **`ProtectHome=`**: `read-only` → `/home`,`/root`,`/run/user` deny **write**; `true`/
  `tmpfs` → deny **all access** (read+write). Access in violation →
  `VIOLATION{ProtectHome}`.
- **`InaccessiblePaths=`**: any access under a listed path → `VIOLATION{InaccessiblePaths}`.
- **`ReadOnlyPaths=`**: a write under a listed path not re-permitted by `ReadWritePaths`
  → `VIOLATION{ReadOnlyPaths}`.
- **`PrivateTmp=yes`**: the unit gets a private `/tmp`,`/var/tmp`; accessing the *host*
  `/tmp` is impossible under enforcement — but SP1's path is the path *as the process sees
  it*, which under PrivateTmp is still `/tmp`, so we **cannot** distinguish host vs private
  `/tmp` from the path alone → PrivateTmp is **not** an overwatch trigger (used only by
  learn). Documented to avoid a false-positive class.

`ReadWritePaths`/`writable[]` always win as exceptions (longest-prefix wins). Matching is
prefix-with-boundary (so `/var/lib/appX` does not match `/var/lib/app`).

### 5.2 Exec hardening
- **Exec-from-denied-path** is free: an `exec` record's `path` (the binary) runs through
  the same read check; execing from an `InaccessiblePaths`/`ProtectHome`/strict-non-writable
  location → the corresponding FS violation.
- **Hardened-unit-execs-from-writable-path** (heuristic, ⚙️ medium/tentative): an `exec`
  whose `path` is under one of the unit's own `writable[]` (or `PrivateTmp`/drop zones)
  **and** the unit has `mdwe` or `ProtectSystem=strict` → `VIOLATION{exec_from_writable}`.
  Reduced confidence (MDWE does not strictly forbid on-disk `execve`); this is the
  React2Shell/EternalRed "ran code from a writable area" shape.

### 5.3 Dedup + findings
- **Dedup:** ⚙️ first-seen per `(unit, path, op, directive)`, bounded (drop-oldest), so a
  process hammering a denied path yields one finding, not thousands.
- **Finding** (`ps_finding` → `ctx->publish`, the `iface_monitor` path): title e.g.
  `"systemd sandbox not enforced: <unit> <op> <path> (declared <directive>)"`; severity
  ⚙️ **high** (FS) / **medium** (exec heuristic); confidence **firm** (FS) / **tentative**
  (exec); `evidence_json` carries `{unit, directive, path, op, fragment_path, process:
  {pid,comm,exe,uid}, mac:{label,mode}, ancestry, sockets}` lifted from the record for
  triage. The `mac` fields explain *why* enforcement may have lapsed.

---

## 6. Learn mode

### 6.1 `unit_envelope` — accumulate per-unit observed access
**File:** `src/agent/src/unit_envelope.{c,h}`. Per unit, maintain bounded sets:
`reads[]`, `writes[]`, `execs[]` (paths, capped with an overflow counter), plus booleans
`touched_home`, `exec_from_writable`, `used_tmp`. Each ring record in learn mode →
`ps_unit_envelope_add(unit, event, path)`. Accumulation is continuous while
`policy_mode=learn`.

### 6.2 Persistence (state file)
The module flushes each dirty unit's envelope to ⚙️ `/var/lib/packetsonde/sandbox-learn/
<unit>.json` periodically (⚙️ ~10s) and on shutdown. Format is a small JSON the CLI reads.
`sandbox-suggest --reset <unit>` deletes the unit's state file.

### 6.3 `sandbox_synth` (pure) — envelope → systemd stanza
**File:** `src/lib/sandbox_synth.{c,h}`. The crux. `ps_sandbox_synth(envelope, opts, out)`:

1. **Path generalization (threshold rollup):** group `writes[]`/`reads[]` by parent
   directory. If a directory holds ≥⚙️`rollup_threshold` (default 3) distinct observed
   files → emit the **directory** rule; otherwise emit the **exact files**. Annotate each
   emitted entry: `# generalized: <N> files` or `# exact`.
2. **Directive synthesis (inverse of §5.1):**
   - `writable` dirs/files → `ReadWritePaths=` (the generalized write set).
   - if writes are confined (don't span `/usr`) → `ProtectSystem=strict`; else `full`.
   - read-only system reads are covered by `ProtectSystem`; emit explicit `ReadOnlyPaths=`
     only where reads fall outside the protected set and you want them pinned.
   - `touched_home == false` → `ProtectHome=true`.
   - `exec_from_writable == false` → `MemoryDenyWriteExecute=yes` (with the W^X caveat as
     a trailing comment).
   - `used_tmp` only as scratch → `PrivateTmp=yes`.
3. **Output:** an annotated `[Service]` stanza to `out`, e.g.

```ini
[Service]
ProtectSystem=strict
ProtectHome=true
PrivateTmp=yes
MemoryDenyWriteExecute=yes        # observed no exec from writable paths; verify (W^X ≠ execve block)
ReadWritePaths=/var/lib/app/db    # generalized: 14 files
ReadWritePaths=/var/log/app       # generalized: 3 files
ReadWritePaths=/run/app.sock      # exact
# learned over <N> records; review before applying. ReadWritePaths are minimal — widen if flows were missed.
```

### 6.4 `sandbox-suggest` verb
**File:** `src/cli/verbs/sandbox_suggest.c`. `packetsonde sandbox-suggest <unit>
[--state-dir <dir>] [--reset] [--threshold N]`: read the unit's envelope state →
`ps_sandbox_synth` → print the stanza. `--reset` clears the unit's accumulated envelope.
Clean error + non-zero exit if no envelope exists for the unit (learn mode not run / unit
not observed).

---

## 7. Config (`[detect]`, via `config_to_env`)

```toml
[detect]
# ... (SP1 keys: enabled, watch_paths, suppress_paths, max_depth, max_events_ps, sink)
policy_mode      = "off"     # off | overwatch | learn
policy_cache_ttl = "300"     # overwatch: per-unit systemctl-show cache seconds
learn_state_dir  = "/var/lib/packetsonde/sandbox-learn"
rollup_threshold = "3"       # learn: distinct files/dir before rolling up to the dir
```

New `config_to_env` mappings: `PS_DETECT_POLICY_MODE`, `PS_DETECT_POLICY_CACHE_TTL`,
`PS_DETECT_LEARN_STATE_DIR`, `PS_DETECT_ROLLUP_THRESHOLD`. `policy_mode` requires SP1
collection (`enabled=1`) to be on — the module logs and no-ops if the ring is never fed.

---

## 8. Error handling & false-positive conservatism

- `systemctl` absent / unit not found / `systemctl show` error → cache a "no policy"
  sentinel for the unit; skip (no findings, no crash).
- Empty/odd `cgroup` → skip (§4.3).
- Overwatch never flags on **absence** of policy — only on a clear violation of a declared
  directive. `ReadWritePaths` exceptions and longest-prefix matching are honored; symlink
  targets are matched as the record reports them (SP1 already resolves the fanotify path
  via `/proc/self/fd`, i.e. the realpath) so symlink-induced false positives are avoided.
- `PrivateTmp` is excluded from overwatch (§5.1) to avoid the host-vs-private `/tmp`
  ambiguity.
- Learn sets are bounded; overflow increments a counter surfaced in the suggestion footer
  (`# note: write set truncated at <cap> paths`) so the operator knows coverage was capped.

---

## 9. Testing

**Unit (pure, fixtures, no privilege):**
- `systemd_policy` derivation: directive strings (incl. `ProtectSystem=strict` +
  `ReadWritePaths` exceptions, `ProtectHome` variants, `InaccessiblePaths`) → expected
  `ps_unit_policy`.
- `policy_eval`: allowed vs each violation type; `ReadWritePaths` exception wins; prefix
  boundary (`/var/lib/app` ≠ `/var/lib/appX`); read vs write op-awareness; exec-from-
  writable heuristic gated on `mdwe`/`strict`.
- `sandbox_synth`: envelope fixtures → expected stanza; **rollup boundary at exactly N**
  (N-1 files → exact, N → dir); annotations present; `ProtectHome`/`MDWE` toggles from the
  booleans.
- `cgroup`→unit extraction across slice nestings.

**Module (synthetic records + stubbed policy):** feed crafted activity-record JSON through
the consumer with an injected policy/state; assert overwatch publishes the expected finding
and learn accumulates + flushes the expected envelope.

**Live (gated):** overwatch — a unit with `ProtectHome=true` (or a `ReadWritePaths`-scoped
unit); read `/home` (or write outside the scope) and assert a finding with the right
directive. Learn — run `policy_mode=learn` over a known service exercising nominal flows,
then `sandbox-suggest <unit>` and eyeball the stanza.

---

## 10. Implementation phasing (two plans, one spec)

This spec is larger than SP1; the build splits into two independently-shippable plans
sharing §4's core:

- **Phase A — core + overwatch:** §4 shared core, §5 `policy_eval` + dedup + findings, the
  `overwatch` mode of the module, the `policy_mode`/cache config. Ships the prod detector.
- **Phase B — learn + synthesis:** §6 `unit_envelope` + persistence + `sandbox_synth` +
  the `sandbox-suggest` verb, the learn-mode tick path, the learn config keys. Ships the
  dev/staging tool.

Each phase is a separate `writing-plans` cycle.

---

## 11. Components summary (boundaries)

| Unit | Lives in | Pure? | Does |
|---|---|---|---|
| `systemd_policy` | `src/lib` | derivation pure; I/O thin | unit → derived FS+exec policy (+cache) |
| `policy_eval` | `src/lib` | pure | (policy, path, op) → ALLOWED/VIOLATION |
| `sandbox_synth` | `src/lib` | pure | envelope → annotated systemd stanza (rollup) |
| `unit_envelope` | `src/agent/src` | accumulate + persist | per-unit observed-access sets + state file |
| `policy_overwatch` | `src/agent/src/modules` | module | tick: drain ring → parse → unit → mode stage |
| `sandbox-suggest` | `src/cli/verbs` | verb | read envelope state → synth → print |

---

## 12. Deferred (later increments)

- **AppArmor + SELinux** policy sources (SP2b/c) — reuse the consumer + the
  policy/finding shapes; add profile/context parsers.
- **Network/socket directives** (`RestrictAddressFamilies`, `IPAddressDeny`,
  `PrivateNetwork`) evaluated against the record's `sockets[]`.
- **`NoNewPrivileges` uid-escalation** — needs ancestor uids in the SP1 record (a small
  `ps_act_ancestor` schema follow-up).
- **Auto-written drop-ins / central-reported suggestions** — we chose CLI-on-demand; these
  are the other delivery options from brainstorming.
- **SP3 statistical baseline / write-then-exec temporal correlation.**

---

## 13. Self-review

- **Decisions ↔ sections:** D1 §4.4/§1; D2 §5; D3 §3/§4.1; D4 §3; D5 §5.3/§6; D6 §6.2;
  D7 §6.3; D8 §5.1/§8. ✓
- **No placeholders:** every component has a file, an interface intent, and a test
  approach; directive semantics and the synthesis mapping are concrete.
- **Scope:** explicitly split into two phased plans (§10); each is one plan's worth.
- **Ambiguity resolved:** `PrivateTmp` excluded from overwatch (host-vs-private ambiguity);
  unit extraction + skip rules defined; rollup boundary defined as ≥N.
- **Consistency:** `ps_unit_policy`/`policy_eval`/`sandbox_synth`/`unit_envelope`/
  `policy_overwatch` referenced uniformly; `policy_mode` values `off|overwatch|learn`
  identical across §3/§7.
