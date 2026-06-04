# packetsonde — Learned Per-Process Behavioral Baseline — Design Spec

**Date:** 2026-06-04
**Status:** Draft, pending review
**Component:** `packetsonde` C agent — a new brain-side `baseline_monitor` module
(consumes the SP1 activity ring), a per-executable baseline state store, and a
`packetsonde baseline` CLI verb. A small SP1 extension (`process.exe` population) is a
prerequisite.

**This is SP3 of the process-level detection track (req-sync §4).** It is the *learned*
detector: it builds a per-process allowlist from observed behavior and flags deviations at
runtime — systemd-independent, complementing SP2 (which checks/synthesizes *declared*
systemd policy). It consumes the same SP1 activity records and reuses SP2's envelope/rollup
concepts. SP3 keys baselines on the **executable**, so a given binary's "normal" behavior
is learned once and enforced everywhere it runs.

---

## 1. Purpose & scope

Learn, per executable, the set of resources it touches during nominal operation, and flag
anything outside that learned set at runtime — running **hybrid-continuous** (always
learning + enforcing): a never-seen access becomes a *candidate* that the operator either
**approves** into the baseline or **denies** (escalating it to a confirmed anomaly).

- **In scope (across phases):** the exe-keyed baseline state model (approved / candidate /
  denied sets, per-exe, persisted); the hybrid enforce-while-learning consumer; the
  `baseline` CLI verb (list / approve / deny / approve-all); findings via the existing
  publish pipeline; `[detect] baseline_mode` config; and the three signal types —
  **file paths** (Phase A), **network destinations** (Phase B), **process spawning**
  (Phase C).
- **SP1 prerequisite (Phase A):** populate `process.exe` (currently empty — a deferred
  `readlink /proc/<pid>/exe` in `proc_enrich`). exe-keying is impossible without it.
- **Out of scope (§13):** statistical/frequency scoring (we chose a set-based allowlist);
  data-volume & connection-timing baselines (not present in the SP1 record — that is
  `flow_tracker` territory); central-driven approval / baseline push; AppArmor/SELinux.

**Relationship to SP2:** SP2 keys by systemd unit and checks/synthesizes *declared* policy.
SP3 keys by executable and learns an *empirical* baseline. They share the SP1 record, the
ring consumer pattern, the finding/publish pipeline, and the directory-rollup idea
(`sandbox_synth`). A process can have both a declared-policy check (SP2) and a learned
baseline (SP3).

---

## 2. Decisions captured (from brainstorming)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Set-based learned allowlist** (not a statistical/distributional model). | Low false-positive; reuses SP2's envelope/rollup; matches the "what's supposed to be here" framing. Statistical scoring deferred. |
| D2 | **Full §4 triad** — file paths + network destinations + process spawning — built in **three phases** (A file+lifecycle, B network, C spawn), one spec. | The triad is the §4 detection value; too large for one plan. Phase A builds the reusable lifecycle/state infrastructure. |
| D3 | **Hybrid-continuous** lifecycle: always learn + enforce; novel → candidate; operator **approve** (→ baseline) or **deny** (→ confirmed anomaly). | The most powerful §4 mode. Subsumes passive learning (run nominally → approve-all → ongoing novelties are the signal). |
| D4 | **Local CLI verb + state files** for approval (agent-local; no central push). | Mirrors the merged `sandbox-suggest` pattern; no new central→agent channel. Candidates still publish to central for visibility. |
| D5 | Baselines are **keyed by executable** (`process.exe`), not systemd unit. | §4 is per-process; systemd-independent; host-portable ("what does `/usr/sbin/nginx` normally do"). Requires the SP1 `exe` prerequisite. |
| D6 | **Directory-prefix matching** for file paths (+ rollup on approve). | A path under a baseline dir is covered, so new files in a known dir don't flood candidates. |
| D7 | **Ownership split:** agent only *appends* `candidates`, only *reads* `baseline`/`denials`; the CLI is the only writer of `baseline`/`denials`; all writes atomic (temp+rename). | Avoids agent/CLI write races without locking. |

---

## 3. Architecture

A new brain-side module `baseline_monitor`, registered like `iface_monitor`/
`policy_overwatch`, draining the SP1 activity ring on its tick. Unprivileged. Active when
`[detect] baseline_mode = on` (⚙️ `off` default). It is independent of SP2's `policy_mode`
— a host can run overwatch and baseline simultaneously.

```
SP1 ring ─drain(tick)→ parse(exe,path,event[,sockets,ancestry]) ─→ baseline_store.get(exe)
                                                                          │
   covered by baseline ─ silent                                          │ match path vs baseline
   in denials ─────────── confirmed-anomaly finding (high) ◀────────────┤
   novel ──────────────── candidate finding (info) + append candidates  ◀┘
                                                                          ▲
              packetsonde baseline <exe> approve|deny|approve-all|list ──┘ (CLI mutates baseline/denials)
              agent reloads baseline/denials every ~10s
```

**SP1 prerequisite (Phase A, first task):** `proc_enrich` must populate `process.exe` via
`readlink <proc_root>/<pid>/exe`. Small, mirrors the `FAN_CLOSE_WRITE` prerequisite that
opened SP2 Phase A. (Until then the record's `exe` is empty and exe-keying can't work.)

---

## 4. State model (per executable)

Each executable gets a directory ⚙️ `<baseline_state_dir>/<slug>/` where `slug` is the exe
path sanitized to a filename (⚙️ non-`[A-Za-z0-9._-]` → `-`, e.g. `/usr/sbin/nginx` →
`usr-sbin-nginx`; the real exe is stored in an `exe` field inside each file to disambiguate
collisions). Three files:

- **`baseline.json`** — the **approved** allowlist (the enforced set). **CLI-owned.**
- **`candidates.json`** — **novel** entries seen but not yet decided. **Agent-appends.**
- **`denials.json`** — entries the operator marked **bad**. **CLI-owned.**

Each file holds, per the active phases, typed entry sets — Phase A: `paths[]` (directory
or exact-file rules); Phase B adds `dests[]`; Phase C adds `spawns[]`. The shape reuses the
`unit_envelope` set idiom; the entry carries its `kind` (`path`/`dest`/`spawn`).

**Reload:** the agent re-reads `baseline.json` + `denials.json` for an exe on a ⚙️ ~10s
timer (and on first sighting), caching them; `candidates.json` is the agent's own append
log. The agent treats `baseline.json` as authoritative — anything in it is never
re-flagged, and a candidate that has since been approved is dropped from its in-memory
pending set on reload.

---

## 5. Enforce-while-learning flow (Phase A — file signal)

Per ring record (`exe`, `path`, `event`):

1. Skip if `exe` empty (pre-prereq records) or `event` not a file op.
2. `store = baseline_store_get(exe)` (cached baseline + denials).
3. **Match** `path` against `baseline.paths` by **directory-prefix** (a path equal to or
   under a baseline entry is covered). If covered → silent, done.
4. Match against `denials.paths` (same prefix rule). If denied → emit a **confirmed
   anomaly** finding (⚙️ severity high) and done (stays flagged until approved).
5. Otherwise **novel**: if not already in the in-memory pending set, append the entry to
   `candidates.json` and emit a **candidate** finding (⚙️ severity info). Dedup so a
   repeated novel path yields one candidate.

`event`→relevance: Phase A treats `open`/`access`/`write`/`exec` path accesses uniformly as
"this exe touched this path" (the read/write distinction matters for SP2, not for a
presence allowlist). Phases B/C add the `dest`/`spawn` checks alongside, same control flow.

---

## 6. Findings

Both finding kinds build JSON via `ps_json` and publish via `ctx->publish` (the
`iface_monitor`/`policy_overwatch` path):

- **candidate** — ⚙️ channel `baseline.candidate`, severity `info`, confidence `tentative`.
  `{exe, kind:"path", entry:<path>, event, process:{pid,comm,uid}, ancestry, sockets}`.
- **confirmed anomaly** (a denied entry re-observed) — ⚙️ channel `baseline.anomaly`,
  severity `high`, confidence `firm`, same evidence.

Candidates publish to central for fleet visibility (D4). Dedup (first-seen per
`exe|kind|entry`) bounds volume — one finding per novel entry, not per event.

---

## 7. `baseline` CLI verb

`packetsonde baseline <exe> <subcommand> [--state-dir D] [--threshold N]`:

- `list` — print the exe's baseline entries, pending candidates, and denials.
- `approve <entry>` — move a candidate → baseline. With **rollup**: approving ≥⚙️`N`(3)
  files under one dir collapses to the dir rule (reuses `sandbox_synth`'s rollup).
- `approve-all` — approve every current candidate (the bootstrap step after a nominal run).
- `deny <entry>` — move a candidate → denials (escalates future sightings to anomalies).

Arg parsing is a **manual order-independent scan** (this CLI's `getopt` does not permute —
see the project memory note; `sandbox-suggest` set the precedent). The verb resolves the
exe's `slug`, reads/writes the three files atomically.

---

## 8. Concurrency / ownership protocol

To avoid agent↔CLI races without file locks (D7):

- **Agent:** appends to `candidates.json` only; reads `baseline.json`/`denials.json` only.
- **CLI:** sole writer of `baseline.json`/`denials.json`; when approving/denying it also
  rewrites `candidates.json` to remove the decided entry.
- **All writes** go through a temp file + `rename(2)` (atomic on the same filesystem), so a
  reader never sees a half-written file.
- **Reconciliation:** the agent, on reload, drops from its in-memory pending set anything
  now present in `baseline.json` or `denials.json` (the CLI may have removed it from
  `candidates.json` concurrently; the agent tolerates a candidate it appended that the CLI
  already promoted — `baseline` is authoritative, so it simply stops flagging it).

The narrow window where both rewrite `candidates.json` is tolerated: a lost append just
means a novel entry is re-appended on its next sighting (idempotent — dedup + the next
event re-creates it). No corruption (atomic rename) and no missed *baseline* entry.

---

## 9. Config (`[detect]`, via `config_to_env`)

```toml
[detect]
# ... (SP1 + SP2 keys)
baseline_mode      = "off"     # off | on  (on = hybrid learn+enforce, keyed by exe)
baseline_state_dir = "/var/lib/packetsonde/baseline"
baseline_reload    = "10"      # seconds between baseline/denials reloads
```

New `config_to_env` mappings: `PS_DETECT_BASELINE_MODE`, `PS_DETECT_BASELINE_STATE_DIR`,
`PS_DETECT_BASELINE_RELOAD`. Requires SP1 collection (`enabled=1`); the module logs and
no-ops if the ring is never fed.

---

## 10. Components (boundaries)

| Unit | Lives in | Pure? | Does |
|---|---|---|---|
| `proc_enrich` exe field | `src/agent/src` (SP1 ext) | I/O | `readlink /proc/<pid>/exe` → `process.exe` |
| `exe_slug` | `src/lib` | pure | exe path → filename slug |
| `baseline_set` | `src/lib` | pure | typed entry set (paths now; dests/spawns later) + dir-prefix match + JSON serde |
| `baseline_store` | `src/agent/src` | I/O | per-exe load/cache/reload of baseline+denials; append candidate (atomic) |
| `baseline_decide` | `src/lib` | pure | (baseline, denials, record-entry) → COVERED / ANOMALY / NOVEL |
| `baseline_monitor` | `src/agent/src/modules` | module | tick: drain ring → parse → decide → emit/append |
| `baseline` verb | `src/cli/verbs` | verb | list/approve/deny/approve-all (atomic writes, rollup) |

The pure units (`exe_slug`, `baseline_set`, `baseline_decide`, and the rollup reused from
`sandbox_synth`) are fixture-tested; the store I/O, module wiring, and verb are integration.

---

## 11. Phasing (one spec, three plans)

- **Phase A — exe prereq + lifecycle + file signal:** SP1 `exe` population; `exe_slug`;
  `baseline_set` (paths) + `baseline_decide`; `baseline_store`; the `baseline_monitor`
  module (file signal, hybrid flow); the `baseline` verb; `[detect] baseline_mode` config.
  Ships the detector for file-path deviations end-to-end.
- **Phase B — network destinations:** add `dests[]` (from `sockets[].raddr`) to the entry
  sets + decide path; the verb learns/approves dests (⚙️ generalize by `ip:port`, with
  port/`/24` rollup on approve). The exfil/lateral-movement signal.
- **Phase C — process spawning:** add `spawns[]` (expected child `comm`/exe from
  `ancestry[]`) + decide path; flag an exe spawning an unexpected child.

Each phase is a separate `writing-plans` cycle, reusing Phase A's store/lifecycle/verb.

---

## 12. Testing

**Unit (pure, fixtures):** `exe_slug` sanitization (incl. collisions/edge chars);
`baseline_set` dir-prefix match (boundary: `/var/lib/app` ≠ `/var/lib/appX`; under-dir
covered) + JSON serde round-trip; `baseline_decide` (covered vs denied vs novel) across the
three sets; rollup-on-approve (≥N files → dir).

**Module (synthetic records + injected store):** feed crafted activity records; assert
covered→silent, denied→anomaly finding, novel→candidate finding + append; dedup.

**CLI:** `list/approve/deny/approve-all` against fixture state dirs (file-based, no root) —
assert candidate→baseline / candidate→denials transitions and the rollup.

**Live (gated, root):** run a service under `baseline_mode=on`, exercise nominal flows,
`baseline <exe> approve-all`, then trigger a novel file access → assert a `baseline.anomaly`
(after `deny`) or `baseline.candidate` finding.

---

## 13. Deferred (later)

- **Statistical / frequency scoring** (per-entry counts, surprise ranking, decay) — we chose
  set-based for v1.
- **Volume & timing baselines** (typical bytes / connection cadence) — not in the SP1
  record; needs `flow_tracker` integration.
- **Central-driven approval / baseline push** — we chose local CLI; a central→agent push
  channel is a separate (cross-repo) build.
- **AppArmor/SELinux** correlation; **Phases B/C** (network, spawn) per §11.

---

## 14. Self-review

- **Decisions ↔ sections:** D1 §1/§5; D2 §11; D3 §3/§5/§7; D4 §6/§7; D5 §3/§4; D6 §5; D7 §8.
- **No placeholders:** every component has a file, role, and test approach; the state-file
  ownership protocol and the decide/flow are concrete; the SP1 prerequisite is explicit.
- **Scope:** explicitly three phased plans (§11); Phase A is one plan's worth.
- **Ambiguity resolved:** exe-keying needs the SP1 `exe` prereq (called out); directory-
  prefix matching defined with the boundary rule; ownership protocol defines who writes
  what; candidate vs anomaly vs covered are the three decide outcomes.
- **Consistency:** `baseline_set`/`baseline_store`/`baseline_decide`/`baseline_monitor`/
  `baseline` verb; `baseline_mode=off|on`; channels `baseline.candidate`/`baseline.anomaly`;
  state files `baseline.json`/`candidates.json`/`denials.json` referenced uniformly.
