# packetsonde — Process/File/Socket Collection Primitives (Linux) — Design Spec

**Date:** 2026-06-03
**Status:** Draft, pending review
**Component:** `packetsonde` C agent — a new privileged collection engine in
`priv_worker` (fanotify + `/proc` enrichment), a `priv_protocol` record message, a
bounded activity ring on the unprivileged side, and a `packetsonde watch` inspect verb.

**This is sub-project 1 of the process-level anomaly-detection track (req-sync §4).**
It builds the *senses* — faithful, process-attributed file/socket observations. It does
**no** scoring. The two scoring tracks that consume this stream are out of scope here and
covered in §13:

- **SP2 — systemd/MAC declared-policy overwatch** (built next): compare observed access
  to the host's own declared policy (`systemd` unit sandboxing + AppArmor/SELinux
  profile); flag divergence. No learning period.
- **SP3 — learned per-process baseline** (passive / bootstrapped / hybrid).

The record schema (§5) is the contract both inherit; this spec keeps it source-agnostic so
SP2/SP3 slot in without reworking collection.

---

## 1. Purpose & scope

Emit a correlated, process-attributed record every time a watched process opens/accesses a
watched path: *who* (process + ancestry + the systemd unit + the MAC label/mode it runs
under), *what* (path + op), and *the network context* (sockets held by the process **and
its session ancestors**). This realizes the collection half of req-sync §4 ("tie file
access to process context and concurrent socket activity") on **Linux only**.

- **In scope:** fanotify (notification-mode) file-event capture on configured watch paths;
  on-demand `/proc` enrichment (process metadata incl. cgroup/unit + MAC label/mode);
  parent-tree ancestry walk to the session/service root; on-demand socket snapshot tagged
  by owning ancestor; a coarse read-only suppression list that gates enrichment; a bounded
  activity ring; the `packetsonde watch` JSONL inspect verb; `[detect]` config via
  `config_to_env`.
- **Out of scope:** any anomaly judgment, baselines, or policy comparison (SP2/SP3);
  shipping raw activity to central; FreeBSD/OpenBSD (req-sync says coarser/sampled — a
  later increment); eBPF (a later scale option — see §2 D-MECH).

**Design principles carried in:** *stay lightweight* (zero idle cost; suppression gates
the expensive work; bounded ring) and *collect ground truth, surface anomalies* — this
sub-project collects ground truth with full attribution; surfacing is SP2/SP3.

---

## 2. Decisions captured (from brainstorming)

| # | Decision | Rationale |
|---|----------|-----------|
| D-MECH | File-access via **fanotify in notification mode** (not inotify, not eBPF). | fanotify events carry the accessing **PID** → process attribution, which §4 requires; inotify gives no PID. Notification mode is passive (never blocks I/O), matching "observe only". Single-binary friendly (syscalls only, no eBPF toolchain/BTF/kernel-version fragility). eBPF deferred as a scale option. |
| D-PRIV | The whole collection engine lives in **`priv_worker`**; it emits correlated records over `priv_protocol` to the unprivileged agent. | fanotify setup needs `CAP_SYS_ADMIN`; reading *other users'* `/proc/<pid>/fd` needs privilege. Mirrors the existing pcap model (privileged worker, unprivileged consumer). |
| D-SNAP | Socket context is an **on-demand snapshot at file-event time**, not a continuous cache. | Zero idle cost; the file event is the anchor, so the correlation window is implicit ("sockets open at the instant of access") — no independent ~100ms timing to tune. |
| D-WALK | The snapshot **walks the parent tree** (`pid→ppid`) to the **session/service root** (ancestor whose parent is PID 1), depth-capped, skipping kernel threads; each socket tagged `{owner_pid, owner_comm, depth}`. | A file-accessing process often holds **no** socket (e.g. a shell under `sshd`, a post-exploit `sh` under `smbd`); the session's network context lives on an ancestor. Stops before init/systemd to avoid attributing daemon listeners. |
| D-OUT | Output goes to a **local bounded ring + a `watch` inspect verb**. **No raw activity is shipped to central.** | §4 reports *flagged* events, not everything; raw shipping would make central a firehose and isn't lightweight. SP2/SP3 consume the ring and emit only findings. |
| D-SUP | A **coarse static suppression list** (path-prefix [+ optional comm], **reads only**) is checked in `priv_worker` **before** enrichment. Never suppresses writes or `FAN_OPEN_EXEC`. | Volume control that makes broad watch coverage affordable, and it gates the expensive `/proc` walk. The expressive per-process envelope is SP2/SP3, *not* here — keeps "what's permissible" logic in one place. Never whitelisting writes/exec-opens preserves the EternalRed signal. |
| D-HOOK | The record captures **cgroup/systemd unit** (`/proc/<pid>/cgroup`) and **MAC label + mode** (`/proc/<pid>/attr/current`) in process metadata now. | Cheap single reads; they are the enabling hooks for SP2 overwatch (map an access to a unit; explain *why* enforcement didn't stop it). The schema is the SP2/SP3 contract, so add them at the source. |
| D-PATHS | Watch paths are **configurable + role-templated**; fanotify mask includes `FAN_OPEN_EXEC`. | A service's risky dirs differ by role (e.g. a Samba share, a web root); `FAN_OPEN_EXEC` is a cheap complementary signal on `execve` (note: `dlopen` is `open`+`mmap`, not `execve`, so library loads are caught via `FAN_OPEN`). |

---

## 3. Architecture & placement

```
                          priv_worker (privileged)                         agent (unprivileged)
  ┌───────────────────────────────────────────────────────────┐      ┌──────────────────────────┐
  │ fan_monitor: fanotify(FAN_OPEN|FAN_ACCESS|FAN_OPEN_EXEC)    │      │ activity_ring (bounded,  │
  │   notif-mode marks on watch_paths                          │      │   drop-oldest + counter) │
  │      │ event {pid, path, mask}                             │      │      │                   │
  │      ▼                                                      │      │      ├─▶ SP2/SP3 consumer│
  │ suppression gate (reads only; comm + path-prefix) ──drop──▶ count  │      └─▶ `packetsonde     │
  │      │ (not suppressed)                                    │      │            watch` (JSONL) │
  │      ▼                                                      │      └──────────────────────────┘
  │ proc_enrich(pid): /proc/<pid>/{stat,status,cmdline,exe,    │                  ▲
  │                   cgroup,attr/current}                     │   priv_protocol  │
  │      │  + ancestry walk pid→…→session/service root         │   PS_PW_MSG_ACTIVITY (record JSON)
  │      ▼                                                      │ ─────────────────┘
  │ sock_snapshot(leaf + ancestors): /proc/<pid>/fd ∩ sock_diag │
  │      ▼                                                      │
  │ activity_record (serialize) ───────────────────────────────┼──────────────────▶
  └───────────────────────────────────────────────────────────┘
```

Privilege boundary: everything that needs root stays in `priv_worker`; the unprivileged
agent only ever sees finished, serialized records. No new privileged surface is exposed to
the network — fanotify is local-only.

---

## 4. Collection pipeline (per file event)

1. **Receive** a fanotify event `{pid, mask, fd→path}` on a watched mark. Resolve the path
   from the event fd (`readlink /proc/self/fd/<event_fd>`), then close it.
2. **Suppress?** If `mask` is a *read* (`FAN_OPEN`/`FAN_ACCESS` without write intent) and
   `(comm, path)` matches the coarse suppression list → increment a dropped counter and
   stop. Writes and `FAN_OPEN_EXEC` are never suppressed. (`comm` for this cheap check is a
   single `/proc/<pid>/comm` read; full enrichment is still skipped.)
3. **Enrich** the leaf pid (`proc_enrich`): read process metadata incl. `cgroup`/unit and
   MAC label/mode.
4. **Ancestry walk**: follow `ppid` to the session/service root (§7), collecting
   `{pid, comm, depth}` per ancestor.
5. **Socket snapshot** (§8): for the leaf and each ancestor, intersect `/proc/<pid>/fd`
   socket inodes with `sock_diag` results; tag each socket with its owner + depth.
6. **Emit**: serialize the `activity_record` (§5) and send it as a `PS_PW_MSG_ACTIVITY`
   frame over `priv_protocol`. The unprivileged agent pushes it onto the `activity_ring`.

If the process exits mid-pipeline (TOCTOU), enrichment/snapshot degrade gracefully:
missing `/proc` reads yield empty fields, the record is still emitted with what was
captured plus a `partial: true` flag.

---

## 5. The activity record (the SP2/SP3 contract)

```json
{
  "v": 1,
  "ts": "2026-06-03T14:22:10Z",
  "event": "open",                         // open | access | exec  (from the fanotify mask)
  "path": "/var/samba/share/evil.so",
  "partial": false,                        // true if some /proc reads raced a process exit
  "process": {
    "pid": 1234, "ppid": 1190, "uid": 0, "sid": 1190,
    "comm": "smbd", "exe": "/usr/sbin/smbd", "cmdline": "/usr/sbin/smbd --foreground",
    "cgroup": "/system.slice/smbd.service",            // /proc/<pid>/cgroup  → systemd unit
    "mac": { "label": "/usr/sbin/smbd", "mode": "complain" }  // /proc/<pid>/attr/current
  },
  "ancestry": [                            // leaf→root order, leaf excluded (it's `process`)
    { "pid": 1190, "comm": "smbd", "depth": 1 }
  ],
  "sockets": [                             // sockets held by leaf + ancestors, tagged by owner
    { "owner_pid": 1190, "owner_comm": "smbd", "depth": 1,
      "proto": "tcp", "laddr": "10.0.0.5:445", "raddr": "203.0.113.5:51344",
      "state": "ESTABLISHED" }
  ]
}
```

Field notes:
- `mac.mode` ∈ `enforce | complain | unconfined | <selinux-context>` (LSM-dependent; raw
  string when not parseable). It is triage gold for SP2: the divergence *is* the finding;
  the mode explains *why* enforcement didn't stop it.
- `depth` 0 = the leaf (in `process`); ≥1 = ancestors. Sockets owned by the leaf carry
  `depth: 0`.
- `cgroup` is the unified (v2) path, or the `name=systemd` controller path (v1); the unit
  basename (`smbd.service`) is what SP2 keys on.

---

## 6. Components (each independently testable)

| Unit | Lives in | Does | Depends on |
|---|---|---|---|
| `fan_monitor` | priv_worker | Set up/maintain fanotify marks on watch paths; read events; resolve path; apply suppression gate. | fanotify syscalls; `suppress` rules |
| `proc_enrich` | priv_worker (pure-ish) | pid → process metadata (incl. cgroup/unit, MAC label/mode); ancestry walk to session/service root. | `/proc` reads only |
| `sock_snapshot` | priv_worker (pure-ish) | For a set of pids, map socket inodes → endpoints. | `/proc/<pid>/fd`, `sock_diag` (NETLINK_INET_DIAG) |
| `activity_record` | shared (`src/lib`) | Schema + serialize/parse. Used by IPC emit and the `watch` verb. | `json` writer |
| `activity_ring` | agent (unprivileged) | Bounded thread-safe ring; drop-oldest + dropped-counter on overflow. | mirror phase-0 `obs_queue` pattern |
| `watch` verb | CLI | Drain/tail the ring → JSONL stdout; `--path`/`--comm` filters. | `activity_record` parse |

`proc_enrich` and `sock_snapshot` are written to take an injectable `/proc` root and an
injectable `sock_diag` source so unit tests run against fixtures with no privilege (the
conftest-style idiom the project already uses).

---

## 7. Ancestry walk + session/service-root rule

Walk `pid → ppid` (each step a `/proc/<pid>/stat` field-4 read). **Stop** when the next
parent would be **PID 1** (init/systemd) — i.e. the current node is the session/service
root (the per-connection `sshd`, a service's main process, a login session leader).
Safeguards: a hard **depth cap (16)**; skip **kernel threads** (ppid 2 / `kthreadd`
lineage); detect cycles (malformed `/proc`) and stop. The leaf is recorded in `process`;
ancestors (depth ≥1, excluding PID 1) populate `ancestry`. Sockets are gathered from the
leaf *and* every ancestor on this path (§8).

Rationale recap: this is what makes a shell-under-`sshd` (or a post-exploit `sh` under
`smbd`) attributable to the remote peer that drove it — the leaf has no socket; the
ancestor does.

---

## 8. Socket snapshot

For each pid in {leaf} ∪ ancestry:
1. Enumerate `/proc/<pid>/fd/*`; for symlinks of the form `socket:[<inode>]`, collect the
   inode.
2. Resolve inodes → endpoints via a single `sock_diag` dump (NETLINK_INET_DIAG for
   TCP/UDP, v4+v6), matched on inode. (Parsing `/proc/net/{tcp,tcp6,udp,udp6}` is the
   fallback if `sock_diag` is unavailable.)
3. Emit one `sockets[]` entry per resolved socket, tagged `{owner_pid, owner_comm, depth,
   proto, laddr, raddr, state}`.

Deduplicate by inode across the ancestry (an inherited fd shared by parent+child is
reported once, attributed to the **nearest-to-root** owner that holds it, so session
sockets attribute to the session owner). Unix-domain and non-IP sockets are ignored in
this increment (IP context is what §4 correlation needs).

---

## 9. Coarse suppression

A static list, shipped-default + operator-extendable, of `(path-prefix [, comm])` rules
that suppress **read** opens only:

- Ship defaults: `/usr/lib`, `/lib`, `/usr/lib64`, `/lib64`, `/usr/share`, `/proc`,
  `/sys`, `/dev` reads by any process; the agent's own pid/exe activity (self-exclusion).
- Operator-extendable via `[detect] suppress_paths`.

Checked in `fan_monitor` **before** enrichment so suppressed reads cost only a comm +
prefix compare. **Never** suppresses `FAN_OPEN_EXEC` or write-intent opens — so a
write-then-`dlopen` of a `.so` in an otherwise-noisy data dir (EternalRed, §12) is never
whitelisted away. Suppression is volume control, **not** security policy; it is
deliberately not per-process-expressive (that is SP2/SP3).

---

## 10. Config (`[detect]`, via `config_to_env`)

```toml
[detect]
enabled       = "0"                 # master switch (default off)
watch_paths   = "/etc,/home"        # comma-separated; configurable + role-templated
suppress_paths = ""                 # operator-added coarse read suppression (prefixes)
max_depth     = "16"                # ancestry walk cap
max_events_ps = "2000"              # global events/sec cap (drop + count over)
```

`config_to_env` mappings added: `PS_DETECT_ENABLED`, `PS_DETECT_WATCH_PATHS`,
`PS_DETECT_SUPPRESS_PATHS`, `PS_DETECT_MAX_DEPTH`, `PS_DETECT_MAX_EVENTS_PS` (same
quote-stripping idiom as existing keys). Role-templated path sets are expressed as named
bundles the operator/salt selects; the templating lives in config/bootstrap, not the
agent (the agent only sees the resolved `watch_paths`).

---

## 11. Lightweight guarantees

- **Zero idle cost:** no polling; `proc_enrich`/`sock_snapshot` run only on a
  non-suppressed event.
- **Suppression gates the expensive work:** benign reads cost a comm + prefix compare; the
  `/proc` walk + socket snapshot happen only for events worth a record.
- **Bounded everywhere:** the activity ring is fixed-capacity (drop-oldest + counter, like
  `obs_queue`); a global `max_events_ps` rate-limit drops + counts under storm; the
  ancestry walk is depth-capped.
- **Never blocks I/O:** notification-mode fanotify only (no permission/blocking mode).
- **Off by default:** `enabled="0"`; opt-in per host/role.

---

## 12. Worked example — EternalRed / SambaCry (CVE-2017-7494)

Validates that the schema carries what the scoring tracks need.

| Exploit step | Record emitted (abridged) |
|---|---|
| Upload `.so` to writable share | `event:open(write) path:/var/samba/share/evil.so process:{smbd,uid:0,cgroup:/system.slice/smbd.service,mac:{mode:complain}} sockets:[{owner:smbd,depth:0,raddr:203.0.113.5:445}]` — **write never suppressed** |
| `smbd` `dlopen`s the `.so` | `event:open path:/var/samba/share/evil.so process:{smbd…} sockets:[{owner:smbd,depth:0,raddr:203.0.113.5}]` — load tied to attacker IP |
| Injected code spawns `sh`, reads `/etc/shadow` | `event:open path:/etc/shadow process:{comm:sh,ppid→smbd} ancestry:[{smbd,depth:1}] sockets:[{owner:smbd,depth:1,raddr:203.0.113.5}]` — **ancestry walk** attributes the shell's read to the attacker socket on `smbd` |

What SP2/SP3 then do with these records (out of scope here): SP2 flags the `/var/samba`
load as outside `smbd`'s declared `ReadWritePaths`, weighted by `mac.mode:complain`; SP3's
learned baseline flags "`smbd` never has an `sh` child" and "library loaded from a data
dir". The collector's job is only to have captured all of it faithfully — which the table
shows it does.

---

## 13. Deferred (later sub-projects)

- **SP2 — systemd/MAC declared-policy overwatch (next):** ingest the host's declared
  policy — `systemd` unit sandboxing (`ReadWritePaths`, `ReadOnlyPaths`, `ProtectSystem`,
  `ProtectHome`, `InaccessiblePaths`, …, via `systemctl show <unit>`) and the
  AppArmor/SELinux profile — build a per-unit permissible envelope, and flag observed
  access (keyed on `process.cgroup`/unit) that diverges, weighted by `process.mac.mode`.
  No learning period. Consumes the §5 record; emits findings via the existing
  reporter/observation pipeline.
- **SP3 — learned per-process baseline:** passive (7-day) / bootstrapped / hybrid envelope
  learning + curation loop; same record, same source-agnostic scoring engine as SP2.
- **Socket-before-file ordering:** the on-demand snapshot sees sockets open *at* the file
  event; a continuous cache (to catch a socket opened-then-closed just before) is a later
  option if SP2/SP3 show a need.
- **eBPF collection backend:** a lower-overhead, more-precise alternative to
  fanotify+`/proc` at high event rates; same record schema.
- **FreeBSD/OpenBSD:** coarser/sampled collection (dtrace / sampled `/proc`) per req-sync;
  the record schema is intended to carry across platforms.
- **Unix-domain / non-IP sockets** in the snapshot.

---

## 14. Self-review

- **Spec coverage vs decisions:** D-MECH §2/§4; D-PRIV §3; D-SNAP §4/§8; D-WALK §7;
  D-OUT §3/§6/D-OUT; D-SUP §9; D-HOOK §5; D-PATHS §10. ✓
- **No placeholders:** every component has a defined interface, source, and test approach;
  config keys and `/proc` sources named concretely.
- **Scope:** single implementation plan's worth — collection only; all scoring explicitly
  in §13. ✓
- **Name consistency:** `fan_monitor`/`proc_enrich`/`sock_snapshot`/`activity_record`/
  `activity_ring`/`watch`; `PS_PW_MSG_ACTIVITY`; `[detect]` keys; record fields identical
  in §5 and the §12 examples.
```
