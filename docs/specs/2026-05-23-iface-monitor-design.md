# packetsonde — Interface Monitor (state + enumeration changes) — Design Spec

**Date:** 2026-05-23
**Status:** Draft, pending review
**Component:** `packetsonde` C agent — a new `iface_monitor` passive module + a small
capture-handle teardown API + two module-ctx capture hooks.

## 1. Purpose

Detect and report changes to the node's network interfaces — **state changes**
(UP↔DOWN / RUNNING, address add/remove) and **enumeration changes** (an interface
appearing or disappearing) — and, because the agent now captures all real interfaces,
**dynamically adjust capture** so a recovered or hot-plugged interface starts being
observed (and a removed/down one stops), without a restart.

Detection is **poll-on-tick** (reusing the module `tick` callback + `getifaddrs`), which
is portable (Linux/BSD/macOS) and needs no new socket/event-loop plumbing. Latency is the
poll interval (seconds) — fine for interface up/down/add/remove.

## 2. Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Detection = poll-on-tick (`getifaddrs` snapshot + diff), interval-configurable. | Reuses the existing `tick` mechanism; portable; no netlink/event-loop work. |
| D2 | Report **and** dynamically re-capture. | The agent captures all real ifaces; a recovered/added iface should auto-capture (completes the dynamic-capture work). |
| D3 | `g_capture` stays the single source of truth for what's captured; the monitor manipulates it via new ctx hooks (`capture_add`/`capture_remove`). | One owner of the capture set; the monitor doesn't duplicate handle bookkeeping. |
| D4 | Findings: `net.iface.added`, `net.iface.removed`, `net.iface.state_change`, `net.iface.addr_change`. `info`, except a monitored iface going **down** is `warning`. | Distinct, queryable kinds; down-link is the actionable one. |
| D5 | Re-capture honors `[capture] exclude` + the 8-iface max. | Same policy as startup; don't auto-capture excluded/virtual ifaces. |

## 3. Components

### 3.1 `iface_snapshot` (new — `src/agent/src/iface_snapshot.{c,h}`; pure diff is testable)
```c
struct ps_iface_snap {
    char     name[64];
    int      up;        /* IFF_UP */
    int      running;   /* IFF_RUNNING (carrier) */
    uint32_t addr_hash; /* order-independent hash of the iface's addresses */
};

/* getifaddrs → unique-per-name snapshots into out[], up to max. Returns count. */
int ps_iface_snapshot(struct ps_iface_snap out[], int max);

enum ps_iface_change_kind { PS_IFC_ADDED, PS_IFC_REMOVED, PS_IFC_STATE, PS_IFC_ADDR };
struct ps_iface_change {
    enum ps_iface_change_kind kind;
    char name[64];
    int  old_up, old_running, new_up, new_running;   /* for STATE */
};

/* Pure: diff prev vs cur (by name); fill changes[] up to max. Returns count.
 * ADDED = in cur not prev; REMOVED = in prev not cur; STATE = up/running differ;
 * ADDR = addr_hash differs (and up/running same). */
int ps_iface_diff(const struct ps_iface_snap *prev, int nprev,
                  const struct ps_iface_snap *cur, int ncur,
                  struct ps_iface_change *changes, int max);
```
`ps_iface_diff` is pure (snapshots in → changes out) → unit-tested. `ps_iface_snapshot`
wraps `getifaddrs` (addresses hashed order-independently so re-ordering isn't a false
change) → exercised live.

### 3.2 `iface_monitor` module (new — `src/agent/src/modules/iface_monitor.c`)
- `init(ctx)`: `ps_iface_snapshot` → store as `st->prev`; store `last_tick_usec = 0`.
- `tick(ctx, now_usec)`: if `now_usec - last < interval_usec` return (throttle). Re-snapshot
  into `cur`; `ps_iface_diff(prev, cur)`; for each change:
  - **publish** a finding (§3.4) via `ctx->publish`.
  - **re-capture** (§3.3): ADDED or STATE→up ⇒ `ctx->capture_add(name)`;
    REMOVED or STATE→down ⇒ `ctx->capture_remove(name)`.
  - copy `cur`→`prev`; update `last`.
- Interval from `PS_IFACE_MONITOR_INTERVAL` (seconds; default 5; `0` disables the module's
  diffing, leaving it inert).
- Registered in the module registry like the other passive modules; it has no `on_packet`
  (it's tick-driven, not packet-driven).

### 3.3 Capture lifecycle (the "act" half)
- **`capture_handle.{c,h}`** — add `int ps_capture_close_iface(struct ps_capture_handle *ch,
  const char *iface, ps_close_pcap_fn close_fn, void *ctx);` — find `iface` in
  `iface_names[]`, invoke `close_fn(ctx, handle_id)` (the priv `CLOSE_PCAP`), compact the
  array (`count--`). Returns 0 if closed, -1 if not present. Add a matching
  `ps_capture_add_iface(ch, open_fn, ctx, iface)` thin wrapper (or reuse `ps_capture_open`)
  that no-ops if `iface` is already in the handle or excluded.
- **module ctx** (`module_api.h`) — add a `close_pcap(ctx, handle)` hook peer to
  `open_pcap`, and two capture-set hooks `capture_add(ctx, iface)` / `capture_remove(ctx,
  iface)` that `main` wires to operate on `g_capture` (apply `[capture] exclude`, respect
  the 8-iface max, use the priv open/close). The monitor calls `capture_add`/`capture_remove`
  — it never touches `g_capture` directly.
- `main` provides the `capture_add`/`capture_remove` implementations (closing over
  `g_capture` + the resolved exclude list) and wires them into every module ctx.

### 3.4 Finding shape (via `ctx->publish`)
`channel` = the kind; JSON body via `ps_json`, e.g.:
```json
{"v":1,"kind":"net.iface.state_change","severity":"warning","iface":"eth1",
 "old":{"up":true,"running":true},"new":{"up":false,"running":false},
 "ts":"<iso>","source":"agent.iface_monitor"}
```
`added`/`removed` carry `iface` (+ `up`/`running` for added); `addr_change` carries `iface`.
Severity `info` except `state_change` to **down** (`up:false`) → `warning`.

### 3.5 Config
- `[iface_monitor] interval` → `PS_IFACE_MONITOR_INTERVAL` (config_to_env mapping; seconds).
- Re-capture reads `PS_CAPTURE_EXCLUDE` (already mapped) via the `main` `capture_add` impl.

## 4. Error handling
- `getifaddrs` failure in a tick → skip this tick (keep `prev`), don't crash; log debug.
- `capture_add` for an excluded / already-captured / max-reached iface → no-op (logged);
  the finding is still published (report is independent of the re-capture outcome).
- `capture_remove` for an iface not currently captured → no-op.
- A flapping iface (rapid up/down) → one finding + one capture action per detected
  transition per tick; the poll interval naturally rate-limits.

## 5. Testing
- **Unit (`test_iface_snapshot`):** `ps_iface_diff` — pure, hand-built snapshots:
  added/removed/state(up→down, down→up)/addr-change detected; no-change → 0; a stable set
  → 0; ordering of the input arrays doesn't matter.
- **Build:** module compiles + registers; agent builds.
- **Live (fleet):** with the daemon running, `ip link set eth1 up` → within one interval a
  `net.iface.state_change` (→up) finding appears **and** `eth1` capture opens (journal
  `shared capture on eth1`); `ip link set eth1 down` → `state_change` (→down, warning) +
  capture closes. Add/remove a dummy/veth iface → `net.iface.added`/`removed` + capture
  add/remove (unless excluded).

## 6. Plan ordering (one spec, two layers)
The implementation plan lands the **detect + report** layer first (snapshot/diff +
`iface_monitor` publishing findings on tick — fully testable on its own), then the
**re-capture** layer (`ps_capture_close_iface` + ctx hooks + `main` wiring + the monitor's
`capture_add`/`capture_remove` calls). Reporting is verifiable before the capture-lifecycle
complexity is in play.

## 7. Deploy / out of scope
- Deploy: rebuild agent + restage + `salt '*' state.apply packetsonde`.
- Out of scope: netlink/real-time detection (poll is sufficient); per-event source-iface
  labels on *other* listeners (separate follow-on: `handle_id → iface_names[]`); skipping
  DOWN ifaces during the *startup* enumerate (separate follow-on). **No hardcoded interface
  names** (consistent with the dynamic-capture work). Generic — public repo.
