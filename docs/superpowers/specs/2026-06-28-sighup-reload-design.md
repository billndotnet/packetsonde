# SIGHUP reload for packetsonded

**Date:** 2026-06-28
**Status:** Approved, pending implementation plan

## Goal

Make `packetsonded` honor `SIGHUP` as a live reload: re-read the config file
and re-scan authorized client keys **without restarting** and without
dropping live capture, listener, or session state. `kill -HUP <pid>` and
`systemctl reload packetsonded` both trigger it.

Today SIGHUP is unhandled — its default disposition terminates the process,
which under `Restart=on-failure` causes an abrupt kill + restart. This
replaces that with a graceful, partial, in-place reload.

Scope: **`packetsonded` only.** `kernelsonded` (on the unmerged
`feat/kernelsonde-split` branch, no authorized-client listener) gets the same
treatment as the explicit next follow-up, not in this spec.

Branch note: this work is **stacked on `fix/network-listener-shutdown-hang`**
(commit `c68ac8c`), because the SIGHUP key-reload test relies on clean driver
shutdown and both touch `network_listener.c`.

## Background (current architecture)

- **Config is one-shot.** `main()` parses the TOML once and calls
  `ps_config_to_env()` (main.c:1118) to translate it into `PS_*` env vars;
  modules and the main setup capture their settings at init via `getenv()`.
  There is no live config object consulted in the event loop.
- **Authorized keys load once.** `network_listener.c`'s `load_authorized()`
  scans `PS_AGENT_AUTHORIZED_DIR` (`$PS_KEY_DIR/authorized`) into the
  in-memory `nl_state.authorized[][32]` / `authorized_n` at module init. New
  `.pub` files are not seen until restart. These are read lock-free by
  per-connection threads in `is_authorized()` — safe today only because the
  array never changes after init.
- **Signals.** `main.c` installs `on_signal` (sets `g_running = 0`) for
  SIGINT/SIGTERM and `SIG_IGN` for SIGPIPE. The priv worker installs none.
- **Module vtable** (`ps_module` in `module_api.h`) has `init`, `shutdown`,
  `on_packet`, `on_job`, `on_response`, `tick` — no reload hook.
- **`ps_log_set_level()`** sets a process-wide `s_min_level` (log.c) — a
  single int, cheap to re-apply.
- **`nl_state.max_clients`** comes from `PS_AGENT_MAX_CLIENTS` (default 64),
  read by the accept loop (network_listener.c:561) — an int, cheap to update.

## What reloads, and what does not

**Reloaded live on SIGHUP:**

1. **Authorized client keys** — re-scan `PS_AGENT_AUTHORIZED_DIR`; pick up
   newly-added `.pub` files and drop removed ones.
2. **Log level** — re-read from the fresh config and call `ps_log_set_level()`.
3. **`max_clients`** — re-read `PS_AGENT_MAX_CLIENTS` and update
   `nl_state.max_clients`.

**Restart-required (logged as unchanged, never half-applied):** capture
interface / exclude, listen address+port, listener TLS toggle, central URL /
check-in interval, and all detect / priv-worker settings. These are captured
at module/worker init and cannot change without teardown.

## Design

### Trigger and loop integration

- Add `static volatile sig_atomic_t g_reload = 0;` and an `on_sighup` handler
  that sets it. Install `signal(SIGHUP, on_sighup)` next to the existing
  handlers in `main()`. **SIGHUP never touches `g_running`** — it cannot
  terminate the agent.
- Retain the config-file path: store it in a `static char g_config_path[...]`
  at startup (where the config is first loaded), so the reload can re-parse
  it. (If config came from `BASE_CONFIG`/default rather than `-c`, store that
  resolved path.)
- At the top of the event loop, before the IPC poll:
  ```c
  if (g_reload) { g_reload = 0; do_reload(); }
  ```
  Reload runs synchronously on the main thread between polls — no reentrancy.

### `do_reload()`

1. Re-parse the TOML from `g_config_path` into a fresh `ps_config`. On parse
   failure: `ps_warn` the error, free the partial config, and **return
   without changing anything** (keep the running config).
2. Re-apply **log level** from the fresh config (same resolution the startup
   path uses), via `ps_log_set_level()`.
3. For each registered module with a non-NULL `reload` hook, call
   `reload(ctx)` (see below).
4. Free the fresh `ps_config`.
5. `ps_info` a one-line summary, e.g.
   `reload: log level=INF; network_listener: 3 authorized key(s), max_clients=64`,
   plus a fixed note that capture / listen / central / detect changes require
   a restart.

`do_reload()` does **not** need to re-run `ps_config_to_env()`: the hot
settings either re-scan a fixed dir (keys) or are re-read by the module's
reload hook (max_clients) or applied directly (log level). Leaving env
untouched avoids the no-overwrite semantics of `config_to_env` and keeps the
blast radius minimal.

### Module `reload` hook

- Add to the `ps_module` vtable, after `tick`:
  ```c
  void (*reload)(ps_module_ctx_t *ctx);
  ```
  Optional; modules that don't set it are skipped. `do_reload` iterates the
  registry (`reg->instances[i].module->reload`) and calls it where non-NULL,
  passing the module's existing ctx.
- **`network_listener` implements `nl_reload`:** re-scan
  `PS_AGENT_AUTHORIZED_DIR` and re-read `PS_AGENT_MAX_CLIENTS`, applying both
  to its `nl_state` under the lock below.

### Thread-safety for the authorized keys

The reload runs on the main thread; `is_authorized()` runs on per-connection
threads. To make concurrent mutation safe:

- Add `pthread_mutex_t auth_lock;` to `nl_state` (init in `nl_init`).
- `nl_reload` builds the new key set into a **temp local** array
  (`uint8_t tmp[MAX_AUTHORIZED][32]`, `size_t tmp_n`) by scanning the dir,
  then under `auth_lock` copies it into `st->authorized` and sets
  `st->authorized_n` (and updates `st->max_clients`).
- `is_authorized()` takes `auth_lock` for the duration of its scan (the array
  is ≤ 64 entries; the critical section is microseconds and does not block on
  I/O). Refactor `load_authorized()` to fill a caller-provided array so both
  init and reload share the scan logic without duplication.

`max_clients` is an `int` read locklessly by the accept loop; updating it
under `auth_lock` while the reader is lock-free is benign (torn int reads
don't occur on the target ABI, and an off-by-one in the cap for one accept is
harmless). No reader change needed for `max_clients`.

### systemd and robustness

- `packaging/packetsonded.service`: add `ExecReload=/bin/kill -HUP $MAINPID`
  so `systemctl reload packetsonded` maps to the reload.
- `packetsonde-priv`: add `signal(SIGHUP, SIG_IGN)` in its `main()`. The
  worker holds no reloadable state and the agent never forwards HUP to it, but
  ignoring it defensively prevents a stray process-group HUP from killing the
  worker out from under the agent.

## Testing

- **Live key reload (shell e2e, mirrors `test_via_*`):** start the
  `test_network_listener_driver` with an empty authorized dir; confirm a
  client connect is rejected; drop the client's `.pub` into the dir; send
  `SIGHUP` to the driver; confirm the same client now connects. Asserts the
  end-to-end "authorize a new CLI without restart" flow. The driver needs a
  `SIGHUP` handler that invokes the module reload path (the driver hosts the
  module directly, like it does for init/shutdown).
- **No-op safety (unit/behavioral):** a module with a NULL `reload` hook is
  skipped without crashing; `do_reload()` with a deliberately bad config path
  logs and leaves the running state unchanged.
- **Regression:** full `ctest` stays green; the existing `test_via_*` suite
  (now leak-free on the base branch) still passes and leaks no drivers.

## Out of scope / follow-ups

- `kernelsonded` SIGHUP reload — the explicit next piece (re-scan its key
  dir + log level; same `reload` hook mechanism). Tracked separately.
- Full live config reload (capture iface, listen port, module re-init) —
  deliberately excluded; a much larger lifecycle change.
