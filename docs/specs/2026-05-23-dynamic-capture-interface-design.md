# packetsonde — Dynamic Capture-Interface Selection — Design Spec

**Date:** 2026-05-23
**Status:** Draft, pending review
**Component:** `packetsonde` C agent — capture-interface resolution (`main.c`), a new
interface-enumeration helper, `config_to_env`, and removal of hardcoded interface names
from the passive listeners.

## 1. Problem

The agent's passive capture targets a single, **hardcoded** interface name:
`main.c` defaults to `eth0` (Linux) / `en0` (macOS) / `em0` (FreeBSD), and each passive
listener independently hardcodes `en0` (literal + `*_DEFAULT_IFACE` defines). On any host
whose primary NIC isn't named that (modern Linux uses `enpXsY` / `ensXX` predictable
names), `pcap` fails to open the interface and **the entire passive-observation layer is
dead** — no ARP/LLDP/CDP/STP/DNS/DHCP/SSDP/NetBIOS/OSPF/VRRP/broadcast capture — and the
knock/discovery path (which feeds off captured broadcast) goes dark with it.

Interface names must **never** be hardcoded; capture must be dynamic per deployment.

## 2. Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Capture **all** of the node's interfaces, **minus `lo` (always) and an operator-declared exclude list**. No name-based defaults beyond loopback. | Zero hardcoded assumptions; a network observer wants every real segment it's attached to; operators exclude virtual/noisy ifaces explicitly. |
| D2 | Resolution order: explicit `[agent] interface` (pin a single iface) → else enumerate-all-minus-exclude. | Keeps an escape hatch to pin one iface; default is dynamic. |
| D3 | One **shared-capture pcap handle per resolved interface** (the existing `ps_capture_handle` already holds up to `PS_CAPTURE_MAX_INTERFACES = 8`); all feed the one module dispatch pipeline. | The multi-interface capacity already exists (the code comment says "one pcap per interface"); listeners consume via `on_packet` and need no change. |
| D4 | Remove `eth0`/`en0`/`em0` literals + `*_DEFAULT_IFACE` defines from `main.c` and the listeners. | The directive: no interface names in code. Listener iface labels were cosmetic (they share the pipeline). |
| D5 | Exclude matching is **prefix-based** (token `veth` excludes `veth*`, `docker` excludes `docker0`/`docker_gwbridge`). | Virtual ifaces have dynamic suffixes; prefix tokens make the exclude list usable. |

## 3. Components

### 3.1 `ps_iface_enumerate` + `ps_iface_excluded` (new — `src/agent/src/iface_enum.{c,h}`)
- `int ps_iface_excluded(const char *name, const char *exclude_csv);` — pure, testable:
  returns 1 if `name == "lo"` OR `name` starts with any comma-separated token in
  `exclude_csv` (empty/NULL csv → only `lo` excluded). Prefix match.
- `int ps_iface_enumerate(const char *exclude_csv, char out[][64], int max);` — calls
  `getifaddrs`, collects **unique** interface names that are not excluded (via
  `ps_iface_excluded`), up to `max`. Returns the count. (De-dups the multiple `getifaddrs`
  entries per iface — AF_INET/AF_INET6/AF_PACKET.)

### 3.2 `main.c` — resolve the capture target list
Replace the hardcoded default block. New logic:
```
exclude = getenv("PS_CAPTURE_EXCLUDE")            # from [capture] exclude
pin     = [agent] interface  (config)            # explicit single-iface override
if pin set:
    targets = [pin]
else:
    targets = ps_iface_enumerate(exclude, ...)    # all minus lo minus exclude
for ifc in targets[:PS_CAPTURE_MAX_INTERFACES]:
    ps_capture_open(&g_capture, ctx_open_pcap, NULL, ifc)   # one handle per iface
log the resolved set (and warn if >8 were found)
```
Delete the `#ifdef __FreeBSD__ "em0" / __APPLE__ "en0" / else "eth0"` block.

### 3.3 `config_to_env.c`
Add mapping `{ "capture", "exclude", "PS_CAPTURE_EXCLUDE" }` so `[capture] exclude` reaches
the env. (`[agent] interface` is read directly by `main` via `ps_config_get`.)

### 3.4 Listener cleanup
Remove the `iface = "en0"` literals (cdp/ssdp/lldp/netbios) and `*_DEFAULT_IFACE "en0"`
defines (dhcp/mld/stp + others). Listeners receive frames via `on_packet` from the shared
pipeline; their stored iface label is unused for capture — drop it (or set to a neutral
label). No behavioral change to packet handling.

## 4. Error handling

- An interface that fails to open (`ps_capture_open` returns error / priv `BAD_IFACE`):
  **warn and continue** — the other interfaces still capture. One bad iface must not kill
  the capture layer (the current single-iface failure does exactly that).
- If **zero** interfaces resolve or all fail to open: log an error (passive capture
  unavailable) but the daemon keeps running (check-in, active probes, agent_listen still
  function).
- `lo` is always excluded; capturing on loopback is never useful here.
- More than `PS_CAPTURE_MAX_INTERFACES` (8) resolved: capture the first 8, warn the rest
  are skipped (operator should exclude some).

## 5. Testing

- **Unit (C, `test_iface_enum`):** `ps_iface_excluded` — `lo` always excluded; empty csv
  excludes only `lo`; prefix tokens (`veth`, `docker`) exclude `veth0`/`docker0` but not
  `ens18`; exact non-prefix names; multiple tokens. (`ps_iface_enumerate` itself wraps
  `getifaddrs` — exercised in the live test.)
- **Build:** agent builds; no `en0`/`em0`/`eth0` string literals remain
  (`! grep -rE '"(en0|em0|eth0)"' src/agent/src` after the change).
- **Live (fleet):** redeploy; on a node, the journal shows `shared capture` opening on
  **each** real interface (not a hardcoded name), passive modules receive packets
  (e.g. ARP/mDNS findings appear), and a knock to a knock-mode node now succeeds
  (broadcast capture is live so `discovery_listener` hears it).

## 6. Deploy

Rebuild the agent + restage the binary + `salt '*' state.apply packetsonde` (fleet). No
central/frontend change. Optionally set `[capture] exclude` in the salt pillar for nodes
with virtual interfaces to suppress (e.g. container hosts) — but the default (all minus
`lo`) works with no config.

## 7. Out of scope / deferred

- Hot-add of interfaces that appear after startup (re-enumerate on a timer / netlink
  watch) — startup enumeration is sufficient for now.
- Per-interface BPF tuning — all interfaces share the existing combined filter.
- `deployment_mode`-driven capture (trunk/bridge promiscuous specifics) — separate concern.
