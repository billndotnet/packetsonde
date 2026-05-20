# Use case guides

packetsonde fits three deployment shapes. The CLI runs the same in all three; the agent is what changes position.

| Guide | Position | When to use |
|---|---|---|
| [Trunk probe](trunk-probe.md) | Agent on a dot1q-trunked host with visibility into many VLANs | You need to audit segments behind ACLs you can't bypass from your laptop |
| [Service-dependency test point](service-dependency.md) | Agent co-located with (or near) a service consumer | You need continuous validation that service A can actually reach its dependencies from where it lives |
| [Passive bridge appliance](bridge-appliance.md) | Small in-line device between two network segments | You need to observe traffic and audit without modifying the network's L2 topology |

All three deployments produce the same finding wire format, so downstream tooling (SIEM, alerting, dashboards) doesn't care which one emitted a record — it's just JSONL with a `host` and an optional `via_agent`.

## Common patterns across all three

**Reading findings.** Findings always go to stdout (or `--auto-append` for cron / store-and-forward). On a TTY they pretty-print; piped, they're JSONL. `jq`, `vector`, splunk-forwarders, and any line-oriented tool can consume them.

**Configuration.** The CLI reads `~/.config/packetsonde/agents.toml` (override with `--config <path>`). Each `[agents.<name>]` block names an agent the CLI can target with `--via <name>`. In v1 the only valid agent name is `local` (the agent on the same machine as the CLI); remote agents land with the network protocol follow-on.

**Privilege.** The agent typically runs privileged (raw sockets, packet capture, dot1q subinterfaces). The CLI is unprivileged by default; raw-socket modes (e.g. ICMP traceroute) require `cap_net_raw` or `sudo`.

**Persistence.** Add `--auto-append` to any run to also tee JSONL to `$XDG_STATE_HOME/packetsonde/findings-YYYY-MM-DD.jsonl`. The output emitter writes both stdout and the dated file under a single mutex, so the file is always parseable.

**Cancellation.** SIGINT (Ctrl-C) cancels in-flight work cleanly — workers finish the probe they started, the emitter flushes, no partial JSON lines.
