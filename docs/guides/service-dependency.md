# Service-dependency test point

## What this is

An agent (or just the CLI on a cron schedule) positioned at the same network coordinates as a real service consumer. From that vantage point, it continuously validates that the consumer's upstream dependencies are reachable, healthy, and behaving as expected. When a dependency breaks, you learn about it from the dependent's perspective — not from a synthetic prober that happens to be in a completely different network position.

The principle: synthetic monitoring tells you "*the internet* says X is up." A service-dependency test point tells you "*the host that actually consumes X* says X is up — or not."

## When to use this

- A service has multiple upstream dependencies (database, cache, identity provider, message bus, third-party API) and outages have historically been "upstream worked from the dashboard, but service A still couldn't reach it."
- The host running the service sits behind NAT / firewall / mesh that's invisible to external monitoring.
- You want to detect *path-specific* failures (one Kubernetes node's egress flapping, one availability zone's transit broken, certificate trust issues that only manifest with a specific resolver).
- Compliance / audit requirements that say "verify every documented dependency is reachable from the documented consumer."

Not the right shape if your monitoring problem is "is the database up *at all*." Use synthetic checks for that. This guide is about "does the host actually have working access to the database."

## Two flavors

### Flavor A — CLI on a cron

Smallest commitment. Install `packetsonde` on the service host, schedule audits via cron, ship findings to your collector.

```bash
# /etc/cron.d/packetsonde-deps
*/5 * * * * svc-user packetsonde --auto-append --quiet audit tls db.example.internal:5432 >> /var/log/packetsonde/deps.log 2>&1
*/5 * * * * svc-user packetsonde --auto-append --quiet audit dns 10.0.0.53                >> /var/log/packetsonde/deps.log 2>&1
*/5 * * * * svc-user packetsonde --auto-append --quiet probe tcp cache.example.internal:6379 >> /var/log/packetsonde/deps.log 2>&1
*/5 * * * * svc-user packetsonde --auto-append --quiet audit http https://api.partner.example.com/health >> /var/log/packetsonde/deps.log 2>&1
```

Findings end up in `~/.local/state/packetsonde/findings-YYYY-MM-DD.jsonl`. Pipe to your collector with `vector`, `filebeat`, or similar.

Add `--fail-on severity>=high` to the cron commands if you want non-zero exit codes from cron when something serious happens (cron will email the failure depending on `MAILTO`).

### Flavor B — Agent + scheduled audits

If you want continuous passive observation (flow tracking, neighbor discovery, listeners for things the service host *receives*) alongside the active dependency checks, install `packetsonded`. The cron above stays; the agent adds its own observation stream.

```bash
sudo apt install packetsonded  # or build + install from source
sudo systemctl enable --now packetsonded
```

The agent runs continuously, writes its own findings to its socket and (depending on config) to its own JSONL file. The CLI's audits still go through stdout / `--auto-append` as in flavor A.

## What to audit

Concretely, list out every documented dependency for the service and choose the right verb per type:

| Dependency type | Verb | Notes |
|---|---|---|
| TLS-fronted DB / cache / message bus | `audit tls host:port` | Catches cert expiry, weak ciphers, hostname mismatch |
| HTTPS API | `audit http https://...` | Adds HTTP security-header check on top of the TLS audit |
| DNS resolver the host uses | `audit dns 10.0.0.53` | Detects open-recursion misconfig, version disclosure |
| SSH / management plane | `audit ssh host` | Banner + version |
| Anything else listening on a port | `probe tcp host:port` | Connect + banner |
| Path / latency to a peer | `probe traceroute host` | Catches routing changes |

The art is picking the right verb. `audit http` against a database port will fail uselessly; `probe tcp` against a TLS service won't catch certificate problems.

## Collecting and using the findings

Recommended pipeline:

```
service host --auto-append-> /var/log/packetsonde/*.jsonl
            -- vector -->     central JSONL store
            -- alert rule --> "tls.expired_cert on db.example.internal in last 5 min"
```

Vector config snippet:

```toml
[sources.packetsonde_local]
type = "file"
include = ["/var/log/packetsonde/*.jsonl"]
read_from = "beginning"

[transforms.packetsonde_parse]
type = "remap"
inputs = ["packetsonde_local"]
source = "."

[sinks.elastic_packetsonde]
type = "elasticsearch"
inputs = ["packetsonde_parse"]
endpoints = ["https://es.internal:9200"]
mode = "data_stream"
data_stream.type = "logs"
data_stream.dataset = "packetsonde"
```

## What makes this distinct from external monitoring

- The `host` field on every finding is the *service consumer's* hostname. You're answering "what does this host see," not "what does some monitoring host see."
- A failure that depends on the host's specific resolver, route, certificate store, or NAT translation is detectable here and only here.
- The cost is one cron entry (or one daemon) per service host. For a fleet, configuration management owns this; no extra infrastructure to run.

## Anti-patterns

- **Don't audit every dependency from every host.** Pick the consumers that matter, and audit *their* dependencies. Otherwise you're running an N×M scan whose cost grows quadratically.
- **Don't use this as a security tool *against* the dependencies.** It's a reliability + posture tool *for* the consumer. The DBA isn't going to thank you for hammering the production DB with TLS handshakes every minute. Pick a polite rate (`--rate 1`, single-digit pps) and a reasonable interval (5+ minutes).
- **Don't tail the findings file from the same cron.** Pipeline the writes (`--auto-append`) and have a separate process ship the file. Two processes writing to the same file with stdout + tee is a recipe for races.
