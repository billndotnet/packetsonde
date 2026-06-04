# Deploying packetsonde with SaltStack (example)

A reference salt state for installing + enrolling the `packetsonded` agent across a
fleet. Environment-specific values (central URL, per-node addresses) live in **your**
pillar, not here — this is a sanitized example.

## Layout

```
packetsonde/
  init.sls                 # the state: user, binaries, systemd unit, config, enroll, service
  packetsonded.toml.jinja  # config template (pillar-driven [central]/[agent_listen]/[discovery])
  packetsonded.service     # systemd unit (grants CAP_NET_RAW/CAP_NET_ADMIN via AmbientCapabilities)
pillar.example.sls         # copy into your pillar tree + adjust
```

## Binaries

The state installs from the salt fileserver (`salt://packetsonde/bin/...`) — no package
repo required. Stage the built agent binaries into your fileserver before applying:

```
salt://packetsonde/bin/packetsonded        # the daemon
salt://packetsonde/bin/packetsonde-priv     # the privileged raw-socket worker (forked by the daemon)
salt://packetsonde/bin/packetsonde           # the CLI
```

(Build them per the top-level README; copy into `<file_root>/packetsonde/bin/`. For a
production install, build a `.deb` from `src/agent/debian/` and switch the state to
`pkg.installed` instead.)

**Bump the build version on every push.** `file.managed` deploys by source hash, so an
unchanged `packetsonde version` string makes it impossible to confirm a host actually
took the new binary. Bump the patch value (`docs/build.md` § Build version) before you
restage, and verify it per host after applying (see *Verify* below). Keep the previous
staging as a sibling backup dir (`bin.bak-<version>-<date>`) for a fast rollback.

## Privilege model

The daemon forks `packetsonde-priv`, which holds the raw sockets. The systemd unit grants
`CAP_NET_RAW CAP_NET_ADMIN` via `AmbientCapabilities`, so the forked worker inherits them —
no `setcap` needed. The main daemon runs as the unprivileged `packetsonded` user.

## Listen modes

- **persistent** — always-on mTLS listener on `agent_listen_port`, for `audit --via` and
  relay ingest.
- **knock** — no idle listener; a signed broadcast knock (caught by the passive discovery
  listener) opens an ephemeral session window. Stealth; requires `discovery_enabled`.
- **both** — both paths.

Set per-node via pillar (see `pillar.example.sls`).

## Apply

`state.apply` needs **root on the master** (it reads the master keys/logs), so dispatch
with `sudo`:

```bash
# pillar top.sls:   '*': [ roles.packetsonde ]   (+ per-node knock overrides)
# states top.sls:   '*': [ packetsonde ]
sudo salt '<minion>' state.apply packetsonde
```

The state is idempotent: on a re-apply it only `changed`s the binaries (when the staged
hash differs) and bounces the service. The agent is **passive** — restarting it does not
disturb the host's primary role (ES, HAProxy, etc.), so a re-apply is low-risk.

### Staged rollout

Don't apply to the whole fleet at once. Stage it:

1. **Canary** — one standalone host. Apply, verify, watch.
2. **Subset** — one member of each HA pair (never both members of a pair in the same
   wave, even though the agent is passive — keeps the rollout honest).
3. **Rest** — the remaining hosts, including the second pair members.

Confirm which minions are actually connected before each wave:

```bash
sudo salt-run manage.up
```

### Verify

After each wave, confirm the service is up **and** running the version you just staged:

```bash
sudo salt -L '<hosts>' cmd.run '/usr/local/bin/packetsonde version; systemctl is-active packetsonded'
```

Every host should report the patch version you pushed and `active`. A host still showing
the old version did not take the binary — investigate before proceeding.

Enrollment lands a `pending` agent at central; an operator validates it (the trust gate)
before its events are accepted. See `docs/specs/central-protocol-v1.md` for the wire
contract.
