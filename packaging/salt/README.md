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

```bash
# pillar top.sls:   '*': [ roles.packetsonde ]   (+ per-node knock overrides)
# states top.sls:   '*': [ packetsonde ]
salt '<minion>' state.apply packetsonde
```

Enrollment lands a `pending` agent at central; an operator validates it (the trust gate)
before its events are accepted. See `docs/specs/central-protocol-v1.md` for the wire
contract.
