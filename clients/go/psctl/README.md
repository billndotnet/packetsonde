# psctl (Go)

A small, cross-platform CLI client for the packetsonde agent's **mTLS TCP IPC
listener** — the channel/payload protocol, run inside a TLS 1.3 tunnel. Unlike
the C `psctl` (Unix socket only), this builds to a single static binary for
Linux/macOS/**Windows**, so a UI or operator on Windows can drive an agent
running in WSL or on the LAN over a certificate-authenticated connection.

## Build

```sh
go build -o psctl .                          # host
GOOS=windows GOARCH=amd64 go build -o psctl.exe .
GOOS=darwin  GOARCH=arm64 go build -o psctl-macos .
```

Stdlib only — no module dependencies.

## Identity & trust

Identity is an Ed25519 keypair in the agent keystore's raw format (32-byte seed
in `<name>.sec`, 32-byte pubkey in `<name>.pub`). `psctl` presents a self-signed
cert carrying that key; the agent authorizes it by matching the pubkey
fingerprint against its `authorized/` dir. `psctl` can pin the agent in turn
with `--agent-fpr`.

```sh
# 1. create a client identity
psctl gen-key client                 # -> client.sec, client.pub, prints fingerprint

# 2. authorize it on the agent host
cp client.pub <PS_KEY_DIR>/authorized/

# 3. agent must run with mTLS TCP enabled, e.g.
#    [network] listen="0.0.0.0:4701"  tls="1"   (or PS_NETWORK_LISTEN / PS_NETWORK_TLS=1)

# 4. talk to it (pin the agent's fingerprint -- get it from `packetsonde key fingerprint agent`)
psctl --host 127.0.0.1 --port 4701 --key client.sec \
      --agent-fpr sha256:<hex> hosts
```

## Verbs

| verb | channel | notes |
|---|---|---|
| `hosts` | `query.hosts` | host table |
| `modules` | `query.modules` | loaded modules |
| `stats` | `query.stats` | aggregate stats |
| `flows` | `query.flows` | active flows |
| `probe <addr> [ports] [proto]` | `probe.request` | default ports=443 proto=tcp |
| `traceroute <dst> [method]` | `traceroute.request` | default method=paris |
| `send <channel> [payload]` | arbitrary | raw frame |
| `listen` | — | print frames the agent pushes (e.g. `discovery.*`) |
| `gen-key <prefix>` | — | create `<prefix>.sec`/`.pub` (no connection) |

Flags: `--host` (127.0.0.1), `--port` (4701), `--key` (`$PS_KEY_DIR/client.sec`),
`--agent-fpr` (pin, recommended), `--timeout` (8s).
