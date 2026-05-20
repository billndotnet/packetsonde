# Agent Discovery Brainstorm

Status: design memo, pre-implementation. Companion to
`agent-network-protocol-brainstorm.md`. Discovery answers "where is the
agent on this subnet?" — the network protocol takes over for "how do I
talk to it once I know."

## Goal

From the CLI, with a broadcast packet on a foreign subnet, learn the
agent's listen address without configuring anything ahead of time and
without leaving a fingerprintable listener for an intruder to find.

## Threat model

- **Local LAN intruder:** can sniff broadcast traffic, can scan hosts on
  the segment. Must not be able to:
    - Discover that a `packetsonded` is present unless they hold a key
      authorised by the operator.
    - Replay a captured probe to elicit a reply.
    - Use the agent as a UDP amplifier.
- **Off-LAN adversary:** out of scope; discovery is broadcast and does
  not cross routers.
- **Compromised key:** revocation is administrative (operator updates
  `revoked_pubkeys` in the agent config and pushes via salt/cfengine/
  manual sync). CLI emits the revocation line; propagation is operator
  responsibility.

## Mechanism

The agent does **not** bind a listening port. It already runs with
`cap_net_raw` / BPF capability for its passive modules; discovery rides
on the same libpcap consumer.

- **Probe**: CLI sends a UDP broadcast packet from an ephemeral source
  port to an arbitrary destination port (default randomised, optionally
  pinned to cover ports like 67 / 137 / 5353 to blend with existing
  broadcast traffic).
- **Capture**: agent's pcap consumer applies the filter
  `ether broadcast and udp` plus a 4-byte magic check at a fixed payload
  offset. Cheap fast-path rejection of normal broadcast noise.
- **Validation**: signature check, timestamp window, nonce LRU. Any
  failure path is **silent drop** — bad magic, bad sig, expired ts,
  unknown pubkey, replay, malformed packet, all yield no response and
  no log line at default verbosity. From a port scan the agent is
  indistinguishable from a host that does not exist.
- **Response**: agent crafts a unicast UDP packet via raw socket
  (src = agent v4 + arbitrary port, dst = client's source IP:port from
  the probe). No bound socket on the agent side, ever.
- **Receipt**: CLI reads replies from the same ephemeral socket it
  sent from. The socket is closed when the discovery operation
  completes; nothing persists for a scanner to find on the CLI host
  either.

## Wire format

Both packets are fixed-size, no length prefixes, no TLV. They fit in a
single UDP datagram with no fragmentation risk on any normal MTU.

### Probe (168 B)

```
offset  size  field
0       4     magic            "PSDP"
4       1     version          0x01
5       1     flags            reserved (0)
6       2     max_skew_ms      client-requested timestamp window, BE u16
8       8     timestamp        ms since UTC epoch, BE
16      16    nonce            random, client-generated
32      32    pubkey           Ed25519 caller identity
64      64    signature        Ed25519 over [0..64]
```

### Reply (136 B)

Strictly ≤ probe so the agent can never be used as a UDP amplifier.

```
offset  size  field
0       4     magic            "PSDR"
1       1     version          0x01
5       1     flags
6       2     _pad             0
8       16    nonce            echoed from probe (client correlation)
24      16    listen_ip        IPv6, v4-mapped for v4
40      2     listen_port
42      32    agent_pub        Ed25519 agent identity (pinnable)
74      64    signature        Ed25519 over [0..74] using agent_pub's key
```

## Replay defense

- Reject if `|now - timestamp| > effective_skew` (silent drop)
- `effective_skew = min(probe.max_skew_ms, agent.max_skew_ms_hard_cap)`
- Defaults:
    - CLI probe `max_skew_ms`: **2000** (2 s)
    - Agent hard cap: **30 000** (30 s)
- Nonce LRU keyed by `(pubkey, nonce)`, TTL = `2 × effective_skew`.
  Bounded at 4096 entries; under flood, oldest entries evict (best the
  agent can do without state growing without bound).
- Per-packet cost under flood: one Ed25519 verify (~50 µs on modern
  hardware). Bound flood capacity at signature-verify rate, not memory.

NTP discipline is a prereq. Hosts with bad clocks appear non-responsive
during discovery; that's a useful operator signal, not a bug.

## Stealth properties

- Default state: discovery **disabled** in agent config. Operator opts
  in per-deployment.
- No listening socket means a port scan returns nothing distinguishable
  from a quiet host. There is no service to fingerprint.
- All invalid probes silently dropped; an attacker cannot use timing or
  presence-of-reply to confirm the agent exists.
- No log lines at debug-default for invalid probes — log volume itself
  cannot fingerprint the agent. Valid probes log at info.
- Probe destination port is a cover-traffic choice, not protocol
  semantics. Defaulting to a random ephemeral makes traffic patterns
  look like ad-hoc software; an operator on a noisy LAN may pin it to
  67 / 137 / 5353 / 1900 to blend with existing broadcast noise.

## CLI surface

```
packetsonde key generate [--name NAME]
    Writes Ed25519 keypair to ~/.config/packetsonde/keys/<name>.{pub,sec},
    prints SHA-256 fingerprint of the pubkey.

packetsonde key list
    Lists local keys with fingerprints.

packetsonde key revoke <fingerprint>
    Marks a local key revoked; prints the line(s) the operator should add
    to each agent's discovery.toml revoked_pubkeys field.

packetsonde key fingerprint <pubkey-file>
    Show SHA-256 fingerprint of an arbitrary pubkey file.

packetsonde discover <cidr|broadcast> [-t WAIT] [-k KEY] [--max-skew DUR] [--cover-port N]
    Send signed broadcast probe to every broadcast address in <cidr>
    (or to the literal broadcast 255.255.255.255 if 'broadcast' given).
    Wait WAIT for replies (default 3 s).
    Use KEY (default: first key in ~/.config/packetsonde/keys/).
    --max-skew bumps the replay window for the agent on this probe
       (default 2s; raise for hosts with bad clocks).
    --cover-port pins the probe destination port (default: random).
    Emits one discovery.agent finding per validated reply with
    agent_pub, listen_ip, listen_port in evidence.
```

## Agent configuration

`$XDG_CONFIG_HOME/packetsonded/discovery.toml`:

```toml
[discovery]
enabled = false
max_skew_ms_hard_cap = 30000   # 30 s ceiling, operator-tunable
allowed_pubkeys = [
  "ed25519:<base64>",
]
revoked_pubkeys = []           # explicit revocations; checked first
listen_ip = "auto"             # what to advertise in reply; auto = primary v4
listen_port = 0                # port the agent's main listener is on
```

## CLI registry integration

The `agents.toml` registry on the CLI side gains a `pubkey` field. On a
successful discovery, the CLI offers to add the discovered agent to the
registry with its `agent_pub`. Subsequent `--via <name>` connects pin
against this key — the discovery handshake is also the trust-on-first-
use moment for the agent network protocol.

## Non-goals (explicitly out of scope)

- Multicast support. Broadcast-only by design.
- Cross-subnet relay. Per-segment is the entire point — air-gapped
  discovery for remote office sites is the use case.
- Automated key distribution. The operator pushes pubkeys to agents via
  whatever configuration management they already use.
- Automated revocation propagation. CLI emits the line; operator pushes.
- Beaconing / unsolicited announcements. Strict request-response.

## Implementation plan (sketch — not the plan itself)

1. `src/lib/discovery.h` / `src/lib/discovery.c` — wire format, sign /
   verify helpers, replay LRU. Shared between CLI and agent.
2. `src/lib/keystore.{h,c}` — Ed25519 keypair load/save/fingerprint.
3. `src/cli/verbs/key.c` — `packetsonde key` subcommands.
4. `src/cli/verbs/discover.c` — extend existing `discover` verb with a
   new `agents` subcommand (sibling to `neighbors` and `hosts`).
5. `src/agent/modules/discovery.c` — pcap consumer + reply path.
6. Wire format tests on the lib; round-trip integration test with a
   loopback agent listening on a dummy interface (BPF on Linux,
   pktap/utun on macOS — TBD; may settle for an emit-only smoke test
   if loopback broadcast is too fiddly).

## Open questions

- Loopback testing strategy. macOS doesn't forward broadcast on lo0; we
  may need a unit-tested library with no integration coverage of the
  pcap path. Acceptable if the library is exhaustively tested.
- Whether to support v6 ND-based discovery (parallel knock over ICMPv6
  RS-like packets). Not required for v1; broadcast covers the operator
  story.
- Whether `discover` should accept a list of CIDRs (for ops who want to
  sweep multiple segments from a hub). Probably yes, but trivial to add
  after v1.
