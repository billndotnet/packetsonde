# Agent Network Protocol — Brainstorm Memo

**Status:** Pre-brainstorm draft. Not a spec. A starting point for the dedicated brainstorming session that should precede any implementation.

**Why this exists:** This is the load-bearing follow-on for `--via <agent>`, multi-VLAN trunk audits, the bridge appliance, the dependency test point, and (eventually) the recipe framework. Wrong decisions here cascade through every subsequent layer. Worth designing carefully, in one sitting, with eyes open.

**Reference:** spec `docs/specs/2026-05-18-packetsonde-cli-design.md`, especially §1.1 (deployment models), §2.6 (agent registry), §8 (follow-ons #11 recipe framework — depends on this protocol).

---

## What this protocol must do

1. **Carry CLI requests to a remote agent and findings back.** `packetsonde audit tls X --via trunkbox` should produce the same finding stream as if the audit ran locally — except the `host` field reflects the agent's host, and a `via_agent` field is present.
2. **Be authenticated.** SSH-like trust model is the stated goal: the CLI knows agents by name + key fingerprint; the agent knows authorized CLI keys.
3. **Survive being deployed in adversarial-adjacent positions.** Trunk probe, bridge appliance, handheld with wifi — all face the public side of a customer network. An attacker who pops the wifi shouldn't pivot through the agent.
4. **Carry findings as a live stream**, not a request/response — long-running audits emit findings continuously.
5. **Eventually carry signed recipe plans** (follow-on #11), be auditable as to *what* the CLI asked the agent to do.
6. **Run cleanly on Mac/Linux/(probably FreeBSD)** without a dependency hell.

## What this protocol explicitly should not do

- **Not be a general-purpose RPC.** It's domain-specific. Resist the urge to make it pluggable for non-packetsonde uses.
- **Not require a third-party message bus.** Agents speak it directly. No Kafka/Redis/NATS in the critical path.
- **Not duplicate what the existing local UNIX-socket protocol does.** That stays for `packetsonde agent <subcmd>` against the local agent. The network protocol is its sibling, not its replacement.
- **Not be HTTP.** Tempting (universal tooling), but HTTP introduces a lot of accidental complexity — verbs, status codes, framing variability, gzip negotiation, header parsing surface — for something that's fundamentally a long-running typed message stream.

---

## Question 1: Transport

Options:

a) **TLS over TCP, mTLS** — both sides present certificates, peer pinning via known fingerprints from `agents.toml`. The classic, well-understood choice.

b) **Noise Protocol Framework** (e.g., `Noise_XK`) — modern, simpler to implement correctly than a full TLS stack, baked-in forward secrecy, identity-hiding patterns available. Used by WireGuard, Lightning Network, Signal.

c) **SSH transport (libssh)** — literal SSH. Auth is solved, ProxyJump/MultiHop is solved, port forwarding is solved. But: libssh adds a real dependency and the abstraction (channels, exec, subsystems) doesn't quite fit "stream of typed messages."

d) **WireGuard tunnel + plaintext-on-top** — let WireGuard own crypto + identity, run packetsonde messages over the resulting cleartext-feeling channel. Operationally clean (agents are WG peers, registry is `wg show`). Coupling: requires WG on every agent host.

e) **Raw TCP with explicit handshake + ChaCha20-Poly1305 framing** — roll-your-own crypto-lite using libsodium. Smallest binary, simplest wire format, but crypto-rolling is famously risky.

**My lean:** **(b) Noise (Noise_XK pattern).** It directly matches the SSH-like trust model (long-term static keys, no PKI), is dramatically smaller than OpenSSL to embed (~2-3kloc with libsodium primitives), has identity-hiding properties that suit "agent in a hostile network," and avoids the operational drag of (d) without the crypto-rolling risk of (e). The cost is that operators can't `openssl s_client` into it for debugging — but the CLI is the only client anyway.

**(a) TLS+mTLS** is the safe default if Noise feels unfamiliar. Use OpenSSL, share the dep with `audit tls`. Cost: cert lifecycle (rotation, expiry, revocation) is real ops surface.

**Worth pressure-testing in the brainstorming session:** what's the operator's first-day experience? "Generate a key on the agent, copy fingerprint into agents.toml, done" is the bar. If (a)/(b)/(c) can't all hit that bar, they're not really viable.

---

## Question 2: Identity & authentication

a) **Trust-on-first-use (SSH style)** — first time a CLI connects to a named agent, it captures the agent's public key and writes the fingerprint into `agents.toml`. Subsequent connections require the fingerprint to match. Symmetric: agent does the same for the CLI.

b) **Pre-shared fingerprints** — operator manually puts agent fingerprints in `agents.toml` and CLI fingerprints in agent's `authorized_clients` file. No TOFU. Most secure, most friction.

c) **Pinned CA** — operator runs a tiny CA, signs agent and CLI certs. PKI-style.

d) **Hybrid** — TOFU by default, fingerprints pinned once captured, manual provisioning supported.

**My lean:** **(d) hybrid**. Make pre-shared the easy path for serious deployments, but allow TOFU for the "I'm prototyping on my laptop and the agent's on a raspberry pi I can see" case. SSH-style. Match the deployment models — auditor with a trunk box should provision keys explicitly; auditor with their own bridge appliance can TOFU.

**Open question:** how are CLI keys provisioned? One key per CLI install? Per user? Per engagement? The recipe framework (follow-on #11) will need signatures tied to recipe authors — that pulls toward "per engagement" or "per author" keys.

---

## Question 3: Wire format

a) **Length-prefixed JSON** — `uint32_t length || json_bytes`. Trivial to debug (tcpdump shows readable JSON inside the encrypted tunnel — well, *the agent* would log it, anyway). Matches the existing IPC.

b) **CBOR** — binary JSON-ish. Smaller, slightly faster to parse, still self-describing. Less debuggable.

c) **Protobuf** — schema-first, smallest wire format. But: third-party dep, code-gen toolchain, schema-versioning rituals.

d) **MessagePack** — middle ground between (a) and (b).

**My lean:** **(a) length-prefixed JSON**. The agent's existing IPC uses JSON; reusing the format means the network protocol is a "wrap the existing IPC in a Noise channel" mental model, not "build a new protocol." Wire-format compactness is a non-concern at audit cadence (kbit/s, not Mbit/s).

**Worth deciding in brainstorming:** is the framing the *same* JSON as the local UNIX socket, or different? I'd argue same — keep the message types unified, treat the transport as orthogonal.

---

## Question 4: Session model

a) **Single bidirectional stream** — CLI opens a connection, sends a "run this audit" request, the agent streams findings + log lines back, CLI closes. One connection per run.

b) **Persistent control connection + per-run sub-channels** — like SSH multiplexing. The CLI keeps a long-lived connection to a frequently-used agent; new runs open sub-channels. Lower latency for repeated commands, more complex.

c) **Request/response (HTTP-shaped)** — CLI sends, agent responds with the full result set. Doesn't fit streaming findings.

**My lean:** **(a) single stream per run**. v1 has no need for the multiplexing complexity of (b). The protocol can grow into (b) later if real-world use shows latency mattering — but starting simple is easier than starting complex and discovering the multiplexing was wrong.

---

## Question 5: Server topology — push vs pull

a) **CLI connects to agent** (agent is the server). Agent listens on a port. CLI initiates. Matches SSH.

b) **Agent connects to CLI** (CLI is the server). Reverse — useful when agents are behind NAT. The CLI maintains a "agent inbox" listener.

c) **Both modes supported**, configured per-agent in the registry.

**My lean:** **(a) for v1**. SSH-shaped. If we hit a NAT scenario, the operator runs an SSH reverse-tunnel themselves and points `--via` at the local end. That's a less-elegant answer than (c), but (c) doubles the security surface (now the CLI also needs to authenticate inbound). Defer.

---

## Question 6: Discovery

a) **No discovery — explicit `agents.toml` only.** Operator types names + addresses. v1.
b) **mDNS / Avahi** — agents announce themselves on the local segment.
c) **Discovery server** — central directory.

**My lean:** **(a) for v1**. The trunk-attached agent is configured by the operator anyway. The handheld bridge can be `--via $(hostname).local` if we want zero-config later, but that's (b) and can wait.

---

## Question 7: Privilege model on the remote agent

If `packetsonde audit tls --via trunkbox` produces findings about TLS 1.0, the agent on `trunkbox` did the actual SSL handshake. Does the agent run with arbitrary network capability? Some restrictions?

a) **Agent has full network capability** — it can connect to any host:port the CLI requests. Simplest. Trust the auditor.

b) **Agent enforces an allowlist** — `agents.toml` on the agent side lists CIDRs the agent will probe. CLI requests outside are refused.

c) **CLI signs requests; agent validates against an authorized-purposes policy** — depends on the recipe framework.

**My lean:** **(a) for v1**, but design the message format to support (b)/(c) via fields that the agent can ignore for now and enforce later. The agent's principal is the authenticated CLI; allowing the auditor to do whatever they're audited-to-do is the right baseline.

**This matters for legal/forensic posture though** — an agent in a customer environment that can be told to do anything by anyone with a valid key is a different liability story than one that only does pre-declared work. The recipe framework follow-on is the right place to land (c).

---

## Question 8: Logging & observability of the protocol itself

The agent should log every authenticated control message it receives. Auditors and (later) the auditees both have legitimate interest in "what did the CLI ask this agent to do."

- Log location: agent-local, append-only, ULID-keyed
- Log content: timestamp, CLI key fingerprint, message type, target (sanitized), run_id
- Log rotation: time-based, with retention configurable per-deployment

This isn't a deep design question, just a feature to *not forget* during implementation.

---

## Question 9: Versioning

The protocol will evolve. v1 needs:

- A version byte in the initial handshake.
- A "feature flags" mechanism for incremental capabilities (e.g., "this agent supports recipes" → set bit 0).
- A documented deprecation policy.

Minimum mechanism: handshake exchanges a `{major: 1, minor: 0, features: ["base"]}` JSON object. Both sides take the intersection. Mismatches fail closed.

---

## Question 10: What's NOT in v1 of this protocol

- **Multi-hop / chained `--via`** ("CLI → bunker → trunkbox"). One hop only in v1.
- **Recipe transport.** That's a payload type added later. The protocol carries it once it exists.
- **File transfer.** No `scp`-equivalent. Findings come back as JSONL; pcaps and other large artifacts get a separate dedicated channel later if needed.
- **Agent-initiated push** ("hey CLI, this just happened"). Agent is reactive in v1.

---

## Suggested brainstorming flow

In rough order, the questions a brainstorming session needs to answer before any code:

1. **Transport** (Q1) — pick one. Pressure-test against the operator-first-day scenario.
2. **Identity** (Q2) — settle TOFU vs pinned.
3. **Wire format** (Q3) — pick one, ideally the same as the existing local IPC.
4. **Session model** (Q4) — start simple.
5. Skim Q5–Q10 to confirm the picks above don't accidentally close off important options.

After that, the spec writes itself: a 2-3 page document covering the four key decisions, the protocol state machine, the message types (which are mostly inherited from the existing IPC), the operator onboarding flow, and the v2 design points the protocol must reserve room for.

**Estimated effort once the design lands:** ~3 weeks of implementation (Noise integration + key management + agent listener + CLI `--via` plumbing + integration tests with a real network-attached agent), plus another ~2 weeks for ops hardening (signal handling on long-lived connections, graceful upgrade, log rotation).

---

## One thing to actively decide on, separately

**libsodium vs OpenSSL** for crypto primitives. The CLI already pulls OpenSSL for `audit tls`. Adding libsodium for Noise means two crypto libraries in one binary. Alternatives:

- Use OpenSSL's ChaCha20-Poly1305 + X25519 primitives directly to build a Noise transport (it's possible; OpenSSL 3.x exposes the needed APIs). One crypto dep.
- Use libsodium for everything including TLS (no, libsodium doesn't do TLS).
- Ship two crypto libs (works, but the binary swells and supply-chain surface doubles).

**My lean:** **OpenSSL-only**, using its primitives to implement Noise. Slightly more work upfront, but the agent's `audit tls` work and the network protocol share crypto code, and there's one library to keep patched.

This is itself worth a 15-minute decision during the brainstorming session.
