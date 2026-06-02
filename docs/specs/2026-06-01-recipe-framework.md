# Recipe Framework — Design Spec

**Date:** 2026-06-01
**Status:** Draft, pending review
**Targets:** v1.7

**References:**
- `~/packetsonde-brainstorms/recipe-framework-brainstorm.md` (decision rationale)
- `docs/specs/2026-05-18-packetsonde-cli-design.md` §8 follow-on #11
- `src/lib/agent_{proto,transport}.{h,c}` (v1.6 `--via` channel — the transport recipes ride on)

---

## 1. Scope

Recipes are **signed, declarative audit definitions** that travel JIT from the auditor's CLI to a remote agent, execute once against a target list, and leave nothing dangerous at rest on the agent. The agent stays a primitive runner (TCP/UDP I/O, regex match, finding emit) plus a signature verifier; everything offensive is pushed at run time.

**v1 covers:** banner-grab style audits — connect, read, match, emit. This is enough to port the small/medium audit modules (`vnc`, `redis`, `memcached`, `ntp`, `telnet`, `ftp`, `pop3`, `imap`, `mysql`-handshake, `postgres`-startup) into recipes.

**v1 does NOT cover:**
- TLS-aware recipes (no `tls_upgrade` opcode in v1; deferred to v2 when JA3/JA4 surfacing is generalized into the engine).
- HTTP-aware recipes (deferred; full HTTP semantics is its own opcode family).
- Composition / includes / persistent state / `goto`. (See §10.)

---

## 2. Lifecycle

```
author.yaml ──build──> author.json ──sign──> author.signed.json
                                                   │
                                  push ────────────┘
                                   │
            CLI ────agent_proto────▶ agent
                                       │
                              fork: packetsonde recipe run author.signed.json
                                       │
                                       ▼
                                findings ───stream───▶ CLI ───▶ stdout
```

Every step is a separate CLI subcommand (§7); each step's output is a regular file on disk. There is no implicit state between steps.

---

## 3. Recipe wire format

Recipes are **JSON on the wire**. Authors write YAML; `packetsonde recipe build` produces canonical JSON. The agent only ever sees JSON. One parser to harden, nicer authoring story.

### 3.1 Canonical JSON

```json
{
  "schema": 1,
  "name": "vnc",
  "version": 1,
  "description": "VNC server reachability and RFB version disclosure",
  "kind_prefix": "vnc",
  "default_port": 5900,
  "budgets": {
    "max_steps":         200,
    "max_recv_bytes":    65536,
    "max_targets":       1024,
    "max_wallclock_ms":  30000
  },
  "steps": [ /* see §5 */ ]
}
```

Canonical = UTF-8, no leading BOM, sorted object keys, no insignificant whitespace, integers (not floats) where the schema says int. `recipe build` emits canonical form; `recipe sign` re-canonicalizes before hashing to defend against author-side serialization drift.

### 3.2 YAML authoring form

Same shape, indentation in place of braces, with two affordances:

- Hex literals: `bytes: !hex "0102ff"` → base16-decoded at build time.
- Block scalars for multi-line literal sends.

Build-time validation rejects anything the canonical form can't express.

---

## 4. Binding types (closing brainstorm Q2)

Every binding produced by a step has a declared static type. The author cannot mix types implicitly; `emit` cross-checks against the finding-schema field types and rejects mismatches at **build** time, not run time.

| Type     | Source opcodes                       | Used by                |
|----------|--------------------------------------|------------------------|
| `conn`   | `connect_tcp`, `connect_udp`         | `send`, `recv`, `close`|
| `bytes`  | `recv`                               | `match`, `emit`        |
| `string` | `match` (named capture)              | `emit`, templates      |
| `int`    | `match` with `as: int`, `$target.port` | `emit`, conditions   |
| `bool`   | `if` results, presence checks        | conditions, `emit`     |

References are written `$name` (binding name) or `$target.host` / `$target.port` for the dispatch-supplied target. References inside string templates expand at run time; references inside typed `emit` evidence fields are resolved by type — `"port": "$target.port"` emits an integer `5900`, not the string `"5900"`.

A reference to a binding that hasn't been produced is a **build-time** error.

---

## 5. Opcode table (v1, frozen)

| Op            | Required inputs                                                       | Produces                       | Notes                             |
|---------------|-----------------------------------------------------------------------|--------------------------------|-----------------------------------|
| `connect_tcp` | `host: string`, `port: int`, `timeout_ms: int`                        | `conn`                         |                                   |
| `connect_udp` | `host: string`, `port: int`, `timeout_ms: int`                        | `conn`                         |                                   |
| `send`        | `conn`, `bytes: bytes|string` (literal or template)                    | —                              |                                   |
| `recv`        | `conn`, `until: newline|n_bytes|regex`, `max_bytes: int`              | `bytes`                        | `max_bytes` ≤ recipe budget       |
| `close`       | `conn`                                                                | —                              |                                   |
| `match`       | `in: bytes|string`, `regex: string`, `captures: [{name, as}]`         | named captures (typed)         | RE2 syntax (no backrefs)          |
| `if`          | `cond: { equals|exists|matches }`                                     | `bool`; gates `then` substeps  | no `else` in v1 (chain `if`s)     |
| `emit`        | `kind: string`, `severity`, `confidence`, `title: string`, `evidence: object` | finding                | severity/confidence enum-checked  |

**Frozen** means: any new opcode bumps the recipe `schema` integer and is signaled by an agent feature flag in the `hello` frame. v1 agents reject schema > 1.

Notably absent (sandboxing boundary, §8):
- No filesystem ops.
- No `exec` / `fork`.
- No raw sockets.
- No unbounded `loop` or `goto`.
- No PCRE features (no backreferences, no lookaround).

---

## 6. Signed envelope

The signed file is **plain JSON wrapping a base64-encoded canonical recipe**.

```json
{
  "schema": 1,
  "recipe_b64":   "<base64(canonical recipe JSON)>",
  "recipe_sha256":"<hex sha-256 of the canonical recipe bytes>",
  "author_pub":   "<base64 ed25519 pubkey, 32 bytes>",
  "signed_at_ms": 1717000000000,
  "signature":    "<base64 ed25519 sig, 64 bytes>"
}
```

**Signed bytes:** `recipe_sha256_raw (32 bytes) || author_pub_raw (32 bytes) || signed_at_ms (8 bytes big-endian)` = exactly 72 bytes. No JSON canonicalization needed for the signature input — it's fixed-layout.

**Agent verification:**
1. Recompute SHA-256 of `base64decode(recipe_b64)`; must equal `recipe_sha256`.
2. Reassemble the 72-byte signing input; `ed25519_verify(signature, input, author_pub)` must pass.
3. Look up `author_pub` in `authorized` keystore (§6.1); the key must carry the `recipe_author` flag.
4. Look up the **dispatcher's** session key (already authenticated via mTLS, v1.6 transport); it must carry the `recipe_run` flag.
5. Only then is the inner recipe JSON parsed and executed.

`signed_at_ms` is recorded in the per-run log and may be sanity-checked against agent wall clock (drift > 24 h → warning, not rejection). It is not a freshness gate in v1.

### 6.1 Authorization flags

Existing keystore entries grow a `flags` array:

```
key = "ed25519-pubkey-base64"
name = "alice-laptop"
flags = ["audit", "recipe_run", "recipe_author"]
```

| Flag             | Grants                                                |
|------------------|-------------------------------------------------------|
| `audit`          | Existing `--via` audit dispatch (v1.6 behavior)       |
| `recipe_run`     | May dispatch *previously-authored* recipes            |
| `recipe_author`  | Signatures by this key are trusted on inbound recipes |

Same keystore, distinct flags. Operators wanting key separation generate two keypairs and split flags between them.

---

## 7. CLI surface

```
packetsonde recipe build  <foo.yaml> [-o foo.json]
packetsonde recipe sign   <foo.json> --key <name> [-o foo.signed.json]
packetsonde recipe verify <foo.signed.json>
packetsonde recipe info   <foo.signed.json>
packetsonde recipe run    <foo.signed.json> [host:port ...] [--target-file=-]
packetsonde recipe push   <foo.signed.json> --via <agent> [host:port ...]
```

- `run` is the in-process execution path. Both the CLI (local mode) and the agent's dispatch (remote mode) invoke the same `run` codepath via `fork+exec` of `packetsonde recipe run`.
- `push` is just `run` with `--via` plumbing — uploads the envelope over the v1.6 channel and the agent re-execs locally.
- Build/sign/verify/info are file-only; no network.

Existing global flags (`--target-file`, `--rate`, `--format jsonl`, `--via`, `--fail-on`) apply.

---

## 8. Resource budgets

Per recipe, enforced by the engine:

| Budget               | Default | Hard cap (config) |
|----------------------|---------|-------------------|
| `max_steps`          | 200     | 10_000            |
| `max_recv_bytes`     | 65 KiB  | 4 MiB             |
| `max_targets`        | 1024    | 65_536            |
| `max_wallclock_ms`   | 30_000  | 300_000           |

A recipe may *lower* a default in its `budgets` block; it may not raise above the hard cap. Exceeding any budget terminates the recipe with a `recipe.budget_exceeded` finding (severity HIGH, evidence includes which budget) and a non-zero exit on the dispatch.

---

## 9. Findings schema delta

The v:1 findings schema is additive-extensible. Two new optional fields:

| Field              | Type   | When present                                        |
|--------------------|--------|-----------------------------------------------------|
| `recipe_sha256`    | string | Set on every finding emitted by the recipe engine   |
| `recipe_author_fp` | string | SHA-256 of `author_pub`, first 16 hex chars         |

Existing consumers ignore unknown fields, so this is non-breaking. `via_agent` (v1.6) co-exists and is set independently when the recipe ran on a remote agent.

---

## 10. Per-run agent log

Append-only JSONL at `${PS_AGENT_LOG_DIR}/recipes.log`, one record per dispatch:

```json
{ "ts":"2026-06-01T19:33:00Z", "run_id":"01HXY...", "recipe_sha256":"...",
  "recipe_name":"vnc", "author_pub_fp":"...", "dispatcher_pub_fp":"...",
  "target_count":12, "findings_emitted":4, "budget_exhausted":false,
  "wallclock_ms":810 }
```

Rotated under the agent's existing log policy. Auditees own this file; it is sufficient evidence of what was run against their environment without auditor cooperation.

---

## 11. Engine architecture

```
src/lib/recipe.h            opcode enums, recipe struct, public API
src/lib/recipe_parse.c      JSON -> in-memory recipe; build-time validation
src/lib/recipe_verify.c     envelope decode, sha256 recheck, ed25519 verify
src/lib/recipe_engine.c     opcode interpreter; budget bookkeeping; bindings table
src/cli/recipe/runner.c     `recipe run` verb entry; wires engine to ps_audit_api
src/cli/verbs/recipe.c      build / sign / verify / info / push dispatcher
src/agent/network_listener.c  recognise `recipe` frame, fork `packetsonde recipe run`
```

**Crash isolation:** the agent forks `packetsonde recipe run`; engine bugs can't take the listener down. Once the engine has six months of soak, an in-process mode is a transparent optimization with no wire change.

**Test surface:** unit tests for parser + verify + engine all link `packetsonde_lib` and run without networking. A `test_recipe_e2e` drives the runner against `openssl s_server`-style fixtures (per-protocol mock).

---

## 12. v1 exclusions (explicit)

- TLS-aware opcodes. No `tls_upgrade`. Recipes that need TLS run as agent-side built-in audits in v1.
- HTTP. Same.
- Recipe composition / `import`.
- Persistent state / KV.
- Per-step try/catch.
- Conditional `goto`.

Each is a possible v2 line item; none changes v1 wire formats.

---

## 13. Open issues (to resolve before §11 code starts)

1. **YAML parser dependency.** Authoring tool needs YAML→JSON. Options: (a) libyaml (small C, well-trodden); (b) hand-roll the subset we need. Lean: (a) — `build` is offline tooling, dep cost is contained.
2. **Regex engine.** RE2 is the obvious safety pick (linear time, no backrefs). It's C++; pulling it in for one feature is heavy. Alternatives: (a) RE2/C wrapper; (b) `re2c`-style precompilation in `recipe build`; (c) POSIX `regex.h` with a build-time validator that rejects backref syntax. Lean: (c) — boring, in libc, validated at build time so authors can't trip pathological patterns.
3. **`if` chaining vs. `else`.** The brainstorm says no else; chained `if`s solve most cases but force authors to repeat conditions. Cheap addition: `else` substep block. Lean: ship without; revisit after first 5 recipes.

---

## 14. Implementation order (mirrors brainstorm §"Suggested order")

1. **`src/lib/recipe_{parse,verify}.c`** + tests. Engine offline-runnable: load envelope, verify sig, build the in-memory recipe. No networking yet. **One PR.**
2. **`src/lib/recipe_engine.c`** + tests. Add the opcode interpreter against an in-memory I/O mock (no real sockets). **One PR.**
3. **`src/cli/recipe/runner.c`** + `recipe run` verb. Wire the engine to real `audit_common` TCP/UDP and to `ps_audit_api` emit. First real recipes: `vnc`, `redis`. **One PR.**
4. **`src/cli/verbs/recipe.c`** — `build` (YAML→JSON), `sign`, `verify`, `info`, `push`. **One PR.**
5. **Agent integration.** `recipe` frame handler, fork dispatch, per-run log. End-to-end test against the v1.6 listener. **One PR.**

Estimated effort: ~3 weeks for steps 1–5, plus ongoing recipe authoring as exposures arise.
