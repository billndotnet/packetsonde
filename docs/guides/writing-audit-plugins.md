# Writing audit plugins

The `audit` verb is pluggable. Each audit kind is one C file that exports a `struct ps_audit_module`, compiles to a `.so` (Linux) / `.dylib` (macOS), and gets discovered by the CLI's loader at runtime. The built-in kinds (`tls`, `dns`, `http`, ...) are themselves built this way; the CLI also statically links them so a fresh install needs no setup. Adding your own kind doesn't require recompiling `packetsonde`.

## What you write

A single source file. Three parts:

```c
#include "audit_module.h"
#include "finding.h"
#include "ulid.h"

struct ps_args;  /* opaque; you do not need its layout */

/* Your audit. Called by the dispatcher with argv positioned at the kind's
 * own arguments (argv[0] = kind name; argv[1] = first user argument). The
 * api struct gives you emit + cancellation callbacks. */
static int my_run(int argc, char **argv,
                  const struct ps_args *opts,
                  const struct ps_audit_api *api) {
    /* ... probe, build a struct ps_finding, call api->emit(&f) ... */
    return 0;
}

/* Static registration record. */
static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "mything",
    .summary     = "What this audit does, one line",
    .run         = my_run,
};

/* The single symbol the loader dlsyms. */
const struct ps_audit_module *ps_audit_module(void) {
    return &MODULE;
}
```

That's the whole interface. Anything else you need (parsing target specs, formatting evidence, opening sockets) is up to you. The `finding.h` and `ulid.h` helpers from `libpacketsonde` give you the wire-format types.

## What the dispatcher does for you

You **do not** set up the output emitter. You **do not** parse `--json`/`--jsonl`/`--auto-append`/`--no-color`. You **do not** snapshot finding counts for `--fail-on`. The dispatcher handles all of that once per audit run, then calls into your `run`. You build findings and hand them to `api->emit(&f)`. Everything else is the CLI's job.

This is the load-bearing benefit of the plugin ABI: a custom audit is ~50 lines of focused probe code, not 250 lines of framework boilerplate.

## Emitting findings

A `struct ps_finding` is the wire format documented in the design spec §3. The library helpers:

```c
char run_id[PS_ULID_STRLEN + 1];
ps_ulid_new(run_id, sizeof(run_id));

struct ps_finding f;
ps_finding_init(&f,
    run_id,                /* groups all findings from this CLI invocation */
    "cli.audit.mything",   /* source: "cli.audit.<your kind>" */
    "host-where-i-ran",    /* host */
    "mything.exposed",     /* kind: dotted lowercase, your namespace */
    PS_SEV_HIGH,           /* info | low | medium | high | critical */
    PS_CONF_CONFIRMED,     /* tentative | firm | confirmed */
    "Short human title");
ps_finding_set_target_ip(&f, "10.0.0.42", 443);
ps_finding_set_evidence_json(&f, "{\"version\":\"1.2.3\"}");

api->emit(&f);
```

`set_evidence_json` takes a caller-supplied JSON object literal that the emitter embeds verbatim under `"evidence":`. You're responsible for it being valid JSON (escape your strings).

## Cancellation

Long-running audits should call `api->cancelled()` between probes. SIGINT in the CLI flips that flag; respect it promptly.

```c
for (size_t i = 0; i < n_targets; i++) {
    if (api->cancelled()) break;
    probe_one(targets[i]);
}
```

## Building

```bash
# macOS
clang -shared -fPIC -O2 -DPS_AUDIT_PLUGIN_BUILD=1 \
    -I /path/to/packetsonde/src/lib \
    -L /path/to/packetsonde/build/src/lib -lpacketsonde_lib \
    -undefined dynamic_lookup \
    -o audit-mything.dylib audit-mything.c

# Linux
clang -shared -fPIC -O2 -DPS_AUDIT_PLUGIN_BUILD=1 \
    -I /path/to/packetsonde/src/lib \
    -L /path/to/packetsonde/build/src/lib -lpacketsonde_lib \
    -o audit-mything.so audit-mything.c
```

The `PS_AUDIT_PLUGIN_BUILD=1` define is what enables the `ps_audit_module()` exported symbol. Without it (the default for the in-tree build) only `ps_audit_<name>_module()` is exported, which is what the static-link path uses.

The filename convention is `audit-<name>.{so,dylib}`. The loader will not scan files that don't match this prefix.

## Installing

```bash
mkdir -p ~/.config/packetsonde/audits
cp audit-mything.dylib ~/.config/packetsonde/audits/
```

Plugins are discovered from (in priority order):

1. `$PS_AUDITS_DIR` (env override; if set, no other paths are searched)
2. `$XDG_CONFIG_HOME/packetsonde/audits` (or `~/.config/packetsonde/audits` if XDG isn't set)
3. `$PS_BUILD_DIR/src/cli/audit` (for in-tree development; matches the CMake plugin output directory)
4. `/usr/local/lib/packetsonde/audits`
5. `/usr/lib/packetsonde/audits`

If a plugin's `name` matches a built-in audit kind, the plugin wins. This lets you shadow a built-in with your own version (e.g., a more-thorough `audit tls` for a specific engagement) without recompiling.

## Debugging

Set `PS_AUDIT_DEBUG=1` to make `dlopen` failures verbose:

```bash
PS_AUDIT_DEBUG=1 PS_AUDITS_DIR=./build packetsonde audit
```

Otherwise loader failures are silent — `packetsonde audit` will simply not list your plugin.

## A complete example

See `examples/audit-plugin/audit-vnc.c` in the repo for a fully working ~100-line plugin that detects exposed VNC servers via the RFB banner. The `build.sh` next to it compiles it on macOS or Linux.

## ABI stability

The plugin ABI is versioned via `PS_AUDIT_ABI_VERSION` in `audit_module.h`. v1 is the first stable contract. Future incompatible changes (struct layout, callback signatures) will bump the major version; the loader checks the version field and silently skips plugins built against a different ABI.

Bumps to `libpacketsonde` that don't change the audit ABI (new helper functions, expanded `ps_finding` fields) don't invalidate existing plugins. Bumps that do will require a rebuild; the CLI will tell you which plugins were rejected via the debug flag.
