#ifndef PS_AUDIT_MODULE_H
#define PS_AUDIT_MODULE_H

#include <stdint.h>

/* Forward declarations — plugins should not depend on the CLI's internal
 * struct layouts. They get a vtable. */
struct ps_finding;
struct ps_args;

/* Callbacks the CLI provides to a running audit module. */
struct ps_audit_api {
    /* Emit a finding through the run's output emitter. Thread-safe at the
     * library level; the plugin owns the finding struct passed in. */
    void (*emit)(struct ps_finding *f);

    /* Returns 1 if the run is being cancelled (SIGINT, timeout, etc.).
     * Long-running audits should poll this between probes. */
    int  (*cancelled)(void);
};

/* The plugin's entry point. argv[0] is the audit kind name (e.g. "tls");
 * argv[1..] are the audit's own arguments (target spec, flags). */
typedef int (*ps_audit_run_fn)(int argc, char **argv,
                                const struct ps_args *opts,
                                const struct ps_audit_api *api);

struct ps_audit_module {
    uint32_t          abi_version;   /* must equal PS_AUDIT_ABI_VERSION */
    const char       *name;          /* lowercase, e.g. "tls", "smb"     */
    const char       *summary;       /* one-line description for `audit` help */
    ps_audit_run_fn   run;
};

/* Bump this whenever the struct or callback signatures change. */
#define PS_AUDIT_ABI_VERSION 1u

/* Each plugin must export this symbol. Returning NULL means the module
 * is incompatible (e.g. needs a feature the host doesn't support); the
 * loader will skip it without warning the user. */
const struct ps_audit_module *ps_audit_module(void);

#endif
