#include "../verbs.h"
#include "../audit_loader.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../util/fail_on.h"
#include "audit_module.h"
#include "finding.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Legacy run-function entry points (audits not yet converted to the
 *      pluggable ABI). These will be retired one file at a time as each
 *      audit is rewritten to export ps_audit_<name>_module(). ---- */

int ps_audit_tls_run          (int argc, char **argv, const struct ps_args *opts);
int ps_audit_dns_run          (int argc, char **argv, const struct ps_args *opts);
int ps_audit_http_run         (int argc, char **argv, const struct ps_args *opts);
int ps_audit_ssh_run          (int argc, char **argv, const struct ps_args *opts);
int ps_audit_smb_run          (int argc, char **argv, const struct ps_args *opts);
int ps_audit_ftp_run          (int argc, char **argv, const struct ps_args *opts);
int ps_audit_redis_run        (int argc, char **argv, const struct ps_args *opts);
int ps_audit_ntp_run          (int argc, char **argv, const struct ps_args *opts);
int ps_audit_memcached_run    (int argc, char **argv, const struct ps_args *opts);
int ps_audit_elasticsearch_run(int argc, char **argv, const struct ps_args *opts);
int ps_audit_smtp_run         (int argc, char **argv, const struct ps_args *opts);
int ps_audit_mysql_run        (int argc, char **argv, const struct ps_args *opts);
int ps_audit_postgresql_run   (int argc, char **argv, const struct ps_args *opts);

struct legacy_kind {
    const char *name;
    int (*run)(int argc, char **argv, const struct ps_args *opts);
    const char *summary;
};

static const struct legacy_kind LEGACY_KINDS[] = {
    { "tls",          ps_audit_tls_run,          "Audit TLS server: protocol, cipher, cert hygiene" },
    { "dns",          ps_audit_dns_run,          "Audit DNS resolver: version leak, open recursion" },
    { "http",         ps_audit_http_run,         "Audit HTTP server: security headers, version leaks" },
    { "ssh",          ps_audit_ssh_run,          "Audit SSH server: banner, known-old version" },
    { "smb",          ps_audit_smb_run,          "Audit SMB server: detect SMB1 (EternalBlue surface)" },
    { "ftp",          ps_audit_ftp_run,          "Audit FTP server: anonymous login, plaintext" },
    { "redis",        ps_audit_redis_run,        "Audit Redis: NOAUTH access detection" },
    { "ntp",          ps_audit_ntp_run,          "Audit NTP: monlist amplification, mode-7 leak" },
    { "memcached",    ps_audit_memcached_run,    "Audit Memcached: no-auth exposure" },
    { "elasticsearch",ps_audit_elasticsearch_run,"Audit Elasticsearch: unauthenticated cluster API" },
    { "smtp",         ps_audit_smtp_run,         "Audit SMTP: STARTTLS support, banner, AUTH advertisement" },
    { "mysql",        ps_audit_mysql_run,        "Audit MySQL/MariaDB: version banner, EOL versions" },
    { "postgresql",   ps_audit_postgresql_run,   "Audit PostgreSQL: SSL support" },
    { NULL, NULL, NULL }
};

/* ---- Pluggable-ABI built-ins (statically linked but exposed via the new
 *      ps_audit_module ABI). As legacy_kind entries are converted, they
 *      move here. ---- */

extern const struct ps_audit_module *ps_audit_telnet_module(void);

static const struct ps_audit_module *(*const BUILTIN_MODULES[])(void) = {
    ps_audit_telnet_module,
    NULL
};

/* ---- Shared run-time state held while a single audit run is executing.
 *      Threading: a single run is single-threaded in v1.3; the api->emit
 *      callback writes through the output emitter which is itself mutexed. ---- */

static struct ps_output    *g_run_out;
static atomic_int           g_run_cancel;

static void api_emit(struct ps_finding *f) {
    if (g_run_out) ps_output_emit(g_run_out, f);
}
static int api_cancelled(void) {
    return atomic_load(&g_run_cancel);
}
static const struct ps_audit_api API = { api_emit, api_cancelled };

/* ---- Plugin / module discovery ---- */

static struct ps_audit_loader g_loader;
static int                    g_loader_initialised = 0;

static const struct ps_audit_module *find_module(const char *name) {
    if (!g_loader_initialised) {
        ps_audit_loader_scan(&g_loader);
        g_loader_initialised = 1;
    }
    const struct ps_audit_loaded *L = ps_audit_loader_find(&g_loader, name);
    if (L) return L->module;
    for (size_t i = 0; BUILTIN_MODULES[i]; i++) {
        const struct ps_audit_module *m = BUILTIN_MODULES[i]();
        if (m && strcmp(m->name, name) == 0) return m;
    }
    return NULL;
}

static const struct legacy_kind *find_legacy(const char *name) {
    for (const struct legacy_kind *k = LEGACY_KINDS; k->name; k++) {
        if (strcmp(k->name, name) == 0) return k;
    }
    return NULL;
}

static void audit_usage(void) {
    fprintf(stderr,
        "Usage: packetsonde audit <kind> <target> [args...]\n"
        "\n"
        "Kinds:\n");

    /* Dedup by name. find_module() already prefers plugins over builtins;
     * here we just need to make sure each kind appears once. */
    if (!g_loader_initialised) {
        ps_audit_loader_scan(&g_loader);
        g_loader_initialised = 1;
    }
    const char *seen[64]; size_t nseen = 0;
    /* Plugins discovered via dlopen. */
    for (size_t i = 0; i < g_loader.count; i++) {
        const struct ps_audit_module *m = g_loader.items[i].module;
        fprintf(stderr, "  %-14s %s  (plugin)\n", m->name, m->summary);
        if (nseen < 64) seen[nseen++] = m->name;
    }
    /* Built-in modules using the new ABI. */
    for (size_t i = 0; BUILTIN_MODULES[i]; i++) {
        const struct ps_audit_module *m = BUILTIN_MODULES[i]();
        if (!m) continue;
        int dup = 0;
        for (size_t j = 0; j < nseen; j++) if (strcmp(seen[j], m->name) == 0) { dup = 1; break; }
        if (dup) continue;
        fprintf(stderr, "  %-14s %s\n", m->name, m->summary);
        if (nseen < 64) seen[nseen++] = m->name;
    }
    /* Legacy run-function audits not yet converted. */
    for (const struct legacy_kind *k = LEGACY_KINDS; k->name; k++) {
        int dup = 0;
        for (size_t j = 0; j < nseen; j++) if (strcmp(seen[j], k->name) == 0) { dup = 1; break; }
        if (dup) continue;
        fprintf(stderr, "  %-14s %s\n", k->name, k->summary);
        if (nseen < 64) seen[nseen++] = k->name;
    }
}

/* Set up output state once, run the audit, snapshot counts at the end. */
static int run_with_output(const struct ps_args *opts,
                           int (*runner)(const struct ps_args *)) {
    struct ps_output_opts oopts; memset(&oopts, 0, sizeof(oopts));
    switch (opts->fmt) {
        case PS_FMT_TEXT:  oopts.fmt_force = PS_OFMT_TEXT;  break;
        case PS_FMT_JSON:  oopts.fmt_force = PS_OFMT_JSON;  break;
        case PS_FMT_JSONL: oopts.fmt_force = PS_OFMT_JSONL; break;
        case PS_FMT_QUIET: oopts.fmt_force = PS_OFMT_QUIET; break;
        default:           oopts.fmt_force = 0;             break;
    }
    oopts.color = opts->no_color ? 0 : 1;
    struct ps_output out;
    ps_output_init(&out, &oopts);
    g_run_out = &out;
    atomic_store(&g_run_cancel, 0);
    int rc = runner(opts);
    ps_output_snapshot(&out, &g_last_run_counts);
    g_run_out = NULL;
    ps_output_close(&out);
    return rc;
}

/* Trampoline used when dispatching a pluggable module via run_with_output. */
struct trampoline_ctx {
    int                         argc;
    char                      **argv;
    const struct ps_audit_module *m;
};
static struct trampoline_ctx g_trampoline;

static int trampoline_runner(const struct ps_args *opts) {
    return g_trampoline.m->run(g_trampoline.argc, g_trampoline.argv, opts, &API);
}

int ps_verb_audit_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { audit_usage(); return 2; }
    const char *kind = argv[1];

    /* Pluggable modules win first (lets a user-supplied .so override a
     * built-in by sharing its name). */
    const struct ps_audit_module *m = find_module(kind);
    if (m) {
        g_trampoline.argc = argc - 1;
        g_trampoline.argv = argv + 1;
        g_trampoline.m    = m;
        return run_with_output(opts, trampoline_runner);
    }

    /* Fall through to legacy run-function dispatch. Each legacy kind still
     * owns its own ps_output setup until it is converted to the new ABI. */
    const struct legacy_kind *L = find_legacy(kind);
    if (L) return L->run(argc - 1, argv + 1, opts);

    fprintf(stderr, "packetsonde audit: unknown kind '%s'\n", kind);
    audit_usage();
    return 2;
}
