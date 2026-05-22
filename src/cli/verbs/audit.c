#include "../args.h"
#include "../audit_loader.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../util/fail_on.h"
#include "audit_module.h"
#include "finding.h"
#include "config.h"
#include "central_config.h"
#include "reporter.h"
#include "../cli_config_util.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Built-in audit modules (new ABI; statically linked into the binary).
 *      Each is also built as a loadable .so/.dylib; the loader dedupes by
 *      name, with plugins taking precedence over builtins of the same name. */

extern const struct ps_audit_module *ps_audit_tls_module(void);
extern const struct ps_audit_module *ps_audit_dns_module(void);
extern const struct ps_audit_module *ps_audit_http_module(void);
extern const struct ps_audit_module *ps_audit_ssh_module(void);
extern const struct ps_audit_module *ps_audit_smb_module(void);
extern const struct ps_audit_module *ps_audit_telnet_module(void);
extern const struct ps_audit_module *ps_audit_ftp_module(void);
extern const struct ps_audit_module *ps_audit_redis_module(void);
extern const struct ps_audit_module *ps_audit_ntp_module(void);
extern const struct ps_audit_module *ps_audit_memcached_module(void);
extern const struct ps_audit_module *ps_audit_elasticsearch_module(void);
extern const struct ps_audit_module *ps_audit_smtp_module(void);
extern const struct ps_audit_module *ps_audit_mysql_module(void);
extern const struct ps_audit_module *ps_audit_postgresql_module(void);
extern const struct ps_audit_module *ps_audit_ldap_module(void);
extern const struct ps_audit_module *ps_audit_imap_module(void);
extern const struct ps_audit_module *ps_audit_pop3_module(void);
extern const struct ps_audit_module *ps_audit_snmp_module(void);
extern const struct ps_audit_module *ps_audit_rdp_module(void);
extern const struct ps_audit_module *ps_audit_mssql_module(void);
extern const struct ps_audit_module *ps_audit_kafka_module(void);
extern const struct ps_audit_module *ps_audit_vnc_module(void);
extern const struct ps_audit_module *ps_audit_haproxy_module(void);
extern const struct ps_audit_module *ps_audit_proxmox_module(void);
extern const struct ps_audit_module *ps_audit_nginx_module(void);
extern const struct ps_audit_module *ps_audit_opnsense_module(void);

static const struct ps_audit_module *(*const BUILTIN_MODULES[])(void) = {
    ps_audit_tls_module,
    ps_audit_dns_module,
    ps_audit_http_module,
    ps_audit_ssh_module,
    ps_audit_smb_module,
    ps_audit_telnet_module,
    ps_audit_ftp_module,
    ps_audit_redis_module,
    ps_audit_ntp_module,
    ps_audit_memcached_module,
    ps_audit_elasticsearch_module,
    ps_audit_smtp_module,
    ps_audit_mysql_module,
    ps_audit_postgresql_module,
    ps_audit_ldap_module,
    ps_audit_imap_module,
    ps_audit_pop3_module,
    ps_audit_snmp_module,
    ps_audit_rdp_module,
    ps_audit_mssql_module,
    ps_audit_kafka_module,
    ps_audit_vnc_module,
    ps_audit_haproxy_module,
    ps_audit_proxmox_module,
    ps_audit_nginx_module,
    ps_audit_opnsense_module,
    NULL
};

static struct ps_output *g_run_out;
static atomic_int        g_run_cancel;

/* When --report is set, audit findings are also collected here and POSTed to
 * central /events after the run completes (local audit path only). */
#define PS_REPORT_BUF_MAX 256
static struct ps_finding g_report_buf[PS_REPORT_BUF_MAX];
static size_t g_report_n = 0;
static int g_report_enabled = 0;

static void api_emit(struct ps_finding *f) {
    if (g_run_out) ps_output_emit(g_run_out, f);
    if (g_report_enabled && g_report_n < PS_REPORT_BUF_MAX) g_report_buf[g_report_n++] = *f;
}

/* Build [central] config from packetsonded.toml and POST the collected findings. */
static void report_collected_findings(void) {
    if (g_report_n == 0) { fprintf(stderr, "report: no findings to report\n"); return; }
    struct ps_config cfg;
    if (ps_config_parse_file(&cfg, "/etc/packetsonded/packetsonded.toml") != 0) {
        fprintf(stderr, "report: cannot read /etc/packetsonded/packetsonded.toml\n");
        return;
    }
    char ub_url[512], ub_id[256], ub_ca[512], ub_kd[512];
    struct ps_central_config cc;
    cc.url = ps_cli_unq(ps_config_get(&cfg, "central", "url"), ub_url, sizeof ub_url);
    cc.agent_id = ps_cli_unq(ps_config_get(&cfg, "central", "agent_id"), ub_id, sizeof ub_id);
    cc.deployment_mode = NULL;
    const char *v = ps_config_get(&cfg, "central", "verify");
    cc.verify = (v && strstr(v, "0")) ? 0 : 1;
    cc.ca_cert = ps_cli_unq(ps_config_get(&cfg, "central", "ca_cert"), ub_ca, sizeof ub_ca);
    cc.checkin_seconds = 60;
    cc.key_dir = ps_cli_unq(ps_config_get(&cfg, "keys", "dir"), ub_kd, sizeof ub_kd);

    struct ps_report_result rr = {0};
    if (ps_report_findings(&cc, NULL, g_report_buf, g_report_n, &rr) == 0)
        fprintf(stderr, "reported to central: accepted %d / rejected %d of %d\n",
                rr.accepted, rr.rejected, rr.total);
    else
        fprintf(stderr, "report to central failed (unreachable / not configured)\n");
    ps_config_free(&cfg);
}
static int api_cancelled(void) {
    return atomic_load(&g_run_cancel);
}
static const struct ps_audit_api API = { api_emit, api_cancelled };

static struct ps_audit_loader g_loader;
static int                    g_loader_initialised = 0;

static void ensure_loader(void) {
    if (!g_loader_initialised) {
        ps_audit_loader_scan(&g_loader);
        g_loader_initialised = 1;
    }
}

static const struct ps_audit_module *find_module(const char *name) {
    ensure_loader();
    const struct ps_audit_loaded *L = ps_audit_loader_find(&g_loader, name);
    if (L) return L->module;
    for (size_t i = 0; BUILTIN_MODULES[i]; i++) {
        const struct ps_audit_module *m = BUILTIN_MODULES[i]();
        if (m && strcmp(m->name, name) == 0) return m;
    }
    return NULL;
}

static void audit_usage(void) {
    fprintf(stderr,
        "Usage: packetsonde audit <kind> <target> [args...]\n"
        "\n"
        "Kinds:\n");
    ensure_loader();
    const char *seen[64]; size_t nseen = 0;
    for (size_t i = 0; i < g_loader.count; i++) {
        const struct ps_audit_module *m = g_loader.items[i].module;
        fprintf(stderr, "  %-14s %s  (plugin)\n", m->name, m->summary);
        if (nseen < 64) seen[nseen++] = m->name;
    }
    for (size_t i = 0; BUILTIN_MODULES[i]; i++) {
        const struct ps_audit_module *m = BUILTIN_MODULES[i]();
        if (!m) continue;
        int dup = 0;
        for (size_t j = 0; j < nseen; j++) if (strcmp(seen[j], m->name) == 0) { dup = 1; break; }
        if (dup) continue;
        fprintf(stderr, "  %-14s %s\n", m->name, m->summary);
        if (nseen < 64) seen[nseen++] = m->name;
    }
}

int ps_audit_via_run(int argc, char **argv, const struct ps_args *opts,
                     struct ps_output *out); /* remote/audit_via.c */

int ps_verb_audit_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { audit_usage(); return 2; }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        audit_usage(); return 0;
    }
    const char *kind = argv[1];

    /* --via <agent>: dispatch to a remote agent over mTLS. The local
     * module table is consulted only when --via is absent; the remote
     * side does its own dispatch. */
    if (opts->via && *opts->via) {
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
        int rc = ps_audit_via_run(argc - 1, argv + 1, opts, &out);
        ps_output_snapshot(&out, &g_last_run_counts);
        ps_output_close(&out);
        return rc;
    }

    const struct ps_audit_module *m = find_module(kind);
    if (!m) {
        fprintf(stderr, "packetsonde audit: unknown kind '%s'\n", kind);
        audit_usage();
        return 2;
    }

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
    g_report_enabled = opts->report ? 1 : 0;
    g_report_n = 0;

    int rc = m->run(argc - 1, argv + 1, opts, &API);

    ps_output_snapshot(&out, &g_last_run_counts);
    g_run_out = NULL;
    ps_output_close(&out);
    if (opts->report) report_collected_findings();
    g_report_enabled = 0;
    return rc;
}
