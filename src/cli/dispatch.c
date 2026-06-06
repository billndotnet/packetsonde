#include "verbs.h"

#include <stdio.h>
#include <string.h>

int  ps_verb_version_run (int argc, char **argv, const struct ps_args *opts);
int  ps_verb_agent_run   (int argc, char **argv, const struct ps_args *opts);
int  ps_verb_audit_run   (int argc, char **argv, const struct ps_args *opts);
int  ps_verb_findings_run(int argc, char **argv, const struct ps_args *opts);
int  ps_verb_config_run  (int argc, char **argv, const struct ps_args *opts);
int  ps_verb_probe_run   (int argc, char **argv, const struct ps_args *opts);
int  ps_verb_discover_run(int argc, char **argv, const struct ps_args *opts);
int  ps_verb_scan_run    (int argc, char **argv, const struct ps_args *opts);
int  ps_verb_report_run  (int argc, char **argv, const struct ps_args *opts);
int  ps_verb_key_run     (int argc, char **argv, const struct ps_args *opts);
int  ps_verb_register_run(int argc, char **argv, const struct ps_args *opts);
int  ps_verb_report_central_run(int argc, char **argv, const struct ps_args *opts);
int  ps_verb_collect_run(int argc, char **argv, const struct ps_args *opts);
int  ps_verb_recipe_run  (int argc, char **argv, const struct ps_args *opts);
int  ps_verb_watch_run   (int argc, char **argv, const struct ps_args *opts);
int  ps_verb_sandbox_suggest_run(int argc, char **argv, const struct ps_args *opts);
int  ps_verb_baseline_run(int argc, char **argv, const struct ps_args *opts);
int  ps_verb_inspect_run (int argc, char **argv, const struct ps_args *opts);

static const struct ps_verb VERBS[] = {
    { "version",  ps_verb_version_run,  "Show packetsonde version" },
    { "audit",    ps_verb_audit_run,    "Run a security audit (tls, dns, ...)" },
    { "scan",     ps_verb_scan_run,     "Active scan (ports)" },
    { "discover", ps_verb_discover_run, "Local discovery: neighbors, hosts" },
    { "probe",    ps_verb_probe_run,    "Single-target probe (tcp, traceroute)" },
    { "findings", ps_verb_findings_run, "Tail / filter / stats JSONL finding records" },
    { "report",   ps_verb_report_run,   "Generate Markdown report from JSONL findings" },
    { "config",   ps_verb_config_run,   "Show resolved configuration" },
    { "agent",    ps_verb_agent_run,    "Control / query the local agent" },
    { "key",      ps_verb_key_run,      "Manage Ed25519 keys (generate/list/fingerprint/revoke)" },
    { "register", ps_verb_register_run, "Enroll this host with central management" },
    { "report-central", ps_verb_report_central_run, "Report findings JSONL to central /events" },
    { "collect",  ps_verb_collect_run,  "Receive + present signed findings (no central)" },
    { "recipe",   ps_verb_recipe_run,   "Run / manage signed declarative audit recipes" },
    { "watch",    ps_verb_watch_run,    "Tail process/file/socket activity records (JSONL)" },
    { "inspect",  ps_verb_inspect_run,  "Live process-activity dashboard (profile keyframe/delta stream)" },
    { "sandbox-suggest", ps_verb_sandbox_suggest_run, "Suggest a systemd sandbox stanza from learned activity" },
    { "baseline", ps_verb_baseline_run, "Manage learned per-exe baselines (list/approve/deny)" },
    { "help",     ps_verb_help_run,     "Show this help" },
    { NULL, NULL, NULL }
};

const struct ps_verb *ps_verbs_find(const char *name) {
    for (const struct ps_verb *v = VERBS; v->name; v++) {
        if (strcmp(v->name, name) == 0) return v;
    }
    return NULL;
}

void ps_verbs_print_list(FILE *fp) {
    for (const struct ps_verb *v = VERBS; v->name; v++) {
        fprintf(fp, "  %-10s %s\n", v->name, v->summary);
    }
}

int ps_verb_help_run(int argc, char **argv, const struct ps_args *opts) {
    (void)argc; (void)argv; (void)opts;
    printf("Verbs:\n");
    ps_verbs_print_list(stdout);
    return 0;
}
