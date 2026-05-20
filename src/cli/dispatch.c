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
    { "help",     ps_verb_help_run,     "Show this help" },
    { NULL, NULL, NULL }
};

const struct ps_verb *ps_verbs_find(const char *name) {
    for (const struct ps_verb *v = VERBS; v->name; v++) {
        if (strcmp(v->name, name) == 0) return v;
    }
    return NULL;
}

int ps_verb_help_run(int argc, char **argv, const struct ps_args *opts) {
    (void)argc; (void)argv; (void)opts;
    printf("Verbs:\n");
    for (const struct ps_verb *v = VERBS; v->name; v++) {
        printf("  %-12s %s\n", v->name, v->summary);
    }
    return 0;
}
