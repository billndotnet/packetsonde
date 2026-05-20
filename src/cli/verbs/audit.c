#include "../verbs.h"

#include <stdio.h>
#include <string.h>

int ps_audit_tls_run (int argc, char **argv, const struct ps_args *opts);
int ps_audit_dns_run (int argc, char **argv, const struct ps_args *opts);
int ps_audit_http_run(int argc, char **argv, const struct ps_args *opts);
int ps_audit_ssh_run (int argc, char **argv, const struct ps_args *opts);
int ps_audit_smb_run (int argc, char **argv, const struct ps_args *opts);

struct audit_kind {
    const char *name;
    int (*run)(int argc, char **argv, const struct ps_args *opts);
    const char *summary;
};

static const struct audit_kind KINDS[] = {
    { "tls",  ps_audit_tls_run,  "Audit TLS server: protocol, cipher, cert hygiene" },
    { "dns",  ps_audit_dns_run,  "Audit DNS resolver: version leak, open recursion" },
    { "http", ps_audit_http_run, "Audit HTTP server: security headers, version leaks" },
    { "ssh",  ps_audit_ssh_run,  "Audit SSH server: banner, known-old version" },
    { "smb",  ps_audit_smb_run,  "Audit SMB server: detect SMB1 (EternalBlue surface)" },
    { NULL, NULL, NULL }
};

static void audit_usage(void) {
    fprintf(stderr,
        "Usage: packetsonde audit <kind> <target> [args...]\n"
        "\n"
        "Kinds:\n");
    for (const struct audit_kind *k = KINDS; k->name; k++) {
        fprintf(stderr, "  %-8s %s\n", k->name, k->summary);
    }
}

int ps_verb_audit_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { audit_usage(); return 2; }
    const char *kind = argv[1];
    for (const struct audit_kind *k = KINDS; k->name; k++) {
        if (strcmp(k->name, kind) == 0) {
            return k->run(argc - 1, argv + 1, opts);
        }
    }
    fprintf(stderr, "packetsonde audit: unknown kind '%s'\n", kind);
    audit_usage();
    return 2;
}
