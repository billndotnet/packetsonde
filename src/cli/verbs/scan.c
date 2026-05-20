#include "../verbs.h"

#include <stdio.h>
#include <string.h>

int ps_scan_ports_run(int argc, char **argv, const struct ps_args *opts);

struct scan_kind {
    const char *name;
    int (*run)(int argc, char **argv, const struct ps_args *opts);
    const char *summary;
};

static const struct scan_kind KINDS[] = {
    { "ports", ps_scan_ports_run, "Connect-scan a target or CIDR" },
    { NULL, NULL, NULL }
};

static void usage(void) {
    fprintf(stderr, "Usage: packetsonde scan <kind> [args...]\n\nKinds:\n");
    for (const struct scan_kind *k = KINDS; k->name; k++)
        fprintf(stderr, "  %-8s %s\n", k->name, k->summary);
}

int ps_verb_scan_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }
    for (const struct scan_kind *k = KINDS; k->name; k++) {
        if (strcmp(k->name, argv[1]) == 0) return k->run(argc - 1, argv + 1, opts);
    }
    fprintf(stderr, "scan: unknown kind '%s'\n", argv[1]);
    usage();
    return 2;
}
