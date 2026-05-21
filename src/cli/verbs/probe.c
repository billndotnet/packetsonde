#include "../verbs.h"

#include <stdio.h>
#include <string.h>

int ps_probe_tcp_run       (int argc, char **argv, const struct ps_args *opts);
int ps_probe_icmp_run      (int argc, char **argv, const struct ps_args *opts);
int ps_probe_traceroute_run(int argc, char **argv, const struct ps_args *opts);

struct probe_kind {
    const char *name;
    int (*run)(int argc, char **argv, const struct ps_args *opts);
    const char *summary;
};

static const struct probe_kind KINDS[] = {
    { "tcp",        ps_probe_tcp_run,        "Single TCP connect + banner" },
    { "icmp",       ps_probe_icmp_run,       "ICMP echo reachability check" },
    { "traceroute", ps_probe_traceroute_run, "Multi-mode traceroute"        },
    { NULL, NULL, NULL }
};

static void usage(void) {
    fprintf(stderr, "Usage: packetsonde probe <kind> [args...]\n\nKinds:\n");
    for (const struct probe_kind *k = KINDS; k->name; k++)
        fprintf(stderr, "  %-10s %s\n", k->name, k->summary);
}

int ps_verb_probe_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        usage(); return 0;
    }
    for (const struct probe_kind *k = KINDS; k->name; k++) {
        if (strcmp(k->name, argv[1]) == 0) {
            return k->run(argc - 1, argv + 1, opts);
        }
    }
    fprintf(stderr, "probe: unknown kind '%s'\n", argv[1]);
    usage();
    return 2;
}
