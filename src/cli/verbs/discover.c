#include "../verbs.h"

#include <stdio.h>
#include <string.h>

int ps_discover_neighbors_run(int argc, char **argv, const struct ps_args *opts);
int ps_discover_hosts_run    (int argc, char **argv, const struct ps_args *opts);
int ps_discover_agents_run   (int argc, char **argv, const struct ps_args *opts);

struct discover_kind {
    const char *name;
    int (*run)(int argc, char **argv, const struct ps_args *opts);
    const char *summary;
};

static const struct discover_kind KINDS[] = {
    { "neighbors", ps_discover_neighbors_run, "Local ARP/NDP table" },
    { "hosts",     ps_discover_hosts_run,     "ARP-sweep / connect-sweep a CIDR" },
    { "agents",    ps_discover_agents_run,    "Signed broadcast for remote packetsonde agents" },
    { NULL, NULL, NULL }
};

static void usage(void) {
    fprintf(stderr, "Usage: packetsonde discover <kind> [args...]\n\nKinds:\n");
    for (const struct discover_kind *k = KINDS; k->name; k++)
        fprintf(stderr, "  %-10s %s\n", k->name, k->summary);
}

int ps_verb_discover_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }
    for (const struct discover_kind *k = KINDS; k->name; k++) {
        if (strcmp(k->name, argv[1]) == 0) return k->run(argc - 1, argv + 1, opts);
    }
    fprintf(stderr, "discover: unknown kind '%s'\n", argv[1]);
    usage();
    return 2;
}
