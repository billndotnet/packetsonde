#include "../verbs.h"
#include "../registry/agents.h"

#include <stdio.h>
#include <string.h>

static void usage(void) {
    fprintf(stderr,
        "Usage:\n"
        "  packetsonde config show\n"
        "  packetsonde config path\n");
}

int ps_verb_config_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }
    const char *sub = argv[1];

    const char *agents_path = opts->config_path ? opts->config_path
                                                 : ps_agents_default_path();
    if (strcmp(sub, "path") == 0) {
        printf("%s\n", agents_path);
        return 0;
    }
    if (strcmp(sub, "show") == 0) {
        printf("agents_config: %s\n", agents_path);
        struct ps_agents A;
        ps_agents_load(&A, agents_path);
        printf("agents (%zu):\n", A.count);
        for (size_t i = 0; i < A.count; i++) {
            const struct ps_agent *a = &A.items[i];
            printf("  - name: %s\n", a->name);
            printf("    address: %s\n", a->address);
            if (a->key_fingerprint[0]) printf("    key_fingerprint: %s\n", a->key_fingerprint);
            if (a->tags[0])            printf("    tags: %s\n",            a->tags);
        }
        ps_agents_destroy(&A);
        return 0;
    }
    usage();
    return 2;
}
