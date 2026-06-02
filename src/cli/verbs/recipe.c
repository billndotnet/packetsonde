/*
 * `packetsonde recipe` verb.
 *
 * In v1 only `recipe run` is implemented; build / sign / verify / info /
 * push land in step #4 of the recipe framework roadmap (spec §14).
 */

#include "../args.h"

#include <stdio.h>
#include <string.h>

int ps_recipe_runner_main(int argc, char **argv, const struct ps_args *opts);

static void usage(void) {
    fprintf(stderr,
        "Usage: packetsonde recipe <subcommand> [args...]\n"
        "\n"
        "Subcommands:\n"
        "  run     Run a recipe (signed or raw) against one or more targets\n"
        "  build   YAML -> canonical JSON                            (NYI: step #4)\n"
        "  sign    Wrap canonical JSON in a signed envelope          (NYI: step #4)\n"
        "  verify  Verify a signed envelope                          (NYI: step #4)\n"
        "  info    Human-readable summary of a recipe / envelope     (NYI: step #4)\n"
        "  push    Run a recipe against an agent via --via           (NYI: step #5)\n");
}

int ps_verb_recipe_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
        usage();
        return argc < 2 ? 2 : 0;
    }
    const char *sub = argv[1];
    if (!strcmp(sub, "run")) {
        return ps_recipe_runner_main(argc - 1, argv + 1, opts);
    }
    if (!strcmp(sub, "build") || !strcmp(sub, "sign")
     || !strcmp(sub, "verify") || !strcmp(sub, "info")
     || !strcmp(sub, "push")) {
        fprintf(stderr, "packetsonde recipe %s: not yet implemented\n", sub);
        return 2;
    }
    fprintf(stderr, "packetsonde recipe: unknown subcommand '%s'\n", sub);
    usage();
    return 2;
}
