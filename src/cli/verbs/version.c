#include "../verbs.h"

#include <stdio.h>

/* PS_VERSION is injected by CMake (-DPS_VERSION="x.y.z") from the root
 * project version. The sentinel below only shows if this file is built
 * outside the CMake project, which makes that mistake obvious. */
#ifndef PS_VERSION
#define PS_VERSION "0.0.0-dev"
#endif

int ps_verb_version_run(int argc, char **argv, const struct ps_args *opts) {
    (void)argc; (void)argv;
    switch (opts->fmt) {
        case PS_FMT_JSON:
        case PS_FMT_JSONL:
            printf("{\"v\":1,\"tool\":\"packetsonde\",\"version\":\"%s\"}\n", PS_VERSION);
            break;
        case PS_FMT_QUIET:
            printf("packetsonde\t%s\n", PS_VERSION);
            break;
        case PS_FMT_AUTO:
        case PS_FMT_TEXT:
        default:
            printf("packetsonde %s\n", PS_VERSION);
            break;
    }
    return 0;
}
