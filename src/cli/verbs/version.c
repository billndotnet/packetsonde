#include "../verbs.h"

#include <stdio.h>

#ifndef PS_VERSION
#define PS_VERSION "0.1.0"
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
