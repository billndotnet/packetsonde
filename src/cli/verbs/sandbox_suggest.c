#include "../verbs.h"
#include "unit_envelope.h"
#include "sandbox_synth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* packetsonde sandbox-suggest <unit> [--state-dir D] [--threshold N] [--reset]
 * Reads <state-dir>/<unit>.json (learn-mode output), synthesizes a systemd
 * sandboxing stanza, prints it. --reset deletes the unit's envelope.
 * Manual, order-independent arg scan (this CLI's getopt does not permute). */
int ps_verb_sandbox_suggest_run(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    const char *dir = "/var/lib/packetsonde/sandbox-learn";
    int threshold = 3, reset = 0;
    const char *unit = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--state-dir") && i + 1 < argc) dir = argv[++i];
        else if (!strcmp(argv[i], "--threshold") && i + 1 < argc) threshold = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--reset")) reset = 1;
        else if (argv[i][0] != '-') unit = argv[i];
    }
    if (!unit) { fprintf(stderr, "usage: packetsonde sandbox-suggest <unit> [--state-dir D] [--threshold N] [--reset]\n"); return 2; }

    char path[512]; snprintf(path, sizeof path, "%s/%s.json", dir, unit);
    if (reset) { remove(path); printf("reset: %s\n", path); return 0; }

    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "sandbox-suggest: no envelope for %s at %s (run with [detect] policy_mode=learn)\n", unit, path); return 1; }
    static char json[1 << 16]; size_t n = fread(json, 1, sizeof json - 1, f); fclose(f); json[n] = 0;

    struct ps_unit_envelope e;
    if (ps_envelope_from_json(json, &e) != 0) { fprintf(stderr, "sandbox-suggest: malformed envelope %s\n", path); return 1; }
    static char out[1 << 16];
    if (ps_sandbox_synth(&e, threshold, out, sizeof out) <= 0) { fprintf(stderr, "sandbox-suggest: synth failed\n"); return 1; }
    fputs(out, stdout);
    return 0;
}
