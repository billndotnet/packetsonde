#include "../verbs.h"
#include "../findings_util/reader.h"
#include "../findings_util/filter.h"
#include "../output/output.h"
#include "finding.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(void) {
    fprintf(stderr,
        "Usage:\n"
        "  packetsonde findings tail   [path]\n"
        "  packetsonde findings filter <expr> [path]\n"
        "\n"
        "<expr>: kind=name | kind~prefix | severity>=level | source=name | target=ip[:port]\n"
        "If path is omitted, reads from stdin.\n");
}

static int do_loop(FILE *in, struct ps_finding_filter *F, const struct ps_args *opts) {
    char line[16384];
    while (fgets(line, sizeof(line), in)) {
        size_t L = strlen(line);
        if (L && line[L-1] == '\n') line[L-1] = '\0';
        if (!line[0]) continue;

        struct ps_finding_lite lite;
        if (ps_finding_parse_line(line, &lite) != 0) continue;
        if (F && !ps_filter_eval(F, &lite)) continue;

        int is_tty = isatty(1);
        int want_text = (opts->fmt == PS_FMT_TEXT) ||
                        (opts->fmt == 0 && is_tty);
        if (want_text) {
            const char *sev = ps_severity_str(lite.severity);
            printf("%-8s  %-24s  %-32s  %s\n",
                   sev, lite.kind, lite.target[0] ? lite.target : "-", lite.title);
        } else {
            printf("%s\n", line);
        }
    }
    return 0;
}

int ps_verb_findings_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }
    const char *sub = argv[1];
    const char *expr = NULL;
    const char *path = NULL;
    int rc = 0;

    if (strcmp(sub, "tail") == 0) {
        if (argc >= 3) path = argv[2];
    } else if (strcmp(sub, "filter") == 0) {
        if (argc < 3) { usage(); return 2; }
        expr = argv[2];
        if (argc >= 4) path = argv[3];
    } else {
        usage();
        return 2;
    }

    struct ps_finding_filter F;
    struct ps_finding_filter *Fp = NULL;
    if (expr) {
        if (ps_filter_parse(expr, &F) != 0) {
            fprintf(stderr, "findings filter: bad expression '%s'\n", expr);
            return 2;
        }
        Fp = &F;
    }

    FILE *in = stdin;
    if (path) {
        in = fopen(path, "r");
        if (!in) { perror(path); return 1; }
    }

    rc = do_loop(in, Fp, opts);

    if (path) fclose(in);
    if (Fp) ps_filter_destroy(Fp);
    return rc;
}
