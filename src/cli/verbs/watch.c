#include "../verbs.h"
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#define PS_WATCH_LINE_MAX 16384

/* Read the agent's activity JSONL sink (set via [detect] sink or PS_DETECT_SINK),
 * optionally filtering by --path/--comm.
 * Without --follow: one-shot dump to EOF then exit 0.
 * With --follow/-f: after reaching EOF, keep polling for new lines (tail -f style). */
int ps_verb_watch_run(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    const char *src = "/var/lib/kernelsonde/activity.jsonl";
    const char *path_filter = NULL, *comm_filter = NULL;
    int follow = 0;
    static struct option lo[] = {
        {"source", required_argument, 0, 's'},
        {"path",   required_argument, 0, 'p'},
        {"comm",   required_argument, 0, 'c'},
        {"follow", no_argument,       0, 'f'},
        {0, 0, 0, 0}
    };
    optind = 1; int o;
    while ((o = getopt_long(argc, argv, "s:p:c:f", lo, NULL)) != -1) {
        if (o == 's') src = optarg;
        else if (o == 'p') path_filter = optarg;
        else if (o == 'c') comm_filter = optarg;
        else if (o == 'f') follow = 1;
    }
    FILE *f = fopen(src, "r");
    if (!f) { fprintf(stderr, "watch: cannot open %s (is [detect] sink configured?)\n", src); return 1; }
    char line[PS_WATCH_LINE_MAX];
    for (;;) {
        while (fgets(line, sizeof line, f)) {
            if (path_filter && !strstr(line, path_filter)) continue;
            if (comm_filter && !strstr(line, comm_filter)) continue;
            fputs(line, stdout);
            fflush(stdout);
        }
        if (!follow) break;
        clearerr(f);
        usleep(200000);
    }
    fclose(f);
    return 0;
}
