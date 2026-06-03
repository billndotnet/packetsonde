#include "../verbs.h"
#include <stdio.h>
#include <string.h>
#include <getopt.h>

#define PS_WATCH_LINE_MAX 16384

/* Tail the agent's activity JSONL sink, optionally filtering by --path/--comm.
 * Mirrors verbs/findings.c's tailing approach (same JSONL idiom). */
int ps_verb_watch_run(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    const char *src = "/var/lib/packetsonde/activity.jsonl";
    const char *path_filter = NULL, *comm_filter = NULL;
    static struct option lo[] = {
        {"source", required_argument, 0, 's'},
        {"path",   required_argument, 0, 'p'},
        {"comm",   required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };
    optind = 1; int o;
    while ((o = getopt_long(argc, argv, "s:p:c:", lo, NULL)) != -1) {
        if (o == 's') src = optarg;
        else if (o == 'p') path_filter = optarg;
        else if (o == 'c') comm_filter = optarg;
    }
    FILE *f = fopen(src, "r");
    if (!f) { fprintf(stderr, "watch: cannot open %s (is [detect] enabled?)\n", src); return 1; }
    char line[PS_WATCH_LINE_MAX];
    while (fgets(line, sizeof line, f)) {
        if (path_filter && !strstr(line, path_filter)) continue;
        if (comm_filter && !strstr(line, comm_filter)) continue;
        fputs(line, stdout);
    }
    fclose(f);
    return 0;
}
