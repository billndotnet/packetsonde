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
        "  packetsonde findings stats  [path]\n"
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

/* -------- stats subcommand -------- */

#define STATS_CAP 256
#define STATS_KEY 128

struct counter {
    char  key[STATS_KEY];
    unsigned long n;
};

struct counters {
    struct counter items[STATS_CAP];
    size_t count;
};

static void counters_bump(struct counters *c, const char *key) {
    if (!key || !*key) key = "(none)";
    for (size_t i = 0; i < c->count; i++) {
        if (strcmp(c->items[i].key, key) == 0) { c->items[i].n++; return; }
    }
    if (c->count >= STATS_CAP) return;  /* drop on overflow; rare */
    snprintf(c->items[c->count].key, sizeof(c->items[c->count].key), "%s", key);
    c->items[c->count].n = 1;
    c->count++;
}

static int counter_cmp_desc(const void *a, const void *b) {
    const struct counter *ca = a, *cb = b;
    if (ca->n != cb->n) return ca->n < cb->n ? 1 : -1;
    return strcmp(ca->key, cb->key);
}

static void counters_print(const char *label, struct counters *c) {
    qsort(c->items, c->count, sizeof(c->items[0]), counter_cmp_desc);
    printf("\n%s:\n", label);
    for (size_t i = 0; i < c->count; i++) {
        printf("  %6lu  %s\n", c->items[i].n, c->items[i].key);
    }
}

static int do_stats(FILE *in) {
    struct counters by_kind     = {0};
    struct counters by_severity = {0};
    struct counters by_source   = {0};
    struct counters by_host     = {0};
    unsigned long total = 0;

    char line[16384];
    while (fgets(line, sizeof(line), in)) {
        size_t L = strlen(line);
        if (L && line[L-1] == '\n') line[L-1] = '\0';
        if (!line[0]) continue;

        struct ps_finding_lite lite;
        if (ps_finding_parse_line(line, &lite) != 0) continue;

        total++;
        counters_bump(&by_kind,     lite.kind);
        counters_bump(&by_severity, ps_severity_str(lite.severity));
        counters_bump(&by_source,   lite.source);

        /* host is not in finding_lite; extract from the raw line */
        char host[128] = "";
        const char *hkey = "\"host\":\"";
        const char *p = strstr(line, hkey);
        if (p) {
            p += strlen(hkey);
            size_t k = 0;
            while (*p && *p != '"' && k + 1 < sizeof(host)) host[k++] = *p++;
            host[k] = '\0';
            counters_bump(&by_host, host);
        }
    }

    printf("Total findings: %lu\n", total);
    counters_print("By severity", &by_severity);
    counters_print("By kind",     &by_kind);
    counters_print("By source",   &by_source);
    counters_print("By host",     &by_host);
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
    } else if (strcmp(sub, "stats") == 0) {
        if (argc >= 3) path = argv[2];
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

    if (strcmp(sub, "stats") == 0) {
        rc = do_stats(in);
    } else {
        rc = do_loop(in, Fp, opts);
    }

    if (path) fclose(in);
    if (Fp) ps_filter_destroy(Fp);
    return rc;
}
