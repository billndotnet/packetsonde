#include "../verbs.h"
#include "../findings_util/reader.h"
#include "finding.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void usage(void) {
    fprintf(stderr,
        "Usage: packetsonde report [path]\n"
        "\n"
        "Reads JSONL findings from <path> (or stdin) and writes a Markdown\n"
        "report grouped by severity and host. Sorted critical -> info.\n"
        "Use --jsonl to bypass the report and pass findings through unchanged.\n");
}

/* Buffered, dynamically-grown finding store. */
struct row {
    char id[64];
    char run_id[64];
    char kind[128];
    char source[128];
    char target[280];
    char host[128];
    char title[256];
    char ts[40];
    char evidence[8192];
    enum ps_severity sev;
};

struct rows {
    struct row *items;
    size_t count, cap;
};

static int rows_push(struct rows *r, const struct row *x) {
    if (r->count == r->cap) {
        size_t nc = r->cap ? r->cap * 2 : 64;
        struct row *g = realloc(r->items, nc * sizeof(*g));
        if (!g) return -1;
        r->items = g; r->cap = nc;
    }
    r->items[r->count++] = *x;
    return 0;
}

/* Severity descending, then host, then kind */
static int row_cmp(const void *a, const void *b) {
    const struct row *x = a, *y = b;
    if (x->sev != y->sev) return x->sev < y->sev ? 1 : -1;
    int c = strcmp(x->host, y->host);
    if (c) return c;
    return strcmp(x->kind, y->kind);
}

/* Extract a string field from a JSONL line. Returns 1 if found. */
static int extract_str(const char *line, const char *key, char *out, size_t outsz) {
    char pat[64]; snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(line, pat);
    if (!p) { if (outsz) out[0] = '\0'; return 0; }
    p += strlen(pat);
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < outsz) {
        if (*p == '\\' && p[1]) { out[i++] = p[1]; p += 2; continue; }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 1;
}

/* Extract the evidence object (everything between "evidence": and the next
 * closing brace at the same depth). */
static int extract_evidence(const char *line, char *out, size_t outsz) {
    out[0] = '\0';
    const char *p = strstr(line, "\"evidence\":");
    if (!p) return 0;
    p += strlen("\"evidence\":");
    while (*p == ' ') p++;
    if (*p != '{') return 0;
    int depth = 0;
    size_t i = 0;
    while (*p && i + 1 < outsz) {
        if (*p == '{') depth++;
        else if (*p == '}') {
            depth--;
            if (depth == 0) { out[i++] = *p; out[i] = '\0'; return 1; }
        }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i > 0;
}

static int parse_row(const char *line, struct row *r) {
    memset(r, 0, sizeof(*r));
    extract_str(line, "id",     r->id,     sizeof(r->id));
    extract_str(line, "run_id", r->run_id, sizeof(r->run_id));
    extract_str(line, "ts",     r->ts,     sizeof(r->ts));
    extract_str(line, "source", r->source, sizeof(r->source));
    extract_str(line, "host",   r->host,   sizeof(r->host));
    extract_str(line, "title",  r->title,  sizeof(r->title));
    if (!extract_str(line, "kind", r->kind, sizeof(r->kind))) return -1;

    char sev[16] = ""; extract_str(line, "severity", sev, sizeof(sev));
    if      (!strcmp(sev, "info"))     r->sev = PS_SEV_INFO;
    else if (!strcmp(sev, "low"))      r->sev = PS_SEV_LOW;
    else if (!strcmp(sev, "medium"))   r->sev = PS_SEV_MEDIUM;
    else if (!strcmp(sev, "high"))     r->sev = PS_SEV_HIGH;
    else if (!strcmp(sev, "critical")) r->sev = PS_SEV_CRITICAL;
    else r->sev = PS_SEV_INFO;

    char ip[64] = "", hostname[256] = "";
    extract_str(line, "ip",       ip,       sizeof(ip));
    extract_str(line, "hostname", hostname, sizeof(hostname));
    const char *pport = strstr(line, "\"port\":");
    long port = pport ? strtol(pport + 7, NULL, 10) : 0;
    const char *primary = ip[0] ? ip : hostname;
    if (primary[0] && port > 0)
        snprintf(r->target, sizeof(r->target), "%s:%ld", primary, port);
    else if (primary[0])
        snprintf(r->target, sizeof(r->target), "%s", primary);

    extract_evidence(line, r->evidence, sizeof(r->evidence));
    return 0;
}

static const char *sev_label(enum ps_severity s) {
    switch (s) {
        case PS_SEV_CRITICAL: return "CRITICAL";
        case PS_SEV_HIGH:     return "HIGH";
        case PS_SEV_MEDIUM:   return "MEDIUM";
        case PS_SEV_LOW:      return "LOW";
        case PS_SEV_INFO:     return "INFO";
    }
    return "INFO";
}

int ps_verb_report_run(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        usage(); return 0;
    }
    const char *path = (argc > 1) ? argv[1] : NULL;
    FILE *in = path ? fopen(path, "r") : stdin;
    if (!in) { perror(path); return 1; }

    struct rows rows = {0};
    char line[16384];
    while (fgets(line, sizeof(line), in)) {
        size_t L = strlen(line);
        if (L && line[L-1] == '\n') line[L-1] = '\0';
        if (!line[0]) continue;
        struct row r;
        if (parse_row(line, &r) == 0) rows_push(&rows, &r);
    }
    if (path) fclose(in);

    if (rows.count == 0) {
        fprintf(stderr, "report: no findings to report\n");
        return 1;
    }

    qsort(rows.items, rows.count, sizeof(rows.items[0]), row_cmp);

    /* Header */
    char date_buf[64];
    time_t now = time(NULL);
    struct tm tm; gmtime_r(&now, &tm);
    strftime(date_buf, sizeof(date_buf), "%Y-%m-%d", &tm);

    printf("# packetsonde report — %s\n\n", date_buf);

    /* Counts by severity */
    unsigned counts[5] = {0};
    for (size_t i = 0; i < rows.count; i++) {
        if (rows.items[i].sev >= 0 && rows.items[i].sev < 5) {
            counts[rows.items[i].sev]++;
        }
    }
    printf("## Summary\n\n");
    printf("- **Total findings:** %zu\n", rows.count);
    printf("- **Critical:** %u\n", counts[PS_SEV_CRITICAL]);
    printf("- **High:** %u\n",     counts[PS_SEV_HIGH]);
    printf("- **Medium:** %u\n",   counts[PS_SEV_MEDIUM]);
    printf("- **Low:** %u\n",      counts[PS_SEV_LOW]);
    printf("- **Info:** %u\n",     counts[PS_SEV_INFO]);

    /* Hosts seen */
    {
        char hosts[64][128]; size_t h = 0;
        for (size_t i = 0; i < rows.count && h < 64; i++) {
            int dup = 0;
            for (size_t j = 0; j < h; j++)
                if (strcmp(hosts[j], rows.items[i].host) == 0) { dup = 1; break; }
            if (!dup) snprintf(hosts[h++], sizeof(hosts[0]), "%s", rows.items[i].host);
        }
        if (h > 0) {
            printf("- **Sources (host):** %zu (", h);
            for (size_t i = 0; i < h; i++) {
                if (i) printf(", ");
                printf("%s", hosts[i]);
            }
            printf(")\n");
        }
    }
    printf("\n");

    /* Group by severity */
    enum ps_severity prev_sev = PS_SEV_CRITICAL + 1;
    char prev_host[128] = "";
    for (size_t i = 0; i < rows.count; i++) {
        struct row *r = &rows.items[i];
        if (r->sev != prev_sev) {
            printf("## %s\n\n", sev_label(r->sev));
            prev_sev = r->sev;
            prev_host[0] = '\0';
        }
        if (strcmp(prev_host, r->host) != 0) {
            printf("### %s\n\n", r->host[0] ? r->host : "(unknown host)");
            snprintf(prev_host, sizeof(prev_host), "%s", r->host);
        }
        printf("- **%s** — %s\n", r->kind, r->title);
        if (r->target[0]) printf("  - target: `%s`\n", r->target);
        if (r->source[0]) printf("  - source: `%s`\n", r->source);
        if (r->ts[0])     printf("  - ts: `%s`\n", r->ts);
        if (r->evidence[0]) {
            printf("  - evidence: `%s`\n", r->evidence);
        }
        printf("\n");
    }

    /* Footer */
    printf("---\n\n*generated by packetsonde report — %s*\n", date_buf);

    free(rows.items);
    return 0;
}
