#include "verbs.h"
#include "config.h"          /* ps_config — from ../agent/src (CLI include path) */
#include "central_config.h"  /* ps_central_config — lib */
#include "reporter.h"        /* ps_report_events, ps_reporter_build_envelopes — lib */
#include "cli_config_util.h" /* ps_cli_unq */
#include "../remote/ingest_via.h"  /* ps_ingest_via */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

int ps_verb_report_central_run(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    const char *cfg_path = "/etc/packetsonded/packetsonded.toml";
    const char *jsonl = NULL, *endpoint = NULL;
    static struct option lo[] = {
        {"config", required_argument, 0, 'c'},
        {"to-central", required_argument, 0, 't'},
        {"endpoint", required_argument, 0, 'e'},
        {0, 0, 0, 0}
    };
    optind = 1; int c;
    while ((c = getopt_long(argc, argv, "c:t:e:", lo, NULL)) != -1) {
        if (c == 'c') cfg_path = optarg;
        else if (c == 't') jsonl = optarg;
        else if (c == 'e') endpoint = optarg;
    }
    if (!jsonl) { fprintf(stderr, "usage: packetsonde report-central --to-central <findings.jsonl>\n"); return 2; }

    struct ps_config cfg;
    if (ps_config_parse_file(&cfg, cfg_path) != 0) {
        fprintf(stderr, "report-central: cannot read %s\n", cfg_path); return 1;
    }
    char ub_url[512], ub_id[256], ub_ca[512], ub_kd[512];
    struct ps_central_config cc;
    cc.url = ps_cli_unq(ps_config_get(&cfg, "central", "url"), ub_url, sizeof ub_url);
    cc.agent_id = ps_cli_unq(ps_config_get(&cfg, "central", "agent_id"), ub_id, sizeof ub_id);
    cc.deployment_mode = NULL;
    {
        const char *v = ps_config_get(&cfg, "central", "verify");
        cc.verify = (v && strstr(v, "0")) ? 0 : 1;
    }
    cc.ca_cert = ps_cli_unq(ps_config_get(&cfg, "central", "ca_cert"), ub_ca, sizeof ub_ca);
    cc.checkin_seconds = 60;
    cc.key_dir = ps_cli_unq(ps_config_get(&cfg, "keys", "dir"), ub_kd, sizeof ub_kd);
    char ub_rm[16], ub_rv[256];
    cc.report_mode = ps_cli_unq(ps_config_get(&cfg, "central", "report_mode"), ub_rm, sizeof ub_rm);
    if (!cc.report_mode || !cc.report_mode[0]) cc.report_mode = "direct";
    cc.relay_via = ps_cli_unq(ps_config_get(&cfg, "central", "relay_via"), ub_rv, sizeof ub_rv);

    FILE *f = fopen(jsonl, "r");
    if (!f) { fprintf(stderr, "report-central: cannot open %s\n", jsonl); ps_config_free(&cfg); return 1; }

    char **events = NULL; size_t n = 0, capn = 0;
    char line[16384];
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] != '{') continue;
        if (n == capn) { capn = capn ? capn * 2 : 64; events = realloc(events, capn * sizeof(char*)); }
        events[n++] = strdup(line);
    }
    fclose(f);

    struct ps_report_result r = {0}; int rc;
    if (strcmp(cc.report_mode, "relay") == 0 && cc.relay_via && cc.relay_via[0]) {
        static char arr[262144];
        int alen = ps_reporter_build_envelopes(&cc, (const char**)events, n, arr, sizeof arr);
        rc = (alen < 0) ? -1 : ps_ingest_via(cc.relay_via, arr, &r);
        r.total = (int)n; r.rejected = r.total - r.accepted;
    } else {
        rc = ps_report_events(&cc, endpoint, (const char**)events, n, &r);
    }
    for (size_t i = 0; i < n; i++) free(events[i]);
    free(events);
    ps_config_free(&cfg);

    if (rc != 0) { fprintf(stderr, "report-central: central unreachable / send failed\n"); return 2; }
    printf("reported: accepted %d / rejected %d of %d (HTTP %d)\n", r.accepted, r.rejected, r.total, r.http_status);
    return r.rejected == 0 ? 0 : 3;
}
