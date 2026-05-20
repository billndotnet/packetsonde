#include "ports.h"
#include "../output/output.h"
#include "../probe/connect.h"
#include "../runstate.h"
#include "../signals.h"
#include "../util/fail_on.h"
#include "../util/targets.h"
#include "../workers/limiter.h"
#include "../workers/workers.h"
#include "finding.h"
#include "ulid.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

static const uint16_t DEFAULT_PORTS[] = {
    21, 22, 23, 25, 53, 80, 110, 143, 443, 587, 993, 995,
    3306, 3389, 5432, 5900, 6379, 8080, 8443
};
static const size_t DEFAULT_PORTS_N = sizeof(DEFAULT_PORTS) / sizeof(DEFAULT_PORTS[0]);

struct scan_ctx {
    struct ps_output  *out;
    struct ps_workers *W;
    const char        *run_id;
    const char        *self_host;
};

struct scan_item {
    struct scan_ctx *ctx;
    char     host[64];
    uint16_t port;
};

static void scan_one(void *arg) {
    struct scan_item *it = (struct scan_item *)arg;
    if (ps_workers_cancelled(it->ctx->W)) { free(it); return; }
    char ip[64] = "";
    if (ps_tcp_open_check(it->host, it->port, 2000, ip, sizeof(ip)) == 0) {
        char title[160];
        snprintf(title, sizeof(title), "Open: %s:%u", ip[0] ? ip : it->host, it->port);
        struct ps_finding f;
        ps_finding_init(&f, it->ctx->run_id, "cli.scan.ports.connect",
                        it->ctx->self_host, "scan.port.open",
                        PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        if (ip[0]) ps_finding_set_target_ip(&f, ip, it->port);
        else       ps_finding_set_target_hostname(&f, it->host, it->port);
        ps_output_emit(it->ctx->out, &f);
    }
    free(it);
}

static void usage(void) {
    fprintf(stderr,
        "Usage: packetsonde scan ports <target|cidr> [-p PORTS]\n"
        "  PORTS: comma list and dash ranges, e.g. 22,80,443,1000-2000\n");
}

int ps_scan_ports_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }

    const char *target = argv[1];
    const char *ports_arg = NULL;
    optind = 2;
    int c;
    while ((c = getopt(argc, argv, "p:")) != -1) {
        if (c == 'p') ports_arg = optarg;
        else { usage(); return 2; }
    }

    struct ps_cidr cidr;
    if (ps_cidr_parse(target, &cidr) != 0) {
        fprintf(stderr, "scan ports: bad target '%s'\n", target);
        return 2;
    }

    struct ps_portset ports = {0};
    if (ports_arg) {
        if (ps_ports_parse(ports_arg, &ports) != 0) {
            fprintf(stderr, "scan ports: bad ports '%s'\n", ports_arg);
            return 2;
        }
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    struct ps_output_opts oopts; memset(&oopts, 0, sizeof(oopts));
    switch (opts->fmt) {
        case PS_FMT_TEXT:  oopts.fmt_force = PS_OFMT_TEXT;  break;
        case PS_FMT_JSON:  oopts.fmt_force = PS_OFMT_JSON;  break;
        case PS_FMT_JSONL: oopts.fmt_force = PS_OFMT_JSONL; break;
        case PS_FMT_QUIET: oopts.fmt_force = PS_OFMT_QUIET; break;
        default:           oopts.fmt_force = 0;             break;
    }
    oopts.color = opts->no_color ? 0 : 1;
    struct ps_output out; ps_output_init(&out, &oopts);

    struct ps_limiter L;
    int rate = opts->rate_pps > 0 ? opts->rate_pps : 100;
    ps_limiter_init(&L, rate);

    struct ps_workers W;
    int concur = opts->concurrency > 0 ? opts->concurrency : 16;
    ps_workers_init(&W, concur, &L);
    ps_signals_install(&W);

    struct scan_ctx ctx = { &out, &W, run_id, self_host };

    const uint16_t *plist = ports_arg ? ports.ports : DEFAULT_PORTS;
    size_t          pcnt  = ports_arg ? ports.count : DEFAULT_PORTS_N;

    for (uint32_t i = 0; i < cidr.count && !ps_workers_cancelled(&W); i++) {
        char host[64];
        if (ps_cidr_addr(&cidr, i, host, sizeof(host)) != 0) continue;
        for (size_t pi = 0; pi < pcnt; pi++) {
            struct scan_item *it = calloc(1, sizeof(*it));
            it->ctx = &ctx;
            snprintf(it->host, sizeof(it->host), "%s", host);
            it->port = plist[pi];
            ps_workers_submit(&W, scan_one, it);
        }
    }

    ps_workers_finish(&W);
    ps_workers_destroy(&W);
    ps_limiter_destroy(&L);
    ps_ports_destroy(&ports);

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
