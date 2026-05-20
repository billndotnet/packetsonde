#include "hosts.h"
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const uint16_t SWEEP_PORTS[] = { 22, 80, 443, 445 };
static const size_t SWEEP_PORTS_N = sizeof(SWEEP_PORTS) / sizeof(SWEEP_PORTS[0]);

struct host_item {
    struct ps_output  *out;
    struct ps_workers *W;
    const char        *run_id;
    const char        *self_host;
    char  host[64];
};

static void check_host(void *arg) {
    struct host_item *it = (struct host_item *)arg;
    if (ps_workers_cancelled(it->W)) { free(it); return; }
    for (size_t i = 0; i < SWEEP_PORTS_N; i++) {
        char ip[64] = "";
        if (ps_tcp_open_check(it->host, SWEEP_PORTS[i], 600, ip, sizeof(ip)) == 0) {
            char title[160];
            snprintf(title, sizeof(title), "host up: %s (port %u)",
                     ip[0] ? ip : it->host, SWEEP_PORTS[i]);
            char ev[160];
            snprintf(ev, sizeof(ev), "{\"first_open_port\":%u}", SWEEP_PORTS[i]);
            struct ps_finding f;
            ps_finding_init(&f, it->run_id, "cli.discover.hosts", it->self_host,
                            "discover.host.up", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
            if (ip[0]) ps_finding_set_target_ip(&f, ip, 0);
            else       ps_finding_set_target_hostname(&f, it->host, 0);
            ps_finding_set_evidence_json(&f, ev);
            ps_output_emit(it->out, &f);
            break;
        }
    }
    free(it);
}

int ps_discover_hosts_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde discover hosts <cidr>\n");
        return 2;
    }
    struct ps_cidr cidr;
    if (ps_cidr_parse(argv[1], &cidr) != 0) {
        fprintf(stderr, "discover hosts: bad target '%s'\n", argv[1]);
        return 2;
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
    int concur = opts->concurrency > 0 ? opts->concurrency : 32;
    ps_workers_init(&W, concur, &L);
    ps_signals_install(&W);

    for (uint32_t i = 0; i < cidr.count && !ps_workers_cancelled(&W); i++) {
        struct host_item *it = calloc(1, sizeof(*it));
        it->out = &out; it->W = &W;
        it->run_id = run_id; it->self_host = self_host;
        if (ps_cidr_addr(&cidr, i, it->host, sizeof(it->host)) != 0) { free(it); continue; }
        ps_workers_submit(&W, check_host, it);
    }

    ps_workers_finish(&W);
    ps_workers_destroy(&W);
    ps_limiter_destroy(&L);

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
