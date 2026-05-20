#include "../args.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../util/fail_on.h"
#include "finding.h"
#include "traceroute.h"
#include "ulid.h"

int ps_probe_traceroute_run(int argc, char **argv, const struct ps_args *opts);

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(void) {
    fprintf(stderr,
        "Usage: packetsonde probe traceroute <target> "
        "[--proto udp|tcp|icmp] [--mode classic|paris|dublin] [--port N]\n"
        "Defaults: --proto udp --mode classic --port 33434\n"
        "TCP, ICMP, Paris, and Dublin modes will land in a follow-on task.\n");
}

int ps_probe_traceroute_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }

    const char *target = argv[1];

    struct ps_traceroute_opts to = PS_TRACEROUTE_DEFAULTS;

    static const struct option longopts[] = {
        { "proto", required_argument, NULL, 'p' },
        { "mode",  required_argument, NULL, 'm' },
        { "port",  required_argument, NULL, 'P' },
        { NULL, 0, NULL, 0 }
    };
    optind = 2;
    int c;
    while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
        switch (c) {
            case 'p':
                if      (!strcmp(optarg, "udp"))  to.proto = PS_TR_PROTO_UDP;
                else if (!strcmp(optarg, "tcp"))  to.proto = PS_TR_PROTO_TCP;
                else if (!strcmp(optarg, "icmp")) to.proto = PS_TR_PROTO_ICMP;
                else { usage(); return 2; }
                break;
            case 'm':
                if      (!strcmp(optarg, "classic")) to.mode = PS_TR_MODE_CLASSIC;
                else if (!strcmp(optarg, "paris"))   to.mode = PS_TR_MODE_PARIS;
                else if (!strcmp(optarg, "dublin"))  to.mode = PS_TR_MODE_DUBLIN;
                else { usage(); return 2; }
                break;
            case 'P':
                to.dst_port = (uint16_t)atoi(optarg);
                break;
            default: usage(); return 2;
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

    struct ps_traceroute_result tr;
    int rc = ps_traceroute_run(target, &to, &tr);
    if (rc != 0) {
        fprintf(stderr,
                "probe traceroute: cannot run (proto=%s mode=%s) - "
                "tcp/icmp + paris/dublin land in a follow-on; udp classic "
                "requires kernel ICMP capability (cap_net_raw on Linux, "
                "sudo on macOS for raw fallback)\n",
                ps_tr_proto_str(to.proto), ps_tr_mode_str(to.mode));
        ps_output_close(&out);
        return 1;
    }

    for (int i = 0; i < tr.hop_count; i++) {
        struct ps_tr_hop *h = &tr.hops[i];
        char title[256];
        if (h->addr[0]) {
            snprintf(title, sizeof(title), "hop %d: %s (%.1f ms)",
                     h->ttl, h->addr, h->rtt_us / 1000.0);
        } else {
            snprintf(title, sizeof(title), "hop %d: *", h->ttl);
        }
        char ev[256];
        snprintf(ev, sizeof(ev),
                 "{\"proto\":\"%s\",\"mode\":\"%s\",\"ttl\":%d,\"rtt_us\":%ld,\"reached_dst\":%s}",
                 ps_tr_proto_str(to.proto), ps_tr_mode_str(to.mode),
                 h->ttl, h->rtt_us, h->reached_dst ? "true" : "false");
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.probe.traceroute", self_host,
                        "probe.traceroute.hop", PS_SEV_INFO, PS_CONF_FIRM, title);
        ps_finding_set_target_hostname(&f, target, 0);
        if (h->addr[0]) ps_finding_set_target_ip(&f, h->addr, 0);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
    }

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
