#include "../verbs.h"
#include "../output/output.h"
#include "../runstate.h"
#include "remote/probe_via.h"

#include <stdio.h>
#include <string.h>

int ps_probe_tcp_run       (int argc, char **argv, const struct ps_args *opts);
int ps_probe_udp_run       (int argc, char **argv, const struct ps_args *opts);
int ps_probe_icmp_run      (int argc, char **argv, const struct ps_args *opts);
int ps_probe_sweep_run     (int argc, char **argv, const struct ps_args *opts);
int ps_probe_traceroute_run(int argc, char **argv, const struct ps_args *opts);

struct probe_kind {
    const char *name;
    int (*run)(int argc, char **argv, const struct ps_args *opts);
    const char *summary;
};

static const struct probe_kind KINDS[] = {
    { "tcp",        ps_probe_tcp_run,        "Single TCP connect + banner" },
    { "udp",        ps_probe_udp_run,        "Single UDP datagram probe"    },
    { "icmp",       ps_probe_icmp_run,       "ICMP echo reachability check" },
    { "sweep",      ps_probe_sweep_run,      "Bulk ICMP reachability sweep" },
    { "traceroute", ps_probe_traceroute_run, "Multi-mode traceroute"        },
    { NULL, NULL, NULL }
};

static void usage(void) {
    fprintf(stderr, "Usage: packetsonde probe <kind> [args...]\n\nKinds:\n");
    for (const struct probe_kind *k = KINDS; k->name; k++)
        fprintf(stderr, "  %-10s %s\n", k->name, k->summary);
}

int ps_verb_probe_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        usage(); return 0;
    }

    /* --via <agent>: dispatch to a remote agent over mTLS. The local
     * kind table is consulted only when --via is absent; the remote
     * side does its own dispatch. */
    if (opts->via && *opts->via) {
        struct ps_output_opts oopts; memset(&oopts, 0, sizeof(oopts));
        switch (opts->fmt) {
            case PS_FMT_TEXT:  oopts.fmt_force = PS_OFMT_TEXT;  break;
            case PS_FMT_JSON:  oopts.fmt_force = PS_OFMT_JSON;  break;
            case PS_FMT_JSONL: oopts.fmt_force = PS_OFMT_JSONL; break;
            case PS_FMT_QUIET: oopts.fmt_force = PS_OFMT_QUIET; break;
            default:           oopts.fmt_force = 0;             break;
        }
        oopts.color = opts->no_color ? 0 : 1;
        struct ps_output out;
        ps_output_init(&out, &oopts);
        int rc = ps_probe_via_run(argc - 1, argv + 1, opts, &out);
        ps_output_snapshot(&out, &g_last_run_counts);
        ps_output_close(&out);
        return rc;
    }

    for (const struct probe_kind *k = KINDS; k->name; k++) {
        if (strcmp(k->name, argv[1]) == 0) {
            return k->run(argc - 1, argv + 1, opts);
        }
    }
    fprintf(stderr, "probe: unknown kind '%s'\n", argv[1]);
    usage();
    return 2;
}
