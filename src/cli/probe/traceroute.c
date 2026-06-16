#include "../args.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../util/fail_on.h"
#include "finding.h"
#include "ptr_cache.h"
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
        "[--proto udp|tcp|icmp] [--mode classic|paris|dublin] [--port N] "
        "[--max-gap K] (stop after K dead hops; default 5, 0=off) "
        "[--ptr] [--ptr-timeout MS]\n"
        "Defaults: --proto udp --mode classic --port 33434 (udp) / 80 (tcp).\n"
        "TCP: connect-based, hits stateful firewalls that drop UDP.\n"
        "ICMP: echo-request, all modes treated as classic.\n");
}

struct tr_emit_ctx {
    struct ps_output          *out;
    const char                *run_id;
    const char                *self_host;
    const char                *target;
    struct ps_traceroute_opts *to;
    struct ps_ptr_cache       *ptr;       /* NULL unless --ptr */
    int                        ptr_timeout_ms;
};

static int tr_emit_cb(const struct ps_tr_hop *h, void *u) {
    struct tr_emit_ctx *c = u;
    char ptr_name[256] = "";
    if (c->ptr && h->addr[0])
        ps_ptr_cache_wait(c->ptr, h->addr, c->ptr_timeout_ms, ptr_name, sizeof(ptr_name));

    char title[512];
    if (h->addr[0] && ptr_name[0])
        snprintf(title, sizeof(title), "hop %d: %s (%s) (%.1f ms)",
                 h->ttl, ptr_name, h->addr, h->rtt_us / 1000.0);
    else if (h->addr[0])
        snprintf(title, sizeof(title), "hop %d: %s (%.1f ms)",
                 h->ttl, h->addr, h->rtt_us / 1000.0);
    else
        snprintf(title, sizeof(title), "hop %d: *", h->ttl);

    /* ptr_name is getnameinfo()/NI_NAMEREQD output (DNS charset) and c->target
     * has already resolved successfully (else no hops would be emitted), so both
     * are JSON-safe; no escaping needed. "ptr" is always present for a stable
     * schema; "traced" records the run's destination per-hop. */
    char ev[640];
    snprintf(ev, sizeof(ev),
             "{\"proto\":\"%s\",\"mode\":\"%s\",\"ttl\":%d,\"rtt_us\":%ld,"
             "\"reached_dst\":%s,\"ptr\":\"%s\",\"traced\":\"%s\"}",
             ps_tr_proto_str(c->to->proto), ps_tr_mode_str(c->to->mode),
             h->ttl, h->rtt_us, h->reached_dst ? "true" : "false", ptr_name, c->target);

    struct ps_finding f;
    ps_finding_init(&f, c->run_id, "cli.probe.traceroute", c->self_host,
                    "probe.traceroute.hop", PS_SEV_INFO, PS_CONF_FIRM, title);
    /* The hop's target is the hop itself (its IP) — NOT the trace destination,
     * so a "*" (no-reply) hop has no target instead of displaying the dest name. */
    if (h->addr[0]) ps_finding_set_target_ip(&f, h->addr, 0);
    ps_finding_set_evidence_json(&f, ev);
    ps_output_emit(c->out, &f);
    return 0;   /* Phase 2 adds SIGINT-driven stop here */
}

int ps_probe_traceroute_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }

    struct ps_traceroute_opts to = PS_TRACEROUTE_DEFAULTS;
    int port_set = 0;
    int enable_ptr = 0;
    int ptr_timeout_ms = 300;

    static const struct option longopts[] = {
        { "proto",       required_argument, NULL, 'p' },
        { "mode",        required_argument, NULL, 'm' },
        { "port",        required_argument, NULL, 'P' },
        { "max-gap",     required_argument, NULL, 'g' },
        { "ptr",         no_argument,       NULL, 'r' },
        { "ptr-timeout", required_argument, NULL, 't' },
        { NULL, 0, NULL, 0 }
    };
    /* getopt does not permute here (POSIX environments stop option scanning at
     * the first non-option), so a target placed before options used to drop the
     * trailing options. Handle the single positional explicitly: when getopt
     * stops at a non-option, capture it as the target, step past it, and resume
     * — so options may appear before, after, or around the target. */
    const char *target = NULL;
    optind = 1;
    for (;;) {
        int c = getopt_long(argc, argv, "", longopts, NULL);
        if (c == -1) {
            if (optind < argc) {                 /* stopped at a non-option */
                if (target) {
                    fprintf(stderr, "probe traceroute: unexpected extra argument '%s'\n", argv[optind]);
                    return 2;
                }
                target = argv[optind++];         /* capture target, resume parsing */
                continue;
            }
            break;                                /* no args left: done */
        }
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
                port_set = 1;
                break;
            case 'g': to.max_gap = atoi(optarg); break;
            case 'r': enable_ptr = 1; break;
            case 't': ptr_timeout_ms = atoi(optarg); break;
            default: usage(); return 2;
        }
    }

    if (!target) { usage(); return 2; }

    /* TCP traceroute targets a service port, not the UDP traceroute port. */
    if (to.proto == PS_TR_PROTO_TCP && !port_set) to.dst_port = 80;

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

    struct ps_ptr_cache *ptr = enable_ptr ? ps_ptr_cache_new() : NULL;
    struct tr_emit_ctx ctx = {
        .out = &out, .run_id = run_id, .self_host = self_host,
        .target = target, .to = &to, .ptr = ptr, .ptr_timeout_ms = ptr_timeout_ms,
    };
    int rc = ps_traceroute_run_cb(target, &to, tr_emit_cb, &ctx);
    if (ptr) ps_ptr_cache_free(ptr);
    if (rc != 0) {
        fprintf(stderr,
                "probe traceroute: cannot run (proto=%s mode=%s) - "
                "udp classic requires kernel ICMP capability (cap_net_raw on "
                "Linux, sudo on macOS for raw fallback)\n",
                ps_tr_proto_str(to.proto), ps_tr_mode_str(to.mode));
        ps_output_close(&out);
        return 1;
    }
    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
