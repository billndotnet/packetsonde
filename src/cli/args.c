#include "args.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ps_args_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options] <verb> [args...]\n"
        "\n"
        "Verbs (v1):\n"
        "  version              Show version\n"
        "  agent <subcmd>       Control / query the local packetsonded agent\n"
        "  help                 Show help\n"
        "\n"
        "Output:\n"
        "  --text               Force text output\n"
        "  --json               Force JSON output\n"
        "  --jsonl              Force JSONL output\n"
        "  --quiet              Tab-separated minimal output\n"
        "  --no-color           Suppress color (also honors NO_COLOR)\n"
        "  --auto-append        Tee JSONL to ~/.local/state/packetsonde/findings-YYYY-MM-DD.jsonl\n"
        "\n"
        "Execution:\n"
        "  --via <name>         Dispatch to a named agent (v1: only 'local')\n"
        "  --concurrency N      Worker pool size (default 16)\n"
        "  --rate PPS           Probe-rate cap\n"
        "  --socket PATH        Override local agent socket path\n"
        "  --config PATH        Override config file location\n"
        "\n"
        "Run `%s help` for command help, or `%s <verb> --help`.\n",
        prog, prog, prog);
}

enum {
    OPT_TEXT = 1000, OPT_JSON, OPT_JSONL, OPT_QUIET,
    OPT_NO_COLOR, OPT_AUTO_APPEND,
    OPT_VIA, OPT_CONCURRENCY, OPT_RATE, OPT_SOCKET, OPT_CONFIG,
    OPT_FAIL_ON
};

int ps_args_parse(int argc, char **argv, struct ps_args *out) {
    if (!argv || !out) return -1;
    memset(out, 0, sizeof(*out));
    out->fmt = PS_FMT_AUTO;

    static const struct option longopts[] = {
        { "text",         no_argument,       NULL, OPT_TEXT },
        { "json",         no_argument,       NULL, OPT_JSON },
        { "jsonl",        no_argument,       NULL, OPT_JSONL },
        { "quiet",        no_argument,       NULL, OPT_QUIET },
        { "no-color",     no_argument,       NULL, OPT_NO_COLOR },
        { "auto-append",  no_argument,       NULL, OPT_AUTO_APPEND },
        { "via",          required_argument, NULL, OPT_VIA },
        { "concurrency",  required_argument, NULL, OPT_CONCURRENCY },
        { "rate",         required_argument, NULL, OPT_RATE },
        { "socket",       required_argument, NULL, OPT_SOCKET },
        { "config",       required_argument, NULL, OPT_CONFIG },
        { "fail-on",      required_argument, NULL, OPT_FAIL_ON },
        { "help",         no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    /* Allow flags only before the verb. The "+" prefix on optstring tells
     * getopt to stop at the first non-option. */
    optind = 1;
    opterr = 0;
    int opt;
    while ((opt = getopt_long(argc, argv, "+h", longopts, NULL)) != -1) {
        switch (opt) {
            case OPT_TEXT:        out->fmt = PS_FMT_TEXT; break;
            case OPT_JSON:        out->fmt = PS_FMT_JSON; break;
            case OPT_JSONL:       out->fmt = PS_FMT_JSONL; break;
            case OPT_QUIET:       out->fmt = PS_FMT_QUIET; break;
            case OPT_NO_COLOR:    out->no_color = true; break;
            case OPT_AUTO_APPEND: out->auto_append = true; break;
            case OPT_VIA:         out->via = optarg; break;
            case OPT_CONCURRENCY: out->concurrency = atoi(optarg); break;
            case OPT_RATE:        out->rate_pps = atoi(optarg); break;
            case OPT_SOCKET:      out->socket_path = optarg; break;
            case OPT_CONFIG:      out->config_path = optarg; break;
            case OPT_FAIL_ON:     out->fail_on = optarg; break;
            case 'h':
                ps_args_usage(argv[0]);
                return 1;   /* not an error; caller exits 0 */
            case '?':
            default:
                fprintf(stderr, "%s: unknown option\n", argv[0]);
                return -1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "%s: missing verb\n", argv[0]);
        return -1;
    }

    out->verb_argc = argc - optind;
    out->verb_argv = argv + optind;
    return 0;
}
