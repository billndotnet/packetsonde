#include "../verbs.h"

#include "psctl_commands.h"   /* from src/agent/src/psctl */
#include "psctl_connection.h"
#include "psctl_format.h"
#include "psctl_shell.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_SOCKET "/tmp/packetsonde-agent.sock"

static enum psctl_fmt map_fmt(enum ps_fmt f) {
    switch (f) {
        case PS_FMT_JSON:
        case PS_FMT_JSONL:  return PSCTL_FMT_JSON;
        case PS_FMT_QUIET:  return PSCTL_FMT_QUIET;
        default:            return PSCTL_FMT_TEXT;
    }
}

static void agent_usage(void) {
    fprintf(stderr,
        "Usage: packetsonde agent <subcmd> [args...]\n"
        "\n"
        "Subcommands:\n"
        "  status               Agent status / version\n"
        "  modules              List discovery modules\n"
        "  enable <module>      Enable a module\n"
        "  disable <module>     Disable a module\n"
        "  hosts                List discovered hosts\n"
        "  host <ip>            Show host detail\n"
        "  stats                Agent statistics\n"
        "  listen [filter]      Stream live events\n"
        "  shell                Interactive REPL\n");
}

int ps_verb_agent_run(int argc, char **argv, const struct ps_args *opts) {
    /* argv[0] is "agent"; agent's own subcommands start at argv[1]. */
    if (argc < 2) {
        agent_usage();
        return 2;
    }

    const char *socket_path = opts->socket_path ? opts->socket_path : DEFAULT_SOCKET;
    enum psctl_fmt fmt = map_fmt(opts->fmt);

    const char *sub = argv[1];
    int sub_argc = argc - 2;
    char **sub_argv = argv + 2;

    /* `status` is a CLI-friendly alias for `version`. */
    if (strcmp(sub, "status") == 0) sub = "version";

    if (strcmp(sub, "shell") == 0) {
        return psctl_shell(socket_path, fmt);
    }

    struct psctl_conn conn;
    if (psctl_connect(&conn, socket_path) < 0) {
        fprintf(stderr, "packetsonde agent: cannot connect to %s\n", socket_path);
        return 1;
    }

    int rc = psctl_dispatch(&conn, sub, sub_argc, sub_argv, fmt);
    psctl_disconnect(&conn);
    return rc == 0 ? 0 : 1;
}
