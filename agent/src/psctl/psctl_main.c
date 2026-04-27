#include "psctl_connection.h"
#include "psctl_commands.h"
#include "psctl_format.h"
#include "psctl_shell.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#ifndef PSCTL_VERSION
/* Pulled from build_config.h if available */
#  ifdef PS_VERSION
#    define PSCTL_VERSION PS_VERSION
#  else
#    define PSCTL_VERSION "0.9.0"
#  endif
#endif

#define DEFAULT_SOCKET "/tmp/packetsonde-agent.sock"

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [options] <command> [args...]\n"
            "       %s [options] shell\n"
            "\n"
            "Options:\n"
            "  -s, --socket PATH   Agent socket (default: %s)\n"
            "  -j, --json          Output raw JSON\n"
            "  -q, --quiet         Tab-separated output for scripting\n"
            "  -h, --help          Show this help\n"
            "\n"
            "Commands:\n"
            "  shell               Interactive REPL\n"
            "  modules             List discovery modules\n"
            "  hosts               List discovered hosts\n"
            "  host <ip>           Show host detail\n"
            "  stats               Agent statistics\n"
            "  listen [filter]     Stream live events\n"
            "  enable <module>     Enable a module\n"
            "  disable <module>    Disable a module\n"
            "  trace <host>        Traceroute to host\n"
            "  ping <host>         Ping host\n"
            "  probe <ip> <port>   TCP port probe\n"
            "  version             Show version info\n"
            "  help                Show command help\n",
            prog, prog, DEFAULT_SOCKET);
}

int main(int argc, char **argv)
{
    const char    *socket_path = DEFAULT_SOCKET;
    enum psctl_fmt fmt         = PSCTL_FMT_TEXT;

    static const struct option long_opts[] = {
        { "socket", required_argument, NULL, 's' },
        { "json",   no_argument,       NULL, 'j' },
        { "quiet",  no_argument,       NULL, 'q' },
        { "help",   no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "s:jqh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 's': socket_path = optarg; break;
        case 'j': fmt = PSCTL_FMT_JSON;  break;
        case 'q': fmt = PSCTL_FMT_QUIET; break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* Remaining args: command + its arguments */
    int    cmd_argc = argc - optind;
    char **cmd_argv = argv + optind;

    if (cmd_argc == 0) {
        /* No command given — drop into shell */
        return psctl_shell(socket_path, fmt);
    }

    const char *cmd = cmd_argv[0];
    int sub_argc = cmd_argc - 1;
    char **sub_argv = cmd_argv + 1;

    /* Shell command */
    if (strcmp(cmd, "shell") == 0) {
        return psctl_shell(socket_path, fmt);
    }

    /* Help — no connection needed */
    if (strcmp(cmd, "help") == 0) {
        psctl_print_help();
        return 0;
    }

    /* Version — optionally connects */
    if (strcmp(cmd, "version") == 0) {
        /* Print psctl version immediately */
        if (fmt == PSCTL_FMT_JSON) {
            /* Agent version requires connection — handled inside psctl_cmd_version */
        }
        struct psctl_conn conn;
        conn.fd = -1;
        psctl_connect(&conn, socket_path); /* ignore failure */
        int rc = psctl_cmd_version(&conn, sub_argc, sub_argv, fmt);
        psctl_disconnect(&conn);
        return rc;
    }

    /* All other commands require a connection */
    struct psctl_conn conn;
    if (psctl_connect(&conn, socket_path) < 0) {
        return 1;
    }

    int rc = psctl_dispatch(&conn, cmd, sub_argc, sub_argv, fmt);

    psctl_disconnect(&conn);
    return (rc == 0) ? 0 : 1;
}
