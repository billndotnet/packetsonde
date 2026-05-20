#include "psctl_shell.h"

#include "psctl_connection.h"
#include "psctl_commands.h"
#include "psctl_format.h"

#include <histedit.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

/* libedit prompt callback */
static const char *prompt_fn(EditLine *el)
{
    (void)el;
    return "psctl> ";
}

/* Tokenize a line into argc/argv (modifies the input string) */
static int tokenize_line(char *line, int *argc_out, char **argv_out, int max_args)
{
    int argc = 0;
    char *p = line;

    while (*p) {
        /* skip leading whitespace */
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        if (argc >= max_args) break;
        argv_out[argc++] = p;

        /* scan to end of token */
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) *p++ = '\0';
    }

    *argc_out = argc;
    return argc;
}

/* Ensure ~/.packetsonde/ directory exists */
static void ensure_history_dir(char *path_out, size_t sz)
{
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";

    snprintf(path_out, sz, "%s/.packetsonde", home);

    struct stat st;
    if (stat(path_out, &st) != 0) {
        mkdir(path_out, 0700);
    }

    size_t dlen = strlen(path_out);
    snprintf(path_out + dlen, sz - dlen, "/history");
}

int psctl_shell(const char *socket_path, enum psctl_fmt fmt)
{
    struct psctl_conn conn;
    conn.fd = -1;

    /* Try to connect; shell still works offline for help/version */
    if (psctl_connect(&conn, socket_path) < 0) {
        fprintf(stderr, "psctl: warning: could not connect to agent at %s\n"
                        "       Some commands will not work.\n", socket_path);
    }

    /* Set up libedit */
    EditLine *el = el_init("psctl", stdin, stdout, stderr);
    if (!el) {
        fprintf(stderr, "psctl: el_init failed\n");
        psctl_disconnect(&conn);
        return -1;
    }

    el_set(el, EL_PROMPT, prompt_fn);
    el_set(el, EL_EDITOR, "emacs");
    el_set(el, EL_SIGNAL, 1);

    /* Set up history */
    History *hist = history_init();
    HistEvent hev;
    if (hist) {
        history(hist, &hev, H_SETSIZE, 500);
        el_set(el, EL_HIST, history, hist);
    }

    /* Load history from file */
    char hist_path[512];
    ensure_history_dir(hist_path, sizeof(hist_path));
    if (hist) {
        history(hist, &hev, H_LOAD, hist_path);
    }

    if (fmt == PSCTL_FMT_TEXT) {
        printf("packetsonde agent control — type 'help' for commands, 'exit' to quit\n");
    }

    int running = 1;
    while (running) {
        int count = 0;
        const char *line = el_gets(el, &count);

        if (!line || count <= 0) {
            /* EOF */
            if (fmt == PSCTL_FMT_TEXT) printf("\n");
            break;
        }

        /* Copy and trim newline */
        char linebuf[4096];
        strncpy(linebuf, line, sizeof(linebuf) - 1);
        linebuf[sizeof(linebuf) - 1] = '\0';
        size_t len = strlen(linebuf);
        while (len > 0 && (linebuf[len-1] == '\n' || linebuf[len-1] == '\r'))
            linebuf[--len] = '\0';

        /* Skip blank lines */
        const char *trimmed = linebuf;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        if (!*trimmed) continue;

        /* Add to history */
        if (hist) history(hist, &hev, H_ENTER, linebuf);

        /* Tokenize */
        char linecopy[4096];
        strncpy(linecopy, trimmed, sizeof(linecopy) - 1);
        linecopy[sizeof(linecopy)-1] = '\0';

        char *argv[64];
        int argc = 0;
        tokenize_line(linecopy, &argc, argv, 64);
        if (argc == 0) continue;

        const char *cmd = argv[0];

        /* Built-ins */
        if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
            running = 0;
        } else if (strcmp(cmd, "help") == 0) {
            psctl_print_help();
        } else {
            /* Reconnect if disconnected */
            if (conn.fd < 0) {
                psctl_connect(&conn, socket_path);
            }
            psctl_dispatch(&conn, cmd, argc - 1, argv + 1, fmt);
        }
    }

    /* Save history */
    if (hist) {
        history(hist, &hev, H_SAVE, hist_path);
        history_end(hist);
    }

    el_end(el);
    psctl_disconnect(&conn);
    return 0;
}
