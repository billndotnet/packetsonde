#include "../verbs.h"

#include "../psctl/psctl_connection.h"

#include <stdio.h>
#include <string.h>

/*
 * `packetsonde detect capture {start|stop} --session <id>`
 *
 * Drives a detect-agent capture session: sends the IPC channel
 * `detect.capture.control` with payload {"action":"start|stop",
 * "session_id":"<id>"} to the local agent and reads the agent's reply on
 * channel `response.capture`. Exit 0 iff the reply carries "ok":true.
 *
 * Reuses the CLI->agent IPC client (psctl_connect/psctl_send/psctl_recv)
 * -- the same Unix-socket frame helper agent.c uses for query.host,
 * traceroute.request, etc.
 *
 * getopt does NOT permute past the `capture`/`start` positionals, so the
 * --session flag is scanned out of argv by hand (per the no-permute gotcha).
 */

#define DEFAULT_SOCKET "/run/packetsonde/agent.sock"
#define DETECT_CHAN_SZ 256
#define DETECT_PAYL_SZ (64 * 1024)

static void detect_usage(void) {
    fprintf(stderr,
        "Usage: packetsonde detect capture <start|stop> --session <id>\n"
        "\n"
        "Control detect-agent capture sessions.\n"
        "\n"
        "Subcommands:\n"
        "  capture start --session <id>   Start teeing detect events to <id>\n"
        "  capture stop  --session <id>   Stop the capture session <id>\n");
}

int ps_verb_detect_run(int argc, char **argv, const struct ps_args *opts) {
    /* argv[0] is "detect". */
    if (argc < 2) {
        detect_usage();
        return 2;
    }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        detect_usage();
        return 0;
    }
    if (strcmp(argv[1], "capture") != 0) {
        fprintf(stderr, "packetsonde detect: unknown subcommand '%s'\n", argv[1]);
        detect_usage();
        return 2;
    }

    if (argc < 3) {
        fprintf(stderr, "packetsonde detect capture: missing action (start|stop)\n");
        detect_usage();
        return 2;
    }
    const char *action = argv[2];
    if (strcmp(action, "start") != 0 && strcmp(action, "stop") != 0) {
        fprintf(stderr, "packetsonde detect capture: invalid action '%s' (expected start|stop)\n", action);
        detect_usage();
        return 2;
    }

    /* Manual argv scan for --session <id> (getopt would not permute past the
     * `capture`/<action> positionals). */
    const char *session = NULL;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--session") == 0 || strcmp(argv[i], "-s") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "packetsonde detect capture: --session requires an argument\n");
                return 2;
            }
            session = argv[++i];
        } else if (strncmp(argv[i], "--session=", 10) == 0) {
            session = argv[i] + 10;
        } else {
            fprintf(stderr, "packetsonde detect capture: unexpected argument '%s'\n", argv[i]);
            detect_usage();
            return 2;
        }
    }
    if (!session || !session[0]) {
        fprintf(stderr, "packetsonde detect capture: --session <id> is required\n");
        detect_usage();
        return 2;
    }

    const char *socket_path = opts->socket_path ? opts->socket_path : DEFAULT_SOCKET;

    struct psctl_conn conn;
    if (psctl_connect(&conn, socket_path) < 0) {
        fprintf(stderr, "packetsonde detect: cannot connect to %s\n", socket_path);
        return 1;
    }

    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"action\":\"%s\",\"session_id\":\"%s\"}", action, session);

    int rc = 1;
    if (psctl_send(&conn, "detect.capture.control", payload) < 0) {
        fprintf(stderr, "packetsonde detect: send failed\n");
        psctl_disconnect(&conn);
        return 1;
    }

    char ch[DETECT_CHAN_SZ], pl[DETECT_PAYL_SZ];
    if (psctl_recv(&conn, ch, sizeof(ch), pl, sizeof(pl), 5000) < 0) {
        fprintf(stderr, "packetsonde detect: no response from agent\n");
        psctl_disconnect(&conn);
        return 1;
    }

    /* The agent replies on channel `response.capture`. */
    if (strcmp(ch, "response.capture") != 0) {
        fprintf(stderr, "packetsonde detect: unexpected reply channel '%s'\n", ch);
        printf("%s\n", pl);
        psctl_disconnect(&conn);
        return 1;
    }

    printf("%s\n", pl);

    /* Success iff the reply payload carries "ok":true. */
    if (strstr(pl, "\"ok\":true") || strstr(pl, "\"ok\": true")) {
        rc = 0;
    }

    psctl_disconnect(&conn);
    return rc;
}
