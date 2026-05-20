#include "psctl_commands.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

/* -------------------------------------------------------------------------- */
/* SIGINT handling for listen command                                          */
/* -------------------------------------------------------------------------- */

static volatile sig_atomic_t g_listen_stop = 0;

static void listen_sigint(int sig)
{
    (void)sig;
    g_listen_stop = 1;
}

/* -------------------------------------------------------------------------- */
/* Buffer sizes                                                                */
/* -------------------------------------------------------------------------- */

#define CHAN_SZ  256
#define PAYL_SZ  (256 * 1024)

/* -------------------------------------------------------------------------- */
/* psctl_cmd_modules                                                           */
/* -------------------------------------------------------------------------- */

int psctl_cmd_modules(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt)
{
    (void)argc; (void)argv;
    if (psctl_send(conn, "query.modules", "{}") < 0) {
        fprintf(stderr, "psctl: send failed\n");
        return -1;
    }
    char ch[CHAN_SZ], pl[PAYL_SZ];
    if (psctl_recv(conn, ch, sizeof(ch), pl, sizeof(pl), 5000) < 0) {
        fprintf(stderr, "psctl: no response from agent\n");
        return -1;
    }
    psctl_print_modules(pl, fmt);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* psctl_cmd_hosts                                                             */
/* -------------------------------------------------------------------------- */

int psctl_cmd_hosts(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt)
{
    (void)argc; (void)argv;
    if (psctl_send(conn, "query.hosts", "{}") < 0) {
        fprintf(stderr, "psctl: send failed\n");
        return -1;
    }
    char ch[CHAN_SZ], pl[PAYL_SZ];
    if (psctl_recv(conn, ch, sizeof(ch), pl, sizeof(pl), 5000) < 0) {
        fprintf(stderr, "psctl: no response from agent\n");
        return -1;
    }
    psctl_print_hosts(pl, fmt);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* psctl_cmd_host                                                              */
/* -------------------------------------------------------------------------- */

int psctl_cmd_host(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt)
{
    if (argc < 1 || !argv[0] || !argv[0][0]) {
        fprintf(stderr, "psctl: host requires an IP address argument\n");
        return -1;
    }
    char payload[256];
    snprintf(payload, sizeof(payload), "{\"ip\":\"%s\"}", argv[0]);

    if (psctl_send(conn, "query.host", payload) < 0) {
        fprintf(stderr, "psctl: send failed\n");
        return -1;
    }
    char ch[CHAN_SZ], pl[PAYL_SZ];
    if (psctl_recv(conn, ch, sizeof(ch), pl, sizeof(pl), 5000) < 0) {
        fprintf(stderr, "psctl: no response from agent\n");
        return -1;
    }
    psctl_print_host(pl, fmt);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* psctl_cmd_stats                                                             */
/* -------------------------------------------------------------------------- */

int psctl_cmd_stats(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt)
{
    (void)argc; (void)argv;
    if (psctl_send(conn, "query.stats", "{}") < 0) {
        fprintf(stderr, "psctl: send failed\n");
        return -1;
    }
    char ch[CHAN_SZ], pl[PAYL_SZ];
    if (psctl_recv(conn, ch, sizeof(ch), pl, sizeof(pl), 5000) < 0) {
        fprintf(stderr, "psctl: no response from agent\n");
        return -1;
    }
    psctl_print_stats(pl, fmt);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* listen helpers                                                              */
/* -------------------------------------------------------------------------- */

struct listen_ctx {
    const char   *filter;
    enum psctl_fmt fmt;
    int            count;
};

static void listen_frame_cb(const char *channel, const char *payload, void *ud)
{
    struct listen_ctx *ctx = ud;
    if (ctx->filter && ctx->filter[0]) {
        if (strstr(channel, ctx->filter) == NULL) return;
    }
    psctl_print_event(channel, payload, ctx->fmt);
    ctx->count++;
}

/* -------------------------------------------------------------------------- */
/* psctl_cmd_listen                                                            */
/* -------------------------------------------------------------------------- */

int psctl_cmd_listen(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt)
{
    const char *filter = (argc > 0 && argv[0]) ? argv[0] : "";

    /* Subscribe to broadcast channel by sending a listen request */
    if (psctl_send(conn, "subscribe", "{}") < 0) {
        /* Non-fatal — agent may not need an explicit subscribe */
    }

    g_listen_stop = 0;
    struct sigaction sa_new, sa_old;
    memset(&sa_new, 0, sizeof(sa_new));
    sa_new.sa_handler = listen_sigint;
    sigaction(SIGINT, &sa_new, &sa_old);

    if (fmt == PSCTL_FMT_TEXT) {
        fprintf(stderr, "Listening for events%s%s... (Ctrl+C to stop)\n",
                filter[0] ? " matching " : "", filter);
    }

    struct listen_ctx ctx = { filter, fmt, 0 };

    char ch[CHAN_SZ], pl[PAYL_SZ];
    while (!g_listen_stop) {
        if (psctl_recv(conn, ch, sizeof(ch), pl, sizeof(pl), 500) == 0) {
            listen_frame_cb(ch, pl, &ctx);
        }
    }

    sigaction(SIGINT, &sa_old, NULL);

    if (fmt == PSCTL_FMT_TEXT) {
        fprintf(stderr, "\nCaptured %d event(s).\n", ctx.count);
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/* psctl_cmd_enable / disable                                                  */
/* -------------------------------------------------------------------------- */

int psctl_cmd_enable(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt)
{
    if (argc < 1 || !argv[0] || !argv[0][0]) {
        fprintf(stderr, "psctl: enable requires a module name\n");
        return -1;
    }
    char payload[256];
    snprintf(payload, sizeof(payload),
             "{\"action\":\"enable\",\"module\":\"%s\"}", argv[0]);
    if (psctl_send(conn, "discovery.control", payload) < 0) {
        fprintf(stderr, "psctl: send failed\n");
        return -1;
    }
    if (fmt == PSCTL_FMT_TEXT) {
        printf("Sent enable request for module '%s'\n", argv[0]);
    } else if (fmt == PSCTL_FMT_QUIET) {
        printf("enable\t%s\tok\n", argv[0]);
    } else {
        printf("{\"action\":\"enable\",\"module\":\"%s\",\"sent\":true}\n", argv[0]);
    }
    return 0;
}

int psctl_cmd_disable(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt)
{
    if (argc < 1 || !argv[0] || !argv[0][0]) {
        fprintf(stderr, "psctl: disable requires a module name\n");
        return -1;
    }
    char payload[256];
    snprintf(payload, sizeof(payload),
             "{\"action\":\"disable\",\"module\":\"%s\"}", argv[0]);
    if (psctl_send(conn, "discovery.control", payload) < 0) {
        fprintf(stderr, "psctl: send failed\n");
        return -1;
    }
    if (fmt == PSCTL_FMT_TEXT) {
        printf("Sent disable request for module '%s'\n", argv[0]);
    } else if (fmt == PSCTL_FMT_QUIET) {
        printf("disable\t%s\tok\n", argv[0]);
    } else {
        printf("{\"action\":\"disable\",\"module\":\"%s\",\"sent\":true}\n", argv[0]);
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/* trace/ping helpers                                                          */
/* -------------------------------------------------------------------------- */

struct trace_ctx {
    const char    *job_id;
    enum psctl_fmt fmt;
    int            done;
    int            hop_count;
};

static void trace_frame_cb(const char *channel, const char *payload, void *ud)
{
    struct trace_ctx *ctx = ud;

    /* Only handle frames matching our job_id */
    if (strstr(payload, ctx->job_id) == NULL) return;

    if (strcmp(channel, "traceroute.hop") == 0) {
        if (ctx->fmt == PSCTL_FMT_JSON) {
            printf("%s\n", payload);
        } else if (ctx->fmt == PSCTL_FMT_QUIET) {
            /* Extract hop, ip, rtt_ms */
            char hop_s[16] = "?", ip[64] = "?", rtt[32] = "?";
            /* hop number */
            char *p = strstr(payload, "\"hop\"");
            if (p) { p += 5; while (*p == ':' || *p == ' ') p++; snprintf(hop_s, sizeof(hop_s), "%lld", strtoll(p, NULL, 10)); }
            /* ip */
            p = strstr(payload, "\"ip\"");
            if (p) {
                p += 4; while (*p == ':' || *p == ' ') p++;
                if (*p == '"') { p++; int i = 0; while (*p && *p != '"' && i < 63) ip[i++] = *p++; ip[i] = '\0'; }
            }
            /* rtt */
            p = strstr(payload, "\"rtt_ms\"");
            if (p) { p += 8; while (*p == ':' || *p == ' ') p++; snprintf(rtt, sizeof(rtt), "%.2f", strtod(p, NULL)); }
            printf("%s\t%s\t%s\n", hop_s, ip, rtt);
        } else {
            /* text */
            char hop_s[16] = "?", ip[64] = "?", hostname[64] = "", rtt[32] = "?";
            char *p = strstr(payload, "\"hop\"");
            if (p) { p += 5; while (*p == ':' || *p == ' ') p++; snprintf(hop_s, sizeof(hop_s), "%lld", strtoll(p, NULL, 10)); }
            p = strstr(payload, "\"ip\"");
            if (p) {
                p += 4; while (*p == ':' || *p == ' ') p++;
                if (*p == '"') { p++; int i = 0; while (*p && *p != '"' && i < 63) ip[i++] = *p++; ip[i] = '\0'; }
            }
            p = strstr(payload, "\"hostname\"");
            if (p) {
                p += 10; while (*p == ':' || *p == ' ') p++;
                if (*p == '"') { p++; int i = 0; while (*p && *p != '"' && i < 63) hostname[i++] = *p++; hostname[i] = '\0'; }
            }
            p = strstr(payload, "\"rtt_ms\"");
            if (p) { p += 8; while (*p == ':' || *p == ' ') p++; snprintf(rtt, sizeof(rtt), "%.2f ms", strtod(p, NULL)); }

            printf(" %3s  %-40s %-40s %s\n",
                   hop_s,
                   hostname[0] ? hostname : "*",
                   ip,
                   rtt);
        }
        ctx->hop_count++;
    } else if (strcmp(channel, "traceroute.complete") == 0) {
        if (ctx->fmt == PSCTL_FMT_JSON) {
            printf("%s\n", payload);
        } else if (ctx->fmt == PSCTL_FMT_TEXT) {
            printf("Trace complete (%d hops)\n", ctx->hop_count);
        }
        ctx->done = 1;
    }
}

/* -------------------------------------------------------------------------- */
/* psctl_cmd_trace                                                             */
/* -------------------------------------------------------------------------- */

int psctl_cmd_trace(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt)
{
    if (argc < 1 || !argv[0] || !argv[0][0]) {
        fprintf(stderr, "psctl: trace requires a destination\n");
        return -1;
    }

    char job_id[32];
    snprintf(job_id, sizeof(job_id), "psctl-%d", getpid());

    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"job_id\":\"%s\",\"destination\":\"%s\","
             "\"method\":\"icmp\",\"max_hops\":30}",
             job_id, argv[0]);

    if (fmt == PSCTL_FMT_TEXT) {
        printf("Tracing route to %s (job %s)...\n", argv[0], job_id);
        printf(" HOP  %-40s %-40s RTT\n", "HOSTNAME", "IP");
    }

    if (psctl_send(conn, "traceroute.request", payload) < 0) {
        fprintf(stderr, "psctl: send failed\n");
        return -1;
    }

    struct trace_ctx ctx = { job_id, fmt, 0, 0 };
    char ch[CHAN_SZ], pl[PAYL_SZ];
    int deadline_ms = 30000;
    while (!ctx.done && deadline_ms > 0) {
        if (psctl_recv(conn, ch, sizeof(ch), pl, sizeof(pl), 500) == 0) {
            trace_frame_cb(ch, pl, &ctx);
        }
        deadline_ms -= 500;
    }
    if (!ctx.done && fmt == PSCTL_FMT_TEXT) {
        printf("Trace timed out\n");
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/* psctl_cmd_ping                                                              */
/* -------------------------------------------------------------------------- */

int psctl_cmd_ping(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt)
{
    if (argc < 1 || !argv[0] || !argv[0][0]) {
        fprintf(stderr, "psctl: ping requires a destination\n");
        return -1;
    }

    char job_id[32];
    snprintf(job_id, sizeof(job_id), "psctl-%d", getpid());

    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"job_id\":\"%s\",\"destination\":\"%s\","
             "\"method\":\"icmp\",\"max_hops\":1}",
             job_id, argv[0]);

    if (fmt == PSCTL_FMT_TEXT) {
        printf("Pinging %s (job %s)...\n", argv[0], job_id);
    }

    if (psctl_send(conn, "traceroute.request", payload) < 0) {
        fprintf(stderr, "psctl: send failed\n");
        return -1;
    }

    struct trace_ctx ctx = { job_id, fmt, 0, 0 };
    char ch[CHAN_SZ], pl[PAYL_SZ];
    int deadline_ms = 5000;
    while (!ctx.done && deadline_ms > 0) {
        if (psctl_recv(conn, ch, sizeof(ch), pl, sizeof(pl), 500) == 0) {
            trace_frame_cb(ch, pl, &ctx);
        }
        deadline_ms -= 500;
    }
    if (!ctx.done && fmt == PSCTL_FMT_TEXT) {
        printf("Ping timed out\n");
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/* psctl_cmd_probe                                                             */
/* -------------------------------------------------------------------------- */

int psctl_cmd_probe(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt)
{
    if (argc < 2 || !argv[0] || !argv[1]) {
        fprintf(stderr, "psctl: probe requires <ip> <port>\n");
        return -1;
    }

    char job_id[32];
    snprintf(job_id, sizeof(job_id), "psctl-%d", getpid());

    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"job_id\":\"%s\",\"address\":\"%s\","
             "\"ports\":[%s],\"proto\":\"tcp\"}",
             job_id, argv[0], argv[1]);

    if (psctl_send(conn, "probe.request", payload) < 0) {
        fprintf(stderr, "psctl: send failed\n");
        return -1;
    }

    if (fmt == PSCTL_FMT_TEXT) {
        printf("Probe %s:%s (job %s)...\n", argv[0], argv[1], job_id);
    }

    char ch[CHAN_SZ], pl[PAYL_SZ];
    int deadline_ms = 10000;
    while (deadline_ms > 0) {
        if (psctl_recv(conn, ch, sizeof(ch), pl, sizeof(pl), 500) == 0) {
            if (strstr(pl, job_id)) {
                psctl_print_event(ch, pl, fmt);
                /* Look for a "complete" or "result" channel */
                if (strstr(ch, "complete") || strstr(ch, "result")) break;
            }
        }
        deadline_ms -= 500;
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/* psctl_cmd_flows                                                             */
/* -------------------------------------------------------------------------- */

int psctl_cmd_flows(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt)
{
    (void)argc; (void)argv;
    if (psctl_send(conn, "query.flows", "{}") < 0) {
        fprintf(stderr, "psctl: send failed\n");
        return -1;
    }
    char ch[CHAN_SZ];
    char *pl = malloc(512 * 1024);
    if (!pl) {
        fprintf(stderr, "psctl: out of memory\n");
        return -1;
    }
    int rc = psctl_recv(conn, ch, sizeof(ch), pl, 512 * 1024, 5000);
    if (rc < 0) {
        fprintf(stderr, "psctl: no response from agent\n");
        free(pl);
        return -1;
    }
    psctl_print_flows(pl, fmt);
    free(pl);
    return 0;
}

/* -------------------------------------------------------------------------- */
/* psctl_cmd_version                                                           */
/* -------------------------------------------------------------------------- */

#ifndef PSCTL_VERSION
#define PSCTL_VERSION "0.9.0"
#endif

int psctl_cmd_version(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt)
{
    (void)argc; (void)argv;

    char agent_version[64] = "(unknown)";

    /* Try to get agent version via stats query */
    if (conn && conn->fd >= 0) {
        if (psctl_send(conn, "query.stats", "{}") == 0) {
            char ch[CHAN_SZ], pl[PAYL_SZ];
            if (psctl_recv(conn, ch, sizeof(ch), pl, sizeof(pl), 3000) == 0) {
                char *p = strstr(pl, "\"agent_version\"");
                if (p) {
                    p += 15;
                    while (*p == ':' || *p == ' ') p++;
                    if (*p == '"') {
                        p++;
                        int i = 0;
                        while (*p && *p != '"' && i < 62) agent_version[i++] = *p++;
                        agent_version[i] = '\0';
                    }
                }
            }
        }
    }

    if (fmt == PSCTL_FMT_JSON) {
        printf("{\"psctl\":\"%s\",\"agent\":\"%s\"}\n",
               PSCTL_VERSION, agent_version);
    } else if (fmt == PSCTL_FMT_QUIET) {
        printf("psctl\t%s\nagent\t%s\n", PSCTL_VERSION, agent_version);
    } else {
        printf("psctl   %s\nagent   %s\n", PSCTL_VERSION, agent_version);
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/* psctl_dispatch                                                              */
/* -------------------------------------------------------------------------- */

typedef int (*cmd_fn)(struct psctl_conn *, int, char **, enum psctl_fmt);

struct cmd_entry {
    const char *name;
    cmd_fn      fn;
};

static const struct cmd_entry cmd_table[] = {
    { "modules",  psctl_cmd_modules  },
    { "hosts",    psctl_cmd_hosts    },
    { "host",     psctl_cmd_host     },
    { "stats",    psctl_cmd_stats    },
    { "listen",   psctl_cmd_listen   },
    { "enable",   psctl_cmd_enable   },
    { "disable",  psctl_cmd_disable  },
    { "trace",    psctl_cmd_trace    },
    { "ping",     psctl_cmd_ping     },
    { "probe",    psctl_cmd_probe    },
    { "flows",    psctl_cmd_flows    },
    { "version",  psctl_cmd_version  },
    { NULL, NULL }
};

int psctl_dispatch(struct psctl_conn *conn, const char *cmd,
                   int argc, char **argv, enum psctl_fmt fmt)
{
    for (int i = 0; cmd_table[i].name; i++) {
        if (strcmp(cmd, cmd_table[i].name) == 0) {
            return cmd_table[i].fn(conn, argc, argv, fmt);
        }
    }
    fprintf(stderr, "psctl: unknown command '%s' (try 'help')\n", cmd);
    return -1;
}
