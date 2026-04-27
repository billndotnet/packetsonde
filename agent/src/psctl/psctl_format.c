#include "psctl_format.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>

/* -------------------------------------------------------------------------- */
/* ANSI color helpers                                                          */
/* -------------------------------------------------------------------------- */

static int use_color(void)
{
    return isatty(STDOUT_FILENO);
}

#define COL_CYAN    "\033[36m"
#define COL_GREEN   "\033[32m"
#define COL_RED     "\033[31m"
#define COL_YELLOW  "\033[33m"
#define COL_RESET   "\033[0m"

static const char *c(const char *code)
{
    return use_color() ? code : "";
}

/* -------------------------------------------------------------------------- */
/* Primitive JSON field extraction — no parser dependency                     */
/* -------------------------------------------------------------------------- */

/*
 * Find a JSON string value for `key`. Writes result into `out` (up to outsz-1
 * bytes, NUL-terminated). Returns 1 on success, 0 if not found.
 */
static int json_get_string(const char *json, const char *key,
                            char *out, size_t outsz)
{
    /* Build search pattern: "key": */
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) { out[0] = '\0'; return 0; }
    p += strlen(pat);
    /* skip whitespace and colon */
    while (*p == ' ' || *p == '\t' || *p == ':' || *p == ' ') p++;
    if (*p != '"') { out[0] = '\0'; return 0; }
    p++; /* skip opening quote */
    size_t i = 0;
    while (*p && *p != '"' && i < outsz - 1) {
        if (*p == '\\') { p++; if (!*p) break; }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 1;
}

/*
 * Find a JSON integer/boolean value for `key`.
 * Returns value on success, default_val on failure.
 */
static int64_t json_get_int(const char *json, const char *key, int64_t default_val)
{
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return default_val;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    if (*p == '"') return default_val; /* it's a string */
    /* handle booleans */
    if (strncmp(p, "true", 4) == 0) return 1;
    if (strncmp(p, "false", 5) == 0) return 0;
    if (strncmp(p, "null", 4) == 0) return default_val;
    return strtoll(p, NULL, 10);
}

/*
 * Iterate JSON array at `key`. For each element (which must be a JSON object),
 * call `cb(element_json, userdata)`. The element_json string is a substring of
 * json pointing at the opening `{`; it is NUL-terminated in a temporary buffer.
 */
typedef void (*json_array_cb)(const char *elem_json, void *ud);

static void json_foreach_object(const char *json, const char *key,
                                 json_array_cb cb, void *ud)
{
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return;
    p += strlen(pat);
    while (*p && *p != '[') p++;
    if (!*p) return;
    p++; /* skip '[' */

    while (*p) {
        /* skip whitespace and commas */
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',') p++;
        if (*p == ']' || !*p) break;
        if (*p != '{') { p++; continue; }

        /* Find matching closing brace */
        const char *start = p;
        int depth = 0;
        const char *end = p;
        while (*end) {
            if (*end == '{') depth++;
            else if (*end == '}') { depth--; if (depth == 0) { end++; break; } }
            end++;
        }
        /* copy into temp buffer */
        size_t len = (size_t)(end - start);
        char *tmp = malloc(len + 1);
        if (!tmp) break;
        memcpy(tmp, start, len);
        tmp[len] = '\0';
        cb(tmp, ud);
        free(tmp);
        p = end;
    }
}

/* -------------------------------------------------------------------------- */
/* psctl_print_modules                                                         */
/* -------------------------------------------------------------------------- */

struct mod_ctx {
    enum psctl_fmt fmt;
    int count;
};

static void print_module_elem(const char *elem, void *ud)
{
    struct mod_ctx *ctx = ud;
    char name[64], status[32], type[32];
    int64_t events;

    json_get_string(elem, "name",   name,   sizeof(name));
    json_get_string(elem, "status", status, sizeof(status));
    json_get_string(elem, "type",   type,   sizeof(type));
    events = json_get_int(elem, "events", 0);

    int enabled = (strcmp(status, "enabled") == 0);

    if (ctx->fmt == PSCTL_FMT_TEXT) {
        const char *scol = enabled ? c(COL_GREEN) : c(COL_RED);
        printf("%-20s %s%-8s%s %7lld  %s\n",
               name, scol, status, c(COL_RESET),
               (long long)events, type);
    } else if (ctx->fmt == PSCTL_FMT_QUIET) {
        printf("%s\t%s\t%lld\t%s\n",
               name, status, (long long)events, type);
    }
    ctx->count++;
}

void psctl_print_modules(const char *json, enum psctl_fmt fmt)
{
    if (fmt == PSCTL_FMT_JSON) {
        printf("%s\n", json);
        return;
    }

    if (fmt == PSCTL_FMT_TEXT) {
        printf("%s%-20s %-8s  %7s  %-10s%s\n",
               c(COL_CYAN), "MODULE", "STATUS", "EVENTS", "TYPE", c(COL_RESET));
    }

    struct mod_ctx ctx = { fmt, 0 };
    json_foreach_object(json, "modules", print_module_elem, &ctx);

    if (fmt == PSCTL_FMT_TEXT && ctx.count == 0) {
        printf("(no modules)\n");
    }
}

/* -------------------------------------------------------------------------- */
/* psctl_print_hosts                                                           */
/* -------------------------------------------------------------------------- */

struct host_ctx {
    enum psctl_fmt fmt;
    int count;
};

static void print_host_elem(const char *elem, void *ud)
{
    struct host_ctx *ctx = ud;
    char ip[64], mac[32], hostname[64], sources[128];
    int64_t last_seen;

    json_get_string(elem, "ip",       ip,       sizeof(ip));
    json_get_string(elem, "mac",      mac,      sizeof(mac));
    json_get_string(elem, "hostname", hostname, sizeof(hostname));
    json_get_string(elem, "sources",  sources,  sizeof(sources));
    last_seen = json_get_int(elem, "last_seen_usec", 0);

    /* Compute "N ago" string */
    char ago[32] = "?";
    if (last_seen > 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        int64_t now_usec = (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
        int64_t delta_s = (now_usec - last_seen) / 1000000;
        if (delta_s < 0) delta_s = 0;
        if (delta_s < 60)
            snprintf(ago, sizeof(ago), "%llds ago", (long long)delta_s);
        else if (delta_s < 3600)
            snprintf(ago, sizeof(ago), "%lldm ago", (long long)(delta_s / 60));
        else
            snprintf(ago, sizeof(ago), "%lldh ago", (long long)(delta_s / 3600));
    }

    if (ctx->fmt == PSCTL_FMT_TEXT) {
        printf("%-20s %-18s %-20s %-16s %s\n",
               ip, mac, hostname, sources, ago);
    } else if (ctx->fmt == PSCTL_FMT_QUIET) {
        printf("%s\t%s\t%s\t%s\t%s\n",
               ip, mac, hostname, sources, ago);
    }
    ctx->count++;
}

void psctl_print_hosts(const char *json, enum psctl_fmt fmt)
{
    if (fmt == PSCTL_FMT_JSON) {
        printf("%s\n", json);
        return;
    }

    if (fmt == PSCTL_FMT_TEXT) {
        printf("%s%-20s %-18s %-20s %-16s %s%s\n",
               c(COL_CYAN),
               "IP", "MAC", "HOSTNAME", "SOURCES", "LAST SEEN",
               c(COL_RESET));
    }

    struct host_ctx ctx = { fmt, 0 };
    json_foreach_object(json, "hosts", print_host_elem, &ctx);

    if (fmt == PSCTL_FMT_TEXT && ctx.count == 0) {
        printf("(no hosts)\n");
    }
}

/* -------------------------------------------------------------------------- */
/* psctl_print_host                                                            */
/* -------------------------------------------------------------------------- */

void psctl_print_host(const char *json, enum psctl_fmt fmt)
{
    if (fmt == PSCTL_FMT_JSON) {
        printf("%s\n", json);
        return;
    }

    char ip[64], mac[32], hostname[64], vendor[64], os[64], sources[128];
    int64_t first_seen, last_seen;

    json_get_string(json, "ip",       ip,       sizeof(ip));
    json_get_string(json, "mac",      mac,      sizeof(mac));
    json_get_string(json, "hostname", hostname, sizeof(hostname));
    json_get_string(json, "vendor",   vendor,   sizeof(vendor));
    json_get_string(json, "os",       os,       sizeof(os));
    json_get_string(json, "sources",  sources,  sizeof(sources));
    first_seen = json_get_int(json, "first_seen_usec", 0);
    last_seen  = json_get_int(json, "last_seen_usec",  0);

    if (fmt == PSCTL_FMT_TEXT) {
        printf("%sHost: %s%s%s\n", c(COL_CYAN), c(COL_RESET), ip, "");
        printf("  %-16s %s\n", "MAC:",      mac[0]      ? mac      : "(unknown)");
        printf("  %-16s %s\n", "Hostname:", hostname[0] ? hostname : "(unknown)");
        printf("  %-16s %s\n", "Vendor:",   vendor[0]   ? vendor   : "(unknown)");
        printf("  %-16s %s\n", "OS:",       os[0]       ? os       : "(unknown)");
        printf("  %-16s %s\n", "Sources:",  sources[0]  ? sources  : "(none)");

        if (first_seen > 0) {
            time_t t = (time_t)(first_seen / 1000000);
            char tbuf[64];
            strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&t));
            printf("  %-16s %s\n", "First seen:", tbuf);
        }
        if (last_seen > 0) {
            time_t t = (time_t)(last_seen / 1000000);
            char tbuf[64];
            strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&t));
            printf("  %-16s %s\n", "Last seen:", tbuf);
        }
    } else {
        /* quiet: tab-separated key=value */
        printf("ip=%s\tmac=%s\thostname=%s\tvendor=%s\tos=%s\tsources=%s\n",
               ip, mac, hostname, vendor, os, sources);
    }
}

/* -------------------------------------------------------------------------- */
/* psctl_print_stats                                                           */
/* -------------------------------------------------------------------------- */

void psctl_print_stats(const char *json, enum psctl_fmt fmt)
{
    if (fmt == PSCTL_FMT_JSON) {
        printf("%s\n", json);
        return;
    }

    char version[32], build_date[64];
    int64_t host_count, module_count, clients;
    int64_t uptime_sec;

    json_get_string(json, "agent_version", version,    sizeof(version));
    json_get_string(json, "build_date",    build_date, sizeof(build_date));
    host_count   = json_get_int(json, "host_count",        0);
    module_count = json_get_int(json, "module_count",       0);
    clients      = json_get_int(json, "clients_connected",  0);
    uptime_sec   = json_get_int(json, "uptime_sec",         0);

    if (fmt == PSCTL_FMT_TEXT) {
        printf("%sAgent Stats%s\n", c(COL_CYAN), c(COL_RESET));
        printf("  %-20s %s\n", "Version:", version[0] ? version : "(unknown)");
        if (build_date[0])
            printf("  %-20s %s\n", "Build date:", build_date);
        printf("  %-20s %lld\n", "Hosts tracked:", (long long)host_count);
        printf("  %-20s %lld\n", "Modules active:", (long long)module_count);
        printf("  %-20s %lld\n", "IPC clients:", (long long)clients);
        if (uptime_sec > 0) {
            long long h = uptime_sec / 3600;
            long long m = (uptime_sec % 3600) / 60;
            long long s = uptime_sec % 60;
            printf("  %-20s %lldh %02lldm %02llds\n", "Uptime:", h, m, s);
        }
    } else {
        printf("version=%s\thosts=%lld\tmodules=%lld\tclients=%lld\tuptime=%lld\n",
               version,
               (long long)host_count, (long long)module_count,
               (long long)clients, (long long)uptime_sec);
    }
}

/* -------------------------------------------------------------------------- */
/* psctl_print_flows                                                           */
/* -------------------------------------------------------------------------- */

struct flow_ctx {
    enum psctl_fmt fmt;
    int count;
};

static const char *proto_name(int64_t proto)
{
    switch (proto) {
        case 1:  return "ICMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        default: return "???";
    }
}

static void print_flow_elem(const char *elem, void *ud)
{
    struct flow_ctx *ctx = ud;

    char src_ip[64], dst_ip[64];
    int64_t proto, src_port, dst_port;
    int64_t pkt_fwd, pkt_rev, bytes_fwd, bytes_rev, duration;

    json_get_string(elem, "src_ip",       src_ip,  sizeof(src_ip));
    json_get_string(elem, "dst_ip",       dst_ip,  sizeof(dst_ip));
    proto     = json_get_int(elem, "proto",        0);
    src_port  = json_get_int(elem, "src_port",     0);
    dst_port  = json_get_int(elem, "dst_port",     0);
    pkt_fwd   = json_get_int(elem, "packets_fwd",  0);
    pkt_rev   = json_get_int(elem, "packets_rev",  0);
    bytes_fwd = json_get_int(elem, "bytes_fwd",    0);
    bytes_rev = json_get_int(elem, "bytes_rev",    0);
    duration  = json_get_int(elem, "duration_sec", 0);

    /* Format endpoint strings as "ip:port" */
    char src_ep[96], dst_ep[96];
    if (src_port > 0)
        snprintf(src_ep, sizeof(src_ep), "%s:%-5lld", src_ip, (long long)src_port);
    else
        snprintf(src_ep, sizeof(src_ep), "%s", src_ip);
    if (dst_port > 0)
        snprintf(dst_ep, sizeof(dst_ep), "%s:%-5lld", dst_ip, (long long)dst_port);
    else
        snprintf(dst_ep, sizeof(dst_ep), "%s", dst_ip);

    int64_t total_bytes = bytes_fwd + bytes_rev;
    int64_t total_pkts  = pkt_fwd  + pkt_rev;

    if (ctx->fmt == PSCTL_FMT_TEXT) {
        printf("%-28s %-28s %-4s %8lld %8lldB %llds\n",
               src_ep, dst_ep,
               proto_name(proto),
               (long long)total_pkts,
               (long long)total_bytes,
               (long long)duration);
    } else if (ctx->fmt == PSCTL_FMT_QUIET) {
        printf("%s\t%s\t%lld\t%lld\t%lld\t%lld\t%lld\t%lld\n",
               src_ep, dst_ep,
               (long long)proto,
               (long long)pkt_fwd,  (long long)pkt_rev,
               (long long)bytes_fwd,(long long)bytes_rev,
               (long long)duration);
    }
    ctx->count++;
}

void psctl_print_flows(const char *json, enum psctl_fmt fmt)
{
    if (fmt == PSCTL_FMT_JSON) {
        printf("%s\n", json);
        return;
    }

    int64_t flow_count = json_get_int(json, "flow_count", 0);

    if (fmt == PSCTL_FMT_TEXT) {
        printf("%s%-28s %-28s %-4s %8s %9s %s%s\n",
               c(COL_CYAN),
               "SRC (ip:port)", "DST (ip:port)", "PROTO",
               "PKTS", "BYTES", "DUR",
               c(COL_RESET));
    }

    struct flow_ctx ctx = { fmt, 0 };
    json_foreach_object(json, "flows", print_flow_elem, &ctx);

    if (fmt == PSCTL_FMT_TEXT) {
        if (ctx.count == 0)
            printf("(no active flows)\n");
        else
            printf("\n%lld total active flow(s), showing %d\n",
                   (long long)flow_count, ctx.count);
    }
}

/* -------------------------------------------------------------------------- */
/* psctl_print_event                                                           */
/* -------------------------------------------------------------------------- */

void psctl_print_event(const char *channel, const char *payload, enum psctl_fmt fmt)
{
    if (fmt == PSCTL_FMT_JSON) {
        printf("{\"channel\":\"%s\",\"payload\":%s}\n", channel, payload);
        return;
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm_info = localtime(&ts.tv_sec);
    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%H:%M:%S", tm_info);

    if (fmt == PSCTL_FMT_TEXT) {
        printf("%s[%s]%s %s%s%s  %s\n",
               c(COL_YELLOW), tbuf, c(COL_RESET),
               c(COL_CYAN), channel, c(COL_RESET),
               payload);
    } else {
        printf("%s\t%s\t%s\n", tbuf, channel, payload);
    }
}

/* -------------------------------------------------------------------------- */
/* psctl_print_help                                                            */
/* -------------------------------------------------------------------------- */

void psctl_print_help(void)
{
    printf("%spsctl — packetsonde agent control%s\n\n", c(COL_CYAN), c(COL_RESET));
    printf("Commands:\n");
    printf("  %-20s %s\n", "modules",         "List all discovery modules and their status");
    printf("  %-20s %s\n", "hosts",           "List all discovered hosts");
    printf("  %-20s %s\n", "host <ip>",       "Show full detail for a specific host");
    printf("  %-20s %s\n", "stats",           "Show agent statistics");
    printf("  %-20s %s\n", "listen [filter]", "Stream live discovery events (Ctrl+C to stop)");
    printf("  %-20s %s\n", "enable <module>", "Enable a discovery module");
    printf("  %-20s %s\n", "disable <module>","Disable a discovery module");
    printf("  %-20s %s\n", "trace <host>",    "Run a traceroute to a host");
    printf("  %-20s %s\n", "ping <host>",     "Ping a host");
    printf("  %-20s %s\n", "probe <ip> <port>","TCP port probe");
    printf("  %-20s %s\n", "flows",           "Show active flow table (top 500 by bytes)");
    printf("  %-20s %s\n", "version",         "Show psctl and agent version");
    printf("  %-20s %s\n", "help",            "Show this help");
    printf("  %-20s %s\n", "exit / quit",     "Exit interactive shell");
    printf("\nOptions:\n");
    printf("  %-20s %s\n", "-s/--socket PATH", "Agent socket path (default: /tmp/packetsonde-agent.sock)");
    printf("  %-20s %s\n", "-j/--json",        "Output raw JSON");
    printf("  %-20s %s\n", "-q/--quiet",       "Tab-separated output for scripting");
    printf("  %-20s %s\n", "-h/--help",        "Show usage");
}
