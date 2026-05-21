#include "audit_module.h"
#include "audit_common.h"
#include "../args.h"
#include "finding.h"
#include "ulid.h"

#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * audit haproxy -- fingerprint a HAProxy frontend or stats endpoint.
 *
 * HAProxy itself is usually transparent — it proxies HTTP/TCP without
 * announcing itself. The two reliable signatures:
 *
 *  1. The /stats page (default URL when `stats enable` is in the config).
 *     Returns an HTML report titled "Statistics Report for pid ..." with
 *     "HAProxy" in the body. Frequently exposed unintentionally; if it's
 *     reachable without auth that's a real finding.
 *
 *  2. Server: header on error pages. HAProxy emits a `Server` header
 *     (typically just "HAProxy" or absent) and an X-* family of headers
 *     in some configs.
 *
 * Default port for the audit is 80 (plain HTTP); operators wanting to
 * audit the dedicated stats listener (often 9000 or 8404) or HTTPS pass
 * the target as host:port. Bracketed IPv6 supported via audit_common.
 *
 * Findings:
 *   haproxy.metadata        info     emitted when any HAProxy signature is matched
 *   haproxy.stats_exposed   high     /stats reachable + identifies as HAProxy report
 */

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    return ps_audit_parse_target(spec, host, host_sz, 80, port);
}

/* Plain HTTP GET. Returns response length on success, -1 otherwise. */
static int http_get(const char *host, uint16_t port, const char *path,
                    int timeout_ms, char *resp, size_t resp_cap,
                    char *ip_out, size_t ip_out_sz) {
    int fd = ps_audit_tcp_connect(host, port, timeout_ms, ip_out, ip_out_sz);
    if (fd < 0) return -1;

    char req[512];
    int rlen = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "User-Agent: packetsonde/audit-haproxy\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n",
        path, host, port);
    if (rlen < 0 || send(fd, req, (size_t)rlen, 0) != (ssize_t)rlen) {
        close(fd); return -1;
    }

    size_t total = 0;
    while (total < resp_cap - 1) {
        ssize_t r = recv(fd, resp + total, resp_cap - 1 - total, 0);
        if (r <= 0) break;
        total += (size_t)r;
    }
    resp[total] = '\0';
    close(fd);
    return (int)total;
}

static void extract_server(const char *resp, char *out, size_t out_sz) {
    out[0] = '\0';
    const char *p = strstr(resp, "\r\nServer:");
    if (!p) return;
    p += 9;
    while (*p == ' ') p++;
    const char *eol = strstr(p, "\r\n");
    if (!eol) return;
    size_t L = (size_t)(eol - p);
    if (L >= out_sz) L = out_sz - 1;
    memcpy(out, p, L); out[L] = '\0';
}

static int response_status(const char *resp) {
    if (strncmp(resp, "HTTP/", 5) != 0) return 0;
    const char *sp = strchr(resp, ' ');
    return sp ? atoi(sp + 1) : 0;
}

static int haproxy_run(int argc, char **argv,
                       const struct ps_args *opts,
                       const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit haproxy <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 80;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit haproxy: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    /* Two GETs:
     *   /        — gather Server header, status, body
     *   /stats   — look for the HAProxy Statistics Report */
    char ip[64] = "", root_resp[32768], stats_resp[32768];
    int n_root  = http_get(host, port, "/",      4000,
                           root_resp,  sizeof(root_resp),  ip, sizeof(ip));
    if (n_root < 0) {
        fprintf(stderr, "audit haproxy: cannot reach %s:%u\n", host, port);
        return 1;
    }
    int n_stats = http_get(host, port, "/stats", 4000,
                           stats_resp, sizeof(stats_resp), NULL, 0);

    char server[128] = "";
    extract_server(root_resp, server, sizeof(server));

    int stats_status = (n_stats > 0) ? response_status(stats_resp) : 0;
    int stats_is_haproxy = (n_stats > 0) &&
                           (strstr(stats_resp, "Statistics Report for") != NULL
                            || strstr(stats_resp, "HAProxy") != NULL);

    /* Detection signals: Server header mentions haproxy (case-insensitive),
     * or /stats matched the HAProxy report signature. */
    int server_hints_haproxy = 0;
    {
        char lc[128] = "";
        for (size_t i = 0; server[i] && i + 1 < sizeof(lc); i++) {
            lc[i] = (server[i] >= 'A' && server[i] <= 'Z')
                  ? (char)(server[i] + 32) : server[i];
            lc[i + 1] = '\0';
        }
        if (strstr(lc, "haproxy")) server_hints_haproxy = 1;
    }
    int detected = server_hints_haproxy || stats_is_haproxy;

    char ev[640];
    snprintf(ev, sizeof(ev),
             "{\"detected\":%s,\"server\":\"%s\","
             "\"stats_status\":%d,\"stats_is_haproxy\":%s}",
             detected ? "true" : "false", server,
             stats_status, stats_is_haproxy ? "true" : "false");
    char title[256];
    if (detected) {
        snprintf(title, sizeof(title),
                 "HAProxy detected at %s:%u%s",
                 host, port,
                 server_hints_haproxy ? " (Server header)" : " (stats page)");
    } else {
        snprintf(title, sizeof(title), "No HAProxy signature at %s:%u", host, port);
    }
    struct ps_finding f;
    ps_finding_init(&f, run_id, "cli.audit.haproxy", self_host,
                    "haproxy.metadata", PS_SEV_INFO, PS_CONF_FIRM, title);
    ps_finding_set_target_ip(&f, ip, port);
    ps_finding_set_target_hostname(&f, host, port);
    ps_finding_set_evidence_json(&f, ev);
    api->emit(&f);

    if (stats_is_haproxy && stats_status == 200) {
        char ev2[256];
        snprintf(ev2, sizeof(ev2), "{\"status\":%d}", stats_status);
        struct ps_finding f2;
        ps_finding_init(&f2, run_id, "cli.audit.haproxy", self_host,
                        "haproxy.stats_exposed", PS_SEV_HIGH, PS_CONF_FIRM,
                        "HAProxy /stats page returned 200 OK without auth");
        ps_finding_set_target_ip(&f2, ip, port);
        ps_finding_set_target_hostname(&f2, host, port);
        ps_finding_set_evidence_json(&f2, ev2);
        api->emit(&f2);
    }
    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "haproxy",
    .summary     = "Audit HAProxy: server-header detect, exposed /stats page",
    .run         = haproxy_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_haproxy_module(void) { return &MODULE; }
