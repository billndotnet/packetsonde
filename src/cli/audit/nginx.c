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
 * audit nginx -- detect nginx + version, look for the classic stub_status
 * exposure.
 *
 * Probes (plain HTTP, port 80 by default; pass host:port for other):
 *   GET /              -> Server header parses 'nginx/X.Y.Z'
 *   GET /nginx_status  -> stub_status_module response is:
 *
 *     Active connections: 12
 *     server accepts handled requests
 *      1234 1234 5678
 *     Reading: 0 Writing: 1 Waiting: 11
 *
 *   When /nginx_status returns 200 with that shape, the operator has
 *   exposed nginx's request-tracking page to the world. That's a real
 *   information-leak finding -- request rates, concurrent connections,
 *   often used in attack-surface scans.
 *
 * Findings:
 *   nginx.metadata          info    always; detected flag + server header
 *   nginx.version_disclosed low     emitted when Server: nginx/X.Y.Z
 *   nginx.status_exposed    medium  /nginx_status returns the stub_status body
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
        "User-Agent: packetsonde/audit-nginx\r\n"
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

/* True if Server header begins with "nginx" (case-sensitive — nginx
 * always lowercases its product token). Captures the version suffix
 * after "nginx/" into version_out. */
static int parse_nginx_server(const char *server, char *version_out, size_t v_sz) {
    version_out[0] = '\0';
    if (strncmp(server, "nginx", 5) != 0) return 0;
    if (server[5] == '/' ) {
        size_t k = 0;
        for (size_t i = 6; server[i] && k + 1 < v_sz; i++) {
            char c = server[i];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') break;
            version_out[k++] = c;
        }
        version_out[k] = '\0';
    }
    return 1;
}

/* Body sniff: stub_status_module's signature line "Active connections: <N>"
 * is unambiguous — it's hardcoded in nginx's source. */
static int is_stub_status_body(const char *resp) {
    const char *body = strstr(resp, "\r\n\r\n");
    if (!body) return 0;
    body += 4;
    return strstr(body, "Active connections:") != NULL
        && strstr(body, "server accepts handled requests") != NULL;
}

static int nginx_run(int argc, char **argv,
                     const struct ps_args *opts,
                     const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit nginx <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 80;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit nginx: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    char ip[64] = "", root_resp[16384], status_resp[16384];
    int n_root = http_get(host, port, "/", 4000,
                          root_resp, sizeof(root_resp), ip, sizeof(ip));
    if (n_root < 0) {
        fprintf(stderr, "audit nginx: cannot reach %s:%u\n", host, port);
        return 1;
    }
    int n_status = http_get(host, port, "/nginx_status", 4000,
                            status_resp, sizeof(status_resp), NULL, 0);

    char server[128] = "", version[64] = "";
    extract_server(root_resp, server, sizeof(server));
    int detected = parse_nginx_server(server, version, sizeof(version));

    int status_code = (n_status > 0) ? response_status(status_resp) : 0;
    int status_exposed = (status_code == 200) && is_stub_status_body(status_resp);

    char ev[640];
    snprintf(ev, sizeof(ev),
             "{\"detected\":%s,\"server\":\"%s\",\"version\":\"%s\","
             "\"stub_status_code\":%d,\"stub_status_exposed\":%s}",
             detected ? "true" : "false", server, version,
             status_code, status_exposed ? "true" : "false");
    char title[256];
    if (detected && version[0]) {
        snprintf(title, sizeof(title), "nginx %s at %s:%u", version, host, port);
    } else if (detected) {
        snprintf(title, sizeof(title), "nginx (version suppressed) at %s:%u", host, port);
    } else {
        snprintf(title, sizeof(title), "No nginx signature at %s:%u", host, port);
    }
    struct ps_finding f;
    ps_finding_init(&f, run_id, "cli.audit.nginx", self_host,
                    "nginx.metadata", PS_SEV_INFO, PS_CONF_FIRM, title);
    ps_finding_set_target_ip(&f, ip, port);
    ps_finding_set_target_hostname(&f, host, port);
    ps_finding_set_evidence_json(&f, ev);
    api->emit(&f);

    if (detected && version[0]) {
        char ev2[160];
        snprintf(ev2, sizeof(ev2), "{\"version\":\"%s\"}", version);
        char title2[160];
        snprintf(title2, sizeof(title2),
                 "nginx version disclosed in Server header: %s", version);
        struct ps_finding f2;
        ps_finding_init(&f2, run_id, "cli.audit.nginx", self_host,
                        "nginx.version_disclosed", PS_SEV_LOW, PS_CONF_FIRM, title2);
        ps_finding_set_target_ip(&f2, ip, port);
        ps_finding_set_target_hostname(&f2, host, port);
        ps_finding_set_evidence_json(&f2, ev2);
        api->emit(&f2);
    }

    if (status_exposed) {
        const char *body = strstr(status_resp, "\r\n\r\n");
        body = body ? body + 4 : status_resp;
        /* Pull the first three lines as evidence — that's the canonical
         * stub_status output minus the trailing connection-state line. */
        char body_clip[512]; size_t k = 0;
        int nl = 0;
        for (size_t i = 0; body[i] && k + 1 < sizeof(body_clip); i++) {
            char c = body[i];
            if (c == '\n' && ++nl >= 3) { body_clip[k++] = c; break; }
            if (c == '"' || c == '\\') {
                if (k + 2 >= sizeof(body_clip)) break;
                body_clip[k++] = '\\'; body_clip[k++] = c;
            } else if (c == '\n') {
                if (k + 2 >= sizeof(body_clip)) break;
                body_clip[k++] = '\\'; body_clip[k++] = 'n';
            } else if (c == '\r') {
                /* skip */
            } else if (c >= 0x20 && c < 0x7f) {
                body_clip[k++] = c;
            }
        }
        body_clip[k] = '\0';
        char ev3[640];
        snprintf(ev3, sizeof(ev3),
                 "{\"path\":\"/nginx_status\",\"status\":%d,\"body_head\":\"%s\"}",
                 status_code, body_clip);
        struct ps_finding f3;
        ps_finding_init(&f3, run_id, "cli.audit.nginx", self_host,
                        "nginx.status_exposed", PS_SEV_MEDIUM, PS_CONF_FIRM,
                        "nginx stub_status page is publicly reachable");
        ps_finding_set_target_ip(&f3, ip, port);
        ps_finding_set_target_hostname(&f3, host, port);
        ps_finding_set_evidence_json(&f3, ev3);
        api->emit(&f3);
    }
    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "nginx",
    .summary     = "Audit nginx: server header, exposed /nginx_status",
    .run         = nginx_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_nginx_module(void) { return &MODULE; }
