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

#include <openssl/err.h>
#include <openssl/ssl.h>

/*
 * audit proxmox -- fingerprint a Proxmox VE web UI / API endpoint.
 *
 * Proxmox VE listens on 8006/tcp (HTTPS) by default. The /api2/json/version
 * endpoint usually returns the running version+release without auth:
 *   {"data":{"version":"7.4-13","repoid":"08ee72e4","release":"7.4"}}
 *
 * If the cluster requires auth even for that, we still detect Proxmox
 * from the login page's HTML title or from the `Server: pve-api-daemon`
 * header.
 *
 * Findings:
 *   proxmox.metadata    info  always emitted; signals detection + version
 *   proxmox.old_version medium  PVE < 7.0 (released July 2021)
 */

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    return ps_audit_parse_target(spec, host, host_sz, 8006, port);
}

/* Open a TLS connection to host:port and issue a single GET request.
 * Writes the raw response (headers + body) into resp. Returns response
 * length on success, -1 on failure. */
static int https_get(const char *host, uint16_t port, const char *path,
                     int timeout_ms, char *resp, size_t resp_cap,
                     char *ip_out, size_t ip_out_sz) {
    int fd = ps_audit_tcp_connect(host, port, timeout_ms, ip_out, ip_out_sz);
    if (fd < 0) return -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); return -1; }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);  /* audits don't require trust */
    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(fd); return -1; }
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd); return -1;
    }

    char req[1024];
    int rlen = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "User-Agent: packetsonde/audit-proxmox\r\n"
        "Accept: application/json,text/html;q=0.9\r\n"
        "Connection: close\r\n\r\n",
        path, host, port);
    if (rlen < 0 || SSL_write(ssl, req, rlen) != rlen) {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd); return -1;
    }

    size_t total = 0;
    while (total < resp_cap - 1) {
        int r = SSL_read(ssl, resp + total, (int)(resp_cap - 1 - total));
        if (r <= 0) break;
        total += (size_t)r;
    }
    resp[total] = '\0';

    SSL_shutdown(ssl);
    SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
    return (int)total;
}

/* Extract "version":"X.Y-Z" from a JSON response body. */
static int extract_version(const char *resp, char *out, size_t out_sz) {
    const char *p = strstr(resp, "\"version\":\"");
    if (!p) return -1;
    p += 11;
    const char *q = strchr(p, '"');
    if (!q) return -1;
    size_t L = (size_t)(q - p);
    if (L >= out_sz) L = out_sz - 1;
    memcpy(out, p, L); out[L] = '\0';
    return 0;
}

/* Server header value. */
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

/* PVE major version comparison. Old = major < 7. */
static int is_old(const char *version) {
    int major = atoi(version);
    return major > 0 && major < 7;
}

static int proxmox_run(int argc, char **argv,
                       const struct ps_args *opts,
                       const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit proxmox <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 8006;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit proxmox: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    char ip[64] = "", resp[16384];
    int n = https_get(host, port, "/api2/json/version", 5000,
                      resp, sizeof(resp), ip, sizeof(ip));
    if (n < 0) {
        fprintf(stderr, "audit proxmox: cannot reach %s:%u\n", host, port);
        return 1;
    }

    char version[64] = "", server[128] = "";
    int have_version = (extract_version(resp, version, sizeof(version)) == 0);
    extract_server(resp, server, sizeof(server));

    /* Detect Proxmox even without /api2 access: Server header
     * "pve-api-daemon" or HTML title containing "Proxmox VE Login". */
    int detected = have_version
                 || strstr(server, "pve-api-daemon") != NULL
                 || strstr(resp, "Proxmox VE") != NULL;

    char ev[512];
    snprintf(ev, sizeof(ev),
             "{\"detected\":%s,\"version\":\"%s\",\"server\":\"%s\"}",
             detected ? "true" : "false", version, server);
    char title[256];
    if (have_version) {
        snprintf(title, sizeof(title), "Proxmox VE %s", version);
    } else if (detected) {
        snprintf(title, sizeof(title), "Proxmox VE (version not disclosed)");
    } else {
        snprintf(title, sizeof(title), "No Proxmox signature at %s:%u", host, port);
    }
    struct ps_finding f;
    ps_finding_init(&f, run_id, "cli.audit.proxmox", self_host,
                    "proxmox.metadata", PS_SEV_INFO, PS_CONF_FIRM, title);
    ps_finding_set_target_ip(&f, ip, port);
    ps_finding_set_target_hostname(&f, host, port);
    ps_finding_set_evidence_json(&f, ev);
    api->emit(&f);

    if (have_version && is_old(version)) {
        char ev2[256];
        snprintf(ev2, sizeof(ev2),
                 "{\"version\":\"%s\",\"recommended_minimum\":\"7.0\"}", version);
        char title2[256];
        snprintf(title2, sizeof(title2),
                 "Proxmox VE %s is older than 7.0 (released Jul 2021)", version);
        struct ps_finding f2;
        ps_finding_init(&f2, run_id, "cli.audit.proxmox", self_host,
                        "proxmox.old_version", PS_SEV_MEDIUM, PS_CONF_FIRM, title2);
        ps_finding_set_target_ip(&f2, ip, port);
        ps_finding_set_target_hostname(&f2, host, port);
        ps_finding_set_evidence_json(&f2, ev2);
        api->emit(&f2);
    }
    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "proxmox",
    .summary     = "Audit Proxmox VE: version disclosure, old-release check",
    .run         = proxmox_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_proxmox_module(void) { return &MODULE; }
