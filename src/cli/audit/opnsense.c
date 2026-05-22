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
#include <openssl/x509v3.h>

/*
 * audit opnsense -- detect an OPNsense web admin endpoint.
 *
 * The login page is HTTPS on port 443. Two reliable identifiers:
 *   - "Server: OPNsense" response header (set by the embedded lighttpd)
 *   - "OPNsense" in the login page <title>
 *
 * We also capture the TLS cert subject CN so operators can inventory
 * which OPNsense instance is on which host. Version isn't disclosed at
 * the root URL (the firmware-status endpoint requires auth) so we don't
 * try to chase it here.
 *
 * Findings:
 *   opnsense.metadata    info  always; detected flag + cert subject CN
 */

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    return ps_audit_parse_target(spec, host, host_sz, 443, port);
}

/* HTTPS GET / and capture both the response and the peer cert subject CN.
 * Returns response length on success, -1 on failure. */
static int https_get_with_cn(const char *host, uint16_t port,
                             int timeout_ms,
                             char *resp, size_t resp_cap,
                             char *cn_out, size_t cn_out_sz,
                             char *ip_out, size_t ip_out_sz) {
    cn_out[0] = '\0';
    int fd = ps_audit_tcp_connect(host, port, timeout_ms, ip_out, ip_out_sz);
    if (fd < 0) return -1;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); return -1; }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(fd); return -1; }
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd); return -1;
    }

    /* Capture cert subject CN — cheap and useful for inventory. */
    X509 *peer = SSL_get_peer_certificate(ssl);
    if (peer) {
        X509_NAME *subj = X509_get_subject_name(peer);
        if (subj) X509_NAME_get_text_by_NID(subj, NID_commonName,
                                            cn_out, (int)cn_out_sz);
        X509_free(peer);
    }

    char req[512];
    int rlen = snprintf(req, sizeof(req),
        "GET / HTTP/1.1\r\n"
        "Host: %s:%u\r\n"
        "User-Agent: packetsonde/audit-opnsense\r\n"
        "Accept: text/html\r\n"
        "Connection: close\r\n\r\n",
        host, port);
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

static int opnsense_run(int argc, char **argv,
                        const struct ps_args *opts,
                        const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit opnsense <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 443;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit opnsense: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    char ip[64] = "", resp[32768], cn[256] = "";
    int n = https_get_with_cn(host, port, 5000,
                              resp, sizeof(resp), cn, sizeof(cn),
                              ip, sizeof(ip));
    if (n < 0) {
        fprintf(stderr, "audit opnsense: cannot reach %s:%u\n", host, port);
        return 1;
    }

    char server[128] = "";
    extract_server(resp, server, sizeof(server));

    /* Detection: Server header == "OPNsense" is the cleanest signal; the
     * HTML title fallback covers reverse-proxy setups that rewrite the
     * upstream Server header. */
    int server_hits = (strstr(server, "OPNsense") != NULL);
    int title_hits  = (strstr(resp,   "Login | OPNsense") != NULL
                       || strstr(resp, "<title>OPNsense") != NULL);
    int detected    = server_hits || title_hits;

    /* JSON-escape the cert CN — operators sometimes use quirky values. */
    char cn_esc[512]; size_t k = 0;
    for (size_t i = 0; cn[i] && k + 2 < sizeof(cn_esc); i++) {
        unsigned char c = (unsigned char)cn[i];
        if (c == '"' || c == '\\') { cn_esc[k++] = '\\'; cn_esc[k++] = (char)c; }
        else if (c >= 0x20 && c < 0x7f) cn_esc[k++] = (char)c;
    }
    cn_esc[k] = '\0';

    char ev[768];
    snprintf(ev, sizeof(ev),
             "{\"detected\":%s,\"server\":\"%s\",\"cert_cn\":\"%s\","
             "\"server_header_match\":%s,\"title_match\":%s}",
             detected ? "true" : "false", server, cn_esc,
             server_hits ? "true" : "false",
             title_hits  ? "true" : "false");
    char title[320];
    if (detected) {
        snprintf(title, sizeof(title),
                 "OPNsense web UI at %s:%u%s%s",
                 host, port,
                 cn_esc[0] ? " (cert CN=" : "",
                 cn_esc[0] ? cn_esc       : "");
        /* close the paren if we opened one */
        if (cn_esc[0]) {
            size_t tl = strlen(title);
            if (tl + 1 < sizeof(title)) { title[tl] = ')'; title[tl + 1] = '\0'; }
        }
    } else {
        snprintf(title, sizeof(title), "No OPNsense signature at %s:%u", host, port);
    }
    struct ps_finding f;
    ps_finding_init(&f, run_id, "cli.audit.opnsense", self_host,
                    "opnsense.metadata", PS_SEV_INFO, PS_CONF_FIRM, title);
    ps_finding_set_target_ip(&f, ip, port);
    ps_finding_set_target_hostname(&f, host, port);
    ps_finding_set_evidence_json(&f, ev);
    api->emit(&f);

    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "opnsense",
    .summary     = "Audit OPNsense web admin: server header + cert CN",
    .run         = opnsense_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_opnsense_module(void) { return &MODULE; }
