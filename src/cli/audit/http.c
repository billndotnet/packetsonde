#include "audit_module.h"
#include "audit_common.h"
#include "../args.h"
#include "finding.h"
#include "ulid.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

/* Parse "host[:port][/path]" or "scheme://host[:port][/path]". */
struct url_parts {
    int  tls;
    char host[256];
    uint16_t port;
    char path[1024];
};

static int parse_url(const char *spec, struct url_parts *u) {
    memset(u, 0, sizeof(*u));
    u->path[0] = '/'; u->path[1] = '\0';
    const char *p = spec;
    if (strncmp(p, "https://", 8) == 0) { u->tls = 1; u->port = 443; p += 8; }
    else if (strncmp(p, "http://", 7) == 0) { u->tls = 0; u->port = 80; p += 7; }
    else { u->tls = 0; u->port = 80; }

    /* Find end of host (':' or '/'). */
    const char *colon = NULL, *slash = NULL;
    for (const char *q = p; *q; q++) {
        if (*q == ':' && !colon && !slash) colon = q;
        if (*q == '/' && !slash) slash = q;
    }
    const char *host_end = colon ? colon : (slash ? slash : p + strlen(p));
    size_t hl = (size_t)(host_end - p);
    if (hl == 0 || hl >= sizeof(u->host)) return -1;
    memcpy(u->host, p, hl); u->host[hl] = '\0';

    if (colon) {
        long pv = strtol(colon + 1, NULL, 10);
        if (pv <= 0 || pv > 65535) return -1;
        u->port = (uint16_t)pv;
    }
    if (slash) {
        size_t pl = strlen(slash);
        if (pl >= sizeof(u->path)) pl = sizeof(u->path) - 1;
        memcpy(u->path, slash, pl); u->path[pl] = '\0';
    }
    return 0;
}

static int tcp_connect(const char *host, uint16_t port, int timeout_ms,
                       char *ip_out, size_t ip_out_sz) {
    return ps_audit_tcp_connect(host, port, timeout_ms, ip_out, ip_out_sz);
}

/* Read all bytes available within the existing socket timeout. */
static int read_all(int fd, SSL *ssl, char *buf, size_t cap) {
    size_t total = 0;
    while (total < cap - 1) {
        ssize_t r;
        if (ssl) r = SSL_read(ssl, buf + total, (int)(cap - 1 - total));
        else     r = recv(fd, buf + total, cap - 1 - total, 0);
        if (r <= 0) break;
        total += (size_t)r;
    }
    buf[total] = '\0';
    return (int)total;
}

static int send_all(int fd, SSL *ssl, const char *buf, size_t n) {
    while (n > 0) {
        ssize_t w;
        if (ssl) w = SSL_write(ssl, buf, (int)n);
        else     w = send(fd, buf, n, 0);
        if (w <= 0) return -1;
        buf += w; n -= (size_t)w;
    }
    return 0;
}

/* Find header value in raw response (case-insensitive name match).
 * Returns 1 if found, 0 otherwise. Writes the trimmed value to out. */
static int find_header(const char *resp, const char *name, char *out, size_t outsz) {
    out[0] = '\0';
    size_t nlen = strlen(name);
    const char *p = strstr(resp, "\r\n\r\n");
    size_t headers_end = p ? (size_t)(p - resp) : strlen(resp);
    /* Scan headers section. */
    p = resp;
    while (p && (size_t)(p - resp) < headers_end) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        if ((size_t)(eol - p) > nlen + 1 && strncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
            const char *v = p + nlen + 1;
            while (*v == ' ' || *v == '\t') v++;
            size_t vlen = (size_t)(eol - v);
            if (vlen >= outsz) vlen = outsz - 1;
            memcpy(out, v, vlen); out[vlen] = '\0'; return 1;
        }
        p = eol + 2;
    }
    return 0;
}

static int response_status(const char *resp) {
    /* "HTTP/1.x NNN ..." */
    if (strncmp(resp, "HTTP/", 5) != 0) return 0;
    const char *sp = strchr(resp, ' ');
    if (!sp) return 0;
    return atoi(sp + 1);
}

struct emit_ctx {
    const struct ps_audit_api *api;
    const char       *run_id;
    const char       *self_host;
    const char       *target_host;
    const char       *target_ip;
    uint16_t          target_port;
    const char       *path;
};

static void emit_h(struct emit_ctx *e, const char *kind,
                   enum ps_severity sev, const char *title,
                   const char *evidence_json) {
    struct ps_finding f;
    ps_finding_init(&f, e->run_id, "cli.audit.http", e->self_host,
                    kind, sev, PS_CONF_FIRM, title);
    if (e->target_ip && e->target_ip[0]) ps_finding_set_target_ip(&f, e->target_ip, e->target_port);
    if (e->target_host && e->target_host[0]) ps_finding_set_target_hostname(&f, e->target_host, e->target_port);
    if (evidence_json) ps_finding_set_evidence_json(&f, evidence_json);
    e->api->emit(&f);
}

static void check_security_headers(struct emit_ctx *e, const char *resp, int tls) {
    char buf[1024];

    /* HSTS (only relevant on https) */
    if (tls) {
        if (!find_header(resp, "Strict-Transport-Security", buf, sizeof(buf))) {
            emit_h(e, "http.missing_hsts", PS_SEV_MEDIUM,
                   "Missing Strict-Transport-Security header",
                   "{\"header\":\"Strict-Transport-Security\"}");
        } else {
            /* HSTS present — check max-age */
            const char *m = strstr(buf, "max-age=");
            long age = m ? strtol(m + 8, NULL, 10) : 0;
            if (age < 15768000 /* 6 months */) {
                char ev[160];
                snprintf(ev, sizeof(ev), "{\"max_age\":%ld,\"recommended\":15768000}", age);
                emit_h(e, "http.weak_hsts", PS_SEV_LOW,
                       "HSTS max-age below recommended 6 months", ev);
            }
        }
    }

    /* X-Content-Type-Options: nosniff */
    if (!find_header(resp, "X-Content-Type-Options", buf, sizeof(buf))) {
        emit_h(e, "http.missing_xcto", PS_SEV_LOW,
               "Missing X-Content-Type-Options header",
               "{\"header\":\"X-Content-Type-Options\"}");
    }

    /* X-Frame-Options or CSP frame-ancestors */
    int xfo = find_header(resp, "X-Frame-Options", buf, sizeof(buf));
    char csp[2048];
    int csp_present = find_header(resp, "Content-Security-Policy", csp, sizeof(csp));
    int frame_ancestors_set = csp_present && strstr(csp, "frame-ancestors") != NULL;
    if (!xfo && !frame_ancestors_set) {
        emit_h(e, "http.missing_frame_protection", PS_SEV_LOW,
               "Neither X-Frame-Options nor CSP frame-ancestors set",
               "{\"headers\":[\"X-Frame-Options\",\"Content-Security-Policy\"]}");
    }

    /* CSP */
    if (!csp_present) {
        emit_h(e, "http.missing_csp", PS_SEV_LOW,
               "Missing Content-Security-Policy header",
               "{\"header\":\"Content-Security-Policy\"}");
    }

    /* Referrer-Policy */
    if (!find_header(resp, "Referrer-Policy", buf, sizeof(buf))) {
        emit_h(e, "http.missing_referrer_policy", PS_SEV_INFO,
               "Missing Referrer-Policy header",
               "{\"header\":\"Referrer-Policy\"}");
    }

    /* Server header disclosure */
    if (find_header(resp, "Server", buf, sizeof(buf))) {
        /* Specific versions in the Server header are a low-severity disclosure. */
        int has_version = 0;
        for (size_t i = 0; buf[i]; i++) if (buf[i] >= '0' && buf[i] <= '9') { has_version = 1; break; }
        if (has_version) {
            char ev[256], esc[160];
            size_t k = 0;
            for (size_t i = 0; buf[i] && k + 2 < sizeof(esc); i++) {
                unsigned char c = (unsigned char)buf[i];
                if (c == '"' || c == '\\') { esc[k++] = '\\'; esc[k++] = (char)c; }
                else if (c >= 0x20 && c < 0x7f) esc[k++] = (char)c;
            }
            esc[k] = '\0';
            snprintf(ev, sizeof(ev), "{\"server\":\"%s\"}", esc);
            emit_h(e, "http.server_version_leak", PS_SEV_LOW,
                   "Server header discloses version", ev);
        }
    }
}

static int http_run(int argc, char **argv,
                      const struct ps_args *opts,
                      const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit http <url|host[:port]>\n");
        return 2;
    }
    struct url_parts u;
    if (parse_url(argv[1], &u) != 0) {
        fprintf(stderr, "audit http: bad URL '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    char ip[64] = "";
    int fd = tcp_connect(u.host, u.port, 4000, ip, sizeof(ip));
    if (fd < 0) {
        fprintf(stderr, "audit http: cannot connect to %s:%u\n", u.host, u.port); return 1;
    }

    SSL_CTX *ctx = NULL; SSL *ssl = NULL;
    if (u.tls) {
        ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_security_level(ctx, 0);
        ssl = SSL_new(ctx);
        SSL_set_tlsext_host_name(ssl, u.host);
        SSL_set_fd(ssl, fd);
        if (SSL_connect(ssl) != 1) {
            fprintf(stderr, "audit http: TLS handshake failed\n");
            SSL_free(ssl); SSL_CTX_free(ctx); close(fd); return 1;
        }
    }

    /* Send GET request */
    char req[1024];
    snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: packetsonde\r\n"
        "Connection: close\r\n"
        "Accept: */*\r\n\r\n",
        u.path, u.host);
    if (send_all(fd, ssl, req, strlen(req)) != 0) {
        fprintf(stderr, "audit http: send failed\n");
        if (ssl) { SSL_free(ssl); SSL_CTX_free(ctx); }
        close(fd); return 1;
    }

    char resp[16384];
    int n = read_all(fd, ssl, resp, sizeof(resp));
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); }
    close(fd);

    if (n <= 0) {
        fprintf(stderr, "audit http: empty response\n"); return 1;
    }

    struct emit_ctx e = { api, run_id, self_host, u.host, ip, u.port, u.path };
    int status = response_status(resp);

    /* Emit metadata finding */
    {
        char server[256] = ""; find_header(resp, "Server", server, sizeof(server));
        char ctype[128]  = ""; find_header(resp, "Content-Type", ctype, sizeof(ctype));
        char title[256];
        snprintf(title, sizeof(title), "%s %d %s",
                 u.tls ? "HTTPS" : "HTTP", status, ctype[0] ? ctype : "");
        char ev[512], srv_e[160];
        size_t k = 0;
        for (size_t i = 0; server[i] && k + 2 < sizeof(srv_e); i++) {
            unsigned char c = (unsigned char)server[i];
            if (c == '"' || c == '\\') { srv_e[k++] = '\\'; srv_e[k++] = (char)c; }
            else if (c >= 0x20 && c < 0x7f) srv_e[k++] = (char)c;
        }
        srv_e[k] = '\0';
        snprintf(ev, sizeof(ev),
                 "{\"status\":%d,\"tls\":%s,\"server\":\"%s\"}",
                 status, u.tls ? "true" : "false", srv_e);
        emit_h(&e, "http.metadata", PS_SEV_INFO, title, ev);
    }

    check_security_headers(&e, resp, u.tls);
    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "http",
    .summary     = "Audit HTTP server: security headers, version leaks",
    .run         = http_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_http_module(void) { return &MODULE; }
