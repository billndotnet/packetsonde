#include "http_client.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int ps_url_parse(const char *url, struct ps_url *o) {
    if (!url || !o) return -1;
    memset(o, 0, sizeof *o);
    const char *p;
    if (strncmp(url, "https://", 8) == 0) { strcpy(o->scheme, "https"); o->port = 443; p = url + 8; }
    else if (strncmp(url, "http://", 7) == 0) { strcpy(o->scheme, "http"); o->port = 80; p = url + 7; }
    else return -1;

    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    size_t hostlen;
    if (colon && (!slash || colon < slash)) {
        hostlen = (size_t)(colon - p);
        o->port = atoi(colon + 1);
    } else {
        hostlen = slash ? (size_t)(slash - p) : strlen(p);
    }
    if (hostlen == 0 || hostlen >= sizeof o->host) return -1;
    memcpy(o->host, p, hostlen);
    o->host[hostlen] = 0;

    if (slash) {
        if (strlen(slash) >= sizeof o->path) return -1;
        strcpy(o->path, slash);
    } else {
        strcpy(o->path, "/");
    }
    return 0;
}

/* Request line + headers (ending in the blank line), no body. The body is
 * written separately so its size is bounded only by the caller's buffer, not by
 * a fixed request buffer here. */
static int build_head(char *buf, size_t cap, const char *method,
                      const struct ps_url *u, size_t blen,
                      const char *extra_headers) {
    int n = snprintf(buf, cap,
        "%s %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n",
        method, u->path, u->host, u->port, blen,
        extra_headers ? extra_headers : "");
    if (n < 0 || (size_t)n >= cap) return -1;
    return n;
}

int ps_http_build_request(char *buf, size_t cap, const char *method,
                          const struct ps_url *u, const char *body,
                          const char *extra_headers) {
    size_t blen = body ? strlen(body) : 0;
    int h = build_head(buf, cap, method, u, blen, extra_headers);
    if (h < 0 || (size_t)h + blen >= cap) return -1;
    memcpy(buf + h, body ? body : "", blen);
    buf[(size_t)h + blen] = 0;
    return h + (int)blen;
}

int ps_http_parse_response(const char *raw, size_t len, int *status_out,
                           const char **body_out) {
    if (!raw || len < 12 || strncmp(raw, "HTTP/1.", 7) != 0) return -1;
    const char *sp = strchr(raw, ' ');
    if (!sp) return -1;
    *status_out = atoi(sp + 1);
    const char *sep = strstr(raw, "\r\n\r\n");
    *body_out = sep ? sep + 4 : raw + len;  /* empty body -> end */
    return 0;
}

#include <openssl/ssl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>

/* Stage of the last failure on this thread, for callers' diagnostics. */
static __thread const char *g_http_err = "none";
const char *ps_http_last_error(void) { return g_http_err; }

static int dial(const char *host, int port, int timeout_s) {
    char portstr[16]; snprintf(portstr, sizeof portstr, "%d", port);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    int fd = -1;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv = { timeout_s > 0 ? timeout_s : 10, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int write_all(int fd, SSL *ssl, const char *p, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > (size_t)1 << 30) chunk = (size_t)1 << 30;
        int w = ssl ? SSL_write(ssl, p + off, (int)chunk)
                    : (int)write(fd, p + off, chunk);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

/* Send head then body over fd or ssl; read response into buf (cap). */
static int io_exchange(int fd, SSL *ssl, const char *head, size_t headlen,
                       const char *body, size_t bodylen,
                       char *buf, size_t cap) {
    if (write_all(fd, ssl, head, headlen) != 0) { g_http_err = "write"; return -1; }
    if (bodylen && write_all(fd, ssl, body, bodylen) != 0) { g_http_err = "write"; return -1; }
    size_t got = 0;
    for (;;) {
        if (got + 1 >= cap) break;  /* cap reached; truncate */
        int r = ssl ? SSL_read(ssl, buf + got, (int)(cap - 1 - got))
                    : (int)read(fd, buf + got, cap - 1 - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    buf[got] = 0;
    return (int)got;
}

int ps_http_request_h(const char *method, const char *url, const char *body,
                      const char *extra_headers,
                      const struct ps_http_opts *opts, int *status_out,
                      char *resp_buf, size_t resp_cap) {
    g_http_err = "none";
    struct ps_url u;
    if (ps_url_parse(url, &u) != 0) { g_http_err = "url"; return -1; }

    size_t blen = body ? strlen(body) : 0;
    char head[4096];
    int headlen = build_head(head, sizeof head, method, &u, blen, extra_headers);
    if (headlen < 0) { g_http_err = "headers"; return -1; }

    int timeout_s = opts ? opts->timeout_s : 10;
    int fd = dial(u.host, u.port, timeout_s);
    if (fd < 0) { g_http_err = "connect"; return -1; }

    int rc = -1;
    SSL_CTX *ctx = NULL; SSL *ssl = NULL;
    int is_https = strcmp(u.scheme, "https") == 0;

    if (is_https) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { g_http_err = "tls"; close(fd); return -1; }
        int verify = opts ? opts->verify : 1;
        if (verify) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
            if (opts && opts->ca_cert && opts->ca_cert[0])
                SSL_CTX_load_verify_locations(ctx, opts->ca_cert, NULL);
            else
                SSL_CTX_set_default_verify_paths(ctx);
        } else {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        }
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, u.host);
        X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), u.host, 0);
        if (SSL_connect(ssl) != 1) { g_http_err = "tls"; goto done; }
    }

    if (io_exchange(fd, ssl, head, (size_t)headlen, body, blen, resp_buf, resp_cap) < 0) goto done;
    {
        const char *bodyp = NULL;
        if (ps_http_parse_response(resp_buf, strlen(resp_buf), status_out, &bodyp) != 0) {
            g_http_err = "response";
            goto done;
        }
        /* shift body to front of resp_buf for the caller's convenience */
        if (bodyp && bodyp != resp_buf) memmove(resp_buf, bodyp, strlen(bodyp) + 1);
        rc = 0;
    }
done:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (ctx) SSL_CTX_free(ctx);
    close(fd);
    return rc;
}

int ps_http_request(const char *method, const char *url, const char *body,
                    const struct ps_http_opts *opts, int *status_out,
                    char *resp_buf, size_t resp_cap) {
    return ps_http_request_h(method, url, body, NULL, opts, status_out, resp_buf, resp_cap);
}

