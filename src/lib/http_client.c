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

int ps_http_build_request(char *buf, size_t cap, const char *method,
                          const struct ps_url *u, const char *body,
                          const char *extra_headers) {
    size_t blen = body ? strlen(body) : 0;
    int n = snprintf(buf, cap,
        "%s %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n"
        "%s",
        method, u->path, u->host, u->port, blen,
        extra_headers ? extra_headers : "",
        body ? body : "");
    if (n < 0 || (size_t)n >= cap) return -1;
    return n;
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
