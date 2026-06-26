#include "recipe.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef INTRUSIVE_RECIPE_DIR
#define INTRUSIVE_RECIPE_DIR "."
#endif

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); return 1; } \
} while (0)

/* ---- mock I/O serving a DISTINCT canned response per connection ---- */
struct mock_io {
    const uint8_t *resp[4]; size_t resp_n[4]; size_t pos[4];
    int nconn;
};
static int mock_connect(void *ctx, const char *host, int port, int t) {
    (void)host; (void)port; (void)t; struct mock_io *m = ctx;
    int fd = m->nconn + 1; m->nconn++; return fd;
}
static int mock_send(void *ctx, int c, const uint8_t *b, size_t n) {
    (void)ctx; (void)c; (void)b; (void)n; return 0;
}
static long mock_recv(void *ctx, int c, uint8_t *buf, size_t cap) {
    struct mock_io *m = ctx;
    int i = c - 1; if (i < 0 || i >= 4 || !m->resp[i]) return 0;
    if (m->pos[i] >= m->resp_n[i]) return 0;
    size_t take = m->resp_n[i] - m->pos[i]; if (take > cap) take = cap;
    memcpy(buf, m->resp[i] + m->pos[i], take); m->pos[i] += take;
    return (long)take;
}
static void mock_close(void *ctx, int c) { (void)ctx; (void)c; }

struct emit_capture { char kind[64], severity[16], evidence[1024]; };
struct mock_sink { struct emit_capture f[8]; size_t n; };
static void mock_emit(void *ctx, const char *k, const char *s, const char *cf,
                      const char *t, const char *ev) {
    (void)cf; (void)t; struct mock_sink *sk = ctx; if (sk->n >= 8) return;
    struct emit_capture *e = &sk->f[sk->n++];
    snprintf(e->kind, sizeof e->kind, "%s", k);
    snprintf(e->severity, sizeof e->severity, "%s", s);
    snprintf(e->evidence, sizeof e->evidence, "%s", ev);
}

static int run_dc(const char *fname, struct mock_io *io, struct mock_sink *sink) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", INTRUSIVE_RECIPE_DIR, fname);
    FILE *fp = fopen(path, "rb");
    if (!fp) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return -2; }
    static uint8_t buf[65536];
    size_t n = fread(buf, 1, sizeof buf, fp); fclose(fp);
    char err[256] = "";
    struct ps_recipe *r = ps_recipe_parse_json(buf, n, err, sizeof err);
    if (!r) { fprintf(stderr, "parse %s: %s\n", fname, err); return -3; }
    struct ps_recipe_io io_api = {
        .ctx = io, .connect_tcp = mock_connect, .connect_udp = mock_connect,
        .send_all = mock_send, .recv_some = mock_recv, .close_conn = mock_close,
    };
    struct ps_recipe_sink sink_api = { .ctx = sink, .emit = mock_emit };
    struct ps_recipe_target tgt = { .host = "10.0.0.1", .port = 80 };
    int rc = ps_recipe_run(r, &tgt, &io_api, &sink_api, err, sizeof err);
    if (rc != 0) fprintf(stderr, "run %s: %s\n", fname, err);
    ps_recipe_free(r);
    return rc;
}

static const char R401[] =
  "HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"NETGEAR\"\r\n\r\n";
static const char R200[] =
  "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<html>admin</html>";
static const char R200_OPEN[] =
  "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<html>login</html>";

/* default creds accepted: 401 unauth -> 200 with default Basic creds */
static int test_accepted(void) {
    struct mock_io io = {0};
    io.resp[0] = (const uint8_t*)R401; io.resp_n[0] = sizeof R401 - 1;
    io.resp[1] = (const uint8_t*)R200; io.resp_n[1] = sizeof R200 - 1;
    struct mock_sink sk = {0};
    CHECK(run_dc("router-defaultcreds-netgear.json", &io, &sk) == 0);
    CHECK(sk.n == 1);
    CHECK(strcmp(sk.f[0].kind, "router.default_creds") == 0);
    CHECK(strcmp(sk.f[0].severity, "critical") == 0);
    CHECK(strstr(sk.f[0].evidence, "\"username\":\"admin\"") != NULL);
    return 0;
}
/* creds rejected: 401 unauth -> 401 with default creds => NO finding */
static int test_rejected(void) {
    struct mock_io io = {0};
    io.resp[0] = (const uint8_t*)R401; io.resp_n[0] = sizeof R401 - 1;
    io.resp[1] = (const uint8_t*)R401; io.resp_n[1] = sizeof R401 - 1;
    struct mock_sink sk = {0};
    CHECK(run_dc("router-defaultcreds-netgear.json", &io, &sk) == 0);
    CHECK(sk.n == 0);
    return 0;
}
/* unprotected page: 200 to first (no auth) => NO finding, no 2nd request */
static int test_unprotected(void) {
    struct mock_io io = {0};
    io.resp[0] = (const uint8_t*)R200_OPEN; io.resp_n[0] = sizeof R200_OPEN - 1;
    struct mock_sink sk = {0};
    CHECK(run_dc("router-defaultcreds-netgear.json", &io, &sk) == 0);
    CHECK(sk.n == 0);
    CHECK(io.nconn == 1); /* second connection never opened */
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_accepted();
    rc |= test_rejected();
    rc |= test_unprotected();
    if (rc == 0) printf("test_recipe_defaultcreds: OK\n");
    return rc;
}
