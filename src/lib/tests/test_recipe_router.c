#include "recipe.h"
#include "tls_probe.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ROUTER_RECIPE_DIR
#define ROUTER_RECIPE_DIR "."
#endif

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); return 1; } \
} while (0)

/* ---- mock I/O: serves one canned response, ignores sent bytes ---- */
struct mock_io {
    const uint8_t *recv_data; size_t recv_n; size_t recv_pos;
    int next_fd;
};
static int mock_connect(void *ctx, const char *host, int port, int t) {
    (void)host; (void)port; (void)t; struct mock_io *m = ctx; return ++m->next_fd;
}
static int mock_send(void *ctx, int c, const uint8_t *b, size_t n) {
    (void)ctx; (void)c; (void)b; (void)n; return 0;
}
static long mock_recv(void *ctx, int c, uint8_t *buf, size_t cap) {
    (void)c; struct mock_io *m = ctx;
    if (m->recv_pos >= m->recv_n) return 0;
    size_t take = m->recv_n - m->recv_pos; if (take > cap) take = cap;
    memcpy(buf, m->recv_data + m->recv_pos, take); m->recv_pos += take;
    return (long)take;
}
static void mock_close(void *ctx, int c) { (void)ctx; (void)c; }
static int mock_tls_upgrade(void *ctx, int c, const char *sni,
                            const char *const *alpn, int t) {
    (void)ctx; (void)c; (void)sni; (void)alpn; (void)t; return 0;
}
static int mock_tls_session(void *ctx, int c, struct ps_tls_info *o) {
    (void)ctx; (void)c; memset(o, 0, sizeof *o);
    snprintf(o->version, sizeof o->version, "TLSv1.3"); return 0;
}

/* ---- sink ---- */
struct emit_capture { char kind[64], confidence[16], evidence[1024]; };
struct mock_sink { struct emit_capture f[16]; size_t n; };
static void mock_emit(void *ctx, const char *k, const char *s, const char *cf,
                      const char *t, const char *ev) {
    (void)s; (void)t; struct mock_sink *sk = ctx; if (sk->n >= 16) return;
    struct emit_capture *e = &sk->f[sk->n++];
    snprintf(e->kind, sizeof e->kind, "%s", k);
    snprintf(e->confidence, sizeof e->confidence, "%s", cf);
    snprintf(e->evidence, sizeof e->evidence, "%s", ev);
}

static int run_router(const char *fname, int port, const uint8_t *resp,
                      size_t resp_n, struct mock_sink *sink, int tls) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", ROUTER_RECIPE_DIR, fname);
    FILE *fp = fopen(path, "rb");
    if (!fp) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return -2; }
    static uint8_t buf[65536];
    size_t n = fread(buf, 1, sizeof buf, fp); fclose(fp);
    char err[256] = "";
    struct ps_recipe *r = ps_recipe_parse_json(buf, n, err, sizeof err);
    if (!r) { fprintf(stderr, "parse %s: %s\n", fname, err); return -3; }
    struct mock_io io = { .recv_data = resp, .recv_n = resp_n };
    struct ps_recipe_io io_api = {
        .ctx = &io, .connect_tcp = mock_connect, .connect_udp = mock_connect,
        .send_all = mock_send, .recv_some = mock_recv, .close_conn = mock_close,
        .tls_upgrade = tls ? mock_tls_upgrade : NULL,
        .tls_session = tls ? mock_tls_session : NULL,
    };
    struct ps_recipe_sink sink_api = { .ctx = sink, .emit = mock_emit };
    struct ps_recipe_target tgt = { .host = "10.0.0.1", .port = port };
    int rc = ps_recipe_run(r, &tgt, &io_api, &sink_api, err, sizeof err);
    if (rc != 0) fprintf(stderr, "run %s: %s\n", fname, err);
    ps_recipe_free(r);
    return rc;
}

/* find a router.identified finding whose evidence contains `needle` */
static const struct emit_capture *find_vendor(struct mock_sink *sk, const char *needle) {
    for (size_t i = 0; i < sk->n; i++)
        if (strcmp(sk->f[i].kind, "router.identified") == 0 && strstr(sk->f[i].evidence, needle))
            return &sk->f[i];
    return NULL;
}

static int test_netgear_realm(void) {
    static const uint8_t R[] =
      "HTTP/1.0 401 Unauthorized\r\n"
      "WWW-Authenticate: Basic realm=\"NETGEAR R7000\"\r\n"
      "Content-Length: 0\r\n\r\n";
    struct mock_sink sk = {0};
    CHECK(run_router("router-id.json", 80, R, sizeof R - 1, &sk, 0) == 0);
    const struct emit_capture *e = find_vendor(&sk, "\"vendor\":\"NETGEAR\"");
    CHECK(e != NULL);
    CHECK(strcmp(e->confidence, "firm") == 0);
    CHECK(strstr(e->evidence, "\"transport\":\"http\"") != NULL);
    return 0;
}
static int test_asus_title(void) {
    static const uint8_t R[] =
      "HTTP/1.1 200 OK\r\nServer: httpd/2.0\r\nContent-Type: text/html\r\n\r\n"
      "<html><head><title>ASUS Login</title></head><body>asuswrt</body></html>";
    struct mock_sink sk = {0};
    CHECK(run_router("router-id.json", 80, R, sizeof R - 1, &sk, 0) == 0);
    CHECK(find_vendor(&sk, "\"vendor\":\"ASUS\"") != NULL);
    return 0;
}
static int test_rompager_tentative(void) {
    static const uint8_t R[] =
      "HTTP/1.0 200 OK\r\nServer: RomPager/4.07\r\n\r\n<html>login</html>";
    struct mock_sink sk = {0};
    CHECK(run_router("router-id.json", 80, R, sizeof R - 1, &sk, 0) == 0);
    const struct emit_capture *e = find_vendor(&sk, "\"signal\":\"server-header\"");
    CHECK(e != NULL);
    CHECK(strcmp(e->confidence, "tentative") == 0);
    return 0;
}
static int test_https_transport(void) {
    static const uint8_t R[] =
      "HTTP/1.0 401 Unauthorized\r\n"
      "WWW-Authenticate: Basic realm=\"NETGEAR R7000\"\r\n\r\n";
    struct mock_sink sk = {0};
    CHECK(run_router("router-id-tls.json", 443, R, sizeof R - 1, &sk, 1) == 0);
    const struct emit_capture *e = find_vendor(&sk, "\"vendor\":\"NETGEAR\"");
    CHECK(e != NULL);
    CHECK(strstr(e->evidence, "\"transport\":\"https\"") != NULL);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_netgear_realm();
    rc |= test_asus_title();
    rc |= test_rompager_tentative();
    rc |= test_https_transport();
    if (rc == 0) printf("test_recipe_router: OK\n");
    return rc;
}
