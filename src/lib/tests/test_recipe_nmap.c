#include "recipe.h"
#include "tls_probe.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NMAP_RECIPE_DIR
#define NMAP_RECIPE_DIR "."
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
    (void)ctx; (void)c;
    memset(o, 0, sizeof *o);
    snprintf(o->version, sizeof o->version, "TLSv1.3");
    return 0;
}

/* ---- sink: capture emitted findings ---- */
struct emit_capture { char kind[64], severity[16], confidence[16], title[256], evidence[2048]; };
struct mock_sink { struct emit_capture f[8]; size_t n; };
static void mock_emit(void *ctx, const char *k, const char *s, const char *cf,
                      const char *t, const char *ev) {
    struct mock_sink *sk = ctx; if (sk->n >= 8) return;
    struct emit_capture *e = &sk->f[sk->n++];
    snprintf(e->kind, sizeof e->kind, "%s", k);
    snprintf(e->severity, sizeof e->severity, "%s", s);
    snprintf(e->confidence, sizeof e->confidence, "%s", cf);
    snprintf(e->title, sizeof e->title, "%s", t);
    snprintf(e->evidence, sizeof e->evidence, "%s", ev);
}

/* ---- helper: load a real recipe file and run it against canned bytes ---- */
static int run_recipe_io(const char *fname, int port, const uint8_t *resp,
                         size_t resp_n, struct mock_sink *sink, int with_tls) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", NMAP_RECIPE_DIR, fname);
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
        .tls_upgrade = with_tls ? mock_tls_upgrade : NULL,
        .tls_session = with_tls ? mock_tls_session : NULL,
    };
    struct ps_recipe_sink sink_api = { .ctx = sink, .emit = mock_emit };
    struct ps_recipe_target tgt = { .host = "10.0.0.1", .port = port };
    int rc = ps_recipe_run(r, &tgt, &io_api, &sink_api, err, sizeof err);
    if (rc != 0) fprintf(stderr, "run %s: %s\n", fname, err);
    ps_recipe_free(r);
    return rc;
}
static int run_recipe(const char *fname, int port, const uint8_t *resp,
                      size_t resp_n, struct mock_sink *sink) {
    return run_recipe_io(fname, port, resp, resp_n, sink, 0);
}
static int run_recipe_tls(const char *fname, int port, const uint8_t *resp,
                          size_t resp_n, struct mock_sink *sink) {
    return run_recipe_io(fname, port, resp, resp_n, sink, 1);
}

/* ---- tests ---- */
static int test_ssh(void) {
    static const uint8_t B[] = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n";
    struct mock_sink sk = {0};
    CHECK(run_recipe("nmap-ssh.json", 22, B, sizeof B - 1, &sk) == 0);
    CHECK(sk.n == 1);
    CHECK(strcmp(sk.f[0].kind, "nmap.service") == 0);
    CHECK(strcmp(sk.f[0].confidence, "confirmed") == 0);
    CHECK(strstr(sk.f[0].evidence, "\"service\":\"ssh\"") != NULL);
    CHECK(strstr(sk.f[0].evidence, "\"product\":\"OpenSSH\"") != NULL);
    CHECK(strstr(sk.f[0].evidence, "\"version\":\"9.6p1\"") != NULL);
    return 0;
}

static int test_ftp(void) {
    static const uint8_t B[] = "220 (vsFTPd 3.0.5)\r\n";
    struct mock_sink sk = {0};
    CHECK(run_recipe("nmap-ftp.json", 21, B, sizeof B - 1, &sk) == 0);
    CHECK(sk.n == 1 && strcmp(sk.f[0].kind, "nmap.service") == 0);
    CHECK(strstr(sk.f[0].evidence, "\"product\":\"vsFTPd\"") != NULL);
    CHECK(strstr(sk.f[0].evidence, "\"version\":\"3.0.5\"") != NULL);
    return 0;
}
static int test_smtp(void) {
    static const uint8_t B[] = "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n";
    struct mock_sink sk = {0};
    CHECK(run_recipe("nmap-smtp.json", 25, B, sizeof B - 1, &sk) == 0);
    CHECK(sk.n == 1 && strcmp(sk.f[0].confidence, "firm") == 0);
    CHECK(strstr(sk.f[0].evidence, "\"service\":\"smtp\"") != NULL);
    CHECK(strstr(sk.f[0].evidence, "\"product\":\"Postfix\"") != NULL);
    CHECK(strstr(sk.f[0].evidence, "\"version\":\"\"") != NULL);
    return 0;
}
static int test_pop3(void) {
    static const uint8_t B[] = "+OK Dovecot ready.\r\n";
    struct mock_sink sk = {0};
    CHECK(run_recipe("nmap-pop3.json", 110, B, sizeof B - 1, &sk) == 0);
    CHECK(sk.n == 1 && strcmp(sk.f[0].confidence, "firm") == 0);
    CHECK(strstr(sk.f[0].evidence, "\"product\":\"Dovecot\"") != NULL);
    return 0;
}
static int test_imap(void) {
    static const uint8_t B[] = "* OK [CAPABILITY IMAP4rev1] Dovecot (Ubuntu) ready.\r\n";
    struct mock_sink sk = {0};
    CHECK(run_recipe("nmap-imap.json", 143, B, sizeof B - 1, &sk) == 0);
    CHECK(sk.n == 1 && strcmp(sk.f[0].confidence, "firm") == 0);
    CHECK(strstr(sk.f[0].evidence, "\"product\":\"Dovecot\"") != NULL);
    return 0;
}
static int test_http(void) {
    static const uint8_t B[] =
      "HTTP/1.1 200 OK\r\nDate: Wed, 18 Jun 2026 00:00:00 GMT\r\n"
      "Server: nginx/1.25.3\r\nContent-Length: 0\r\n\r\n";
    struct mock_sink sk = {0};
    CHECK(run_recipe("nmap-http.json", 80, B, sizeof B - 1, &sk) == 0);
    CHECK(sk.n == 1 && strcmp(sk.f[0].confidence, "confirmed") == 0);
    CHECK(strstr(sk.f[0].evidence, "\"product\":\"nginx\"") != NULL);
    CHECK(strstr(sk.f[0].evidence, "\"version\":\"1.25.3\"") != NULL);
    return 0;
}
static int test_memcached(void) {
    static const uint8_t B[] = "VERSION 1.6.21\r\n";
    struct mock_sink sk = {0};
    CHECK(run_recipe("nmap-memcached.json", 11211, B, sizeof B - 1, &sk) == 0);
    CHECK(sk.n == 1 && strcmp(sk.f[0].confidence, "confirmed") == 0);
    CHECK(strstr(sk.f[0].evidence, "\"product\":\"memcached\"") != NULL);
    CHECK(strstr(sk.f[0].evidence, "\"version\":\"1.6.21\"") != NULL);
    return 0;
}
static int test_redis(void) {
    static const uint8_t B[] =
      "$120\r\n# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\n";
    struct mock_sink sk = {0};
    CHECK(run_recipe("nmap-redis.json", 6379, B, sizeof B - 1, &sk) == 0);
    CHECK(sk.n == 1 && strcmp(sk.f[0].confidence, "confirmed") == 0);
    CHECK(strstr(sk.f[0].evidence, "\"product\":\"Redis\"") != NULL);
    CHECK(strstr(sk.f[0].evidence, "\"version\":\"7.2.4\"") != NULL);
    return 0;
}
static int test_vnc(void) {
    static const uint8_t B[] = "RFB 003.008\n";
    struct mock_sink sk = {0};
    CHECK(run_recipe("nmap-vnc.json", 5900, B, sizeof B - 1, &sk) == 0);
    CHECK(sk.n == 1 && strcmp(sk.f[0].confidence, "confirmed") == 0);
    CHECK(strstr(sk.f[0].evidence, "\"product\":\"VNC\"") != NULL);
    CHECK(strstr(sk.f[0].evidence, "\"version\":\"3.8\"") != NULL);
    return 0;
}
static int test_https(void) {
    static const uint8_t B[] =
      "HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\nContent-Length: 0\r\n\r\n";
    struct mock_sink sk = {0};
    CHECK(run_recipe_tls("nmap-https.json", 443, B, sizeof B - 1, &sk) == 0);
    CHECK(sk.n == 1 && strcmp(sk.f[0].confidence, "confirmed") == 0);
    CHECK(strstr(sk.f[0].evidence, "\"service\":\"https\"") != NULL);
    CHECK(strstr(sk.f[0].evidence, "\"product\":\"Apache\"") != NULL);
    CHECK(strstr(sk.f[0].evidence, "\"version\":\"2.4.58\"") != NULL);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_ssh();
    rc |= test_ftp();
    rc |= test_smtp();
    rc |= test_pop3();
    rc |= test_imap();
    rc |= test_http();
    rc |= test_memcached();
    rc |= test_redis();
    rc |= test_vnc();
    rc |= test_https();
    if (rc == 0) printf("test_recipe_nmap: OK\n");
    return rc;
}
