/* Recipe engine TLS opcodes (schema 2). Parser checks always run; the
 * handshake/enum/e2e checks need `openssl s_server` and run under PS_TLS_LIVE=1. */
#include "recipe.h"
#include "tls_probe.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/ssl.h>

#define CHECK(c) do{ if(!(c)){ fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c); return 1; } }while(0)

/* ---- parser checks (no network) ----------------------------------------- */

static struct ps_recipe *parse(const char *json, char *err, size_t errsz) {
    return ps_recipe_parse_json((const uint8_t *)json, strlen(json), err, errsz);
}

static int test_parser(void) {
    char err[256];
    /* schema-2 recipe with the new opcodes + match-any parses */
    const char *ok =
      "{\"schema\":2,\"name\":\"t\",\"version\":1,\"kind_prefix\":\"tls\",\"steps\":["
      "{\"op\":\"tls_enum\",\"host\":\"$target.host\",\"port\":\"$target.port\",\"timeout_ms\":1000},"
      "{\"op\":\"match\",\"any\":\"tls_accepted_ciphers\",\"regex\":\"RC4\",\"out\":\"w\"},"
      "{\"op\":\"if\",\"cond\":\"any_in\",\"list\":\"tls_accepted_protocols\",\"set\":[\"TLS1.0\"],\"then\":["
      "{\"op\":\"emit\",\"kind\":\"tls.old\",\"severity\":\"medium\",\"confidence\":\"firm\",\"title\":\"x\"}]}]}";
    struct ps_recipe *r = parse(ok, err, sizeof(err));
    CHECK(r != NULL);
    CHECK(r->budgets.max_tls_probes == 200);   /* default */
    ps_recipe_free(r);

    /* schema-1 recipe using a TLS opcode is rejected */
    const char *bad =
      "{\"schema\":1,\"name\":\"t\",\"version\":1,\"kind_prefix\":\"tls\",\"steps\":["
      "{\"op\":\"tls_enum\",\"host\":\"h\",\"port\":443,\"timeout_ms\":1000}]}";
    CHECK(parse(bad, err, sizeof(err)) == NULL);
    CHECK(strstr(err, "schema 2") != NULL);

    /* match.any against a non-strlist binding is rejected */
    const char *bad2 =
      "{\"schema\":2,\"name\":\"t\",\"version\":1,\"kind_prefix\":\"tls\",\"steps\":["
      "{\"op\":\"connect_tcp\",\"host\":\"h\",\"port\":443,\"timeout_ms\":1000,\"out\":\"c\"},"
      "{\"op\":\"match\",\"any\":\"c\",\"regex\":\"x\"}]}";
    CHECK(parse(bad2, err, sizeof(err)) == NULL);

    /* max_tls_probes override is honoured */
    const char *bud =
      "{\"schema\":2,\"name\":\"t\",\"version\":1,\"kind_prefix\":\"tls\","
      "\"budgets\":{\"max_tls_probes\":7},\"steps\":["
      "{\"op\":\"tls_enum\",\"host\":\"h\",\"port\":443,\"timeout_ms\":1000}]}";
    struct ps_recipe *rb = parse(bud, err, sizeof(err));
    CHECK(rb != NULL && rb->budgets.max_tls_probes == 7);
    ps_recipe_free(rb);
    return 0;
}

/* ---- live fixture + a TLS-aware io backend ------------------------------- */

static pid_t g_srv = 0;

static int start_s_server(int port, const char *protoflag, const char *cipher) {
    if (system("openssl req -x509 -newkey rsa:2048 -keyout /tmp/ps_rtls_k.pem "
               "-out /tmp/ps_rtls_c.pem -days 1 -nodes -subj /CN=localhost >/dev/null 2>&1") != 0) return -1;
    char ports[16]; snprintf(ports, sizeof(ports), "%d", port);
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int dn = open("/dev/null", 1); if (dn >= 0) { dup2(dn, 1); dup2(dn, 2); }
        execlp("openssl", "openssl", "s_server", "-accept", ports,
               "-key", "/tmp/ps_rtls_k.pem", "-cert", "/tmp/ps_rtls_c.pem",
               protoflag, "-cipher", cipher, "-www", "-quiet", (char *)NULL);
        _exit(127);
    }
    g_srv = pid;
    for (int i = 0; i < 50; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa = {0}; sa.sin_family = AF_INET; sa.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) { close(fd); return 0; }
        close(fd); usleep(100000);
    }
    return -1;
}
static void stop_s_server(void) { if (g_srv > 0) { kill(g_srv, SIGTERM); waitpid(g_srv, NULL, 0); g_srv = 0; } }

struct tio { struct { int fd; SSL *ssl; struct ps_tls_info info; } m[8]; size_t n; };
static SSL *tio_ssl(struct tio *c, int fd) { for (size_t i = 0; i < c->n; i++) if (c->m[i].fd == fd) return c->m[i].ssl; return NULL; }
static int tio_connect(void *v, const char *h, int p, int t) {
    (void)v; (void)t;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0}; sa.sin_family = AF_INET; sa.sin_port = htons(p);
    inet_pton(AF_INET, h, &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    return fd;
}
static int tio_send(void *v, int fd, const uint8_t *b, size_t n) {
    SSL *s = tio_ssl(v, fd);
    if (s) { size_t k = 0; while (k < n) { int w = SSL_write(s, b + k, (int)(n - k)); if (w <= 0) return -1; k += (size_t)w; } return 0; }
    size_t k = 0; while (k < n) { ssize_t w = send(fd, b + k, n - k, 0); if (w <= 0) return -1; k += (size_t)w; } return 0;
}
static long tio_recv(void *v, int fd, uint8_t *b, size_t c) {
    SSL *s = tio_ssl(v, fd);
    if (s) { int r = SSL_read(s, b, (int)c); if (r > 0) return r; return SSL_get_error(s, r) == SSL_ERROR_ZERO_RETURN ? 0 : -1; }
    ssize_t r = recv(fd, b, c, 0); return r < 0 ? -1 : (long)r;
}
static void tio_close(void *v, int fd) {
    struct tio *c = v;
    for (size_t i = 0; i < c->n; i++) if (c->m[i].fd == fd && c->m[i].ssl) { SSL_shutdown(c->m[i].ssl); SSL_free(c->m[i].ssl); c->m[i].ssl = NULL; }
    if (fd >= 0) close(fd);
}
static int tio_up(void *v, int fd, const char *sni, const char *const *alpn, int t) {
    struct tio *c = v; struct ps_tls_info info;
    SSL *s = ps_tls_upgrade_fd(fd, sni, alpn, t, &info);
    if (!s) return -1;
    c->m[c->n].fd = fd; c->m[c->n].ssl = s; c->m[c->n].info = info; c->n++;
    return 0;
}
static int tio_sess(void *v, int fd, struct ps_tls_info *o) {
    struct tio *c = v;
    for (size_t i = 0; i < c->n; i++) if (c->m[i].fd == fd) { *o = c->m[i].info; return 0; }
    return -1;
}
static int tio_probe(void *v, const char *h, int p, const char *mn, const char *mx,
                     const char *cl, const char *st, int t, struct ps_tls_probe_result *o) {
    (void)v; return ps_tls_probe(h, p, mn, mx, cl, st, t, o);
}

struct cap { char kinds[8][64]; char titles[8][256]; size_t n; };
static void cap_emit(void *ctx, const char *kind, const char *sev, const char *conf,
                     const char *title, const char *ev) {
    (void)sev; (void)conf; (void)ev;
    struct cap *c = ctx;
    if (c->n >= 8) return;
    snprintf(c->kinds[c->n], 64, "%s", kind);
    snprintf(c->titles[c->n], 256, "%s", title);
    c->n++;
}
static int cap_has(struct cap *c, const char *kind) {
    for (size_t i = 0; i < c->n; i++) if (!strcmp(c->kinds[i], kind)) return (int)i + 1;
    return 0;
}

static int run(const char *json, int port, struct cap *cap, char *err, size_t errsz) {
    struct ps_recipe *r = ps_recipe_parse_json((const uint8_t *)json, strlen(json), err, errsz);
    if (!r) return -2;
    struct tio io = {0};
    struct ps_recipe_io io_api = {
        .ctx = &io, .connect_tcp = tio_connect, .send_all = tio_send, .recv_some = tio_recv,
        .close_conn = tio_close, .tls_upgrade = tio_up, .tls_session = tio_sess, .tls_probe = tio_probe,
    };
    struct ps_recipe_sink sink = { .ctx = cap, .emit = cap_emit };
    struct ps_recipe_target tgt = { .host = "127.0.0.1", .port = port };
    int rc = ps_recipe_run(r, &tgt, &io_api, &sink, err, errsz);
    ps_recipe_free(r);
    return rc;
}

static int test_live(void) {
    char err[256];

    /* TLS_UPGRADE: self-signed leaf surfaced + continue-over-TLS reaches s_server -www */
    const int P1 = 14533;
    CHECK(start_s_server(P1, "-tls1_2", "ECDHE-RSA-AES128-GCM-SHA256") == 0);
    const char *up =
      "{\"schema\":2,\"name\":\"up\",\"version\":1,\"kind_prefix\":\"tls\",\"steps\":["
      "{\"op\":\"connect_tcp\",\"host\":\"$target.host\",\"port\":\"$target.port\",\"timeout_ms\":3000,\"out\":\"c\"},"
      "{\"op\":\"tls_upgrade\",\"conn\":\"c\",\"sni\":\"localhost\",\"timeout_ms\":3000},"
      "{\"op\":\"if\",\"cond\":\"equals\",\"binding\":\"cert_self_signed\",\"literal\":\"1\",\"then\":["
      "{\"op\":\"emit\",\"kind\":\"tls.selfsigned\",\"severity\":\"medium\",\"confidence\":\"firm\","
      "\"title\":\"$tls_version $cert_subject_cn\"}]},"
      "{\"op\":\"send\",\"conn\":\"c\",\"bytes\":\"GET / HTTP/1.0\\r\\n\\r\\n\"},"
      "{\"op\":\"recv\",\"conn\":\"c\",\"until\":\"n_bytes\",\"n_bytes\":12,\"max_bytes\":64,\"out\":\"resp\"},"
      "{\"op\":\"if\",\"cond\":\"matches\",\"binding\":\"resp\",\"literal\":\"HTTP\",\"then\":["
      "{\"op\":\"emit\",\"kind\":\"tls.http\",\"severity\":\"info\",\"confidence\":\"firm\",\"title\":\"over-tls\"}]}]}";
    struct cap c1 = {0};
    int rc = run(up, P1, &c1, err, sizeof(err));
    stop_s_server();
    CHECK(rc == 0);
    int idx = cap_has(&c1, "tls.selfsigned");
    CHECK(idx > 0);
    CHECK(strstr(c1.titles[idx - 1], "TLS1.2") != NULL);
    CHECK(strstr(c1.titles[idx - 1], "localhost") != NULL);
    CHECK(cap_has(&c1, "tls.http") > 0);   /* SEND/RECV rode the TLS channel */

    /* TLS_ENUM: a TLS1.0 + AES128-SHA (CBC) server trips weak-cipher + deprecated-proto.
     * (RC4 needs OpenSSL's legacy provider; TLS1.0+CBC at SECLEVEL=0 is serveable.) */
    const int P2 = 14534;
    CHECK(start_s_server(P2, "-tls1", "AES128-SHA:@SECLEVEL=0") == 0);
    const char *en =
      "{\"schema\":2,\"name\":\"en\",\"version\":1,\"kind_prefix\":\"tls\",\"steps\":["
      "{\"op\":\"tls_enum\",\"host\":\"$target.host\",\"port\":\"$target.port\","
      "\"protocols\":[\"TLS1.0\",\"TLS1.2\"],\"timeout_ms\":3000},"
      "{\"op\":\"if\",\"cond\":\"any_matches\",\"list\":\"tls_accepted_ciphers\",\"regex\":\"RC4|3DES|NULL|AES128-SHA\",\"then\":["
      "{\"op\":\"emit\",\"kind\":\"tls.weak_cipher\",\"severity\":\"high\",\"confidence\":\"firm\",\"title\":\"$tls_accepted_ciphers\"}]},"
      "{\"op\":\"if\",\"cond\":\"any_in\",\"list\":\"tls_accepted_protocols\",\"set\":[\"SSLv3\",\"TLS1.0\",\"TLS1.1\"],\"then\":["
      "{\"op\":\"emit\",\"kind\":\"tls.deprecated_protocol\",\"severity\":\"medium\",\"confidence\":\"firm\",\"title\":\"$tls_accepted_protocols\"}]}]}";
    struct cap c2 = {0};
    rc = run(en, P2, &c2, err, sizeof(err));
    stop_s_server();
    CHECK(rc == 0);
    CHECK(cap_has(&c2, "tls.weak_cipher") > 0);
    CHECK(cap_has(&c2, "tls.deprecated_protocol") > 0);
    idx = cap_has(&c2, "tls.deprecated_protocol");
    CHECK(strstr(c2.titles[idx - 1], "TLS1.0") != NULL);

    /* max_tls_probes halts the sweep */
    const int P3 = 14535;
    CHECK(start_s_server(P3, "-tls1_2", "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384") == 0);
    const char *bud =
      "{\"schema\":2,\"name\":\"b\",\"version\":1,\"kind_prefix\":\"tls\",\"budgets\":{\"max_tls_probes\":1},\"steps\":["
      "{\"op\":\"tls_enum\",\"host\":\"$target.host\",\"port\":\"$target.port\",\"protocols\":[\"TLS1.2\"],\"timeout_ms\":3000}]}";
    struct cap c3 = {0};
    rc = run(bud, P3, &c3, err, sizeof(err));
    stop_s_server();
    CHECK(rc != 0);
    CHECK(strstr(err, "max_tls_probes") != NULL);
    return 0;
}

int main(void) {
    if (test_parser() != 0) return 1;
    if (getenv("PS_TLS_LIVE")) { if (test_live() != 0) { stop_s_server(); return 1; } }
    printf("ok\n");
    return 0;
}
