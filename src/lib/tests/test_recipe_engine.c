#include "recipe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); return 1; } \
} while (0)

/* ---- in-memory mock backends -------------------------------------------- */

struct mock_io {
    /* Canned response served by recv_some. */
    const uint8_t *recv_data;
    size_t         recv_n;
    size_t         recv_pos;

    /* Captures of the send_all calls. */
    uint8_t        sent[4096];
    size_t         sent_n;

    /* Captures of the connect call. */
    int            connect_calls;
    char           connect_host[256];
    int            connect_port;

    int            next_fd;
};

static int mock_connect_tcp(void *ctx, const char *host, int port, int timeout_ms) {
    (void)timeout_ms;
    struct mock_io *m = ctx;
    m->connect_calls++;
    snprintf(m->connect_host, sizeof(m->connect_host), "%s", host);
    m->connect_port = port;
    return ++m->next_fd;
}

static int mock_send_all(void *ctx, int conn, const uint8_t *buf, size_t n) {
    (void)conn;
    struct mock_io *m = ctx;
    if (m->sent_n + n > sizeof(m->sent)) return -1;
    memcpy(m->sent + m->sent_n, buf, n);
    m->sent_n += n;
    return 0;
}

static long mock_recv_some(void *ctx, int conn, uint8_t *buf, size_t cap) {
    (void)conn;
    struct mock_io *m = ctx;
    if (m->recv_pos >= m->recv_n) return 0; /* EOF */
    size_t remaining = m->recv_n - m->recv_pos;
    size_t take = remaining < cap ? remaining : cap;
    memcpy(buf, m->recv_data + m->recv_pos, take);
    m->recv_pos += take;
    return (long)take;
}

static void mock_close(void *ctx, int conn) { (void)ctx; (void)conn; }

/* ---- sink ---------------------------------------------------------------- */

struct emit_capture {
    char kind[64];
    char severity[16];
    char confidence[16];
    char title[256];
    char evidence[1024];
};

struct mock_sink {
    struct emit_capture findings[8];
    size_t              n;
};

static void mock_emit(void *ctx, const char *kind, const char *sev,
                      const char *conf, const char *title, const char *evidence) {
    struct mock_sink *s = ctx;
    if (s->n >= 8) return;
    struct emit_capture *e = &s->findings[s->n++];
    snprintf(e->kind,       sizeof(e->kind),       "%s", kind);
    snprintf(e->severity,   sizeof(e->severity),   "%s", sev);
    snprintf(e->confidence, sizeof(e->confidence), "%s", conf);
    snprintf(e->title,      sizeof(e->title),      "%s", title);
    snprintf(e->evidence,   sizeof(e->evidence),   "%s", evidence);
}

/* ---- the VNC recipe (same as test_recipe.c, canonical form) -------------- */

static const char VNC_RECIPE[] =
    "{\"default_port\":5900,\"description\":\"VNC reachability + RFB version\","
    "\"kind_prefix\":\"vnc\",\"name\":\"vnc\",\"schema\":1,"
    "\"steps\":["
      "{\"host\":\"$target.host\",\"op\":\"connect_tcp\",\"out\":\"c\","
       "\"port\":\"$target.port\",\"timeout_ms\":4000},"
      "{\"conn\":\"c\",\"max_bytes\":64,\"op\":\"recv\",\"out\":\"banner\","
       "\"until\":\"newline\"},"
      "{\"captures\":["
        "{\"as\":\"int\",\"name\":\"major\"},"
        "{\"as\":\"int\",\"name\":\"minor\"}"
      "],\"in\":\"banner\",\"op\":\"match\","
       "\"regex\":\"^RFB ([0-9]{3})\\\\.([0-9]{3})\"},"
      "{\"evidence\":{"
         "\"rfb_major\":{\"as\":\"int\",\"value\":\"$major\"},"
         "\"rfb_minor\":{\"as\":\"int\",\"value\":\"$minor\"},"
         "\"port\":{\"as\":\"int\",\"value\":\"$target.port\"}"
       "},\"kind\":\"vnc.metadata\",\"op\":\"emit\",\"severity\":\"info\","
       "\"confidence\":\"firm\","
       "\"title\":\"VNC server (RFB $major.$minor)\"},"
      "{\"conn\":\"c\",\"op\":\"close\"}"
    "],\"version\":1}";

static int test_e2e_vnc(void) {
    char err[256] = "";
    struct ps_recipe *r = ps_recipe_parse_json((const uint8_t *)VNC_RECIPE,
                                               sizeof(VNC_RECIPE) - 1,
                                               err, sizeof(err));
    if (!r) fprintf(stderr, "parse: %s\n", err);
    CHECK(r != NULL);

    static const char BANNER[] = "RFB 003.008\n";
    struct mock_io io = {0};
    io.recv_data = (const uint8_t *)BANNER;
    io.recv_n = sizeof(BANNER) - 1;

    struct ps_recipe_io io_api = {
        .ctx = &io,
        .connect_tcp = mock_connect_tcp,
        .send_all = mock_send_all,
        .recv_some = mock_recv_some,
        .close_conn = mock_close,
    };
    struct mock_sink sink = {0};
    struct ps_recipe_sink sink_api = { .ctx = &sink, .emit = mock_emit };

    struct ps_recipe_target target = { .host = "10.0.0.1", .port = 5900 };

    int rc = ps_recipe_run(r, &target, &io_api, &sink_api, err, sizeof(err));
    if (rc != 0) fprintf(stderr, "run: %s\n", err);
    CHECK(rc == 0);

    /* The connect was attempted with the templated host:port. */
    CHECK(io.connect_calls == 1);
    CHECK(strcmp(io.connect_host, "10.0.0.1") == 0);
    CHECK(io.connect_port == 5900);

    /* One finding was emitted. */
    CHECK(sink.n == 1);
    CHECK(strcmp(sink.findings[0].kind,       "vnc.metadata") == 0);
    CHECK(strcmp(sink.findings[0].severity,   "info") == 0);
    CHECK(strcmp(sink.findings[0].confidence, "firm") == 0);
    /* Title template expanded major/minor. */
    CHECK(strcmp(sink.findings[0].title, "VNC server (RFB 3.8)") == 0);
    /* Evidence: int-typed fields render as JSON integers, NOT quoted strings. */
    CHECK(strstr(sink.findings[0].evidence, "\"rfb_major\":3") != NULL);
    CHECK(strstr(sink.findings[0].evidence, "\"rfb_minor\":8") != NULL);
    CHECK(strstr(sink.findings[0].evidence, "\"port\":5900")   != NULL);

    ps_recipe_free(r);
    return 0;
}

/* `recv until n_bytes`: 4-byte length-prefixed protocol, no newline. */
static const char NB_RECIPE[] =
    "{\"kind_prefix\":\"x\",\"name\":\"x\",\"schema\":1,"
    "\"steps\":["
      "{\"host\":\"$target.host\",\"op\":\"connect_tcp\",\"out\":\"c\","
       "\"port\":\"$target.port\",\"timeout_ms\":1000},"
      "{\"conn\":\"c\",\"max_bytes\":4,\"op\":\"recv\",\"out\":\"hdr\","
       "\"n_bytes\":4,\"until\":\"n_bytes\"},"
      "{\"evidence\":{\"hdr\":\"$hdr\"},\"kind\":\"x.t\",\"op\":\"emit\","
       "\"severity\":\"info\",\"confidence\":\"firm\",\"title\":\"got\"},"
      "{\"conn\":\"c\",\"op\":\"close\"}"
    "],\"version\":1}";

static int test_recv_n_bytes(void) {
    char err[256] = "";
    struct ps_recipe *r = ps_recipe_parse_json((const uint8_t *)NB_RECIPE,
                                               sizeof(NB_RECIPE) - 1,
                                               err, sizeof(err));
    if (!r) fprintf(stderr, "parse: %s\n", err);
    CHECK(r != NULL);

    static const char DATA[] = "ABCDEXTRA";
    struct mock_io io = {0};
    io.recv_data = (const uint8_t *)DATA;
    io.recv_n = sizeof(DATA) - 1;

    struct ps_recipe_io io_api = {
        .ctx = &io,
        .connect_tcp = mock_connect_tcp,
        .recv_some = mock_recv_some,
        .close_conn = mock_close,
    };
    struct mock_sink sink = {0};
    struct ps_recipe_sink sink_api = { .ctx = &sink, .emit = mock_emit };
    struct ps_recipe_target target = { .host = "h", .port = 1 };

    CHECK(ps_recipe_run(r, &target, &io_api, &sink_api, err, sizeof(err)) == 0);
    CHECK(sink.n == 1);
    CHECK(strstr(sink.findings[0].evidence, "\"hdr\":\"ABCD\"") != NULL);
    ps_recipe_free(r);
    return 0;
}

/* `if exists` gates an emit on a capture binding being set. */
static const char IF_RECIPE[] =
    "{\"kind_prefix\":\"x\",\"name\":\"x\",\"schema\":1,"
    "\"steps\":["
      "{\"host\":\"$target.host\",\"op\":\"connect_tcp\",\"out\":\"c\","
       "\"port\":\"$target.port\",\"timeout_ms\":1000},"
      "{\"conn\":\"c\",\"max_bytes\":32,\"op\":\"recv\",\"out\":\"b\","
       "\"until\":\"newline\"},"
      "{\"captures\":[{\"as\":\"string\",\"name\":\"tag\"}],"
       "\"in\":\"b\",\"op\":\"match\",\"regex\":\"^TAG=([A-Z]+)\"},"
      "{\"binding\":\"tag\",\"cond\":\"exists\",\"op\":\"if\","
       "\"then\":[{\"evidence\":{\"tag\":\"$tag\"},\"kind\":\"x.t\","
                  "\"op\":\"emit\",\"severity\":\"info\",\"confidence\":\"firm\","
                  "\"title\":\"tagged $tag\"}]},"
      "{\"conn\":\"c\",\"op\":\"close\"}"
    "],\"version\":1}";

static int test_if_exists_skips_when_no_match(void) {
    char err[256] = "";
    struct ps_recipe *r = ps_recipe_parse_json((const uint8_t *)IF_RECIPE,
                                               sizeof(IF_RECIPE) - 1,
                                               err, sizeof(err));
    CHECK(r != NULL);

    /* Banner doesn't match TAG=, so capture binding `tag` never gets set,
     * so the `if exists` gate is false, so emit is skipped. */
    static const char BANNER[] = "OTHER\n";
    struct mock_io io = {0};
    io.recv_data = (const uint8_t *)BANNER;
    io.recv_n = sizeof(BANNER) - 1;
    struct ps_recipe_io io_api = {
        .ctx = &io, .connect_tcp = mock_connect_tcp,
        .recv_some = mock_recv_some, .close_conn = mock_close,
    };
    struct mock_sink sink = {0};
    struct ps_recipe_sink sink_api = { .ctx = &sink, .emit = mock_emit };
    struct ps_recipe_target target = { .host = "h", .port = 1 };

    CHECK(ps_recipe_run(r, &target, &io_api, &sink_api, err, sizeof(err)) == 0);
    CHECK(sink.n == 0);
    ps_recipe_free(r);
    return 0;
}

static int test_if_exists_fires_when_matched(void) {
    char err[256] = "";
    struct ps_recipe *r = ps_recipe_parse_json((const uint8_t *)IF_RECIPE,
                                               sizeof(IF_RECIPE) - 1,
                                               err, sizeof(err));
    CHECK(r != NULL);

    static const char BANNER[] = "TAG=HELLO\n";
    struct mock_io io = {0};
    io.recv_data = (const uint8_t *)BANNER;
    io.recv_n = sizeof(BANNER) - 1;
    struct ps_recipe_io io_api = {
        .ctx = &io, .connect_tcp = mock_connect_tcp,
        .recv_some = mock_recv_some, .close_conn = mock_close,
    };
    struct mock_sink sink = {0};
    struct ps_recipe_sink sink_api = { .ctx = &sink, .emit = mock_emit };
    struct ps_recipe_target target = { .host = "h", .port = 1 };

    CHECK(ps_recipe_run(r, &target, &io_api, &sink_api, err, sizeof(err)) == 0);
    CHECK(sink.n == 1);
    CHECK(strstr(sink.findings[0].title, "tagged HELLO") != NULL);
    CHECK(strstr(sink.findings[0].evidence, "\"tag\":\"HELLO\"") != NULL);
    ps_recipe_free(r);
    return 0;
}

/* Budget enforcement: max_steps lower than actual step count → failure. */
static const char BUDGET_RECIPE[] =
    "{\"budgets\":{\"max_steps\":2},\"kind_prefix\":\"x\",\"name\":\"x\","
    "\"schema\":1,\"steps\":["
      "{\"host\":\"$target.host\",\"op\":\"connect_tcp\",\"out\":\"c\","
       "\"port\":\"$target.port\",\"timeout_ms\":1000},"
      "{\"conn\":\"c\",\"max_bytes\":8,\"op\":\"recv\",\"out\":\"b\","
       "\"until\":\"newline\"},"
      "{\"conn\":\"c\",\"op\":\"close\"}"
    "],\"version\":1}";

static int test_budget_max_steps(void) {
    char err[256] = "";
    struct ps_recipe *r = ps_recipe_parse_json((const uint8_t *)BUDGET_RECIPE,
                                               sizeof(BUDGET_RECIPE) - 1,
                                               err, sizeof(err));
    CHECK(r != NULL);
    CHECK(r->budgets.max_steps == 2);

    static const char DATA[] = "x\n";
    struct mock_io io = {0};
    io.recv_data = (const uint8_t *)DATA;
    io.recv_n = sizeof(DATA) - 1;
    struct ps_recipe_io io_api = {
        .ctx = &io, .connect_tcp = mock_connect_tcp,
        .recv_some = mock_recv_some, .close_conn = mock_close,
    };
    struct ps_recipe_target target = { .host = "h", .port = 1 };
    int rc = ps_recipe_run(r, &target, &io_api, NULL, err, sizeof(err));
    CHECK(rc != 0);
    CHECK(strstr(err, "max_steps") != NULL);
    ps_recipe_free(r);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_e2e_vnc();
    rc |= test_recv_n_bytes();
    rc |= test_if_exists_skips_when_no_match();
    rc |= test_if_exists_fires_when_matched();
    rc |= test_budget_max_steps();
    if (rc == 0) printf("test_recipe_engine: OK\n");
    return rc;
}
