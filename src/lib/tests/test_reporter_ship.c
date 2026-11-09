/* src/lib/tests/test_reporter_ship.c
 *
 * End-to-end shipping of observation batches through the real reporter and the
 * real HTTP client, against a loopback HTTP sink running in a thread. The sink
 * counts envelopes per POST and checks the body is a well-formed
 * {"envelopes":[...]} array, so these tests see exactly what reached the wire.
 *
 * Regressions covered:
 *   - a batch whose request exceeded the HTTP client's fixed 8 KiB request
 *     buffer was never sent (no connect) and the whole batch was dropped;
 *   - one item whose envelope could not be built dropped its whole batch;
 *   - a skipped first item produced "[,{" (invalid JSON);
 *   - items beyond the 256 KiB batch buffer were silently truncated.
 */
#include "reporter.h"
#include "keystore.h"
#include "http_client.h"
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---------------------------------------------------------------- sink --- */

#define SINK_MAX_POSTS 64
struct sink {
    int lfd;
    int port;
    volatile int stop;
    pthread_t th;
    int posts;                       /* complete requests received */
    int envelopes[SINK_MAX_POSTS];   /* envelopes in each POST */
    int malformed;                   /* bodies that were not a clean array */
    size_t max_body;
};

static int count_sub(const char *hay, const char *needle) {
    int c = 0; size_t nl = strlen(needle);
    for (const char *p = strstr(hay, needle); p; p = strstr(p + nl, needle)) c++;
    return c;
}

static void sink_handle(struct sink *s, int fd) {
    size_t cap = 4u << 20, got = 0;
    char *buf = malloc(cap + 1);
    assert(buf);
    long clen = -1; char *body = NULL;
    for (;;) {
        ssize_t r = read(fd, buf + got, cap - got);
        if (r <= 0) break;
        got += (size_t)r; buf[got] = 0;
        if (!body) {
            char *sep = strstr(buf, "\r\n\r\n");
            if (sep) {
                body = sep + 4;
                const char *cl = strstr(buf, "Content-Length: ");
                clen = cl ? atol(cl + 16) : 0;
            }
        }
        if (body && (long)(got - (size_t)(body - buf)) >= clen) break;
    }
    if (body && clen >= 0 && (long)(got - (size_t)(body - buf)) >= clen) {
        body[clen] = 0;
        int n = count_sub(body, "\"envelope_v\":1");
        if (s->posts < SINK_MAX_POSTS) s->envelopes[s->posts] = n;
        s->posts++;
        if ((size_t)clen > s->max_body) s->max_body = (size_t)clen;
        size_t bl = strlen(body);
        if (strncmp(body, "{\"envelopes\":[", 14) != 0 || bl < 16 ||
            strcmp(body + bl - 2, "]}") != 0 ||
            strstr(body, "[,") || strstr(body, ",]") || strstr(body, "},,{"))
            s->malformed++;
        char resp[256];
        int rl = snprintf(resp, sizeof resp,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            "Connection: close\r\n\r\n{\"accepted\":%d,\"rejected\":0}", n);
        if (write(fd, resp, (size_t)rl) < 0) { /* test sink: ignore */ }
    }
    free(buf);
}

static void *sink_main(void *arg) {
    struct sink *s = arg;
    while (!s->stop) {
        struct pollfd p = { s->lfd, POLLIN, 0 };
        if (poll(&p, 1, 50) <= 0) continue;
        int fd = accept(s->lfd, NULL, NULL);
        if (fd < 0) continue;
        sink_handle(s, fd);
        close(fd);
    }
    return NULL;
}

static void sink_start(struct sink *s) {
    memset(s, 0, sizeof *s);
    s->lfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(s->lfd >= 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
    assert(bind(s->lfd, (struct sockaddr *)&a, sizeof a) == 0);
    assert(listen(s->lfd, 16) == 0);
    socklen_t al = sizeof a;
    assert(getsockname(s->lfd, (struct sockaddr *)&a, &al) == 0);
    s->port = ntohs(a.sin_port);
    assert(pthread_create(&s->th, NULL, sink_main, s) == 0);
}

static int sink_stop(struct sink *s) {
    s->stop = 1;
    pthread_join(s->th, NULL);
    close(s->lfd);
    int total = 0;
    for (int i = 0; i < s->posts && i < SINK_MAX_POSTS; i++) total += s->envelopes[i];
    return total;
}

/* ------------------------------------------------------------- fixtures --- */

static char g_keydir[64];
static char g_url[64];

static void setup_cc(struct ps_central_config *cc, const struct sink *s) {
    memset(cc, 0, sizeof *cc);
    snprintf(g_url, sizeof g_url, "http://127.0.0.1:%d", s->port);
    cc->url = g_url; cc->agent_id = "agent-test"; cc->verify = 0; cc->key_dir = g_keydir;
}

/* A plausible passive observation of roughly `pad` + 200 bytes. */
static char *make_obs(int i, size_t pad, char fill) {
    char *p = malloc(pad + 512);
    assert(p);
    char *f = malloc(pad + 1);
    assert(f);
    memset(f, fill, pad); f[pad] = 0;
    snprintf(p, pad + 512,
        "{\"v\":1,\"id\":\"obs-%04d\",\"ts\":\"2026-01-01T00:00:%02dZ\","
        "\"kind\":\"passive.example\",\"data\":{\"mac\":\"02:00:00:00:00:%02x\","
        "\"name\":\"device-%d\",\"note\":\"%s\"}}", i, i % 60, i & 0xff, i, f);
    free(f);
    return p;
}

static void free_all(char **v, size_t n) { for (size_t i = 0; i < n; i++) free(v[i]); }

/* --------------------------------------------------------------- tests --- */

/* Harness sanity: a small batch reaches the sink intact (passes before and
 * after the fix, so a failure elsewhere is not the harness). */
static void test_small_batch_ships(void) {
    struct sink s; sink_start(&s);
    struct ps_central_config cc; setup_cc(&cc, &s);
    char *ev[3]; for (int i = 0; i < 3; i++) ev[i] = make_obs(i, 40, 'a');
    struct ps_report_result rr; memset(&rr, 0, sizeof rr);
    int rc = ps_report_observations(&cc, NULL, (const char **)ev, 3, &rr);
    int got = sink_stop(&s);
    assert(rc == 0);
    assert(got == 3 && s.posts == 1 && s.malformed == 0);
    assert(rr.http_status == 200 && rr.accepted == 3);
    free_all(ev, 3);
}

/* The production failure: a routine batch of ~30 small observations makes a
 * request body larger than 8 KiB. It must reach the server, not be dropped
 * before connect. */
static void test_typical_batch_ships(void) {
    struct sink s; sink_start(&s);
    struct ps_central_config cc; setup_cc(&cc, &s);
    enum { N = 30 };
    char *ev[N]; for (int i = 0; i < N; i++) ev[i] = make_obs(i, 200, 'b');
    struct ps_report_result rr; memset(&rr, 0, sizeof rr);
    int rc = ps_report_observations(&cc, NULL, (const char **)ev, N, &rr);
    int got = sink_stop(&s);
    fprintf(stderr, "  typical: rc=%d posts=%d envelopes=%d max_body=%zu\n",
            rc, s.posts, got, s.max_body);
    assert(s.max_body > 8192 || s.posts == 0);  /* the case is the >8 KiB one */
    assert(rc == 0);
    assert(got == N && s.malformed == 0);
    assert(rr.accepted == N);
    free_all(ev, N);
}

/* One item whose envelope cannot be built (control bytes escape six-fold past
 * the envelope buffer) must be skipped, not take its whole batch down. */
static void test_one_unbuildable_item_does_not_drop_batch(void) {
    struct sink s; sink_start(&s);
    struct ps_central_config cc; setup_cc(&cc, &s);
    enum { N = 7, BAD = 3 };
    char *ev[N];
    for (int i = 0; i < N; i++) ev[i] = make_obs(i, 40, 'c');
    free(ev[BAD]); ev[BAD] = make_obs(BAD, 3600, '\x01');
    struct ps_report_result rr; memset(&rr, 0, sizeof rr);
    int rc = ps_report_observations(&cc, NULL, (const char **)ev, N, &rr);
    int got = sink_stop(&s);
    fprintf(stderr, "  one-bad: rc=%d posts=%d envelopes=%d\n", rc, s.posts, got);
    assert(rc == 0);
    assert(got == N - 1 && s.malformed == 0);
    assert(rr.total == N && rr.skipped == 1 && rr.unsent == 0 && rr.accepted == N - 1);
    free_all(ev, N);
}

/* A batch whose envelopes exceed the 256 KiB batch buffer must ship every item
 * (in more than one POST), not silently truncate the tail. */
static void test_oversized_batch_ships_everything(void) {
    struct sink s; sink_start(&s);
    struct ps_central_config cc; setup_cc(&cc, &s);
    enum { N = 50 };
    char *ev[N];
    /* '"' inside the note doubles under escaping: ~8 KiB per envelope. */
    for (int i = 0; i < N; i++) {
        ev[i] = make_obs(i, 3800, 'd');
        char *note = strstr(ev[i], "\"note\":\"") + 8;
        for (int k = 0; k < 3800; k += 2) note[k] = '\\', note[k + 1] = '"';
    }
    struct ps_report_result rr; memset(&rr, 0, sizeof rr);
    int rc = ps_report_observations(&cc, NULL, (const char **)ev, N, &rr);
    int got = sink_stop(&s);
    fprintf(stderr, "  oversized: rc=%d posts=%d envelopes=%d max_body=%zu\n",
            rc, s.posts, got, s.max_body);
    assert(rc == 0);
    assert(got == N && s.malformed == 0 && s.posts >= 2);
    assert(rr.accepted == N && rr.skipped == 0 && rr.unsent == 0 && rr.posts == s.posts);
    free_all(ev, N);
}

/* Central unreachable: the call fails, nothing counts as delivered, and every
 * item is accounted for as unsent (not silently counted as shipped). */
static void test_unreachable_accounts_every_item(void) {
    struct sink s; sink_start(&s);
    struct ps_central_config cc; setup_cc(&cc, &s);
    sink_stop(&s);                       /* port now closed: connect refused */
    enum { N = 5 };
    char *ev[N]; for (int i = 0; i < N; i++) ev[i] = make_obs(i, 40, 'g');
    struct ps_report_result rr; memset(&rr, 0, sizeof rr);
    int rc = ps_report_observations(&cc, NULL, (const char **)ev, N, &rr);
    assert(rc == -1);
    assert(rr.total == N && rr.unsent == N && rr.skipped == 0 && rr.accepted == 0);
    assert(strcmp(ps_http_last_error(), "connect") == 0);
    free_all(ev, N);
}

/* A skipped first item must not leave a leading comma ("[,{"). */
static void test_skipped_first_item_keeps_array_valid(void) {
    struct ps_central_config cc; memset(&cc, 0, sizeof cc);
    cc.url = "http://unused.invalid"; cc.agent_id = "agent-test"; cc.key_dir = g_keydir;
    char *big = make_obs(0, 17000, 'e');           /* payload > 16 KiB: unbuildable */
    char *ok = make_obs(1, 40, 'f');
    const char *ev[] = { big, ok };
    static char out[65536];
    int n = ps_reporter_build_envelopes(&cc, ev, 2, out, sizeof out);
    assert(n > 0);
    assert(strncmp(out, "[{", 2) == 0);
    assert(count_sub(out, "\"envelope_v\":1") == 1);
    assert(out[n - 1] == ']');
    free(big); free(ok);
}

/* The HTTP client itself must send bodies larger than its header buffer. */
static void test_http_large_body(void) {
    struct sink s; sink_start(&s);
    char url[64]; snprintf(url, sizeof url, "http://127.0.0.1:%d/x", s.port);
    size_t bl = 100000;
    char *body = malloc(bl + 64);
    assert(body);
    int o = snprintf(body, bl + 64, "{\"envelopes\":[{\"envelope_v\":1,\"pad\":\"");
    memset(body + o, 'z', bl); o += (int)bl;
    o += snprintf(body + o, 64, "\"}]}");
    struct ps_http_opts opts = { 0, NULL, 5 };
    int status = 0; char resp[1024];
    int rc = ps_http_request("POST", url, body, &opts, &status, resp, sizeof resp);
    sink_stop(&s);
    assert(rc == 0 && status == 200);
    assert(s.posts == 1 && s.max_body == (size_t)o && s.malformed == 0);
    free(body);
}

static const struct { const char *name; void (*fn)(void); } TESTS[] = {
    { "small",      test_small_batch_ships },
    { "http_large", test_http_large_body },
    { "typical",    test_typical_batch_ships },
    { "one_bad",    test_one_unbuildable_item_does_not_drop_batch },
    { "first_skip", test_skipped_first_item_keeps_array_valid },
    { "oversized",  test_oversized_batch_ships_everything },
    { "unreachable", test_unreachable_accounts_every_item },
};

/* No argument runs every test; one argument runs just that test by name. */
int main(int argc, char **argv) {
    struct ps_keypair kp; assert(ps_keystore_generate(&kp) == 0);
    snprintf(g_keydir, sizeof g_keydir, "/tmp/ps_ship_XXXXXX");
    assert(mkdtemp(g_keydir));
    assert(ps_keystore_save(g_keydir, "agent", &kp) == 0);

    for (size_t i = 0; i < sizeof TESTS / sizeof TESTS[0]; i++) {
        if (argc > 1 && strcmp(argv[1], TESTS[i].name) != 0) continue;
        fprintf(stderr, "- %s\n", TESTS[i].name);
        TESTS[i].fn();
    }

    char p[128];
    snprintf(p, sizeof p, "%s/agent.pub", g_keydir); unlink(p);
    snprintf(p, sizeof p, "%s/agent.sec", g_keydir); unlink(p);
    rmdir(g_keydir);
    printf("test_reporter_ship: OK\n");
    return 0;
}
