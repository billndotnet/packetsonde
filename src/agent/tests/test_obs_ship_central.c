/* Queued observations and dedupe summaries through the REAL shipping path:
 * ps_central_checkin_stop -> ps_obs_ship_cycle -> ship_to_central ->
 * reporter -> HTTP, against a loopback sink that answers a scripted status
 * per POST. Checks how central's answers translate: transport failure / 5xx
 * / 408 / 429 keep what was not delivered (queue items stay at the head of
 * the queue, summaries are re-staged) and the retry is byte-identical (same
 * envelope sigs, which central dedups on); 2xx delivers and its
 * per-envelope verdict is final (accepted items are never re-sent); any
 * other 4xx is poison and is not retried. */
#include "obs_dedupe.h"
#include "obs_queue.h"
#include "central_checkin.h"
#include "keystore.h"
#include "platform/platform.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int g_fail;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

#define MAXP 64
struct sink {
    int lfd, port;
    volatile int stop;
    pthread_t th;
    int script[MAXP], nscript;   /* status per POST; -1 = close without answer */
    int posts;
    char *body[MAXP];
    int status[MAXP];
    int accept_short;   /* a 200 reports this many fewer accepted envelopes */
};

static void handle(struct sink *s, int fd) {
    size_t cap = 1u << 20, got = 0;
    char *buf = malloc(cap + 1);
    long clen = -1; char *b = NULL;
    for (;;) {
        ssize_t r = read(fd, buf + got, cap - got);
        if (r <= 0) break;
        got += (size_t)r; buf[got] = 0;
        if (!b) {
            char *sep = strstr(buf, "\r\n\r\n");
            if (sep) { b = sep + 4; const char *cl = strstr(buf, "Content-Length: "); clen = cl ? atol(cl + 16) : 0; }
        }
        if (b && (long)(got - (size_t)(b - buf)) >= clen) break;
    }
    if (b && clen >= 0) {
        b[clen] = 0;
        int i = s->posts++;
        if (i < MAXP) s->body[i] = strdup(b);
        int code = i < s->nscript ? s->script[i] : 200;
        if (i < MAXP) s->status[i] = code;
        if (code > 0) {
            char resp[256];
            int n = 0;
            for (const char *p = strstr(b, "\"envelope_v\":1"); p; p = strstr(p + 1, "\"envelope_v\":1")) n++;
            int rl = snprintf(resp, sizeof resp,
                "HTTP/1.1 %d X\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
                "{\"accepted\":%d,\"rejected\":%d}", code,
                code == 200 ? n - s->accept_short : 0, code == 200 ? s->accept_short : 0);
            if (write(fd, resp, (size_t)rl) < 0) { /* ignore */ }
        }
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
        handle(s, fd);
        close(fd);
    }
    return NULL;
}

static void sink_start(struct sink *s, const int *script, int n) {
    memset(s, 0, sizeof *s);
    if (n > 0) memcpy(s->script, script, (size_t)n * sizeof *script);
    s->nscript = n;
    s->lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s->lfd, (struct sockaddr *)&a, sizeof a) != 0 || listen(s->lfd, 16) != 0) { perror("sink"); exit(2); }
    socklen_t al = sizeof a;
    getsockname(s->lfd, (struct sockaddr *)&a, &al);
    s->port = ntohs(a.sin_port);
    pthread_create(&s->th, NULL, sink_main, s);
    char url[64];
    snprintf(url, sizeof url, "http://127.0.0.1:%d", s->port);
    setenv("PS_CENTRAL_URL", url, 1);
}

static void sink_stop(struct sink *s) {
    s->stop = 1;
    pthread_join(s->th, NULL);
    close(s->lfd);
}
static void sink_free(struct sink *s) { for (int i = 0; i < s->posts && i < MAXP; i++) free(s->body[i]); }

/* three keys, two repeats each, windows still open (stop forces them) */
static void make_pending(void) {
    struct ps_obs_dedupe_cfg c;
    ps_obs_dedupe_cfg_defaults(&c);
    if (ps_obs_dedupe_init(&c) != 0) exit(2);
    ps_obs_queue_init();
    int64_t now = (int64_t)(ps_platform_wall_usec() / 1000);
    char obs[64];
    for (int k = 0; k < 3; k++) {
        snprintf(obs, sizeof obs, "{\"group\":\"ship%d\"}", k);
        for (int i = 0; i < 3; i++) ps_obs_dedupe_offer("discovery.mld", obs, now + i);
    }
}

/* status (or -1: connection closed without an answer) for the first POST,
 * then 200 */
static void retry_case(int first) {
    int script[2] = { first, 200 };
    struct sink s;
    sink_start(&s, script, 2);
    make_pending();
    ps_central_checkin_stop();
    CHECK(s.posts == 1);
    CHECK(ps_obs_dedupe_staged() == 3);       /* whole batch re-staged */
    CHECK(ps_obs_dedupe_count() == 0);
    ps_central_checkin_stop();                /* central answers 200 now */
    CHECK(s.posts == 2);
    CHECK(s.body[0] && s.body[1] && strcmp(s.body[0], s.body[1]) == 0);   /* byte-identical */
    CHECK(ps_obs_dedupe_staged() == 0);
    ps_central_checkin_stop();                /* nothing left to send */
    CHECK(s.posts == 2);
    sink_stop(&s);
    sink_free(&s);
    if (g_fail) fprintf(stderr, "  (case first=%d)\n", first);
}

static void test_retryable(void) {
    retry_case(503);
    retry_case(500);
    retry_case(429);
    retry_case(408);
    retry_case(-1);
}

static void test_unreachable(void) {
    struct sink s;
    sink_start(&s, NULL, 0);
    sink_stop(&s);                            /* port closed: connect refused */
    make_pending();
    ps_central_checkin_stop();
    CHECK(ps_obs_dedupe_staged() == 3);
}

static void test_poison_and_ok(void) {
    int script[1] = { 400 };
    struct sink s;
    sink_start(&s, script, 1);
    make_pending();
    ps_central_checkin_stop();
    CHECK(s.posts == 1);
    CHECK(ps_obs_dedupe_staged() == 0 && ps_obs_dedupe_count() == 0);   /* poison: not retried */
    ps_central_checkin_stop();
    CHECK(s.posts == 1);
    sink_stop(&s);
    sink_free(&s);

    struct sink t;
    sink_start(&t, NULL, 0);
    make_pending();
    ps_central_checkin_stop();
    CHECK(t.posts == 1 && t.body[0] && strstr(t.body[0], "\"envelope_v\":1"));
    CHECK(ps_obs_dedupe_staged() == 0 && ps_obs_dedupe_count() == 0);
    sink_stop(&t);
    sink_free(&t);
}


/* ---- queued (raw) observations ---------------------------------------- */

static void reset_all(void) {
    struct ps_obs_dedupe_cfg c;
    ps_obs_dedupe_cfg_defaults(&c);
    if (ps_obs_dedupe_init(&c) != 0) exit(2);
    ps_obs_queue_init();
}

/* item i carries the token "obsid-<i>"; `pad` quote-heavy bytes make its
 * envelope large (each '"' is escaped once in the payload and again in the
 * envelope) */
static void push_raw(int i, int pad) {
    char obs[PS_OBS_ITEM_MAX], ev[PS_OBS_ITEM_MAX];
    int o = snprintf(obs, sizeof obs, "{\"id\":\"obsid-%05d\",\"pad\":\"", i);
    for (int k = 0; k + 1 < pad; k += 2) { obs[o++] = '\\'; obs[o++] = '"'; }
    o += snprintf(obs + o, sizeof obs - (size_t)o, "\"}");
    size_t n = ps_obs_build_event(ev, sizeof ev, "discovery.test", "2026-01-01T00:00:00Z",
                                  obs, (size_t)o);
    if (n == 0) { fprintf(stderr, "push_raw: item too large\n"); exit(2); }
    ps_obs_queue_push(ev, n);
}

/* the obsid tokens of one POST body, in order */
static int ids_in(const char *body, int *out, int max) {
    int n = 0;
    for (const char *p = body ? strstr(body, "obsid-") : NULL; p && n < max;
         p = strstr(p + 6, "obsid-"))
        out[n++] = atoi(p + 6);
    return n;
}

/* every id delivered with a 200, in POST order; checks no id twice */
static int delivered(const struct sink *s, int *out, int max) {
    int n = 0;
    for (int i = 0; i < s->posts && i < MAXP; i++)
        if (s->status[i] == 200) n += ids_in(s->body[i], out + n, max - n);
    for (int a = 0; a < n; a++)
        for (int b = a + 1; b < n; b++) CHECK(out[a] != out[b]);
    return n;
}

/* Central behind a proxy answering 503 for three cycles, then 200: nothing
 * is lost, the order is kept, nothing is delivered twice, and each outage
 * cycle makes ONE POST (no retry loop inside a cycle). */
static void test_raw_survives_outage(void) {
    int script[3] = { 503, 503, 503 };
    struct sink s;
    sink_start(&s, script, 3);
    reset_all();
    enum { N = 120 };
    for (int i = 0; i < N; i++) push_raw(i, 0);
    for (int cyc = 1; cyc <= 3; cyc++) {
        ps_central_checkin_stop();
        CHECK(s.posts == cyc);
        CHECK(ps_obs_queue_count() == N);
    }
    /* every outage POST was the same head batch, byte-identical */
    CHECK(s.body[0] && s.body[2] && strcmp(s.body[0], s.body[2]) == 0);
    ps_central_checkin_stop();                /* central is back */
    CHECK(ps_obs_queue_count() == 0);
    CHECK(s.posts == 3 + 3);                  /* 50 + 50 + 20 */
    int ids[2 * N];
    int n = delivered(&s, ids, 2 * N);
    CHECK(n == N);
    for (int i = 0; i < n && i < N; i++) CHECK(ids[i] == i);
    ps_central_checkin_stop();
    CHECK(s.posts == 6);
    sink_stop(&s);
    sink_free(&s);
}

/* 408 and 429 (and transport failure) are retried; the retry is identical. */
static void raw_retry_case(int first) {
    int script[1] = { first };
    struct sink s;
    sink_start(&s, script, 1);
    reset_all();
    for (int i = 0; i < 5; i++) push_raw(i, 0);
    ps_central_checkin_stop();
    CHECK(s.posts == 1 && ps_obs_queue_count() == 5);
    ps_central_checkin_stop();
    CHECK(s.posts == 2 && ps_obs_queue_count() == 0);
    if (first > 0) CHECK(s.body[0] && s.body[1] && strcmp(s.body[0], s.body[1]) == 0);
    int ids[16];
    CHECK(delivered(&s, ids, 16) == 5);
    sink_stop(&s);
    sink_free(&s);
    if (g_fail) fprintf(stderr, "  (raw case first=%d)\n", first);
}

static void test_raw_retryable(void) {
    raw_retry_case(408);
    raw_retry_case(429);
    raw_retry_case(500);
    raw_retry_case(-1);
}

/* A 400 (or 413, 404, ...) is final: dropped once, never re-sent. */
static void raw_poison_case(int code) {
    int script[1] = { code };
    struct sink s;
    sink_start(&s, script, 1);
    reset_all();
    for (int i = 0; i < 5; i++) push_raw(i, 0);
    ps_central_checkin_stop();
    CHECK(s.posts == 1 && ps_obs_queue_count() == 0);
    ps_central_checkin_stop();
    ps_central_checkin_stop();
    CHECK(s.posts == 1);
    sink_stop(&s);
    sink_free(&s);
    if (g_fail) fprintf(stderr, "  (poison case %d)\n", code);
}

static void test_raw_poison(void) {
    raw_poison_case(400);
    raw_poison_case(413);
    raw_poison_case(404);
}

/* The queue fills while central is down: drop-oldest keeps it bounded and
 * counts every drop; on recovery the newest PS_OBS_QUEUE_CAP arrive in order. */
static void test_raw_queue_full_during_outage(void) {
    int script[2] = { 503, 503 };
    struct sink s;
    sink_start(&s, script, 2);
    reset_all();
    enum { EXTRA = 44 };
    for (int i = 0; i < PS_OBS_QUEUE_CAP; i++) push_raw(i, 0);
    ps_central_checkin_stop();
    CHECK(ps_obs_queue_count() == PS_OBS_QUEUE_CAP && ps_obs_queue_dropped() == 0);
    for (int i = PS_OBS_QUEUE_CAP; i < PS_OBS_QUEUE_CAP + EXTRA; i++) push_raw(i, 0);
    CHECK(ps_obs_queue_count() == PS_OBS_QUEUE_CAP);
    CHECK(ps_obs_queue_dropped() == EXTRA);
    ps_central_checkin_stop();
    CHECK(ps_obs_queue_count() == PS_OBS_QUEUE_CAP);
    ps_central_checkin_stop();                /* recovered */
    CHECK(ps_obs_queue_count() == 0);
    int ids[2 * PS_OBS_QUEUE_CAP];
    int n = delivered(&s, ids, 2 * PS_OBS_QUEUE_CAP);
    CHECK(n == PS_OBS_QUEUE_CAP);
    for (int i = 0; i < n; i++) CHECK(ids[i] == EXTRA + i);
    sink_stop(&s);
    sink_free(&s);
}

/* Partial acceptance inside a 2xx: central's verdict is final, so neither
 * the accepted nor the rejected envelopes are sent again. */
static void test_raw_partial_accept_in_2xx(void) {
    struct sink s;
    sink_start(&s, NULL, 0);
    s.accept_short = 2;
    reset_all();
    for (int i = 0; i < 10; i++) push_raw(i, 0);
    ps_central_checkin_stop();
    CHECK(s.posts == 1 && ps_obs_queue_count() == 0);
    ps_central_checkin_stop();
    CHECK(s.posts == 1);
    sink_stop(&s);
    sink_free(&s);
}

/* A batch too large for one POST: the first POST is answered 200, the second
 * 503. Only the second POST's items stay queued, the accepted ones are not
 * re-sent, and the order holds. */
static void test_raw_split_batch_partial(void) {
    int script[2] = { 200, 503 };
    struct sink s;
    sink_start(&s, script, 2);
    reset_all();
    enum { N = PS_OBS_SHIP_BATCH };
    for (int i = 0; i < N; i++) push_raw(i, 3600);
    ps_central_checkin_stop();
    CHECK(s.posts == 2);
    int first[N];
    int a = ids_in(s.body[0], first, N);
    CHECK(a > 0 && a < N);
    CHECK(ps_obs_queue_count() == N - a);
    ps_central_checkin_stop();
    CHECK(ps_obs_queue_count() == 0);
    int ids[2 * N];
    int n = delivered(&s, ids, 2 * N);
    CHECK(n == N);
    for (int i = 0; i < n && i < N; i++) CHECK(ids[i] == i);
    /* the retry starts exactly where the 200 stopped */
    int r[N];
    CHECK(s.posts >= 3 && ids_in(s.body[2], r, N) > 0 && r[0] == a);
    /* and it is the same bytes as the failed POST */
    CHECK(s.body[1] && s.body[2] && strcmp(s.body[1], s.body[2]) == 0);
    sink_stop(&s);
    sink_free(&s);
}

/* Queue items and summaries both pending, central down: one POST, the
 * queue kept, no summary flushed (so none can be lost); then both ship. */
static void test_raw_and_summaries_outage(void) {
    int script[1] = { 503 };
    struct sink s;
    sink_start(&s, script, 1);
    make_pending();
    for (int i = 0; i < 3; i++) push_raw(i, 0);
    ps_central_checkin_stop();
    CHECK(s.posts == 1 && ps_obs_queue_count() == 3);
    CHECK(ps_obs_dedupe_count() == 3 && ps_obs_dedupe_staged() == 0);
    ps_central_checkin_stop();
    CHECK(s.posts == 3 && ps_obs_queue_count() == 0);
    CHECK(ps_obs_dedupe_count() == 0 && ps_obs_dedupe_staged() == 0);
    sink_stop(&s);
    sink_free(&s);
}

int main(void) {
    char keydir[64];
    snprintf(keydir, sizeof keydir, "/tmp/ps_obsship_XXXXXX");
    if (!mkdtemp(keydir)) return 2;
    struct ps_keypair kp;
    if (ps_keystore_generate(&kp) != 0 || ps_keystore_save(keydir, "agent", &kp) != 0) return 2;
    setenv("PS_KEY_DIR", keydir, 1);
    setenv("PS_CENTRAL_AGENT_ID", "agent-test", 1);
    setenv("PS_CENTRAL_VERIFY", "0", 1);

    test_retryable();
    test_unreachable();
    test_poison_and_ok();
    test_raw_survives_outage();
    test_raw_retryable();
    test_raw_poison();
    test_raw_queue_full_during_outage();
    test_raw_partial_accept_in_2xx();
    test_raw_split_batch_partial();
    test_raw_and_summaries_outage();

    char p[128];
    snprintf(p, sizeof p, "%s/agent.pub", keydir); unlink(p);
    snprintf(p, sizeof p, "%s/agent.sec", keydir); unlink(p);
    rmdir(keydir);
    if (g_fail) { fprintf(stderr, "%d check(s) failed\n", g_fail); return 1; }
    printf("test_obs_ship_central: all passed\n");
    return 0;
}
