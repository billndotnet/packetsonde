/* Dedupe summaries through the REAL shipping path: ps_central_checkin_stop ->
 * ps_obs_ship_cycle -> ship_to_central -> reporter -> HTTP, against a
 * loopback sink that answers a scripted status per POST. Checks how central's
 * answers translate: transport failure / 5xx / 429 re-stage the whole batch
 * and the retry is byte-identical (same envelope sigs, which central dedups
 * on); 2xx delivers; a non-429 4xx is poison and is not retried. */
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

#define MAXP 16
struct sink {
    int lfd, port;
    volatile int stop;
    pthread_t th;
    int script[MAXP], nscript;   /* status per POST; -1 = close without answer */
    int posts;
    char *body[MAXP];
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
        if (code > 0) {
            char resp[256];
            int n = 0;
            for (const char *p = strstr(b, "\"envelope_v\":1"); p; p = strstr(p + 1, "\"envelope_v\":1")) n++;
            int rl = snprintf(resp, sizeof resp,
                "HTTP/1.1 %d X\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
                "{\"accepted\":%d,\"rejected\":0}", code, code == 200 ? n : 0);
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

    char p[128];
    snprintf(p, sizeof p, "%s/agent.pub", keydir); unlink(p);
    snprintf(p, sizeof p, "%s/agent.sec", keydir); unlink(p);
    rmdir(keydir);
    if (g_fail) { fprintf(stderr, "%d check(s) failed\n", g_fail); return 1; }
    printf("test_obs_ship_central: all passed\n");
    return 0;
}
