/*
 * test_relay_forward -- the relay forwarder's body builder and handle_ingest.
 *
 * The body a relay POSTs to central must stay inside its cap however many or
 * however large the envelopes it is handed, must always be valid JSON (an
 * envelope is forwarded whole or dropped and counted, never cut), must read
 * only the frame bytes it was given, and must not be shared between sessions
 * that forward at the same time.
 *
 * Pulls the module source in directly, as test_network_listener_driver does.
 */
#include "packetsonde/module_api.h"

#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ps_info(const char *fmt, ...)  { (void)fmt; }
void ps_warn(const char *fmt, ...)  { (void)fmt; }
void ps_error(const char *fmt, ...) { (void)fmt; }
void ps_debug(const char *fmt, ...) { (void)fmt; }
int ps_module_register(const ps_module_t *mod) { (void)mod; return 0; }

#include "modules/network_listener.c"

static int g_fail;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

/* ---- minimal strict JSON validator ------------------------------- */

static const char *jv_value(const char *p);
static const char *jv_ws(const char *p) { while (*p == ' ' || *p == '\n' || *p == '\t' || *p == '\r') p++; return p; }
static const char *jv_string(const char *p) {
    if (*p++ != '"') return NULL;
    for (; *p && *p != '"'; p++) {
        if ((unsigned char)*p < 0x20) return NULL;
        if (*p == '\\' && !*++p) return NULL;
    }
    return *p == '"' ? p + 1 : NULL;
}
static const char *jv_value(const char *p) {
    p = jv_ws(p);
    if (*p == '"') return jv_string(p);
    if (*p == '{' || *p == '[') {
        char close = *p == '{' ? '}' : ']';
        p = jv_ws(p + 1);
        if (*p == close) return p + 1;
        for (;;) {
            if (close == '}') {
                if (!(p = jv_string(jv_ws(p)))) return NULL;
                p = jv_ws(p);
                if (*p++ != ':') return NULL;
            }
            if (!(p = jv_value(p))) return NULL;
            p = jv_ws(p);
            if (*p == close) return p + 1;
            if (*p++ != ',') return NULL;
        }
    }
    if (!strncmp(p, "true", 4)) return p + 4;
    if (!strncmp(p, "false", 5)) return p + 5;
    if (!strncmp(p, "null", 4)) return p + 4;
    const char *s = p;
    if (*p == '-') p++;
    while ((*p >= '0' && *p <= '9') || *p == '.' || *p == 'e' || *p == 'E' || *p == '+' || *p == '-') p++;
    return p > s ? p : NULL;
}
static int json_ok(const char *s) { const char *e = jv_value(s); return e && *jv_ws(e) == '\0'; }

static int count(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = strstr(hay, needle); p; p = strstr(p + 1, needle)) n++;
    return n;
}

/* ---- fake attestation -------------------------------------------- */

/* Writes {"by":"<tag>","sig":"<sig>"}; optionally pauses on a given call so a
 * second session can run in the middle of this one's build. */
struct fake {
    const char     *tag;
    int             calls;
    int             pause_on;          /* 0 = never */
    pthread_mutex_t *mu;
    pthread_cond_t  *cv;
    int            *paused, *resume;
};

static int fake_attest(void *ud, const char *sig, char *out, size_t cap) {
    struct fake *f = ud;
    if (++f->calls == f->pause_on) {
        pthread_mutex_lock(f->mu);
        *f->paused = 1;
        pthread_cond_broadcast(f->cv);
        while (!*f->resume) pthread_cond_wait(f->cv, f->mu);
        pthread_mutex_unlock(f->mu);
    }
    int n = snprintf(out, cap, "{\"by\":\"%s\",\"sig\":\"%s\"}", f->tag, sig);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

static int build(const char *frame, size_t cap, struct fake *f, struct nl_fwd_result *r) {
    return nl_build_relay_forward((const uint8_t *)frame, strlen(frame), cap, fake_attest, f, r);
}

/* Frame of n envelopes {"ed25519_sig":"<tag><i>","pad":"<pad x padlen>"}. */
static char *make_frame(int n, const char *tag, size_t padlen) {
    size_t cap = 64 + (size_t)n * (64 + padlen);
    char *f = malloc(cap), *p = f;
    p += sprintf(p, "{\"type\":\"ingest\",\"envelopes\":[");
    for (int i = 0; i < n; i++) {
        p += sprintf(p, "%s{\"ed25519_sig\":\"%s%d\",\"pad\":\"", i ? "," : "", tag, i);
        memset(p, 'x', padlen); p += padlen;
        p += sprintf(p, "\"}");
    }
    sprintf(p, "]}");
    return f;
}

/* ---- builder ----------------------------------------------------- */

static void test_basic_and_braces_in_strings(void) {
    struct fake f = { .tag = "R" };
    struct nl_fwd_result r;
    const char *frame =
        "{\"type\":\"ingest\",\"envelopes\":[{\"a\":1,\"ed25519_sig\":\"S1\"},"
        "{\"t\":\"x}y{\\\"]\",\"ed25519_sig\":\"S2\"}]}";
    CHECK(build(frame, PS_NL_RELAY_FWD_MAX, &f, &r) == 0);
    const char *want =
        "{\"envelopes\":[{\"a\":1,\"ed25519_sig\":\"S1\",\"relay_path\":[{\"by\":\"R\",\"sig\":\"S1\"}]},"
        "{\"t\":\"x}y{\\\"]\",\"ed25519_sig\":\"S2\",\"relay_path\":[{\"by\":\"R\",\"sig\":\"S2\"}]}]}";
    CHECK(r.body && strcmp(r.body, want) == 0);
    CHECK(r.len == strlen(want));
    CHECK(r.forwarded == 2 && r.dropped == 0);
    CHECK(json_ok(r.body));
    free(r.body);
}

static void test_rejects_bad_input(void) {
    struct fake f = { .tag = "R" };
    struct nl_fwd_result r;
    CHECK(build("{\"type\":\"ingest\"}", PS_NL_RELAY_FWD_MAX, &f, &r) == -1);
    CHECK(r.body == NULL);
    CHECK(build("{\"envelopes\":[]}", 16, &f, &r) == -1);  /* skeleton needs 17 */
    CHECK(build("{\"envelopes\":[]}", 17, &f, &r) == 0);
    CHECK(r.body && strcmp(r.body, "{\"envelopes\":[]}") == 0);
    free(r.body);
}

/* One envelope larger than the whole cap, between two that fit. */
static void test_oversized_item_dropped_whole(void) {
    char frame[4096];
    char pad[1001]; memset(pad, 'z', 1000); pad[1000] = 0;
    snprintf(frame, sizeof frame,
             "{\"envelopes\":[{\"ed25519_sig\":\"a\"},{\"ed25519_sig\":\"b\",\"pad\":\"%s\"},"
             "{\"ed25519_sig\":\"c\"}]}", pad);
    struct fake f = { .tag = "R" };
    struct nl_fwd_result r;
    CHECK(build(frame, 512, &f, &r) == 0);
    CHECK(r.forwarded == 2 && r.dropped == 1);
    CHECK(r.len < 512);
    CHECK(json_ok(r.body));
    CHECK(strstr(r.body, "zzz") == NULL);
    CHECK(count(r.body, "relay_path") == 2);
    free(r.body);

    /* Over the per-envelope cap, even with room in the body. */
    char *big = make_frame(1, "s", PS_NL_RELAY_ITEM_MAX);
    struct fake g = { .tag = "R" };
    CHECK(build(big, PS_NL_RELAY_FWD_MAX, &g, &r) == 0);
    CHECK(r.forwarded == 0 && r.dropped == 1);
    CHECK(strcmp(r.body, "{\"envelopes\":[]}") == 0);
    free(r.body); free(big);
}

/* A full 64 KiB frame of small envelopes expands well past the production
 * cap once each gets a relay_path entry. */
static void test_many_items_over_production_cap(void) {
    char *frame = make_frame(1500, "sig", 4);
    CHECK(strlen(frame) < 64 * 1024);
    struct fake f = { .tag = "relay-attestation-padding-padding-padding-padding-padding-"
                             "padding-padding-padding-padding-padding-padding-padding-" };
    struct nl_fwd_result r;
    CHECK(build(frame, PS_NL_RELAY_FWD_MAX, &f, &r) == 0);
    CHECK(r.dropped > 0);
    CHECK(r.forwarded > 0);
    CHECK(r.forwarded + r.dropped == 1500);
    CHECK(r.len < PS_NL_RELAY_FWD_MAX);
    CHECK(r.len == strlen(r.body));
    CHECK(json_ok(r.body));
    CHECK(count(r.body, "relay_path") == r.forwarded);
    free(r.body); free(frame);
}

/* Body exactly cap - 1 bytes fits; one byte less cap drops the item. */
static void test_exact_boundary(void) {
    const char *frame = "{\"envelopes\":[{\"ed25519_sig\":\"A\"},{\"ed25519_sig\":\"B\"}]}";
    struct fake f = { .tag = "R" };
    struct nl_fwd_result r;
    CHECK(build(frame, PS_NL_RELAY_FWD_MAX, &f, &r) == 0);
    char *full = r.body; size_t L = r.len;
    CHECK(r.forwarded == 2);

    struct fake g = { .tag = "R" };
    CHECK(build(frame, L + 1, &g, &r) == 0);          /* exactly fits */
    CHECK(r.forwarded == 2 && r.dropped == 0);
    CHECK(r.len == L && strcmp(r.body, full) == 0);
    free(r.body);

    struct fake h = { .tag = "R" };
    CHECK(build(frame, L, &h, &r) == 0);              /* one byte short */
    CHECK(r.forwarded == 1 && r.dropped == 1);
    CHECK(json_ok(r.body));
    CHECK(strstr(r.body, "\"B\"") == NULL);
    CHECK(r.len < L);
    free(r.body);
    free(full);
}

/* The frame is not NUL-terminated on the wire; bytes past len are not ours. */
static void test_reads_only_len_bytes(void) {
    const char *keep = "{\"envelopes\":[{\"ed25519_sig\":\"in\"}";
    const char *rest = ",{\"ed25519_sig\":\"past-len\"}]}";
    size_t kl = strlen(keep), rl = strlen(rest);
    char *buf = malloc(kl + rl);                     /* no terminator anywhere */
    memcpy(buf, keep, kl); memcpy(buf + kl, rest, rl);
    struct fake f = { .tag = "R" };
    struct nl_fwd_result r;
    CHECK(nl_build_relay_forward((const uint8_t *)buf, kl, PS_NL_RELAY_FWD_MAX,
                                 fake_attest, &f, &r) == 0);
    CHECK(r.forwarded == 1);
    CHECK(strstr(r.body, "past-len") == NULL);
    CHECK(json_ok(r.body));
    free(r.body);
    CHECK(nl_build_relay_forward((const uint8_t *)buf, kl + rl, PS_NL_RELAY_FWD_MAX,
                                 fake_attest, &f, &r) == 0);
    CHECK(r.forwarded == 2);
    free(r.body);
    free(buf);
}

/* ---- two sessions forwarding at once ------------------------------ */

struct job { const char *frame; struct fake *f; struct nl_fwd_result r; int rc; };
static void *job_run(void *arg) {
    struct job *j = arg;
    j->rc = build(j->frame, PS_NL_RELAY_FWD_MAX, j->f, &j->r);
    return NULL;
}

static void test_concurrent_sessions_isolated(void) {
    char *fa = make_frame(20, "AAA", 32), *fb = make_frame(20, "BBB", 32);
    struct fake ea = { .tag = "relay-A" }, eb = { .tag = "relay-B" };
    struct nl_fwd_result wa, wb;
    CHECK(build(fa, PS_NL_RELAY_FWD_MAX, &ea, &wa) == 0);
    CHECK(build(fb, PS_NL_RELAY_FWD_MAX, &eb, &wb) == 0);

    /* A pauses inside its build (after appending some envelopes) while B
     * builds start to finish; then A completes. */
    pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
    int paused = 0, resume = 0;
    struct fake a = { .tag = "relay-A", .pause_on = 10, .mu = &mu, .cv = &cv,
                      .paused = &paused, .resume = &resume };
    struct fake b = { .tag = "relay-B" };
    struct job ja = { fa, &a, {0}, -1 }, jb = { fb, &b, {0}, -1 };
    pthread_t ta, tb;
    pthread_create(&ta, NULL, job_run, &ja);
    pthread_mutex_lock(&mu);
    while (!paused) pthread_cond_wait(&cv, &mu);
    pthread_mutex_unlock(&mu);
    pthread_create(&tb, NULL, job_run, &jb);
    pthread_join(tb, NULL);
    pthread_mutex_lock(&mu);
    resume = 1;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mu);
    pthread_join(ta, NULL);

    CHECK(ja.rc == 0 && jb.rc == 0);
    CHECK(ja.r.body && jb.r.body && ja.r.body != jb.r.body);
    CHECK(ja.r.body && strcmp(ja.r.body, wa.body) == 0);
    CHECK(jb.r.body && strcmp(jb.r.body, wb.body) == 0);
    CHECK(ja.r.body && strstr(ja.r.body, "BBB") == NULL && strstr(ja.r.body, "relay-B") == NULL);
    CHECK(jb.r.body && strstr(jb.r.body, "AAA") == NULL && strstr(jb.r.body, "relay-A") == NULL);
    CHECK(ja.r.body && json_ok(ja.r.body));
    CHECK(jb.r.body && json_ok(jb.r.body));
    free(ja.r.body); free(jb.r.body); free(wa.body); free(wb.body);
    free(fa); free(fb);
}

/* ---- handle_ingest end to end against a loopback central ---------- */

struct sink { int lfd, port; pthread_t th; char *body; };

static void *sink_main(void *arg) {
    struct sink *s = arg;
    struct pollfd p = { s->lfd, POLLIN, 0 };
    if (poll(&p, 1, 10000) <= 0) return NULL;
    int fd = accept(s->lfd, NULL, NULL);
    if (fd < 0) return NULL;
    size_t cap = 2u << 20, got = 0;
    char *buf = malloc(cap + 1), *b = NULL;
    long clen = -1;
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
        s->body = strdup(b);
        char resp[256];
        int rl = snprintf(resp, sizeof resp,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
            "{\"accepted\":%d,\"rejected\":0}", count(b, "\"relay_path\""));
        if (write(fd, resp, (size_t)rl) < 0) { /* ignore */ }
    }
    free(buf);
    close(fd);
    return NULL;
}

static void sink_start(struct sink *s) {
    memset(s, 0, sizeof *s);
    s->lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s->lfd, (struct sockaddr *)&a, sizeof a) != 0 || listen(s->lfd, 4) != 0) { perror("sink"); exit(2); }
    socklen_t al = sizeof a;
    getsockname(s->lfd, (struct sockaddr *)&a, &al);
    s->port = ntohs(a.sin_port);
    pthread_create(&s->th, NULL, sink_main, s);
    char url[64];
    snprintf(url, sizeof url, "http://127.0.0.1:%d", s->port);
    setenv("PS_CENTRAL_URL", url, 1);
}

static void test_handle_ingest_oversized_frame(void) {
    static struct nl_state st;
    memset(&st, 0, sizeof st);
    CHECK(ps_keystore_generate(&st.agent_kp) == 0);
    const char *peer = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    setenv("PS_RELAY_ALLOW_SOURCES", peer, 1);
    setenv("PS_CENTRAL_AGENT_ID", "relay-under-test", 1);
    setenv("PS_CENTRAL_VERIFY", "0", 1);

    /* What one session can deliver: well under the 64 KiB read buffer, but
     * each tiny envelope gains a ~250-byte relay_path entry, so the body
     * runs past the cap. Where the last envelope lands against the cap
     * depends on the exact sizes, so sweep several envelope sizes. */
    const int n = 1200;
    for (size_t pad = 0; pad < 8; pad++) {
        char *frame = make_frame(n, "s", pad);
        CHECK(strlen(frame) < 64 * 1024);

        struct sink s;
        sink_start(&s);
        char ack[1024];
        int accepted = handle_ingest(&st, peer, (const uint8_t *)frame, strlen(frame), ack, sizeof ack);
        pthread_join(s.th, NULL);
        close(s.lfd);

        CHECK(s.body != NULL);
        if (s.body) {
            CHECK(strlen(s.body) < PS_NL_RELAY_FWD_MAX);
            CHECK(json_ok(s.body));
            CHECK(count(s.body, "\"relay_path\"") == accepted);
        }
        const char *rj = strstr(ack, "\"rejected\":");
        int rejected = rj ? atoi(rj + 11) : -1;
        CHECK(accepted > 0);
        CHECK(rejected > 0);
        CHECK(accepted + rejected == n);
        CHECK(json_ok(ack));
        free(s.body);
        free(frame);
    }
    unsetenv("PS_CENTRAL_URL");
}

int main(void) {
    test_basic_and_braces_in_strings();
    test_rejects_bad_input();
    test_oversized_item_dropped_whole();
    test_many_items_over_production_cap();
    test_exact_boundary();
    test_reads_only_len_bytes();
    test_concurrent_sessions_isolated();
    test_handle_ingest_oversized_frame();
    if (g_fail) { fprintf(stderr, "test_relay_forward: %d failure(s)\n", g_fail); return 1; }
    printf("test_relay_forward: ok\n");
    return 0;
}
