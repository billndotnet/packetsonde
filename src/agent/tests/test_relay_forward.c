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

#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
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

/* The CLI's half of the ingest exchange; its connect step is not used here. */
#include "remote/ingest_via.c"
int ps_via_connect(const char *agent_name, struct ps_at_ctx *ctx_out,
                   SSL **ssl_out, struct ps_ap_io *io_out) {
    (void)agent_name; (void)ctx_out; (void)ssl_out; (void)io_out;
    return -1;
}

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

/* Loopback central: serves `want` POSTs one after another, keeping each body,
 * and answers each with accepted = the number of relay_path entries in it. */
struct sink { int lfd, port, want, got; pthread_t th; char *body; char *bodies[4]; };

static void *sink_main(void *arg) {
    struct sink *s = arg;
    for (s->got = 0; s->got < s->want; s->got++) {
        struct pollfd p = { s->lfd, POLLIN, 0 };
        if (poll(&p, 1, 10000) <= 0) break;
        int fd = accept(s->lfd, NULL, NULL);
        if (fd < 0) break;
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
            s->bodies[s->got] = strdup(b);
            char resp[256];
            int rl = snprintf(resp, sizeof resp,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
                "{\"accepted\":%d,\"rejected\":0}", count(b, "\"relay_path\""));
            if (write(fd, resp, (size_t)rl) < 0) { /* ignore */ }
        }
        free(buf);
        close(fd);
    }
    s->body = s->bodies[0];
    return NULL;
}

static void sink_start_n(struct sink *s, int want) {
    memset(s, 0, sizeof *s);
    s->want = want;
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

static void sink_start(struct sink *s) { sink_start_n(s, 1); }

static void test_handle_ingest_oversized_frame(void) {
    static struct nl_state st;
    memset(&st, 0, sizeof st);
    CHECK(ps_keystore_generate(&st.agent_kp) == 0);
    const char *peer = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    setenv("PS_RELAY_ALLOW_SOURCES", peer, 1);
    setenv("PS_CENTRAL_AGENT_ID", "relay-under-test", 1);
    setenv("PS_CENTRAL_VERIFY", "0", 1);

    /* A frame under 64 KiB, far below the frame limit, yet
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

/* ---- the relay's source allow list ------------------------------- */

/* PS_RELAY_ALLOW_SOURCES used to be matched with strstr, so any peer whose
 * fingerprint occurred anywhere in the list text (a fragment of an allowed
 * fingerprint, or of two adjacent entries) was allowed. Entries are now
 * compared whole. */
static void test_allow_list_whole_tokens(void) {
    const char *fp  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const char *fp2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    char list[512];
    snprintf(list, sizeof list, "%s, sha256:%s", fp, fp2);

    CHECK(nl_source_allowed(list, fp));
    CHECK(nl_source_allowed(list, fp2));                   /* "sha256:" form */
    CHECK(nl_source_allowed(" sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n", fp));
    CHECK(!nl_source_allowed(list, "0123456789abcdef"));   /* prefix of an entry */
    CHECK(!nl_source_allowed(list, "89abcdef01234567"));   /* inside an entry */
    CHECK(!nl_source_allowed(list, "cdef, sha256:fedc"));  /* across entries */
    CHECK(!nl_source_allowed(list, "sha256"));
    CHECK(!nl_source_allowed(list, ""));
    CHECK(!nl_source_allowed("", fp));
    CHECK(!nl_source_allowed(NULL, fp));
    char longer[80];
    snprintf(longer, sizeof longer, "%s0", fp);
    CHECK(!nl_source_allowed(list, longer));

    /* End to end: a fragment of an allowed fingerprint is refused before
     * anything is forwarded (no central is listening here). */
    static struct nl_state st;
    memset(&st, 0, sizeof st);
    CHECK(ps_keystore_generate(&st.agent_kp) == 0);
    setenv("PS_RELAY_ALLOW_SOURCES", list, 1);
    setenv("PS_CENTRAL_URL", "http://127.0.0.1:9", 1);
    const char *fr = "{\"type\":\"ingest\",\"envelopes\":[{\"ed25519_sig\":\"a\"}]}";
    char ack[1024];
    CHECK(handle_ingest(&st, "0123456789abcdef", (const uint8_t *)fr, strlen(fr), ack, sizeof ack) == 0);
    CHECK(strstr(ack, "source not allowed") != NULL);

    /* ... while the whole fingerprint, listed with its prefix, is forwarded. */
    struct sink s;
    sink_start(&s);
    CHECK(handle_ingest(&st, fp2, (const uint8_t *)fr, strlen(fr), ack, sizeof ack) == 1);
    pthread_join(s.th, NULL);
    close(s.lfd);
    CHECK(s.body != NULL && count(s.body, "\"relay_path\"") == 1);
    free(s.body);
    unsetenv("PS_CENTRAL_URL");
}

/* ---- whole sessions: the CLI's ingest exchange against nl_serve -------- */

static const char *k_peer = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static struct nl_state *relay_state(void) {
    static struct nl_state st;
    static int ready;
    if (!ready) {
        memset(&st, 0, sizeof st);
        CHECK(ps_keystore_generate(&st.agent_kp) == 0);
        ready = 1;
    }
    setenv("PS_RELAY_ALLOW_SOURCES", k_peer, 1);
    setenv("PS_CENTRAL_AGENT_ID", "relay-under-test", 1);
    setenv("PS_CENTRAL_VERIFY", "0", 1);
    return &st;
}

static ssize_t fd_read(void *ctx, void *buf, size_t n) {
    ssize_t r;
    do r = read(*(int *)ctx, buf, n); while (r < 0 && errno == EINTR);
    return r;
}
static ssize_t fd_write(void *ctx, const void *buf, size_t n) {
    ssize_t w;
    do w = send(*(int *)ctx, buf, n, MSG_NOSIGNAL); while (w < 0 && errno == EINTR);
    return w;
}

struct relay_job { int fd; const char *peer; pthread_t th; };
static void *relay_run(void *arg) {
    struct relay_job *j = arg;
    struct ps_ap_io io = { fd_read, fd_write, &j->fd };
    nl_serve(relay_state(), &io, j->peer);
    close(j->fd);
    return NULL;
}

/* Starts a relay session on one end of a socketpair and, as ps_via_connect
 * does, sends the client hello on the other; returns the client end. */
static int relay_start(struct relay_job *j, const char *peer) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
    j->fd = sv[1]; j->peer = peer;
    pthread_create(&j->th, NULL, relay_run, j);
    struct ps_ap_io io = { fd_read, fd_write, &sv[0] };
    const char *h = "{\"type\":\"hello\",\"v\":1,\"client_fingerprint\":\"sha256:test\"}";
    CHECK(ps_ap_write_frame(&io, h, strlen(h)) == PS_AP_OK);
    return sv[0];
}

/* Envelope array whose ingest frame is exactly frame_len bytes: envelopes of
 * `pad` filler, the last one sized to land on the length. */
static char *make_array(size_t frame_len, const char *tag, size_t pad, int *n_out) {
    size_t want = frame_len - strlen(INGEST_PREFIX) - 1;
    char *a = malloc(want + 1);
    size_t w = 0; int n = 0;
    a[w++] = '[';
    for (int last = 0; !last; n++) {
        char head[96];
        int hl = snprintf(head, sizeof head, "%s{\"ed25519_sig\":\"%s%d\",\"pad\":\"",
                          n ? "," : "", tag, n);
        size_t fixed = (size_t)hl + 2, room = want - w - 1, p = pad;
        if (room < fixed) { fprintf(stderr, "make_array: bad geometry\n"); exit(2); }
        if (room < 2 * (fixed + pad)) { p = room - fixed; last = 1; }
        memcpy(a + w, head, (size_t)hl); w += (size_t)hl;
        memset(a + w, 'x', p); w += p;
        memcpy(a + w, "\"}", 2); w += 2;
    }
    a[w++] = ']'; a[w] = 0;
    if (w != want) { fprintf(stderr, "make_array: %zu != %zu\n", w, want); exit(2); }
    *n_out = n;
    return a;
}

/* Frames just past the old 64 KiB read buffer, one under the protocol limit
 * and exactly at it all reach central; one over is refused by the CLI before
 * it connects. */
static void test_session_frame_sizes(void) {
    const size_t sizes[] = { 64 * 1024 + 1, PS_AGENT_FRAME_MAX - 1, PS_AGENT_FRAME_MAX };
    for (size_t k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        int n;
        char *arr = make_array(sizes[k], "s", 900, &n);
        char *frame; size_t flen;
        CHECK(ps_ingest_build_frame(arr, &frame, &flen) == 0);
        CHECK(flen == sizes[k] && strlen(frame) == sizes[k]);

        struct sink s; sink_start(&s);
        struct relay_job j;
        int cfd = relay_start(&j, k_peer);
        struct ps_ap_io cio = { fd_read, fd_write, &cfd };
        struct ps_report_result r = {0};
        char why[256];
        int rc = ps_ingest_exchange(&cio, frame, flen, &r, why, sizeof why);
        close(cfd);
        pthread_join(j.th, NULL);
        pthread_join(s.th, NULL);
        close(s.lfd);

        if (rc != 0) fprintf(stderr, "  frame %zu bytes: %s\n", sizes[k], why);
        CHECK(rc == 0);
        CHECK(r.accepted > 0);
        CHECK(r.accepted + r.rejected == n);
        CHECK(s.body != NULL);
        if (s.body) {
            CHECK(json_ok(s.body));
            CHECK(count(s.body, "\"relay_path\"") == r.accepted);
        }
        free(s.body); free(frame); free(arr);
    }

    int n;
    char *arr = make_array(PS_AGENT_FRAME_MAX + 1, "s", 900, &n);
    char *frame = (char *)arr; size_t flen = 0;
    CHECK(ps_ingest_build_frame(arr, &frame, &flen) == -1);
    CHECK(frame == NULL);
    CHECK(flen == PS_AGENT_FRAME_MAX + 1);
    free(arr);
}

/* A frame header over the limit gets an error frame naming the reason, and
 * the relay neither reads the payload nor contacts central. */
static void test_session_over_max_answered(void) {
    struct relay_job j;
    int cfd = relay_start(&j, k_peer);
    struct ps_ap_io cio = { fd_read, fd_write, &cfd };
    uint32_t over = PS_AGENT_FRAME_MAX + 1;
    uint8_t hdr[4] = { (uint8_t)(over >> 24), (uint8_t)(over >> 16), (uint8_t)(over >> 8), (uint8_t)over };
    CHECK(fd_write(&cfd, hdr, 4) == 4);
    char junk[4096]; memset(junk, 'x', sizeof junk); junk[0] = '{';
    CHECK(fd_write(&cfd, junk, sizeof junk) == (ssize_t)sizeof junk);

    uint8_t buf[1024]; size_t blen;
    char type[32];
    CHECK(ps_ap_read_frame(&cio, buf, sizeof buf, &blen) == PS_AP_OK);
    CHECK(ps_ap_frame_type(buf, blen, type, sizeof type) == 0 && strcmp(type, "hello") == 0);
    int rc = ps_ap_read_frame(&cio, buf, sizeof buf - 1, &blen);
    CHECK(rc == PS_AP_OK);
    if (rc == PS_AP_OK) {
        buf[blen] = 0;
        CHECK(ps_ap_frame_type(buf, blen, type, sizeof type) == 0 && strcmp(type, "error") == 0);
        CHECK(strstr((char *)buf, "frame too large") != NULL);
        CHECK(json_ok((char *)buf));
    }
    /* Then the session ends (EOF, or a reset since the payload went unread). */
    rc = ps_ap_read_frame(&cio, buf, sizeof buf, &blen);
    CHECK(rc == PS_AP_ERR_EOF || rc == PS_AP_ERR_IO);
    close(cfd);
    pthread_join(j.th, NULL);
}

static void *hello_then_close(void *arg) {
    int fd = *(int *)arg;
    struct ps_ap_io io = { fd_read, fd_write, &fd };
    const char *h = "{\"type\":\"hello\",\"v\":1}";
    ps_ap_write_frame(&io, h, strlen(h));
    uint8_t b[256]; size_t bl;
    ps_ap_read_frame(&io, b, sizeof b, &bl);
    close(fd);
    return NULL;
}

/* The CLI turns each way a relay can answer into a result or a stated reason. */
static void test_cli_reports_relay_answers(void) {
    struct ps_report_result r;
    char why[256];

    /* Refusal from the relay: its message, not a silent zero. */
    struct relay_job j;
    int cfd = relay_start(&j, k_peer);
    struct ps_ap_io cio = { fd_read, fd_write, &cfd };
    memset(&r, 0, sizeof r);
    CHECK(ps_ingest_exchange(&cio, "not-json", 8, &r, why, sizeof why) == -1);
    CHECK(strcmp(why, "relay refused the batch: malformed frame") == 0);
    close(cfd);
    pthread_join(j.th, NULL);

    /* An ack carrying a refusal detail: returned to the caller to print. */
    cfd = relay_start(&j, "not-an-allowed-source");
    cio.ctx = &cfd;
    memset(&r, 0, sizeof r);
    const char *fr = "{\"type\":\"ingest\",\"envelopes\":[{\"ed25519_sig\":\"a\"}]}";
    CHECK(ps_ingest_exchange(&cio, fr, strlen(fr), &r, why, sizeof why) == 0);
    CHECK(r.accepted == 0 && r.rejected == 0);
    CHECK(strcmp(why, "source not allowed") == 0);
    close(cfd);
    pthread_join(j.th, NULL);

    /* A relay that hangs up without answering. */
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    pthread_t th;
    pthread_create(&th, NULL, hello_then_close, &sv[1]);
    cio.ctx = &sv[0];
    CHECK(ps_ingest_exchange(&cio, fr, strlen(fr), &r, why, sizeof why) == -1);
    CHECK(strcmp(why, "relay closed the session without an ack") == 0);
    pthread_join(th, NULL);
    close(sv[0]);
}

/* Two sessions read and forward large frames at the same time; each one's
 * envelopes reach central in its own POST only. */
struct client_job {
    const char *frame; size_t flen; pthread_barrier_t *go;
    struct relay_job relay; int cfd; int rc; struct ps_report_result r; char why[256];
};
static void *client_run(void *arg) {
    struct client_job *c = arg;
    struct ps_ap_io io = { fd_read, fd_write, &c->cfd };
    pthread_barrier_wait(c->go);
    c->rc = ps_ingest_exchange(&io, c->frame, c->flen, &c->r, c->why, sizeof c->why);
    return NULL;
}

static void test_concurrent_large_sessions(void) {
    /* "@" occurs in no base64 or hex attestation, so a tag match is a real one. */
    const char *tags[2] = { "@A@", "@B@" };
    struct client_job c[2];
    char *arrs[2]; int ns[2];
    pthread_barrier_t go;
    pthread_barrier_init(&go, NULL, 2);
    struct sink s; sink_start_n(&s, 2);
    pthread_t ct[2];
    for (int i = 0; i < 2; i++) {
        memset(&c[i], 0, sizeof c[i]);
        arrs[i] = make_array(600 * 1024 + (size_t)i * 333, tags[i], 700, &ns[i]);
        char *f; CHECK(ps_ingest_build_frame(arrs[i], &f, &c[i].flen) == 0);
        c[i].frame = f; c[i].go = &go;
        c[i].cfd = relay_start(&c[i].relay, k_peer);
        pthread_create(&ct[i], NULL, client_run, &c[i]);
    }
    for (int i = 0; i < 2; i++) {
        pthread_join(ct[i], NULL);
        close(c[i].cfd);
        pthread_join(c[i].relay.th, NULL);
    }
    pthread_join(s.th, NULL);
    close(s.lfd);

    CHECK(s.got == 2);
    for (int i = 0; i < 2; i++) {
        CHECK(c[i].rc == 0);
        CHECK(c[i].r.accepted > 0);
        CHECK(c[i].r.accepted + c[i].r.rejected == ns[i]);
        const char *mine = tags[i], *other = tags[1 - i];
        int found = 0;
        for (int b = 0; b < s.got; b++) {
            if (!s.bodies[b] || !strstr(s.bodies[b], mine)) continue;
            found++;
            CHECK(strstr(s.bodies[b], other) == NULL);
            CHECK(json_ok(s.bodies[b]));
            CHECK(count(s.bodies[b], "\"relay_path\"") == c[i].r.accepted);
        }
        CHECK(found == 1);
        free((char *)c[i].frame); free(arrs[i]);
    }
    for (int b = 0; b < s.got; b++) free(s.bodies[b]);
    pthread_barrier_destroy(&go);
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
    test_allow_list_whole_tokens();
    test_session_frame_sizes();
    test_session_over_max_answered();
    test_cli_reports_relay_answers();
    test_concurrent_large_sessions();
    unsetenv("PS_CENTRAL_URL");
    if (g_fail) { fprintf(stderr, "test_relay_forward: %d failure(s)\n", g_fail); return 1; }
    printf("test_relay_forward: ok\n");
    return 0;
}
