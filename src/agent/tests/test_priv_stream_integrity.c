/*
 * test_priv_stream_integrity — the priv worker -> brain stream must never
 * lose frame alignment.
 *
 * The brain socket is an AF_UNIX SOCK_STREAM socketpair and the worker's end
 * is non-blocking. A data frame written while the buffer is nearly full can
 * be accepted only in part (a short write). If the rest is then discarded,
 * the reader's next "header" is the middle of a packet and the brain dies
 * with "recv payload N exceeds buffer", N being captured bytes.
 *
 * These tests drive the worker's real write helper against the brain's real
 * reader (priv_client.c) through a socketpair with tiny buffers, so short
 * writes are frequent, and check that every frame arrives whole or not at all.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "priv_protocol.h"
#include "priv_client.h"
#include "priv_frame_io.h"

static int g_failures = 0;

#define CHECK(cond, ...) do {                                         \
    if (!(cond)) {                                                    \
        fprintf(stderr, "  FAIL %s:%d: ", __FILE__, __LINE__);         \
        fprintf(stderr, __VA_ARGS__);                                 \
        fprintf(stderr, "\n");                                        \
        g_failures++;                                                 \
    }                                                                 \
} while (0)

/* Deterministic per-sequence frame shape. Sizes span small (atomic) frames
 * and frames large enough that the kernel splits them into several chunks. */
static uint32_t pkt_len_for(uint32_t seq)
{
    uint32_t x = seq * 2654435761u;
    x ^= x >> 13;
    switch (seq % 4) {
    case 0:  return 40 + (x % 200);         /* flow-tracker sized   */
    case 1:  return 60 + (x % 1500);        /* MTU sized            */
    case 2:  return 4000 + (x % 12000);     /* jumbo / GRO sized    */
    default: return 16000 + (x % 40000);    /* large GRO aggregate  */
    }
}

static uint8_t pkt_byte(uint32_t seq, uint32_t i)
{
    return (uint8_t)((seq * 131u) + (i * 7u) + (i >> 8));
}

static void set_small_buffers(int wfd, int rfd)
{
    int sz = 4096;
    setsockopt(wfd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    setsockopt(rfd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
}

static void set_nonblock(int fd, int on)
{
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, on ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK));
}

/* ------------------------------------------------------------------ */
/* Test 1: many variable-sized PACKET_DATA frames against a slow reader */
/* ------------------------------------------------------------------ */

#define N_FRAMES 6000
#define SENTINEL_HANDLE 0xBEEF

/* What the priv worker does per data frame: finish a started frame when the
 * socket has room (its poll loop asks for POLLOUT while one is pending),
 * then offer the new frame. */
static uint8_t g_tail[sizeof(struct ps_priv_msg) + PS_MAX_FRAME_PAYLOAD];

static int worker_send(struct ps_frame_writer *w, const uint8_t *frame, size_t n)
{
    if (ps_frame_writer_pending(w)) {
        struct pollfd pfd = { .fd = w->fd, .events = POLLOUT, .revents = 0 };
        if (poll(&pfd, 1, 0) > 0 && ps_frame_writer_flush(w) < 0) return PS_FRAME_BROKEN;
    }
    return ps_frame_writer_send_lossy(w, frame, n);
}

/* The final command-style frame, written as the worker writes a response. */
static int send_sentinel(struct ps_frame_writer *w)
{
    uint8_t b[sizeof(struct ps_priv_msg)];
    size_t sn = ps_priv_encode_response(b, sizeof(b), PS_OP_ERROR,
                                        PS_STATUS_OK, SENTINEL_HANDLE, NULL, 0);
    return ps_frame_writer_send_all(w, b, sn, 10000);
}


struct reader_ctx {
    int      fd;
    unsigned long stall_after;    /* frames received before one long pause (0 = none) */
    int      stall_ms;
    uint8_t  outcome[N_FRAMES];   /* 1 = received intact */
    unsigned long received;
    int      recv_error;          /* ps_priv_client_recv returned -1 */
    int      bad_frames;
    int      out_of_order;
    int      got_sentinel;
};

static struct ps_priv_client g_pc;                 /* large: keep off stack */
static uint8_t g_payload[PS_MAX_FRAME_PAYLOAD];

static void *reader_main(void *arg)
{
    struct reader_ctx *rc = arg;
    ps_priv_client_init(&g_pc, rc->fd);
    long last_seq = -1;
    unsigned long n_frames = 0;

    for (;;) {
        struct ps_priv_msg hdr;
        int n = ps_priv_client_recv(&g_pc, &hdr, g_payload, sizeof(g_payload));
        if (n < 0) { rc->recv_error = 1; break; }
        if (n == 0) { usleep(50); continue; }

        if (hdr.opcode == PS_OP_ERROR && hdr.handle_id == SENTINEL_HANDLE) {
            rc->got_sentinel = 1;
            break;
        }
        if (hdr.opcode != PS_OP_PACKET_DATA || hdr.payload_len < 8) {
            if (rc->bad_frames++ < 3)
                fprintf(stderr, "  reader: desync, opcode=0x%02x len=%u\n",
                        hdr.opcode, hdr.payload_len);
            break;
        }
        uint64_t seq64;
        memcpy(&seq64, g_payload, 8);
        uint32_t seq = (uint32_t)seq64;
        int ok = seq64 < N_FRAMES && hdr.handle_id == (uint16_t)(seq & 0x0fff) &&
                 hdr.payload_len == 8 + pkt_len_for(seq);
        for (uint32_t i = 0; ok && i < hdr.payload_len - 8; i++)
            if (g_payload[8 + i] != pkt_byte(seq, i)) ok = 0;
        if (!ok) {
            if (rc->bad_frames++ < 3)
                fprintf(stderr, "  reader: corrupt frame seq=%llu len=%u\n",
                        (unsigned long long)seq64, hdr.payload_len);
            break;
        }
        if ((long)seq <= last_seq) rc->out_of_order++;
        last_seq = seq;
        rc->outcome[seq] = 1;
        rc->received++;

        /* Drain slowly so the writer keeps hitting a full buffer. */
        if ((++n_frames % 8) == 0) usleep(200);
        /* One long stall, as when the agent's main thread is busy. */
        if (rc->stall_after && n_frames == rc->stall_after) usleep((useconds_t)rc->stall_ms * 1000);
    }
    /* Once framing is lost (or the sentinel arrived) keep draining raw bytes
     * until EOF so the writer never blocks on a reader that has given up. */
    uint8_t sink[4096];
    for (;;) {
        ssize_t r = read(rc->fd, sink, sizeof(sink));
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
    }
    return NULL;
}

static void test_lossy_frames_stay_aligned(void)
{
    printf("test: variable-sized PACKET_DATA frames survive a backed-up stream\n");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
    int wfd = sv[0], rfd = sv[1];
    set_small_buffers(wfd, rfd);
    set_nonblock(wfd, 1);

    static struct reader_ctx rc;
    memset(&rc, 0, sizeof(rc));
    rc.fd = rfd;
    pthread_t th;
    pthread_create(&th, NULL, reader_main, &rc);

    static uint8_t pkt[PS_MAX_MSG_PAYLOAD];
    static uint8_t frame[sizeof(struct ps_priv_msg) + PS_MAX_FRAME_PAYLOAD];
    static uint8_t result[N_FRAMES];
    struct ps_frame_writer w;
    ps_frame_writer_init(&w, wfd, g_tail, sizeof(g_tail));
    int broken = 0;

    for (uint32_t seq = 0; seq < N_FRAMES; seq++) {
        uint32_t len = pkt_len_for(seq);
        for (uint32_t i = 0; i < len; i++) pkt[i] = pkt_byte(seq, i);
        size_t n = ps_priv_encode_packet_data(frame, sizeof(frame),
                                              (uint16_t)(seq & 0x0fff),
                                              (uint64_t)seq, pkt, len);
        if (n == 0) { fprintf(stderr, "encode failed\n"); exit(2); }
        int r = worker_send(&w, frame, n);
        result[seq] = (uint8_t)(r == PS_FRAME_SENT || r == PS_FRAME_QUEUED);
        if (r == PS_FRAME_BROKEN) { broken = 1; break; }
    }

    /* Sentinel: a command-style response; it finishes any started frame. */
    CHECK(broken || send_sentinel(&w) == PS_FRAME_SENT, "sentinel response not sent");
    struct ps_frame_stats st = w.stats;
    close(wfd);
    pthread_join(th, NULL);
    close(rfd);

    unsigned long sent_whole = 0, lost = 0, ghosts = 0;
    for (uint32_t s = 0; s < N_FRAMES; s++) {
        if (result[s]) sent_whole++;
        if (result[s] && !rc.outcome[s]) lost++;
        if (!result[s] && rc.outcome[s]) ghosts++;
    }
    printf("  writer: sent=%lu dropped=%lu partial=%lu broken=%d; "
           "reader: received=%lu\n", st.sent, st.dropped, st.partial, broken,
           rc.received);

    /* Non-vacuous: the run must actually exercise short writes and drops. */
    CHECK(st.partial > 0, "no short write occurred; the test exercised nothing");
    CHECK(st.dropped > 0, "nothing was dropped; the reader was never backed up");
    CHECK(!broken, "writer reported a broken stream with a live reader");

    CHECK(!rc.recv_error, "reader lost framing (ps_priv_client_recv failed)");
    CHECK(rc.bad_frames == 0, "reader saw %d corrupt/misaligned frame(s)", rc.bad_frames);
    CHECK(rc.got_sentinel, "reader never resynced to the final command frame");
    CHECK(rc.out_of_order == 0, "frames arrived out of order");
    CHECK(lost == 0, "%lu frame(s) reported sent never arrived intact", lost);
    CHECK(ghosts == 0, "%lu frame(s) reported dropped arrived anyway", ghosts);
    CHECK(rc.received == sent_whole, "received %lu, writer sent %lu whole",
          rc.received, sent_whole);
}

/* ------------------------------------------------------------------ */
/* Test 2: a frame that cannot be finished is reported, not swallowed  */
/* ------------------------------------------------------------------ */

static void test_unfinishable_frame_is_broken(void)
{
    printf("test: a reader that never drains costs frames, not the stream; a gone reader breaks it\n");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
    int wfd = sv[0], rfd = sv[1];
    set_small_buffers(wfd, rfd);
    set_nonblock(wfd, 1);

    static uint8_t pkt[PS_MAX_MSG_PAYLOAD];
    static uint8_t frame[sizeof(struct ps_priv_msg) + PS_MAX_FRAME_PAYLOAD];
    memset(pkt, 0xAB, sizeof(pkt));
    size_t n = ps_priv_encode_packet_data(frame, sizeof(frame), 1, 1, pkt, 30000);

    /* Nobody reads rfd. A frame starts and cannot end: its remainder is kept,
     * every later frame is dropped whole, and no call waits. */
    struct ps_frame_writer w;
    ps_frame_writer_init(&w, wfd, g_tail, sizeof(g_tail));
    int r = PS_FRAME_SENT, queued = 0, broken = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < 1000; i++) {
        r = worker_send(&w, frame, n);
        if (r == PS_FRAME_QUEUED) queued++;
        if (r == PS_FRAME_BROKEN) broken = 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;

    CHECK(queued == 1, "want exactly one started frame, got %d", queued);
    CHECK(w.stats.partial == 1, "never produced a short write");
    CHECK(ps_frame_writer_pending(&w), "the started frame's remainder was not kept");
    CHECK(w.stats.dropped_pending > 900, "frames behind the started one were not dropped (%lu)",
          w.stats.dropped_pending);
    CHECK(!broken, "a stalled reader broke the stream");
    CHECK(ms < 500, "1000 sends against a stalled reader took %ld ms", ms);

    /* A response gives up at its deadline and marks the writer broken (part
     * of a frame may be in the stream). */
    uint8_t b[sizeof(struct ps_priv_msg)];
    size_t sn = ps_priv_encode_response(b, sizeof(b), PS_OP_ERROR, PS_STATUS_OK, 1, NULL, 0);
    CHECK(ps_frame_writer_send_all(&w, b, sn, 100) == PS_FRAME_BROKEN, "send_all ignored its deadline");
    CHECK(worker_send(&w, frame, n) == PS_FRAME_BROKEN, "broken writer accepted a frame");

    /* The peer going away is a hard error for a fresh writer too. */
    close(rfd);
    struct ps_frame_writer w2;
    ps_frame_writer_init(&w2, wfd, g_tail, sizeof(g_tail));
    CHECK(worker_send(&w2, frame, n) == PS_FRAME_BROKEN, "send to a closed peer did not report broken");
    close(wfd);
}

/* ------------------------------------------------------------------ */
/* Writer unit checks: the remainder is the frame's own bytes, in order */
/* ------------------------------------------------------------------ */

static void test_writer_tail_exact(void)
{
    printf("test: a buffered remainder is finished byte-exact, before any later frame\n");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
    int wfd = sv[0], rfd = sv[1];
    set_small_buffers(wfd, rfd);
    set_nonblock(wfd, 1);
    set_nonblock(rfd, 1);

    static uint8_t a[40000], bb[40000], got[200000];
    for (size_t i = 0; i < sizeof a; i++) { a[i] = (uint8_t)(i * 3 + 1); bb[i] = (uint8_t)(i * 5 + 2); }
    struct ps_frame_writer w;
    ps_frame_writer_init(&w, wfd, g_tail, sizeof(g_tail));

    CHECK(ps_frame_writer_send_lossy(&w, a, sizeof a) == PS_FRAME_QUEUED, "frame A not queued");
    /* The caller reuses its buffer at once: the remainder must be a copy. */
    static uint8_t a_copy[40000];
    memcpy(a_copy, a, sizeof a);
    memset(a, 0xEE, sizeof a);
    CHECK(ps_frame_writer_send_lossy(&w, bb, sizeof bb) == PS_FRAME_DROPPED, "B not dropped behind A");

    /* A frame larger than the tail buffer is refused whole, even when the
     * socket has room: its remainder could not be kept if the write fell
     * short. (Own socketpair, so nothing lands in the stream under test.) */
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) { perror("socketpair"); exit(2); }
    set_nonblock(sp[0], 1);
    set_nonblock(sp[1], 1);
    struct ps_frame_writer small;
    uint8_t tiny[16];
    ps_frame_writer_init(&small, sp[0], tiny, sizeof tiny);
    CHECK(ps_frame_writer_send_lossy(&small, bb, 17) == PS_FRAME_DROPPED, "oversize frame not refused");
    CHECK(ps_frame_writer_send_lossy(&small, bb, 16) == PS_FRAME_SENT, "frame of tail size refused");
    uint8_t chk[64];
    CHECK(read(sp[1], chk, sizeof chk) == 16, "refused frame reached the stream");
    close(sp[0]); close(sp[1]);

    /* Drain while finishing A, then send B whole. */
    size_t g = 0;
    for (int spins = 0; spins < 100000 && ps_frame_writer_pending(&w); spins++) {
        ssize_t r = read(rfd, got + g, sizeof got - g);
        if (r > 0) g += (size_t)r;
        CHECK(ps_frame_writer_flush(&w) >= 0, "flush failed");
    }
    CHECK(!ps_frame_writer_pending(&w), "A never finished");
    int rb;
    do {
        ssize_t r = read(rfd, got + g, sizeof got - g);
        if (r > 0) g += (size_t)r;
        rb = ps_frame_writer_send_lossy(&w, bb, sizeof bb);
    } while (rb == PS_FRAME_DROPPED);
    while (ps_frame_writer_pending(&w) || g < sizeof a_copy + sizeof bb) {
        ssize_t r = read(rfd, got + g, sizeof got - g);
        if (r > 0) g += (size_t)r;
        if (ps_frame_writer_flush(&w) < 0) break;
        if (r <= 0) usleep(100);
    }
    CHECK(g == sizeof a_copy + sizeof bb, "stream carried %zu bytes", g);
    CHECK(memcmp(got, a_copy, sizeof a_copy) == 0, "frame A arrived altered");
    CHECK(memcmp(got + sizeof a_copy, bb, sizeof bb) == 0, "frame B arrived altered");
    close(wfd);
    close(rfd);
}

/* ------------------------------------------------------------------ */
/* Test 3: the largest legal frame fits the brain's receive buffer     */
/* ------------------------------------------------------------------ */

/* Writer thread: blocking write of one buffer to completion. */
struct blob_writer { int fd; const uint8_t *b; size_t n; };

static void *blob_writer_main(void *a)
{
    struct blob_writer *p = a;
    size_t off = 0;
    while (off < p->n) {
        ssize_t r = write(p->fd, p->b + off, p->n - off);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        off += (size_t)r;
    }
    return NULL;
}

static void test_max_packet_frame_fits(void)
{
    printf("test: a maximum-size PACKET_DATA frame is accepted by the brain\n");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }

    static uint8_t pkt[PS_MAX_MSG_PAYLOAD];
    static uint8_t frame[sizeof(struct ps_priv_msg) + PS_MAX_FRAME_PAYLOAD];
    memset(pkt, 0x5A, sizeof(pkt));
    /* The worker's pcap capture length tops out at PS_MAX_MSG_PAYLOAD. */
    size_t n = ps_priv_encode_packet_data(frame, sizeof(frame), 3, 42, pkt,
                                          PS_MAX_MSG_PAYLOAD);
    CHECK(n == sizeof(struct ps_priv_msg) + 8 + PS_MAX_MSG_PAYLOAD,
          "max frame did not encode into a PS_MAX_FRAME_PAYLOAD buffer");

    pthread_t th;
    struct blob_writer w = { sv[0], frame, n };
    pthread_create(&th, NULL, blob_writer_main, &w);

    ps_priv_client_init(&g_pc, sv[1]);
    struct ps_priv_msg hdr;
    int r = 0;
    for (int i = 0; i < 2000 && r == 0; i++) {
        r = ps_priv_client_recv(&g_pc, &hdr, g_payload, sizeof(g_payload));
        if (r == 0) usleep(500);
    }
    pthread_join(th, NULL);
    CHECK(r == (int)n, "brain recv of a max-size frame returned %d, want %zu", r, n);
    if (r > 0)
        CHECK(hdr.opcode == PS_OP_PACKET_DATA && hdr.payload_len == 8 + PS_MAX_MSG_PAYLOAD,
              "max frame header mangled");
    close(sv[0]);
    close(sv[1]);
}

/* ------------------------------------------------------------------ */
/* Test 4: an async frame too big for the command-wait queue is dropped */
/*         whole, never handed out truncated                             */
/* ------------------------------------------------------------------ */

struct fake_worker { int fd; uint32_t big_len; };

static void *fake_worker_main(void *arg)
{
    struct fake_worker *fw = arg;
    /* Read the command header the brain sends (CLOSE_PCAP, no payload). */
    struct ps_priv_msg cmd;
    size_t got = 0;
    while (got < sizeof(cmd)) {
        ssize_t r = read(fw->fd, (uint8_t *)&cmd + got, sizeof(cmd) - got);
        if (r <= 0) return NULL;
        got += (size_t)r;
    }
    /* Before answering, emit an async packet larger than the async queue
     * slot, then a small one, then the response. */
    static uint8_t pkt[PS_MAX_MSG_PAYLOAD];
    static uint8_t buf[3 * (sizeof(struct ps_priv_msg) + PS_MAX_FRAME_PAYLOAD)];
    for (uint32_t i = 0; i < fw->big_len; i++) pkt[i] = (uint8_t)(i * 13u);
    size_t off = ps_priv_encode_packet_data(buf, sizeof(buf), 7, 1, pkt, fw->big_len);
    off += ps_priv_encode_packet_data(buf + off, sizeof(buf) - off, 7, 2, pkt, 64);
    off += ps_priv_encode_response(buf + off, sizeof(buf) - off, PS_OP_CLOSE_PCAP,
                                   PS_STATUS_OK, cmd.handle_id, NULL, 0);
    size_t w = 0;
    while (w < off) {
        ssize_t r = write(fw->fd, buf + w, off - w);
        if (r <= 0) break;
        w += (size_t)r;
    }
    return NULL;
}

static void test_oversize_async_frame_not_truncated(void)
{
    printf("test: an oversize async frame during a command wait is not handed out truncated\n");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
    struct fake_worker fw = { sv[1], PS_PRIV_CLIENT_ASYNC_MSG_MAX + 1000 };
    pthread_t th;
    pthread_create(&th, NULL, fake_worker_main, &fw);

    ps_priv_client_init(&g_pc, sv[0]);
    int rc = ps_priv_client_close_pcap(&g_pc, 5);
    CHECK(rc == 0, "command round trip failed (%d)", rc);
    pthread_join(th, NULL);

    /* Every frame the brain hands out must carry exactly the bytes sent. */
    int seen_small = 0;
    for (int i = 0; i < 4; i++) {
        struct ps_priv_msg hdr;
        memset(g_payload, 0, sizeof(g_payload));
        int r = ps_priv_client_recv(&g_pc, &hdr, g_payload, sizeof(g_payload));
        if (r <= 0) break;
        uint64_t seq;
        memcpy(&seq, g_payload, 8);
        uint32_t len = hdr.payload_len - 8;
        int ok = 1;
        for (uint32_t k = 0; k < len; k++)
            if (g_payload[8 + k] != (uint8_t)(k * 13u)) { ok = 0; break; }
        CHECK(ok, "async frame seq=%llu len=%u handed out with wrong bytes",
              (unsigned long long)seq, len);
        if (seq == 2) seen_small = 1;
    }
    CHECK(seen_small, "the small async frame queued behind the oversize one was lost");
    close(sv[0]);
    close(sv[1]);
}

/* Once the stream is marked broken it must never be written to or read again:
 * module shutdown (flow_tracker releasing its pcap handles) still issues
 * close_pcap after the main loop stopped on a broken stream, and a command
 * sent into a desynced stream would block reading a reply that cannot be
 * framed. The command must fail at once, without a byte on the wire. */
static void test_broken_stream_refuses_commands(void)
{
    printf("test: a command on a broken stream fails without touching the socket\n");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
    struct timeval tv = { 0, 200 * 1000 };       /* no hang if it does read */
    setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ps_priv_client_init(&g_pc, sv[0]);
    g_pc.broken = 1;
    int rc = ps_priv_client_close_pcap(&g_pc, 3);
    CHECK(rc == -1, "close_pcap on a broken stream returned %d", rc);

    set_nonblock(sv[1], 1);
    uint8_t b[64];
    ssize_t n = read(sv[1], b, sizeof(b));
    CHECK(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
          "close_pcap on a broken stream wrote %zd byte(s) to the worker", n);
    close(sv[0]);
    close(sv[1]);
}

/* ------------------------------------------------------------------ */
/* Test: a reader stall longer than any finish deadline                */
/* ------------------------------------------------------------------ */

/* The agent's main thread can stall for seconds (a TLS handshake, a DNS
 * lookup, module init). A frame half-written when that happens must not cost
 * the stream: the writer may drop new frames whole, but it must neither
 * report the stream broken nor corrupt it, and every frame it accepted must
 * arrive once the reader resumes. */
static void test_reader_stall_keeps_stream(void)
{
    printf("test: a 3 s reader stall neither breaks nor corrupts the stream\n");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
    int wfd = sv[0], rfd = sv[1];
    set_small_buffers(wfd, rfd);
    set_nonblock(wfd, 1);

    static struct reader_ctx rc;
    memset(&rc, 0, sizeof(rc));
    rc.fd = rfd;
    rc.stall_after = 50;
    rc.stall_ms = 3000;
    pthread_t th;
    pthread_create(&th, NULL, reader_main, &rc);

    static uint8_t pkt[PS_MAX_MSG_PAYLOAD];
    static uint8_t frame[sizeof(struct ps_priv_msg) + PS_MAX_FRAME_PAYLOAD];
    static uint8_t result[N_FRAMES];
    struct ps_frame_writer w;
    ps_frame_writer_init(&w, wfd, g_tail, sizeof(g_tail));
    int broken = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    long worst_ms = 0;

    /* Emulates the worker: frames keep coming (a capture) for 4 s. */
    uint32_t seq = 0;
    for (;; seq++) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long el = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
        if (el > 4000 || seq >= N_FRAMES) break;
        uint32_t len = pkt_len_for(seq);
        for (uint32_t i = 0; i < len; i++) pkt[i] = pkt_byte(seq, i);
        size_t n = ps_priv_encode_packet_data(frame, sizeof(frame),
                                              (uint16_t)(seq & 0x0fff),
                                              (uint64_t)seq, pkt, len);
        struct timespec a, b;
        clock_gettime(CLOCK_MONOTONIC, &a);
        int r = worker_send(&w, frame, n);
        clock_gettime(CLOCK_MONOTONIC, &b);
        long ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
        if (ms > worst_ms) worst_ms = ms;
        result[seq] = (uint8_t)(r == PS_FRAME_SENT || r == PS_FRAME_QUEUED);
        if (r == PS_FRAME_BROKEN) { broken = 1; break; }
        usleep(500);
    }

    CHECK(broken || send_sentinel(&w) == PS_FRAME_SENT, "sentinel response not sent");
    struct ps_frame_stats st = w.stats;
    close(wfd);
    pthread_join(th, NULL);
    close(rfd);

    unsigned long lost = 0, ghosts = 0;
    for (uint32_t s2 = 0; s2 < seq && s2 < N_FRAMES; s2++) {
        if (result[s2] && !rc.outcome[s2]) lost++;
        if (!result[s2] && rc.outcome[s2]) ghosts++;
    }
    printf("  writer: frames=%u sent=%lu dropped=%lu partial=%lu broken=%d worst=%ldms; "
           "reader: received=%lu\n", seq, st.sent, st.dropped, st.partial, broken,
           worst_ms, rc.received);
    CHECK(!broken, "a reader stall broke the stream (the worker would exit)");
    CHECK(st.dropped > 0, "nothing was dropped during the stall; the test exercised nothing");
    CHECK(worst_ms < 200, "a send blocked the writer for %ld ms", worst_ms);
    CHECK(!rc.recv_error && rc.bad_frames == 0, "reader lost framing");
    CHECK(rc.got_sentinel, "reader never reached the final command frame");
    CHECK(lost == 0, "%lu frame(s) reported sent never arrived", lost);
    CHECK(ghosts == 0, "%lu frame(s) reported dropped arrived anyway", ghosts);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    test_lossy_frames_stay_aligned();
    test_unfinishable_frame_is_broken();
    test_writer_tail_exact();
    test_max_packet_frame_fits();
    test_oversize_async_frame_not_truncated();
    test_broken_stream_refuses_commands();
    test_reader_stall_keeps_stream();
    if (g_failures) {
        printf("FAILED: %d check(s)\n", g_failures);
        return 1;
    }
    printf("all priv stream integrity tests passed\n");
    return 0;
}
