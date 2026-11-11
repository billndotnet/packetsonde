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

struct reader_ctx {
    int      fd;
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
    struct ps_frame_stats st = {0};
    int broken = 0;

    for (uint32_t seq = 0; seq < N_FRAMES; seq++) {
        uint32_t len = pkt_len_for(seq);
        for (uint32_t i = 0; i < len; i++) pkt[i] = pkt_byte(seq, i);
        size_t n = ps_priv_encode_packet_data(frame, sizeof(frame),
                                              (uint16_t)(seq & 0x0fff),
                                              (uint64_t)seq, pkt, len);
        if (n == 0) { fprintf(stderr, "encode failed\n"); exit(2); }
        int r = ps_priv_write_frame_lossy(wfd, frame, n, 2000, &st);
        result[seq] = (uint8_t)(r == PS_FRAME_SENT);
        if (r == PS_FRAME_BROKEN) { broken = 1; break; }
    }

    /* Sentinel: a command-style response, written to completion. */
    uint8_t sent_buf[sizeof(struct ps_priv_msg)];
    size_t sn = ps_priv_encode_response(sent_buf, sizeof(sent_buf), PS_OP_ERROR,
                                        PS_STATUS_OK, SENTINEL_HANDLE, NULL, 0);
    set_nonblock(wfd, 0);
    size_t off = 0;
    while (off < sn) {
        ssize_t w = write(wfd, sent_buf + off, sn - off);
        if (w < 0) { if (errno == EINTR) continue; break; }
        off += (size_t)w;
    }
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
    printf("test: a frame that cannot be finished reports a broken stream\n");
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); exit(2); }
    int wfd = sv[0], rfd = sv[1];
    set_small_buffers(wfd, rfd);
    set_nonblock(wfd, 1);

    static uint8_t pkt[PS_MAX_MSG_PAYLOAD];
    static uint8_t frame[sizeof(struct ps_priv_msg) + PS_MAX_FRAME_PAYLOAD];
    memset(pkt, 0xAB, sizeof(pkt));
    size_t n = ps_priv_encode_packet_data(frame, sizeof(frame), 1, 1, pkt, 30000);

    /* Nobody reads rfd. Keep writing until a frame starts but cannot end. */
    struct ps_frame_stats st = {0};
    int r = PS_FRAME_SENT;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < 1000 && r != PS_FRAME_BROKEN; i++) {
        r = ps_priv_write_frame_lossy(wfd, frame, n, 100, &st);
        if (st.partial > 0) break;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;

    CHECK(st.partial > 0, "never produced a short write");
    CHECK(r == PS_FRAME_BROKEN,
          "short write with a stalled reader returned %d, want PS_FRAME_BROKEN", r);
    CHECK(ms >= 90 && ms < 1500, "bounded wait took %ld ms (bound 100 ms)", ms);
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

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    test_lossy_frames_stay_aligned();
    test_unfinishable_frame_is_broken();
    test_max_packet_frame_fits();
    test_oversize_async_frame_not_truncated();
    test_broken_stream_refuses_commands();
    if (g_failures) {
        printf("FAILED: %d check(s)\n", g_failures);
        return 1;
    }
    printf("all priv stream integrity tests passed\n");
    return 0;
}
