#include "priv_frame_io.h"

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifdef MSG_NOSIGNAL
#  define PS_FRAME_SEND_FLAGS (MSG_DONTWAIT | MSG_NOSIGNAL)
#else
#  define PS_FRAME_SEND_FLAGS MSG_DONTWAIT
#endif

/* One non-blocking send: bytes taken (>= 0; 0 = would block) or -1 on a hard
 * error. */
static ssize_t send_some(int fd, const uint8_t *buf, size_t n)
{
    ssize_t r;
    do {
        r = send(fd, buf, n, PS_FRAME_SEND_FLAGS);
    } while (r < 0 && errno == EINTR);
    if (r < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
    return r;
}

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void ps_frame_writer_init(struct ps_frame_writer *w, int fd,
                          uint8_t *tail, size_t tail_cap)
{
    memset(w, 0, sizeof(*w));
    w->fd = fd;
    w->tail = tail;
    w->tail_cap = tail ? tail_cap : 0;
}

int ps_frame_writer_pending(const struct ps_frame_writer *w)
{
    return w->tail_off < w->tail_len;
}

int ps_frame_writer_flush(struct ps_frame_writer *w)
{
    if (w->broken) return PS_FRAME_BROKEN;
    while (w->tail_off < w->tail_len) {
        ssize_t r = send_some(w->fd, w->tail + w->tail_off, w->tail_len - w->tail_off);
        if (r < 0) { w->broken = 1; return PS_FRAME_BROKEN; }
        if (r == 0) return 0;
        w->tail_off += (size_t)r;
    }
    w->tail_off = w->tail_len = 0;
    return 1;
}

int ps_frame_writer_send_lossy(struct ps_frame_writer *w,
                               const uint8_t *buf, size_t n)
{
    if (w->broken) return PS_FRAME_BROKEN;
    if (n == 0) return PS_FRAME_SENT;

    /* A started frame owns the stream until it is finished. */
    int f = ps_frame_writer_flush(w);
    if (f < 0) return PS_FRAME_BROKEN;
    if (f == 0) {
        w->stats.dropped++;
        w->stats.dropped_pending++;
        return PS_FRAME_DROPPED;
    }
    /* Only a frame whose remainder can be buffered may be started. */
    if (n > w->tail_cap) {
        w->stats.dropped++;
        return PS_FRAME_DROPPED;
    }

    /* The only point at which the frame may be dropped: none of it is in
     * the stream yet. */
    ssize_t r = send_some(w->fd, buf, n);
    if (r < 0) { w->broken = 1; return PS_FRAME_BROKEN; }
    if (r == 0) {
        w->stats.dropped++;
        return PS_FRAME_DROPPED;
    }
    w->stats.sent++;
    if ((size_t)r == n) return PS_FRAME_SENT;

    /* Started but not finished: keep the remainder for the poll loop. */
    w->stats.partial++;
    w->tail_len = n - (size_t)r;
    w->tail_off = 0;
    memcpy(w->tail, buf + r, w->tail_len);
    return PS_FRAME_QUEUED;
}

/* Wait until fd is writable or the deadline passes (deadline < 0: no limit).
 * Returns 0 when writable (or worth retrying), -1 on error or timeout. */
static int wait_writable(int fd, long long deadline)
{
    int tmo = -1;
    if (deadline >= 0) {
        long long left = deadline - now_ms();
        if (left <= 0) { errno = ETIMEDOUT; return -1; }
        tmo = left > 1000 ? 1000 : (int)left;
    } else {
        tmo = 1000;
    }
    struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
    int pr = poll(&pfd, 1, tmo);
    if (pr < 0) return errno == EINTR ? 0 : -1;
    if (pr > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
        errno = EPIPE;
        return -1;
    }
    return 0;
}

int ps_frame_writer_send_all(struct ps_frame_writer *w,
                             const uint8_t *buf, size_t n, int timeout_ms)
{
    if (w->broken) return PS_FRAME_BROKEN;
    long long deadline = timeout_ms < 0 ? -1 : now_ms() + timeout_ms;

    for (;;) {
        int f = ps_frame_writer_flush(w);
        if (f < 0) return PS_FRAME_BROKEN;
        if (f == 1) break;
        if (wait_writable(w->fd, deadline) < 0) { w->broken = 1; return PS_FRAME_BROKEN; }
    }

    size_t off = 0;
    while (off < n) {
        ssize_t r = send_some(w->fd, buf + off, n - off);
        if (r < 0) { w->broken = 1; return PS_FRAME_BROKEN; }
        if (r > 0) { off += (size_t)r; continue; }
        if (wait_writable(w->fd, deadline) < 0) { w->broken = 1; return PS_FRAME_BROKEN; }
    }
    return PS_FRAME_SENT;
}
