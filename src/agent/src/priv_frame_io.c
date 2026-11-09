#include "priv_frame_io.h"

#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifdef MSG_NOSIGNAL
#  define PS_FRAME_SEND_FLAGS (MSG_DONTWAIT | MSG_NOSIGNAL)
#else
#  define PS_FRAME_SEND_FLAGS MSG_DONTWAIT
#endif

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int ps_priv_write_frame_lossy(int fd, const uint8_t *buf, size_t n,
                              int finish_timeout_ms,
                              struct ps_frame_stats *stats)
{
    /* First attempt: the only point at which the frame may be dropped,
     * because no byte of it is in the stream yet. */
    ssize_t r;
    do {
        r = send(fd, buf, n, PS_FRAME_SEND_FLAGS);
    } while (r < 0 && errno == EINTR);

    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (stats) stats->dropped++;
            return PS_FRAME_DROPPED;
        }
        return PS_FRAME_BROKEN;
    }
    if ((size_t)r == n) {
        if (stats) stats->sent++;
        return PS_FRAME_SENT;
    }

    /* Short write: part of the frame is already in the stream. Dropping the
     * rest would leave the reader parsing payload bytes as the next header,
     * so the frame must be finished. Bound the wait: a reader that cannot
     * take the remainder within the deadline is stuck, and the stream is
     * reported broken rather than silently corrupted. */
    if (stats) stats->partial++;
    size_t off = (size_t)r;
    long long deadline = now_ms() + finish_timeout_ms;

    while (off < n) {
        r = send(fd, buf + off, n - off, PS_FRAME_SEND_FLAGS);
        if (r > 0) {
            off += (size_t)r;
            continue;
        }
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return PS_FRAME_BROKEN;

        long long left = deadline - now_ms();
        if (left <= 0) {
            errno = ETIMEDOUT;
            return PS_FRAME_BROKEN;
        }
        struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
        int pr = poll(&pfd, 1, (int)left);
        if (pr < 0 && errno != EINTR) return PS_FRAME_BROKEN;
        if (pr > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) return PS_FRAME_BROKEN;
    }

    if (stats) stats->sent++;
    return PS_FRAME_SENT;
}
