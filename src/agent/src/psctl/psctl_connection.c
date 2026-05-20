#include "psctl_connection.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>

/* Write exactly n bytes, retrying on EINTR */
static int write_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    size_t remaining = n;
    while (remaining > 0) {
        ssize_t r = write(fd, p, remaining);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += r;
        remaining -= (size_t)r;
    }
    return 0;
}

/* Read exactly n bytes, retrying on EINTR */
static int read_all(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    size_t remaining = n;
    while (remaining > 0) {
        ssize_t r = read(fd, p, remaining);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1; /* EOF */
        p += r;
        remaining -= (size_t)r;
    }
    return 0;
}

static void encode_u32le(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)(v & 0xff);
    out[1] = (uint8_t)((v >> 8) & 0xff);
    out[2] = (uint8_t)((v >> 16) & 0xff);
    out[3] = (uint8_t)((v >> 24) & 0xff);
}

static uint32_t decode_u32le(const uint8_t *b)
{
    return (uint32_t)b[0]
         | ((uint32_t)b[1] << 8)
         | ((uint32_t)b[2] << 16)
         | ((uint32_t)b[3] << 24);
}

int psctl_connect(struct psctl_conn *conn, const char *socket_path)
{
    conn->fd = -1;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "psctl: socket(): %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "psctl: connect(%s): %s\n", socket_path, strerror(errno));
        close(fd);
        return -1;
    }

    conn->fd = fd;
    return 0;
}

void psctl_disconnect(struct psctl_conn *conn)
{
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
}

int psctl_send(struct psctl_conn *conn, const char *channel, const char *payload)
{
    if (!channel) channel = "";
    if (!payload)  payload  = "";

    uint32_t ch_len = (uint32_t)strlen(channel);
    uint32_t pl_len = (uint32_t)strlen(payload);

    uint8_t hdr[4];

    /* channel length */
    encode_u32le(hdr, ch_len);
    if (write_all(conn->fd, hdr, 4) < 0) return -1;

    /* channel bytes */
    if (ch_len > 0 && write_all(conn->fd, channel, ch_len) < 0) return -1;

    /* payload length */
    encode_u32le(hdr, pl_len);
    if (write_all(conn->fd, hdr, 4) < 0) return -1;

    /* payload bytes */
    if (pl_len > 0 && write_all(conn->fd, payload, pl_len) < 0) return -1;

    return 0;
}

int psctl_recv(struct psctl_conn *conn,
               char *channel_buf, size_t ch_bufsz,
               char *payload_buf, size_t pl_bufsz,
               int timeout_ms)
{
    /* Wait for data with poll */
    struct pollfd pfd;
    pfd.fd = conn->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) return -1; /* timeout or error */
    if (!(pfd.revents & POLLIN)) return -1;

    uint8_t hdr[4];

    /* Read channel length */
    if (read_all(conn->fd, hdr, 4) < 0) return -1;
    uint32_t ch_len = decode_u32le(hdr);

    if (ch_len >= ch_bufsz) {
        fprintf(stderr, "psctl: channel too long (%u)\n", ch_len);
        return -1;
    }

    if (ch_len > 0 && read_all(conn->fd, channel_buf, ch_len) < 0) return -1;
    channel_buf[ch_len] = '\0';

    /* Read payload length */
    if (read_all(conn->fd, hdr, 4) < 0) return -1;
    uint32_t pl_len = decode_u32le(hdr);

    if (pl_len >= pl_bufsz) {
        fprintf(stderr, "psctl: payload too long (%u)\n", pl_len);
        return -1;
    }

    if (pl_len > 0 && read_all(conn->fd, payload_buf, pl_len) < 0) return -1;
    payload_buf[pl_len] = '\0';

    return 0;
}

int psctl_recv_loop(struct psctl_conn *conn, int timeout_ms,
                    psctl_frame_fn fn, void *userdata)
{
    char channel[256];
    char payload[256 * 1024];
    int count = 0;
    int remaining_ms = timeout_ms;

    /* We do a rough time-budget loop */
    while (remaining_ms > 0) {
        struct pollfd pfd;
        pfd.fd = conn->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int rc = poll(&pfd, 1, remaining_ms);
        if (rc <= 0) break;
        if (!(pfd.revents & POLLIN)) break;

        if (psctl_recv(conn,
                       channel, sizeof(channel),
                       payload, sizeof(payload),
                       0 /* data is ready, don't block */) == 0)
        {
            if (fn) fn(channel, payload, userdata);
            count++;
        } else {
            break;
        }

        /* Decrement conservatively — callers pass generous timeouts */
        remaining_ms -= 50;
    }

    return count;
}
