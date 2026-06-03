#include "priv_client.h"
#include "log.h"

#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <string.h>

/* Write exactly n bytes, handling EINTR. Returns 0 on success, -1 on error. */
static int write_all(int fd, const uint8_t *buf, size_t n)
{
    while (n > 0) {
        ssize_t r = write(fd, buf, n);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        buf += r;
        n   -= (size_t)r;
    }
    return 0;
}

/* Read exactly n bytes, handling EINTR. Returns 0 on success, -1 on error/EOF. */
static int read_all(int fd, uint8_t *buf, size_t n)
{
    while (n > 0) {
        ssize_t r = read(fd, buf, n);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) {
            /* EOF */
            return -1;
        }
        buf += r;
        n   -= (size_t)r;
    }
    return 0;
}

/* Send encoded message and read back the command response header.
 * Async messages (PACKET_DATA, RAW_RESPONSE) that arrive before the
 * command response are buffered in pc->async_queue for later processing.
 * Returns 0 on success, -1 on error. Writes response header to *resp. */
static int send_and_recv(struct ps_priv_client *pc,
                         const uint8_t *msg, size_t msg_len,
                         struct ps_priv_msg *resp)
{
    if (write_all(pc->fd, msg, msg_len) < 0) {
        ps_error("priv_client: write failed: %s", strerror(errno));
        return -1;
    }

    /* Read messages until we get a non-async response (opcode < 0x80 means
     * it's a command ack; opcodes 0x81/0x82 are async data from pcap/raw). */
    for (;;) {
        struct ps_priv_msg hdr;
        if (read_all(pc->fd, (uint8_t *)&hdr, sizeof(hdr)) < 0) {
            ps_error("priv_client: read response failed: %s", strerror(errno));
            return -1;
        }

        if (hdr.opcode == PS_OP_PACKET_DATA || hdr.opcode == PS_OP_RAW_RESPONSE ||
            hdr.opcode == PS_OP_ACTIVITY_DATA) {
            /* Async message — buffer it for later event loop processing */
            if (hdr.payload_len > 0) {
                if (pc->async_count < PS_PRIV_CLIENT_ASYNC_QUEUE_SIZE) {
                    struct ps_async_msg *am = &pc->async_queue[pc->async_count];
                    am->hdr = hdr;
                    uint32_t to_read = hdr.payload_len;
                    if (to_read > PS_PRIV_CLIENT_ASYNC_MSG_MAX) to_read = PS_PRIV_CLIENT_ASYNC_MSG_MAX;
                    if (read_all(pc->fd, am->payload, to_read) < 0) return -1;
                    /* Skip any excess beyond our buffer */
                    if (hdr.payload_len > PS_PRIV_CLIENT_ASYNC_MSG_MAX) {
                        uint8_t discard[4096];
                        uint32_t remaining = hdr.payload_len - PS_PRIV_CLIENT_ASYNC_MSG_MAX;
                        while (remaining > 0) {
                            uint32_t chunk = remaining > sizeof(discard) ? sizeof(discard) : remaining;
                            if (read_all(pc->fd, discard, chunk) < 0) return -1;
                            remaining -= chunk;
                        }
                    }
                    pc->async_count++;
                } else {
                    /* Queue full — discard payload */
                    uint8_t discard[4096];
                    uint32_t remaining = hdr.payload_len;
                    while (remaining > 0) {
                        uint32_t chunk = remaining > sizeof(discard) ? sizeof(discard) : remaining;
                        if (read_all(pc->fd, discard, chunk) < 0) return -1;
                        remaining -= chunk;
                    }
                }
            } else if (pc->async_count < PS_PRIV_CLIENT_ASYNC_QUEUE_SIZE) {
                struct ps_async_msg *am = &pc->async_queue[pc->async_count];
                am->hdr = hdr;
                pc->async_count++;
            }
            continue; /* Keep reading until we get the command response */
        }

        /* This is the command response we were waiting for */
        /* Consume any payload attached to the response (usually 0) */
        if (hdr.payload_len > 0) {
            uint8_t discard[256];
            uint32_t remaining = hdr.payload_len;
            while (remaining > 0) {
                uint32_t chunk = remaining > sizeof(discard) ? sizeof(discard) : remaining;
                if (read_all(pc->fd, discard, chunk) < 0) return -1;
                remaining -= chunk;
            }
        }
        *resp = hdr;
        return 0;
    }
}

void ps_priv_client_init(struct ps_priv_client *pc, int fd)
{
    memset(pc, 0, sizeof(*pc));
    pc->fd = fd;
}

int ps_priv_client_open_pcap(struct ps_priv_client *pc,
                              const char *iface,
                              const char *filter,
                              uint32_t snaplen)
{
    uint8_t buf[PS_MAX_MSG_PAYLOAD + sizeof(struct ps_priv_msg)];
    size_t n = ps_priv_encode_open_pcap(buf, sizeof(buf), iface, filter, snaplen);
    if (n == 0) {
        ps_error("priv_client: open_pcap encode overflow");
        return -1;
    }

    struct ps_priv_msg resp;
    if (send_and_recv(pc, buf, n, &resp) < 0) {
        return -1;
    }

    if (resp.status != PS_STATUS_OK) {
        ps_error("priv_client: open_pcap failed with status %d", resp.status);
        return -1;
    }

    return (int)resp.handle_id;
}

int ps_priv_client_close_pcap(struct ps_priv_client *pc, uint16_t handle_id)
{
    uint8_t buf[sizeof(struct ps_priv_msg)];
    size_t n = ps_priv_encode_close_handle(buf, sizeof(buf), PS_OP_CLOSE_PCAP, handle_id);
    if (n == 0) {
        ps_error("priv_client: close_pcap encode overflow");
        return -1;
    }

    struct ps_priv_msg resp;
    if (send_and_recv(pc, buf, n, &resp) < 0) {
        return -1;
    }

    if (resp.status != PS_STATUS_OK) {
        ps_error("priv_client: close_pcap failed with status %d", resp.status);
        return -1;
    }

    return 0;
}

int ps_priv_client_create_raw_socket(struct ps_priv_client *pc,
                                      uint8_t af, uint8_t proto)
{
    uint8_t buf[sizeof(struct ps_priv_msg) + 2];
    size_t n = ps_priv_encode_create_raw_socket(buf, sizeof(buf), af, proto);
    if (n == 0) {
        ps_error("priv_client: create_raw_socket encode overflow");
        return -1;
    }

    struct ps_priv_msg resp;
    if (send_and_recv(pc, buf, n, &resp) < 0) {
        return -1;
    }

    if (resp.status != PS_STATUS_OK) {
        ps_error("priv_client: create_raw_socket failed with status %d", resp.status);
        return -1;
    }

    return (int)resp.handle_id;
}

int ps_priv_client_close_raw_socket(struct ps_priv_client *pc, uint16_t handle_id)
{
    uint8_t buf[sizeof(struct ps_priv_msg)];
    size_t n = ps_priv_encode_close_handle(buf, sizeof(buf), PS_OP_CLOSE_RAW_SOCKET, handle_id);
    if (n == 0) {
        ps_error("priv_client: close_raw_socket encode overflow");
        return -1;
    }

    struct ps_priv_msg resp;
    if (send_and_recv(pc, buf, n, &resp) < 0) {
        return -1;
    }

    if (resp.status != PS_STATUS_OK) {
        ps_error("priv_client: close_raw_socket failed with status %d", resp.status);
        return -1;
    }

    return 0;
}

int ps_priv_client_send_raw(struct ps_priv_client *pc,
                             uint16_t handle_id, uint8_t ttl,
                             const struct sockaddr *dest, socklen_t dest_len,
                             const uint8_t *pkt, uint32_t pkt_len)
{
    uint8_t buf[PS_MAX_MSG_PAYLOAD + sizeof(struct ps_priv_msg)];
    size_t n = ps_priv_encode_send_raw(buf, sizeof(buf), handle_id, ttl,
                                        dest, dest_len, pkt, pkt_len);
    if (n == 0) {
        ps_error("priv_client: send_raw encode overflow");
        return -1;
    }

    struct ps_priv_msg resp;
    if (send_and_recv(pc, buf, n, &resp) < 0) {
        return -1;
    }

    if (resp.status != PS_STATUS_OK) {
        ps_error("priv_client: send_raw failed with status %d", resp.status);
        return -1;
    }

    return 0;
}

int ps_priv_client_recv(struct ps_priv_client *pc,
                         struct ps_priv_msg *hdr,
                         uint8_t *payload_buf, size_t bufsz)
{
    /* First drain any messages buffered during synchronous command waits */
    if (pc->async_count > 0) {
        struct ps_async_msg *am = &pc->async_queue[0];
        *hdr = am->hdr;
        uint32_t copy = hdr->payload_len;
        if (copy > bufsz) copy = (uint32_t)bufsz;
        if (copy > 0) memcpy(payload_buf, am->payload, copy);
        /* Shift queue down */
        pc->async_count--;
        if (pc->async_count > 0) {
            memmove(&pc->async_queue[0], &pc->async_queue[1],
                    (size_t)pc->async_count * sizeof(pc->async_queue[0]));
        }
        return (int)(sizeof(*hdr) + hdr->payload_len);
    }

    struct pollfd pfd;
    pfd.fd     = pc->fd;
    pfd.events = POLLIN;

    int r = poll(&pfd, 1, 0);
    if (r < 0) {
        if (errno == EINTR) return 0;
        return -1;
    }
    if (r == 0) {
        return 0;  /* Nothing available */
    }

    /* Read the 8-byte header */
    ssize_t n = read(pc->fd, hdr, sizeof(*hdr));
    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN) return 0;
        return -1;
    }
    if (n == 0) {
        return -1;  /* EOF — priv worker died */
    }
    if (n < (ssize_t)sizeof(*hdr)) {
        /* Partial header: read the rest */
        if (read_all(pc->fd, (uint8_t *)hdr + n, sizeof(*hdr) - (size_t)n) < 0) {
            return -1;
        }
    }

    /* Read payload if any */
    uint32_t payload_len = hdr->payload_len;
    if (payload_len > 0) {
        if (payload_len > bufsz) {
            ps_error("priv_client: recv payload %u exceeds buffer %zu", payload_len, bufsz);
            return -1;
        }
        if (read_all(pc->fd, payload_buf, payload_len) < 0) {
            return -1;
        }
    }

    return (int)(sizeof(*hdr) + payload_len);
}

int ps_priv_client_fd(struct ps_priv_client *pc)
{
    return pc->fd;
}
