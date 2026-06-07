#include "ipc_server.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

/* ---------------------------------------------------------------------------
 * Frame encoding
 * -------------------------------------------------------------------------*/

int ps_ipc_encode_frame(uint8_t *buf, size_t bufsz,
                        const char *channel,
                        const char *payload, uint32_t payload_len)
{
    uint32_t ch_len = (uint32_t)strlen(channel);
    /* 4 (ch_len) + ch_len + 4 (pl_len) + payload_len */
    size_t total = 4u + ch_len + 4u + payload_len;

    if (total > bufsz) {
        ps_error("ipc_encode_frame: buffer too small (%zu needed, %zu available)",
                 total, bufsz);
        return -1;
    }

    uint8_t *p = buf;

    /* channel name length — little-endian */
    p[0] = (uint8_t)(ch_len & 0xFF);
    p[1] = (uint8_t)((ch_len >> 8) & 0xFF);
    p[2] = (uint8_t)((ch_len >> 16) & 0xFF);
    p[3] = (uint8_t)((ch_len >> 24) & 0xFF);
    p += 4;

    /* channel name bytes */
    memcpy(p, channel, ch_len);
    p += ch_len;

    /* payload length — little-endian */
    p[0] = (uint8_t)(payload_len & 0xFF);
    p[1] = (uint8_t)((payload_len >> 8) & 0xFF);
    p[2] = (uint8_t)((payload_len >> 16) & 0xFF);
    p[3] = (uint8_t)((payload_len >> 24) & 0xFF);
    p += 4;

    /* payload bytes */
    memcpy(p, payload, payload_len);

    return (int)total;
}

/* ---------------------------------------------------------------------------
 * Frame reader — incremental byte-at-a-time state machine
 * -------------------------------------------------------------------------*/

void ps_frame_reader_init(struct ps_frame_reader *r)
{
    memset(r, 0, sizeof(*r));
    r->state = PS_FRAME_CH_LEN;
}

void ps_frame_reader_free(struct ps_frame_reader *r)
{
    free(r->payload);
    r->payload = NULL;
    r->payload_cap = 0;
}

void ps_frame_reader_reset(struct ps_frame_reader *r)
{
    /* Keep the payload allocation if it already exists */
    r->state       = PS_FRAME_CH_LEN;
    r->len_pos     = 0;
    r->channel_len = 0;
    r->channel_pos = 0;
    r->payload_len = 0;
    r->payload_pos = 0;
    memset(r->len_buf, 0, sizeof(r->len_buf));
    memset(r->channel, 0, sizeof(r->channel));
}

/*
 * Feed one byte into the reader.
 * Returns:
 *   1  — complete frame is ready; channel and payload are valid
 *   0  — more bytes needed
 *  -1  — protocol error (oversized field, allocation failure)
 *
 * After returning 1, the reader is automatically reset for the next frame.
 */
int ps_frame_reader_feed(struct ps_frame_reader *r, uint8_t byte)
{
    switch (r->state) {

    /* --- reading 4-byte channel name length --- */
    case PS_FRAME_CH_LEN:
        r->len_buf[r->len_pos++] = byte;
        if (r->len_pos == 4) {
            r->channel_len = (uint32_t)r->len_buf[0]
                           | ((uint32_t)r->len_buf[1] << 8)
                           | ((uint32_t)r->len_buf[2] << 16)
                           | ((uint32_t)r->len_buf[3] << 24);
            r->len_pos = 0;

            if (r->channel_len == 0 || r->channel_len >= PS_IPC_MAX_CHANNEL) {
                ps_error("ipc_frame_reader: channel_len %u out of range", r->channel_len);
                return -1;
            }
            r->channel_pos = 0;
            r->state = PS_FRAME_CH_DATA;
        }
        return 0;

    /* --- reading channel name bytes --- */
    case PS_FRAME_CH_DATA:
        r->channel[r->channel_pos++] = (char)byte;
        if (r->channel_pos == r->channel_len) {
            r->channel[r->channel_pos] = '\0';
            r->len_pos = 0;
            r->state = PS_FRAME_PL_LEN;
        }
        return 0;

    /* --- reading 4-byte payload length --- */
    case PS_FRAME_PL_LEN:
        r->len_buf[r->len_pos++] = byte;
        if (r->len_pos == 4) {
            r->payload_len = (uint32_t)r->len_buf[0]
                           | ((uint32_t)r->len_buf[1] << 8)
                           | ((uint32_t)r->len_buf[2] << 16)
                           | ((uint32_t)r->len_buf[3] << 24);
            r->len_pos = 0;

            if (r->payload_len > PS_IPC_MAX_PAYLOAD) {
                ps_error("ipc_frame_reader: payload_len %u exceeds limit", r->payload_len);
                return -1;
            }

            /* Grow payload buffer if needed */
            if (r->payload_len > r->payload_cap) {
                free(r->payload);
                r->payload = malloc(r->payload_len + 1);
                if (!r->payload) {
                    ps_error("ipc_frame_reader: malloc failed for payload (%u bytes)", r->payload_len);
                    r->payload_cap = 0;
                    return -1;
                }
                r->payload_cap = r->payload_len;
            }

            r->payload_pos = 0;

            /* Zero-length payload is valid — complete immediately */
            if (r->payload_len == 0) {
                if (r->payload) r->payload[0] = '\0';
                ps_frame_reader_reset(r);
                return 1;
            }

            r->state = PS_FRAME_PL_DATA;
        }
        return 0;

    /* --- reading payload bytes --- */
    case PS_FRAME_PL_DATA:
        r->payload[r->payload_pos++] = (char)byte;
        if (r->payload_pos == r->payload_len) {
            r->payload[r->payload_pos] = '\0';
            /* Reset for next frame; caller must use channel/payload before
             * feeding more bytes, but payload buffer is kept. */
            r->state       = PS_FRAME_CH_LEN;
            r->len_pos     = 0;
            r->channel_pos = 0;
            /* Do NOT clear channel[] or payload[] — caller reads them now */
            return 1;
        }
        return 0;
    }

    /* Should never reach here */
    return -1;
}

/* ---------------------------------------------------------------------------
 * IPC server — AF_UNIX SOCK_STREAM
 * -------------------------------------------------------------------------*/

int ps_ipc_server_init(struct ps_ipc_server *srv, const char *socket_path,
                        ps_ipc_on_frame_fn on_frame, void *userdata)
{
    memset(srv, 0, sizeof(*srv));
    srv->listen_fd     = -1;
    srv->tcp_listen_fd = -1;
    srv->on_frame      = on_frame;
    srv->userdata      = userdata;
    srv->client_count  = 0;

    for (int i = 0; i < PS_IPC_MAX_CLIENTS; i++)
        srv->clients[i].fd = -1;

    /* Ensure the socket's parent directory exists. Under systemd this is
     * created host-visibly by RuntimeDirectory= (/run/packetsonde), but
     * create it defensively so the agent also works when run directly or
     * before the unit's RuntimeDirectory has been provisioned. PrivateTmp
     * does NOT privatize /run, so a socket here is reachable from the host
     * namespace (unlike the old /tmp/packetsonde-agent.sock). */
    {
        char dir[256];
        strncpy(dir, socket_path, sizeof(dir) - 1);
        dir[sizeof(dir) - 1] = '\0';
        char *slash = strrchr(dir, '/');
        if (slash && slash != dir) {
            *slash = '\0';
            if (mkdir(dir, 0755) < 0 && errno != EEXIST)
                ps_warn("ipc_server_init: mkdir('%s') failed: %s",
                        dir, strerror(errno));
        }
    }

    /* Remove stale socket file */
    unlink(socket_path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        ps_error("ipc_server_init: socket() failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        ps_error("ipc_server_init: socket path too long");
        close(fd);
        return -1;
    }
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    /* Remove a stale socket from an unclean prior shutdown; otherwise bind()
     * fails with EADDRINUSE and the agent crash-loops. systemd guarantees a
     * single instance, so unconditionally unlinking the path is safe. */
    if (unlink(socket_path) == 0)
        ps_warn("ipc_server_init: removed stale socket '%s'", socket_path);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ps_error("ipc_server_init: bind() failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, PS_IPC_MAX_CLIENTS) < 0) {
        ps_error("ipc_server_init: listen() failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Make socket world-accessible so unprivileged UI processes can connect.
     * The agent drops privs after creating the socket — the UI runs as the
     * normal user and needs permission to connect. */
    chmod(socket_path, 0666);

    srv->listen_fd = fd;
    ps_info("ipc_server: listening on %s", socket_path);
    return 0;
}

int ps_ipc_server_add_tcp(struct ps_ipc_server *srv,
                           const char *bind_addr, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        ps_error("ipc_server_add_tcp: socket() failed: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (bind_addr && bind_addr[0] != '\0') {
        inet_pton(AF_INET, bind_addr, &addr.sin_addr);
    } else {
        addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ps_error("ipc_server_add_tcp: bind(%s:%d) failed: %s",
                 bind_addr ? bind_addr : "0.0.0.0", port, strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, PS_IPC_MAX_CLIENTS) < 0) {
        ps_error("ipc_server_add_tcp: listen() failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    srv->tcp_listen_fd = fd;
    ps_info("ipc_server: TCP listener on %s:%d",
            bind_addr ? bind_addr : "0.0.0.0", port);
    return 0;
}

void ps_ipc_server_shutdown(struct ps_ipc_server *srv)
{
    for (int i = 0; i < PS_IPC_MAX_CLIENTS; i++) {
        if (srv->clients[i].fd >= 0) {
            ps_frame_reader_free(&srv->clients[i].reader);
            close(srv->clients[i].fd);
            srv->clients[i].fd = -1;
        }
    }
    if (srv->listen_fd >= 0) {
        close(srv->listen_fd);
        srv->listen_fd = -1;
    }
    if (srv->tcp_listen_fd >= 0) {
        close(srv->tcp_listen_fd);
        srv->tcp_listen_fd = -1;
    }
    srv->client_count = 0;
}

/*
 * Accept a new client into the first available slot.
 * Returns slot index or -1 if full.
 */
static int ipc_accept_client(struct ps_ipc_server *srv)
{
    if (srv->client_count >= PS_IPC_MAX_CLIENTS) {
        ps_warn("ipc_server: max clients (%d) reached, rejecting connection",
                PS_IPC_MAX_CLIENTS);
        /* Accept and immediately close to clear the queue entry */
        int tmp = accept(srv->listen_fd, NULL, NULL);
        if (tmp >= 0) close(tmp);
        return -1;
    }

    int cfd = accept(srv->listen_fd, NULL, NULL);
    if (cfd < 0) {
        ps_error("ipc_server: accept() failed: %s", strerror(errno));
        return -1;
    }

    for (int i = 0; i < PS_IPC_MAX_CLIENTS; i++) {
        if (srv->clients[i].fd < 0) {
            srv->clients[i].fd = cfd;
            ps_frame_reader_init(&srv->clients[i].reader);
            srv->client_count++;
            ps_info("ipc_server: client connected (slot %d, fd %d)", i, cfd);
            return i;
        }
    }

    /* Should not reach here given the count check above */
    close(cfd);
    return -1;
}

/*
 * Disconnect and clean up a client slot.
 */
static void ipc_drop_client(struct ps_ipc_server *srv, int slot)
{
    ps_info("ipc_server: client disconnected (slot %d, fd %d)",
            slot, srv->clients[slot].fd);
    ps_frame_reader_free(&srv->clients[slot].reader);
    close(srv->clients[slot].fd);
    srv->clients[slot].fd = -1;
    srv->client_count--;
}

int ps_ipc_server_poll(struct ps_ipc_server *srv, int timeout_ms)
{
    /* Build pollfd array: listen fds first, then active clients */
    struct pollfd fds[PS_IPC_MAX_CLIENTS + 2]; /* +2 for unix + tcp listeners */
    int slot_map[PS_IPC_MAX_CLIENTS];
    int nfds = 0;
    int unix_poll_idx = -1;
    int tcp_poll_idx = -1;

    if (srv->listen_fd >= 0) {
        unix_poll_idx = nfds;
        fds[nfds].fd      = srv->listen_fd;
        fds[nfds].events  = POLLIN;
        fds[nfds].revents = 0;
        nfds++;
    }

    if (srv->tcp_listen_fd >= 0) {
        tcp_poll_idx = nfds;
        fds[nfds].fd      = srv->tcp_listen_fd;
        fds[nfds].events  = POLLIN;
        fds[nfds].revents = 0;
        nfds++;
    }

    int client_start_idx = nfds;
    for (int i = 0; i < PS_IPC_MAX_CLIENTS; i++) {
        if (srv->clients[i].fd >= 0) {
            slot_map[nfds - client_start_idx] = i;
            fds[nfds].fd       = srv->clients[i].fd;
            fds[nfds].events   = POLLIN;
            fds[nfds].revents  = 0;
            nfds++;
        }
    }

    int rc = poll(fds, (nfds_t)nfds, timeout_ms);
    if (rc < 0) {
        if (errno == EINTR) return 0;
        ps_error("ipc_server_poll: poll() failed: %s", strerror(errno));
        return -1;
    }
    if (rc == 0) return 0;

    /* Check Unix listen_fd for new connections */
    if (unix_poll_idx >= 0 && (fds[unix_poll_idx].revents & POLLIN)) {
        ipc_accept_client(srv);
    }

    /* Check TCP listen_fd for new connections */
    if (tcp_poll_idx >= 0 && (fds[tcp_poll_idx].revents & POLLIN)) {
        /* Accept TCP client into the same client array */
        if (srv->client_count < PS_IPC_MAX_CLIENTS) {
            int cfd = accept(srv->tcp_listen_fd, NULL, NULL);
            if (cfd >= 0) {
                for (int i = 0; i < PS_IPC_MAX_CLIENTS; i++) {
                    if (srv->clients[i].fd < 0) {
                        srv->clients[i].fd = cfd;
                        ps_frame_reader_init(&srv->clients[i].reader);
                        srv->client_count++;
                        ps_info("ipc_server: TCP client connected (slot %d, fd %d)", i, cfd);
                        break;
                    }
                }
            }
        } else {
            int tmp = accept(srv->tcp_listen_fd, NULL, NULL);
            if (tmp >= 0) close(tmp);
            ps_warn("ipc_server: max clients, rejecting TCP connection");
        }
    }

    /* Check client fds */
    int client_poll_count = nfds - client_start_idx;
    for (int j = 0; j < client_poll_count; j++) {
        int pfd_idx = j + client_start_idx;
        int slot    = slot_map[j];

        if (!(fds[pfd_idx].revents & (POLLIN | POLLHUP | POLLERR)))
            continue;

        if (fds[pfd_idx].revents & (POLLHUP | POLLERR)) {
            ipc_drop_client(srv, slot);
            continue;
        }

        /* Read available bytes and feed to frame reader */
        uint8_t read_buf[4096];
        ssize_t n = read(srv->clients[slot].fd, read_buf, sizeof(read_buf));
        if (n <= 0) {
            ipc_drop_client(srv, slot);
            continue;
        }

        for (ssize_t k = 0; k < n; k++) {
            int fr = ps_frame_reader_feed(&srv->clients[slot].reader, read_buf[k]);
            if (fr == 1) {
                /* Complete frame — invoke callback */
                if (srv->on_frame) {
                    srv->on_frame(srv->clients[slot].fd,
                                  srv->clients[slot].reader.channel,
                                  srv->clients[slot].reader.payload,
                                  srv->clients[slot].reader.payload_len,
                                  srv->userdata);
                }
                /* reader has already reset itself in ps_frame_reader_feed */
            } else if (fr < 0) {
                ps_warn("ipc_server: frame error on slot %d, dropping client", slot);
                ipc_drop_client(srv, slot);
                break;
            }
        }
    }

    return 0;
}

int ps_ipc_server_broadcast(struct ps_ipc_server *srv,
                             const char *channel,
                             const char *payload, uint32_t payload_len)
{
    if (srv->client_count == 0) return 0;

    /* Encode once */
    size_t bufsz = 4u + strlen(channel) + 4u + payload_len;
    uint8_t *buf = malloc(bufsz);
    if (!buf) {
        ps_error("ipc_server_broadcast: malloc failed");
        return -1;
    }

    int frame_len = ps_ipc_encode_frame(buf, bufsz, channel, payload, payload_len);
    if (frame_len < 0) {
        free(buf);
        return -1;
    }

    int sent = 0;
    for (int i = 0; i < PS_IPC_MAX_CLIENTS; i++) {
        if (srv->clients[i].fd < 0) continue;

        size_t  remaining = (size_t)frame_len;
        const uint8_t *wp = buf;
        int ok = 1;
        while (remaining > 0) {
            ssize_t w = write(srv->clients[i].fd, wp, remaining);
            if (w < 0) {
                if (errno == EINTR) continue;
                ps_warn("ipc_server_broadcast: write to slot %d failed: %s",
                        i, strerror(errno));
                ipc_drop_client(srv, i);
                ok = 0;
                break;
            }
            wp        += w;
            remaining -= (size_t)w;
        }
        if (ok) sent++;
    }

    free(buf);
    return sent;
}

int ps_ipc_server_send_to(struct ps_ipc_server *srv, int client_fd,
                           const char *channel,
                           const char *payload, uint32_t payload_len)
{
    if (client_fd < 0) return 0;

    size_t bufsz = 4u + strlen(channel) + 4u + payload_len;
    uint8_t *buf = malloc(bufsz);
    if (!buf) {
        ps_error("ipc_server_send_to: malloc failed");
        return -1;
    }

    int frame_len = ps_ipc_encode_frame(buf, bufsz, channel, payload, payload_len);
    if (frame_len < 0) {
        free(buf);
        return -1;
    }

    size_t remaining = (size_t)frame_len;
    const uint8_t *wp = buf;
    while (remaining > 0) {
        ssize_t w = write(client_fd, wp, remaining);
        if (w < 0) {
            if (errno == EINTR) continue;
            ps_warn("ipc_server_send_to: write to fd %d failed: %s",
                    client_fd, strerror(errno));
            free(buf);
            return -1;
        }
        wp        += w;
        remaining -= (size_t)w;
    }

    free(buf);
    return 1;
}
