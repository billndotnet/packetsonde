#include "ipc_server.h"
#include "log.h"
#include "agent_transport.h"   /* ps_at_* mTLS helpers (pulls in keystore.h + openssl) */
#include "keystore.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <openssl/ssl.h>

/* ---------------------------------------------------------------------------
 * TLS state for the TCP listener (opaque to the header)
 * -------------------------------------------------------------------------*/

#define PS_IPC_MAX_AUTHORIZED 64
/* Bound the TLS handshake + per-record reads so a slow/stalled TCP peer can't
 * freeze the single-threaded poll loop. */
#define PS_IPC_TLS_IO_TIMEOUT_SEC 10
/* Client sockets are non-blocking after accept, so a broadcast write to a client
 * whose send buffer is full returns EAGAIN instead of blocking the whole agent.
 * We then wait briefly (POLL_MS) for it to drain, up to MAX_WAITS slices total,
 * before giving up and dropping the client. ~750ms ceiling per stuck client. */
#define PS_IPC_WRITE_POLL_MS   50
#define PS_IPC_WRITE_MAX_WAITS 15
/* ipc_client_read sentinel: the non-blocking socket has no data ready yet (a
 * partial TLS record, or EAGAIN). NOT an error -- stop reading this pass and let
 * the level-triggered poll re-signal when the rest arrives. Distinct from 0 (EOF
 * -> drop) and -1 (real error -> drop). */
#define PS_IPC_WOULDBLOCK (-2)

struct ps_ipc_tls {
    struct ps_at_ctx ctx;
    uint8_t authorized[PS_IPC_MAX_AUTHORIZED][PS_KEYSTORE_PUBKEY_SIZE];
    size_t  authorized_n;
};

/* Load raw 32-byte client pubkeys from <dir>/*.pub into the allowlist.
 * Mirrors network_listener.c load_authorized(). */
static void ipc_tls_load_authorized(struct ps_ipc_tls *t, const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) {
        ps_info("ipc_server: authorized dir '%s' missing -- no TCP clients can connect", dir);
        return;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL && t->authorized_n < PS_IPC_MAX_AUTHORIZED) {
        size_t n = strlen(de->d_name);
        if (n < 5 || strcmp(de->d_name + n - 4, ".pub") != 0) continue;
        char p[1100]; snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        FILE *f = fopen(p, "rb");
        if (!f) continue;
        if (fread(t->authorized[t->authorized_n], 1,
                  PS_KEYSTORE_PUBKEY_SIZE, f) == PS_KEYSTORE_PUBKEY_SIZE) {
            t->authorized_n++;
        }
        fclose(f);
    }
    closedir(d);
    ps_info("ipc_server: %zu authorized client pubkey(s) loaded from %s",
            t->authorized_n, dir);
}

/* Is the connected peer's pubkey fingerprint in the allowlist? Walks the full
 * list even after a match so timing can't enumerate it. */
static int ipc_tls_is_authorized(struct ps_ipc_tls *t, SSL *ssl)
{
    char fpr[PS_KEYSTORE_FPR_HEX_SIZE];
    if (ps_at_peer_fingerprint(ssl, fpr, sizeof(fpr)) != 0) return 0;
    int matched = 0;
    for (size_t i = 0; i < t->authorized_n; i++) {
        char expected[PS_KEYSTORE_FPR_HEX_SIZE];
        ps_keystore_fingerprint(t->authorized[i], expected);
        if (strcmp(fpr, expected) == 0) matched = 1;
    }
    return matched;
}

/* ssl-aware client I/O. ssl==NULL -> plaintext fd. Returns >0 bytes, 0 on EOF,
 * -1 on a real error, or PS_IPC_WOULDBLOCK when the non-blocking socket has no
 * data ready (partial TLS record / EAGAIN). Callers must treat PS_IPC_WOULDBLOCK
 * as "retry later", NOT as a disconnect. */
static ssize_t ipc_client_read(struct ps_ipc_client *c, uint8_t *buf, size_t n)
{
    if (c->ssl) {
        int r = SSL_read((SSL *)c->ssl, buf, (int)n);
        if (r > 0) return (ssize_t)r;
        int err = SSL_get_error((SSL *)c->ssl, r);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            return PS_IPC_WOULDBLOCK;
        if (err == SSL_ERROR_ZERO_RETURN) return 0; /* clean TLS shutdown */
        return -1;
    }
    ssize_t r = read(c->fd, buf, n);
    if (r >= 0) return r;
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return PS_IPC_WOULDBLOCK;
    return -1;
}

/* Write the whole buffer; returns 0 on success, -1 on error (caller drops the
 * client). The client fd is non-blocking, so when its send buffer is full the
 * write returns EAGAIN / SSL_ERROR_WANT_WRITE; we wait briefly for it to drain
 * but bound the total wait so one slow or dead client can't freeze the
 * single-threaded server -- we give up and let the caller drop it instead. */
static int ipc_client_write_all(struct ps_ipc_client *c,
                                const uint8_t *buf, size_t n)
{
    size_t off = 0;
    int waits = 0;
    while (off < n) {
        if (c->ssl) {
            int r = SSL_write((SSL *)c->ssl, buf + off, (int)(n - off));
            if (r > 0) { off += (size_t)r; waits = 0; continue; }
            int err = SSL_get_error((SSL *)c->ssl, r);
            if (err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_READ)
                return -1;  /* real TLS error */
            /* socket buffer full -> fall through to the bounded drain wait */
        } else {
            ssize_t w = write(c->fd, buf + off, n - off);
            if (w > 0) { off += (size_t)w; waits = 0; continue; }
            if (w == 0) return -1;
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK) return -1;
        }
        if (++waits > PS_IPC_WRITE_MAX_WAITS) return -1; /* too slow -> drop */
        struct pollfd p = { .fd = c->fd, .events = POLLOUT };
        poll(&p, 1, PS_IPC_WRITE_POLL_MS);
    }
    return 0;
}

static struct ps_ipc_client *ipc_find_by_fd(struct ps_ipc_server *srv, int fd)
{
    for (int i = 0; i < PS_IPC_MAX_CLIENTS; i++)
        if (srv->clients[i].fd == fd) return &srv->clients[i];
    return NULL;
}

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

            /* Zero-length payload is valid — complete immediately. Reset only
             * the parse STATE for the next frame; preserve channel[]/payload[]
             * so the caller can read them (mirrors the PS_FRAME_PL_DATA path).
             * NOTE: must NOT call ps_frame_reader_reset() here -- it memsets
             * channel[], which would hand the callback an empty channel and
             * silently break every empty-payload request (query.hosts, etc.). */
            if (r->payload_len == 0) {
                if (r->payload) r->payload[0] = '\0';
                r->state       = PS_FRAME_CH_LEN;
                r->len_pos     = 0;
                r->channel_pos = 0;
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

    /* The Unix domain socket is optional. A TCP-only deployment (UE client over
     * mTLS TCP) passes a NULL/empty/"none" path to skip binding it entirely --
     * it's dead surface there. The poll loop already treats listen_fd == -1 as
     * "no unix listener", and a TCP listener is added separately via add_tcp. */
    if (!socket_path || !*socket_path ||
        strcmp(socket_path, "none") == 0 || strcmp(socket_path, "-") == 0) {
        ps_info("ipc_server: Unix domain socket disabled (TCP-only)");
        return 0;
    }

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

int ps_ipc_server_enable_tls(struct ps_ipc_server *srv)
{
    struct ps_ipc_tls *t = calloc(1, sizeof(*t));
    if (!t) {
        ps_error("ipc_server_enable_tls: calloc failed");
        return -1;
    }

    /* Keystore dir: PS_KEY_DIR, else the keystore default. */
    char kdir[1024];
    const char *kd = getenv("PS_KEY_DIR");
    if (kd && *kd) {
        snprintf(kdir, sizeof(kdir), "%s", kd);
    } else if (ps_keystore_default_dir(kdir, sizeof(kdir)) != 0) {
        ps_error("ipc_server_enable_tls: cannot resolve key dir");
        free(t);
        return -1;
    }

    const char *kname = getenv("PS_NETWORK_KEY");
    if (!kname || !*kname) kname = "agent";

    struct ps_keypair kp;
    if (ps_keystore_load(kdir, kname, &kp) != 0) {
        ps_error("ipc_server_enable_tls: cannot load key '%s' from %s", kname, kdir);
        free(t);
        return -1;
    }
    /* Need the secret half to present our own cert. */
    int has_sec = 0;
    for (size_t i = 0; i < PS_KEYSTORE_SECKEY_SIZE; i++)
        if (kp.seckey[i]) { has_sec = 1; break; }
    if (!has_sec) {
        ps_error("ipc_server_enable_tls: key '%s' is pubkey-only", kname);
        free(t);
        return -1;
    }

    /* Authorized client pubkeys. */
    char auth_dir[1100];
    const char *ad = getenv("PS_NETWORK_AUTHORIZED_DIR");
    if (ad && *ad) snprintf(auth_dir, sizeof(auth_dir), "%s", ad);
    else           snprintf(auth_dir, sizeof(auth_dir), "%s/authorized", kdir);
    ipc_tls_load_authorized(t, auth_dir);

    /* Don't die on a write to a half-closed TLS client. */
    ps_at_block_sigpipe();

    /* SERVER ctx with empty expected_fpr (NULL) -> accept any well-formed peer
     * cert in the handshake; the authorized-dir check runs post-handshake. */
    if (ps_at_ctx_init(&t->ctx, PS_AT_SERVER, &kp, NULL) != 0) {
        ps_error("ipc_server_enable_tls: ps_at_ctx_init failed");
        free(t);
        return -1;
    }

    srv->tls = t;
    char fpr[PS_KEYSTORE_FPR_HEX_SIZE];
    ps_keystore_fingerprint(kp.pubkey, fpr);
    ps_info("ipc_server: TCP mTLS enabled (identity sha256:%s, %zu authorized client(s))",
            fpr, t->authorized_n);
    return 0;
}

void ps_ipc_server_shutdown(struct ps_ipc_server *srv)
{
    for (int i = 0; i < PS_IPC_MAX_CLIENTS; i++) {
        if (srv->clients[i].fd >= 0) {
            ps_frame_reader_free(&srv->clients[i].reader);
            if (srv->clients[i].ssl) {
                ps_at_close((SSL *)srv->clients[i].ssl);  /* also closes the fd */
                srv->clients[i].ssl = NULL;
            } else {
                close(srv->clients[i].fd);
            }
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
    if (srv->tls) {
        ps_at_ctx_destroy(&srv->tls->ctx);
        free(srv->tls);
        srv->tls = NULL;
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

    /* Non-blocking so a stuck client can't block the agent on a broadcast write
     * (mirrors the TCP path). */
    {
        int fl = fcntl(cfd, F_GETFL, 0);
        if (fl >= 0) fcntl(cfd, F_SETFL, fl | O_NONBLOCK);
    }
    for (int i = 0; i < PS_IPC_MAX_CLIENTS; i++) {
        if (srv->clients[i].fd < 0) {
            srv->clients[i].fd          = cfd;
            srv->clients[i].ssl         = NULL;   /* Unix clients are plaintext */
            srv->clients[i].handshaking = 0;      /* no TLS handshake (clear any stale slot state) */
            srv->clients[i].hs_deadline = 0;
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
    if (srv->clients[slot].ssl) {
        ps_at_close((SSL *)srv->clients[slot].ssl);  /* also closes the fd */
        srv->clients[slot].ssl = NULL;
    } else {
        close(srv->clients[slot].fd);
    }
    srv->clients[slot].fd = -1;
    srv->clients[slot].handshaking = 0;
    srv->client_count--;
}

int ps_ipc_server_poll(struct ps_ipc_server *srv, int timeout_ms)
{
    /* Reap any handshake past its deadline (a stalled/half-open peer holding a slot). Runs every poll
     * call -- even idle ones (timeout 0 -> rc 0 returns early) -- so a stuck handshake can't leak a slot. */
    {
        long now = (long)time(NULL);
        for (int i = 0; i < PS_IPC_MAX_CLIENTS; i++) {
            if (srv->clients[i].fd >= 0 && srv->clients[i].handshaking && now >= srv->clients[i].hs_deadline) {
                ps_warn("ipc_server: TLS handshake timed out (slot %d)", i);
                ipc_drop_client(srv, i);
            }
        }
    }

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
            /* A handshaking client may be waiting to WRITE a handshake record, so poll both ways. */
            fds[nfds].events   = srv->clients[i].handshaking ? (short)(POLLIN | POLLOUT) : (short)POLLIN;
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

    /* Check TCP listen_fd for new connections. The mTLS handshake is NON-BLOCKING from accept: set the
     * fd non-blocking, BEGIN the handshake, and add the client in a HANDSHAKING state. The poll loop
     * below drives it (ps_at_accept_drive) as the fd signals, so one client's slow handshake never
     * freezes the single-threaded loop -- the agent keeps serving every other client meanwhile. */
    if (tcp_poll_idx >= 0 && (fds[tcp_poll_idx].revents & POLLIN)) {
        int cfd = accept(srv->tcp_listen_fd, NULL, NULL);
        if (cfd >= 0) {
            if (srv->client_count >= PS_IPC_MAX_CLIENTS) {
                ps_warn("ipc_server: max clients, rejecting TCP connection");
                close(cfd);
            } else {
                int fl = fcntl(cfd, F_GETFL, 0);
                if (fl >= 0) fcntl(cfd, F_SETFL, fl | O_NONBLOCK);

                void *ssl = NULL;
                int handshaking = 0;
                if (srv->tls) {
                    SSL *s = ps_at_accept_begin(&srv->tls->ctx, cfd);
                    if (!s) { ps_warn("ipc_server: ps_at_accept_begin failed"); close(cfd); cfd = -1; }
                    else { ssl = s; handshaking = 1; }
                }
                if (cfd >= 0) {
                    for (int i = 0; i < PS_IPC_MAX_CLIENTS; i++) {
                        if (srv->clients[i].fd < 0) {
                            srv->clients[i].fd          = cfd;
                            srv->clients[i].ssl         = ssl;
                            srv->clients[i].handshaking = handshaking;
                            srv->clients[i].hs_deadline = (long)time(NULL) + PS_IPC_TLS_IO_TIMEOUT_SEC;
                            ps_frame_reader_init(&srv->clients[i].reader);
                            srv->client_count++;
                            ps_info("ipc_server: TCP client %s (slot %d, fd %d%s)",
                                    handshaking ? "handshaking" : "connected", i, cfd, ssl ? ", mTLS" : "");
                            break;
                        }
                    }
                }
            }
        }
    }

    /* Check client fds */
    int client_poll_count = nfds - client_start_idx;
    for (int j = 0; j < client_poll_count; j++) {
        int pfd_idx = j + client_start_idx;
        int slot    = slot_map[j];
        struct ps_ipc_client *c = &srv->clients[slot];

        if (c->fd < 0) continue;  /* dropped earlier this pass */

        short re = fds[pfd_idx].revents;
        if (re & (POLLHUP | POLLERR)) {
            ipc_drop_client(srv, slot);
            continue;
        }

        /* Drive an in-progress mTLS handshake incrementally (never read app data while handshaking).
         * One client advancing its handshake here does not block the others -- each gets its turn as
         * its fd signals. On completion, enforce the authorized-pubkey allowlist before going live. */
        if (c->handshaking) {
            if (re & (POLLIN | POLLOUT)) {
                int hr = ps_at_accept_drive(&srv->tls->ctx, (SSL *)c->ssl);
                if (hr == 1) {
                    if (!ipc_tls_is_authorized(srv->tls, (SSL *)c->ssl)) {
                        ps_warn("ipc_server: rejected TCP client; pubkey not authorized (slot %d)", slot);
                        ipc_drop_client(srv, slot);
                        continue;
                    }
                    c->handshaking = 0;
                    ps_info("ipc_server: TCP client connected (slot %d, fd %d, mTLS)", slot, c->fd);
                } else if (hr < 0) {
                    ps_warn("ipc_server: TCP TLS handshake failed (slot %d)", slot);
                    ipc_drop_client(srv, slot);
                    continue;
                }
                /* hr == 0: still in progress -- wait for the next signal */
            }
            continue;
        }

        /* Service when the socket is readable OR the TLS layer already has
         * decrypted bytes buffered. The latter is essential: with TLS 1.3 the
         * client's first app-data record can be coalesced into the same TCP
         * segment as its handshake Finished and consumed by SSL_accept, so the
         * socket looks empty and poll() never flags it -- but SSL_pending() is
         * non-zero. Without this check that first frame (e.g. query.hosts)
         * would sit unread forever. */
        int pending = (c->ssl && SSL_pending((SSL *)c->ssl) > 0);
        if (!(re & POLLIN) && !pending)
            continue;

        /* Drain: one read for plaintext (poll is level-triggered and will
         * re-signal), and keep reading while the TLS layer still buffers data. */
        int dropped = 0;
        do {
            uint8_t read_buf[4096];
            ssize_t n = ipc_client_read(c, read_buf, sizeof(read_buf));
            if (n == PS_IPC_WOULDBLOCK) break;  /* no data ready; wait for poll */
            if (n <= 0) {
                ipc_drop_client(srv, slot);
                dropped = 1;
                break;
            }
            for (ssize_t k = 0; k < n; k++) {
                int fr = ps_frame_reader_feed(&c->reader, read_buf[k]);
                if (fr == 1) {
                    /* Complete frame — invoke callback (reader self-resets) */
                    if (srv->on_frame) {
                        srv->on_frame(c->fd, c->reader.channel,
                                      c->reader.payload, c->reader.payload_len,
                                      srv->userdata);
                    }
                } else if (fr < 0) {
                    ps_warn("ipc_server: frame error on slot %d, dropping client", slot);
                    ipc_drop_client(srv, slot);
                    dropped = 1;
                    break;
                }
            }
        } while (!dropped && c->fd >= 0 && c->ssl && SSL_pending((SSL *)c->ssl) > 0);
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
        if (ipc_client_write_all(&srv->clients[i], buf, (size_t)frame_len) != 0) {
            ps_warn("ipc_server_broadcast: write to slot %d failed", i);
            ipc_drop_client(srv, i);
        } else {
            sent++;
        }
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

    /* Route through the client slot so TLS clients go via SSL_write. The fd
     * comes from the on_frame callback, so the slot is normally live; fall
     * back to a plaintext write if it has already been dropped. */
    struct ps_ipc_client *c = ipc_find_by_fd(srv, client_fd);
    int rc;
    if (c) {
        rc = ipc_client_write_all(c, buf, (size_t)frame_len);
    } else {
        struct ps_ipc_client tmp = { .fd = client_fd, .ssl = NULL };
        rc = ipc_client_write_all(&tmp, buf, (size_t)frame_len);
    }

    free(buf);
    if (rc != 0) {
        ps_warn("ipc_server_send_to: write to fd %d failed", client_fd);
        return -1;
    }
    return 1;
}
