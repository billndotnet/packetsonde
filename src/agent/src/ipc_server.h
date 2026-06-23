#ifndef PS_IPC_SERVER_H
#define PS_IPC_SERVER_H

#include <stdint.h>
#include <stddef.h>

#define PS_IPC_MAX_CHANNEL  128
#define PS_IPC_MAX_PAYLOAD  (256 * 1024)
#define PS_IPC_MAX_CLIENTS  8

int ps_ipc_encode_frame(uint8_t *buf, size_t bufsz,
                        const char *channel,
                        const char *payload, uint32_t payload_len);

enum ps_frame_state {
    PS_FRAME_CH_LEN,
    PS_FRAME_CH_DATA,
    PS_FRAME_PL_LEN,
    PS_FRAME_PL_DATA
};

struct ps_frame_reader {
    enum ps_frame_state state;
    uint8_t  len_buf[4];
    int      len_pos;
    char     channel[PS_IPC_MAX_CHANNEL];
    uint32_t channel_len;
    uint32_t channel_pos;
    char    *payload;
    uint32_t payload_len;
    uint32_t payload_pos;
    uint32_t payload_cap;
};

void ps_frame_reader_init(struct ps_frame_reader *r);
void ps_frame_reader_free(struct ps_frame_reader *r);
void ps_frame_reader_reset(struct ps_frame_reader *r);
int  ps_frame_reader_feed(struct ps_frame_reader *r, uint8_t byte);

struct ps_ipc_client {
    int fd;
    struct ps_frame_reader reader;
    void *ssl;   /* SSL* when this client arrived over the mTLS TCP listener;
                  * NULL for plaintext (Unix socket or non-TLS TCP). Opaque
                  * here so the header stays free of <openssl/ssl.h>. */
};

typedef void (*ps_ipc_on_frame_fn)(int client_fd, const char *channel,
                                    const char *payload, uint32_t payload_len,
                                    void *userdata);

/* TLS state for the TCP listener; opaque (defined in ipc_server.c so the
 * header pulls in no OpenSSL / keystore types). NULL = plaintext TCP. */
struct ps_ipc_tls;

struct ps_ipc_server {
    int listen_fd;      /* AF_UNIX listener (-1 if not used) */
    int tcp_listen_fd;  /* AF_INET TCP listener (-1 if not used) */
    struct ps_ipc_client clients[PS_IPC_MAX_CLIENTS];
    int client_count;
    ps_ipc_on_frame_fn on_frame;
    void *userdata;
    struct ps_ipc_tls *tls;  /* when set, TCP clients must complete an mTLS
                              * handshake and present an authorized pubkey */
};

/** Initialize with a Unix domain socket (local IPC). */
int  ps_ipc_server_init(struct ps_ipc_server *srv, const char *socket_path,
                         ps_ipc_on_frame_fn on_frame, void *userdata);

/** Add a TCP listener on the given address and port (e.g., "0.0.0.0", 4701).
 *  Can be called after init to run both Unix + TCP simultaneously.
 *  Returns 0 on success, -1 on error. */
int  ps_ipc_server_add_tcp(struct ps_ipc_server *srv,
                            const char *bind_addr, int port);

/** Require mTLS on the TCP listener: every TCP client must complete a TLS 1.3
 *  handshake with a self-signed Ed25519 cert and present a pubkey whose
 *  fingerprint appears in the authorized-keys directory. The channel/payload
 *  wire protocol is unchanged -- it just runs inside the TLS tunnel.
 *
 *  Identity + allowlist are resolved from the environment (matching the
 *  network_listener module so operators configure keys once):
 *    PS_KEY_DIR                 keystore dir (else keystore default dir)
 *    PS_NETWORK_KEY             agent keypair name (default "agent")
 *    PS_NETWORK_AUTHORIZED_DIR  client pubkey dir (default <keydir>/authorized)
 *
 *  Call after ps_ipc_server_add_tcp(). Returns 0 on success, -1 on error
 *  (missing/!secret key, ctx init failure). On failure the TCP listener is
 *  left plaintext; the caller decides whether that is fatal. */
int  ps_ipc_server_enable_tls(struct ps_ipc_server *srv);

void ps_ipc_server_shutdown(struct ps_ipc_server *srv);
int  ps_ipc_server_poll(struct ps_ipc_server *srv, int timeout_ms);
int  ps_ipc_server_broadcast(struct ps_ipc_server *srv,
                              const char *channel,
                              const char *payload, uint32_t payload_len);
int  ps_ipc_server_send_to(struct ps_ipc_server *srv, int client_fd,
                            const char *channel,
                            const char *payload, uint32_t payload_len);

#endif
