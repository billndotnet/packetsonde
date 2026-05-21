#ifndef PS_AGENT_TRANSPORT_H
#define PS_AGENT_TRANSPORT_H

/*
 * Agent network protocol -- TLS 1.3 transport with Ed25519 cert auth.
 *
 * Both sides present a self-signed X.509 cert whose key is the long-term
 * Ed25519 identity from the keystore (the same key used for discovery).
 * Peer identity is established post-handshake by hashing the peer's
 * SubjectPublicKeyInfo and matching it against a pinned fingerprint
 * carried in agents.toml (client) or the authorized-keys directory
 * (server).
 *
 * We deliberately do not use a CA: there is no PKI, no rotation, no
 * revocation list. Identity = pubkey, lifecycle = whoever owns the
 * keystore. This matches the SSH-style trust model the project commits
 * to in the brainstorm memo.
 *
 * TLS only does framing + AEAD here. All authentication decisions live
 * in the verify callback that compares fingerprints.
 */

#include "agent_proto.h"
#include "keystore.h"

#include <openssl/ssl.h>
#include <stddef.h>
#include <stdint.h>

#define PS_AT_FPR_SIZE  PS_KEYSTORE_FPR_HEX_SIZE  /* 65 incl. NUL */

/* Side-of-channel. Server mode requires SSL_VERIFY_PEER to make mTLS
 * unconditional; client mode requires the same. */
enum ps_at_side { PS_AT_CLIENT = 0, PS_AT_SERVER = 1 };

struct ps_at_ctx {
    SSL_CTX        *ssl_ctx;
    enum ps_at_side side;
    /* Buffer for the expected-peer fingerprint, NUL-terminated SHA-256
     * hex of the peer's pubkey. Empty string means "accept any peer
     * whose fingerprint appears in authorized_dir" (server) or "TOFU
     * the first cert we see and just verify it's well-formed" (client).
     * v1 requires the field be set on both sides. */
    char            expected_fpr[PS_AT_FPR_SIZE];
};

/* Set up a SSL_CTX wired for self-signed Ed25519 mTLS. The caller-supplied
 * keypair becomes our X.509 identity. If `expected_peer_fpr` is non-NULL
 * and non-empty, only a peer presenting that exact SHA-256 SPKI hex string
 * will pass the verify callback.
 *
 * Returns 0 on success, -1 on any OpenSSL failure. On success, the caller
 * owns out->ssl_ctx and must free with SSL_CTX_free when done. */
int  ps_at_ctx_init(struct ps_at_ctx *out,
                    enum ps_at_side side,
                    const struct ps_keypair *kp,
                    const char *expected_peer_fpr);

void ps_at_ctx_destroy(struct ps_at_ctx *ctx);

/* Connect to host:port over TCP, perform the TLS handshake, validate the
 * peer's pubkey fingerprint. Returns a connected SSL* on success, NULL on
 * failure. On success the caller owns the SSL* and must call ps_at_close. */
SSL *ps_at_connect(struct ps_at_ctx *ctx, const char *host, uint16_t port);

/* Accept one TLS connection on an already-bound, listening TCP socket.
 * Returns a connected SSL* on success, NULL on failure. The accepted
 * peer's pubkey fingerprint is checked against ctx->expected_fpr (which
 * may be a single-peer pin) -- callers that need a multi-peer allowlist
 * can leave expected_fpr empty in the ctx and call ps_at_peer_fingerprint
 * after the handshake to consult their own authorized set. */
SSL *ps_at_accept(struct ps_at_ctx *ctx, int listen_fd);

/* Fingerprint of the connected peer's pubkey, written as sha256:<64 hex>.
 * Returns 0 on success. */
int  ps_at_peer_fingerprint(SSL *ssl, char *out_hex, size_t out_cap);

/* Wrap an SSL* in the agent_proto I/O abstraction so framing code can use
 * it. The returned struct's `ctx` field points at `ssl`; do not free until
 * all framed I/O is done. */
void ps_at_make_io(SSL *ssl, struct ps_ap_io *out);

/* Send TLS close_notify, free the SSL, close the underlying fd. */
void ps_at_close(SSL *ssl);

#endif
