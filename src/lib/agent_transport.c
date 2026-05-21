#include "agent_transport.h"
#include "keystore.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* ---- Self-signed X.509 from an Ed25519 keypair --------------------- */

/* Build an EVP_PKEY from the keystore's raw seed + pubkey. OpenSSL's raw
 * Ed25519 secret is the 32-byte seed (matches keystore.h on disk). */
static EVP_PKEY *evp_from_keypair(const struct ps_keypair *kp) {
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                        kp->seckey, PS_KEYSTORE_SECKEY_SIZE);
}

/* Self-signed cert valid for 100 years. Subject/issuer carry no useful
 * information -- we identify by the pubkey hash. The cert is just a
 * carrier for the pubkey inside the TLS handshake. */
static X509 *make_self_signed(EVP_PKEY *id_key) {
    X509 *c = X509_new();
    if (!c) return NULL;
    X509_set_version(c, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(c), 1);

    X509_NAME *n = X509_NAME_new();
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
                               (const uint8_t *)"packetsonde", -1, -1, 0);
    X509_set_subject_name(c, n);
    X509_set_issuer_name (c, n);
    X509_NAME_free(n);

    X509_gmtime_adj(X509_getm_notBefore(c), 0);
    X509_gmtime_adj(X509_getm_notAfter (c), 60L * 60 * 24 * 365 * 100);

    X509_set_pubkey(c, id_key);

    /* Ed25519 X.509 signatures use NULL message digest. */
    if (X509_sign(c, id_key, NULL) == 0) {
        X509_free(c);
        return NULL;
    }
    return c;
}

/* ---- Peer pubkey hash --------------------------------------------- */

/* SHA-256 of the peer's 32-byte raw Ed25519 pubkey, hex-encoded. */
static int sha256_pubkey_hex(EVP_PKEY *pk, char *out_hex, size_t out_cap) {
    if (out_cap < PS_KEYSTORE_FPR_HEX_SIZE) return -1;
    uint8_t raw[PS_KEYSTORE_PUBKEY_SIZE];
    size_t rl = sizeof(raw);
    if (EVP_PKEY_get_raw_public_key(pk, raw, &rl) != 1) return -1;
    if (rl != PS_KEYSTORE_PUBKEY_SIZE) return -1;
    return ps_keystore_fingerprint(raw, out_hex);
}

/* ---- TLS verify callback ------------------------------------------- */
/*
 * Strategy: tell OpenSSL to skip its built-in chain validation (which
 * would fail because the peer's cert is self-signed and not in any
 * trust store) by returning 1 from the verify_cb. We then do the *real*
 * verification at the end of the handshake by comparing the peer's
 * pubkey hash against the expected fingerprint that the caller pinned
 * on the SSL via SSL_set_ex_data.
 */

static int verify_accept_all(int preverify_ok, X509_STORE_CTX *ctx) {
    (void)preverify_ok; (void)ctx;
    return 1; /* defer everything to the post-handshake fingerprint check */
}

/* ---- ssize_t shims so SSL_read/write match the ps_ap_io callbacks --- */

static ssize_t io_ssl_read(void *ctx, void *buf, size_t n) {
    int r = SSL_read((SSL *)ctx, buf, (int)n);
    if (r > 0) return r;
    int err = SSL_get_error((SSL *)ctx, r);
    if (err == SSL_ERROR_ZERO_RETURN) return 0; /* peer close_notify */
    return -1;
}

static ssize_t io_ssl_write(void *ctx, const void *buf, size_t n) {
    int w = SSL_write((SSL *)ctx, buf, (int)n);
    return w > 0 ? w : -1;
}

void ps_at_make_io(SSL *ssl, struct ps_ap_io *out) {
    out->read  = io_ssl_read;
    out->write = io_ssl_write;
    out->ctx   = ssl;
}

/* ---- Public API ---------------------------------------------------- */

int ps_at_ctx_init(struct ps_at_ctx *out,
                   enum ps_at_side side,
                   const struct ps_keypair *kp,
                   const char *expected_peer_fpr) {
    /* Writes against a half-closed TLS connection would otherwise raise
     * SIGPIPE and kill the process. The CLI and agent both have nontrivial
     * cleanup paths we'd rather run. */
    static int sigpipe_blocked = 0;
    if (!sigpipe_blocked) { signal(SIGPIPE, SIG_IGN); sigpipe_blocked = 1; }
    memset(out, 0, sizeof(*out));
    out->side = side;
    if (expected_peer_fpr && *expected_peer_fpr) {
        snprintf(out->expected_fpr, sizeof(out->expected_fpr),
                 "%s", expected_peer_fpr);
    }

    const SSL_METHOD *method = (side == PS_AT_SERVER)
        ? TLS_server_method() : TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) return -1;
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    EVP_PKEY *id = evp_from_keypair(kp);
    if (!id) { SSL_CTX_free(ctx); return -1; }
    X509 *cert = make_self_signed(id);
    if (!cert) { EVP_PKEY_free(id); SSL_CTX_free(ctx); return -1; }
    if (SSL_CTX_use_certificate(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey (ctx, id)   != 1) {
        X509_free(cert); EVP_PKEY_free(id); SSL_CTX_free(ctx);
        return -1;
    }
    /* Both objects are refcounted; SSL_CTX took its ref. */
    X509_free(cert);
    EVP_PKEY_free(id);

    /* Require client cert in both directions (mTLS). */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify_accept_all);
    SSL_CTX_set_verify_depth(ctx, 1);

    out->ssl_ctx = ctx;
    return 0;
}

void ps_at_ctx_destroy(struct ps_at_ctx *ctx) {
    if (ctx && ctx->ssl_ctx) {
        SSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
    }
}

int ps_at_peer_fingerprint(SSL *ssl, char *out_hex, size_t out_cap) {
    X509 *peer = SSL_get_peer_certificate(ssl);
    if (!peer) return -1;
    EVP_PKEY *pk = X509_get_pubkey(peer);
    int rc = pk ? sha256_pubkey_hex(pk, out_hex, out_cap) : -1;
    if (pk) EVP_PKEY_free(pk);
    X509_free(peer);
    return rc;
}

/* ---- After the handshake, enforce the pinned fingerprint (if any). */
static int enforce_pin(struct ps_at_ctx *ctx, SSL *ssl) {
    if (ctx->expected_fpr[0] == '\0') return 0; /* no pin set; caller will check */
    char got[PS_KEYSTORE_FPR_HEX_SIZE];
    if (ps_at_peer_fingerprint(ssl, got, sizeof(got)) != 0) return -1;
    return (strcmp(got, ctx->expected_fpr) == 0) ? 0 : -1;
}

/* ---- TCP connect helper ------------------------------------------- */

static int tcp_connect(const char *host, uint16_t port) {
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    int fd = -1;
    for (struct addrinfo *r = res; r; r = r->ai_next) {
        fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, r->ai_addr, r->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

SSL *ps_at_connect(struct ps_at_ctx *ctx, const char *host, uint16_t port) {
    int fd = tcp_connect(host, port);
    if (fd < 0) return NULL;
    SSL *ssl = SSL_new(ctx->ssl_ctx);
    if (!ssl) { close(fd); return NULL; }
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1 || enforce_pin(ctx, ssl) != 0) {
        SSL_free(ssl); close(fd); return NULL;
    }
    return ssl;
}

SSL *ps_at_accept(struct ps_at_ctx *ctx, int listen_fd) {
    struct sockaddr_storage ss; socklen_t sl = sizeof(ss);
    int fd = accept(listen_fd, (struct sockaddr *)&ss, &sl);
    if (fd < 0) return NULL;
    SSL *ssl = SSL_new(ctx->ssl_ctx);
    if (!ssl) { close(fd); return NULL; }
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) != 1 || enforce_pin(ctx, ssl) != 0) {
        SSL_free(ssl); close(fd); return NULL;
    }
    return ssl;
}

void ps_at_close(SSL *ssl) {
    if (!ssl) return;
    int fd = SSL_get_fd(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    if (fd >= 0) close(fd);
}
