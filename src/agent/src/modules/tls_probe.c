/*
 * tls_probe.c — TLS ClientHello handshake inspector for PacketSonde Agent
 *
 * Performs a full TLS handshake to a target host:port and extracts:
 *   - Negotiated TLS version (e.g. "TLSv1.3")
 *   - Certificate CN from subject
 *   - SAN list from X.509 extensions
 *   - Negotiated ALPN protocol (e.g. "h2", "http/1.1")
 *
 * Triggered by the "probe.request" IPC channel with proto == "tls".
 * Probe runs synchronously in on_job (blocking, 5s connect + 5s handshake).
 *
 * Output channel: probe.result
 *   {
 *     "job_id": "...",
 *     "address": "1.2.3.4",
 *     "port": 443,
 *     "proto": "tcp",
 *     "state": "open",
 *     "tls": {
 *       "version": "TLSv1.3",
 *       "cert_cn": "*.example.com",
 *       "cert_san": ["*.example.com", "example.com"],
 *       "alpn": ["h2"]
 *     }
 *   }
 *
 * Compiled only when HAVE_OPENSSL is defined (OpenSSL or LibreSSL present).
 */

#ifdef HAVE_OPENSSL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#include "packetsonde/module_api.h"
#include "json.h"
#include "log.h"

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define TLS_PROBE_CONNECT_TIMEOUT_SEC  5
#define TLS_PROBE_HANDSHAKE_TIMEOUT_SEC 5
#define TLS_PROBE_DEFAULT_PORT         443
#define TLS_PROBE_CN_MAX               256
#define TLS_PROBE_SAN_MAX              32
#define TLS_PROBE_SAN_LEN              256

/* ALPN wire format: length-prefixed protocol list */
/* "h2" (2 bytes) + "http/1.1" (8 bytes) + 2 length bytes = 12 bytes */
static const unsigned char TLS_ALPN_PROTOS[] = {
    2, 'h', '2',
    8, 'h', 't', 't', 'p', '/', '1', '.', '1'
};

/* ------------------------------------------------------------------ */
/* Module state                                                         */
/* ------------------------------------------------------------------ */

struct tls_probe_state {
    SSL_CTX *ctx;
};

/* ------------------------------------------------------------------ */
/* TCP connect with timeout                                             */
/* ------------------------------------------------------------------ */

/*
 * Create a non-blocking TCP socket and connect to addr:port.
 * Times out after timeout_sec seconds.
 * Returns the connected (blocking) socket fd on success, -1 on failure.
 */
static int tls_tcp_connect(const struct sockaddr_in *sa, int timeout_sec)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;

    /* Set non-blocking for the connect phase */
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) { close(s); return -1; }
    if (fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0) { close(s); return -1; }

    int rc = connect(s, (const struct sockaddr *)sa, sizeof(*sa));
    if (rc < 0 && errno != EINPROGRESS) {
        close(s);
        return -1;
    }

    /* Wait for connect to complete */
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(s, &wfds);

    struct timeval tv;
    tv.tv_sec  = timeout_sec;
    tv.tv_usec = 0;

    rc = select(s + 1, NULL, &wfds, NULL, &tv);
    if (rc <= 0) {
        /* Timeout or error */
        close(s);
        return -1;
    }

    /* Check for connect error */
    int err = 0;
    socklen_t errlen = sizeof(err);
    getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errlen);
    if (err != 0) {
        close(s);
        return -1;
    }

    /* Restore blocking mode for SSL */
    if (fcntl(s, F_SETFL, flags) < 0) { close(s); return -1; }

    return s;
}

/* ------------------------------------------------------------------ */
/* TLS handshake with timeout                                           */
/* ------------------------------------------------------------------ */

/*
 * Perform SSL_connect() with a select()-based timeout.
 * Returns 0 on success, -1 on timeout/error.
 */
static int tls_do_handshake(SSL *ssl, int sock_fd, int timeout_sec)
{
    /* Set non-blocking during handshake so we can timeout */
    int flags = fcntl(sock_fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK);

    int deadline_loops = timeout_sec * 100;   /* 10ms ticks × 100 = 1s per loop */
    int loops = 0;

    while (loops < deadline_loops) {
        int rc = SSL_connect(ssl);
        if (rc == 1) {
            /* Handshake complete — restore blocking */
            if (flags >= 0) fcntl(sock_fd, F_SETFL, flags);
            return 0;
        }

        int ssl_err = SSL_get_error(ssl, rc);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            fd_set rfds, wfds;
            FD_ZERO(&rfds);
            FD_ZERO(&wfds);
            if (ssl_err == SSL_ERROR_WANT_READ)  FD_SET(sock_fd, &rfds);
            if (ssl_err == SSL_ERROR_WANT_WRITE) FD_SET(sock_fd, &wfds);

            struct timeval tv;
            tv.tv_sec  = 0;
            tv.tv_usec = 10000;   /* 10ms */

            int sr = select(sock_fd + 1, &rfds, &wfds, NULL, &tv);
            if (sr < 0) break;
            loops++;
            continue;
        }

        /* Fatal SSL error */
        break;
    }

    if (flags >= 0) fcntl(sock_fd, F_SETFL, flags);
    return -1;
}

/* ------------------------------------------------------------------ */
/* Certificate extraction                                               */
/* ------------------------------------------------------------------ */

/*
 * Extract the Common Name from the certificate subject.
 * cn_out must be at least TLS_PROBE_CN_MAX bytes.
 */
static void extract_cert_cn(X509 *cert, char *cn_out, size_t cn_len)
{
    cn_out[0] = '\0';
    if (!cert) return;

    X509_NAME *subject = X509_get_subject_name(cert);
    if (!subject) return;

    int idx = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    if (idx < 0) return;

    X509_NAME_ENTRY *entry = X509_NAME_get_entry(subject, idx);
    if (!entry) return;

    ASN1_STRING *asn1 = X509_NAME_ENTRY_get_data(entry);
    if (!asn1) return;

    /* ASN1_STRING_get0_data returns UTF-8 bytes (or whatever encoding) */
    const unsigned char *data = ASN1_STRING_get0_data(asn1);
    int len = ASN1_STRING_length(asn1);
    if (len <= 0) return;

    size_t copy_len = (size_t)len < cn_len - 1 ? (size_t)len : cn_len - 1;
    memcpy(cn_out, data, copy_len);
    cn_out[copy_len] = '\0';
}

/*
 * Extract SAN (Subject Alternative Name) DNS entries from the certificate.
 * san_list: array of TLS_PROBE_SAN_MAX char[TLS_PROBE_SAN_LEN] buffers.
 * Returns count of SANs extracted.
 */
static int extract_cert_sans(X509 *cert,
                              char san_list[][TLS_PROBE_SAN_LEN],
                              int max_sans)
{
    if (!cert) return 0;

    GENERAL_NAMES *sans = (GENERAL_NAMES *)X509_get_ext_d2i(
        cert, NID_subject_alt_name, NULL, NULL);
    if (!sans) return 0;

    int count = 0;
    int num = sk_GENERAL_NAME_num(sans);

    for (int i = 0; i < num && count < max_sans; i++) {
        GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
        if (!gn) continue;
        if (gn->type != GEN_DNS) continue;

        ASN1_STRING *asn1 = gn->d.dNSName;
        if (!asn1) continue;

        const unsigned char *data = ASN1_STRING_get0_data(asn1);
        int len = ASN1_STRING_length(asn1);
        if (len <= 0) continue;

        size_t copy_len = (size_t)len < TLS_PROBE_SAN_LEN - 1
                        ? (size_t)len
                        : TLS_PROBE_SAN_LEN - 1;
        memcpy(san_list[count], data, copy_len);
        san_list[count][copy_len] = '\0';
        count++;
    }

    GENERAL_NAMES_free(sans);
    return count;
}

/* ------------------------------------------------------------------ */
/* Publishing                                                           */
/* ------------------------------------------------------------------ */

static void publish_result(ps_module_ctx_t *ctx,
                            const char *job_id,
                            const char *address,
                            int port,
                            const char *state,
                            const char *tls_version,
                            const char *cert_cn,
                            char san_list[][TLS_PROBE_SAN_LEN],
                            int san_count,
                            const char *alpn)
{
    char buf[2048];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "job_id",  job_id);
    ps_json_key_string(&j, "address", address);
    ps_json_key_int   (&j, "port",    (int64_t)port);
    ps_json_key_string(&j, "proto",   "tcp");
    ps_json_key_string(&j, "state",   state);

    if (tls_version || cert_cn || san_count > 0 || alpn) {
        /* "tls": { ... } sub-object, built inline on j via key_object_begin. */
        ps_json_key_object_begin(&j, "tls");
        if (tls_version && tls_version[0])
            ps_json_key_string(&j, "version", tls_version);
        if (cert_cn && cert_cn[0])
            ps_json_key_string(&j, "cert_cn", cert_cn);
        if (san_count > 0) {
            ps_json_array_begin(&j, "cert_san");
            for (int i = 0; i < san_count; i++)
                ps_json_array_string(&j, san_list[i]);
            ps_json_array_end(&j);
        }
        if (alpn && alpn[0]) {
            ps_json_array_begin(&j, "alpn");
            ps_json_array_string(&j, alpn);
            ps_json_array_end(&j);
        }
        ps_json_object_end(&j);  /* close "tls" */
    }

    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0)
        ctx->publish(ctx, "probe.result", buf, (uint32_t)j.len);
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int tls_init(ps_module_ctx_t *ctx)
{
    struct tls_probe_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("tls_probe: out of memory");
        return -1;
    }

    /* Initialize OpenSSL */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                     OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    st->ctx = SSL_CTX_new(TLS_client_method());
    if (!st->ctx) {
        ps_error("tls_probe: SSL_CTX_new failed");
        free(st);
        return -1;
    }

    /* Don't verify peer certs — we want to inspect even self-signed */
    SSL_CTX_set_verify(st->ctx, SSL_VERIFY_NONE, NULL);

    /* Set ALPN protos: h2, http/1.1 */
    if (SSL_CTX_set_alpn_protos(st->ctx,
                                 TLS_ALPN_PROTOS,
                                 sizeof(TLS_ALPN_PROTOS)) != 0) {
        ps_warn("tls_probe: SSL_CTX_set_alpn_protos failed");
    }

    ctx->userdata = st;
    ps_info("tls_probe: initialized (OpenSSL %s)", OpenSSL_version(OPENSSL_VERSION));
    return 0;
}

static void tls_shutdown(ps_module_ctx_t *ctx)
{
    struct tls_probe_state *st = (struct tls_probe_state *)ctx->userdata;
    if (!st) return;

    if (st->ctx) {
        SSL_CTX_free(st->ctx);
        st->ctx = NULL;
    }

    free(st);
    ctx->userdata = NULL;
    ps_info("tls_probe: shutdown");
}

static int tls_on_job(ps_module_ctx_t *ctx, const struct ps_job *job)
{
    struct tls_probe_state *st = (struct tls_probe_state *)ctx->userdata;
    if (!st || !st->ctx) return -1;

    /* Only handle "tls" method */
    if (job->method[0] != '\0' && strcmp(job->method, "tls") != 0)
        return 0;   /* not for us */

    int port = job->tcp_port > 0 ? job->tcp_port : TLS_PROBE_DEFAULT_PORT;

    /* Resolve destination (IPv4 only) */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(job->destination, NULL, &hints, &res);
    if (rc != 0) {
        ps_warn("tls_probe: getaddrinfo('%s') failed: %s",
                job->destination, gai_strerror(rc));
        publish_result(ctx, job->job_id, job->destination, port,
                       "error", NULL, NULL, NULL, 0, NULL);
        return -1;
    }

    struct sockaddr_in sa;
    memcpy(&sa, res->ai_addr, sizeof(sa));
    sa.sin_port = htons((uint16_t)port);

    char addr_str[64];
    inet_ntop(AF_INET, &sa.sin_addr, addr_str, sizeof(addr_str));
    freeaddrinfo(res);

    ps_info("tls_probe: job '%s' → %s:%d", job->job_id, addr_str, port);

    /* TCP connect */
    int sock = tls_tcp_connect(&sa, TLS_PROBE_CONNECT_TIMEOUT_SEC);
    if (sock < 0) {
        ps_info("tls_probe: job '%s' TCP connect failed → closed/filtered",
                job->job_id);
        publish_result(ctx, job->job_id, addr_str, port,
                       "closed", NULL, NULL, NULL, 0, NULL);
        return 0;
    }

    /* Create SSL object */
    SSL *ssl = SSL_new(st->ctx);
    if (!ssl) {
        ps_warn("tls_probe: SSL_new failed for job '%s'", job->job_id);
        close(sock);
        publish_result(ctx, job->job_id, addr_str, port,
                       "error", NULL, NULL, NULL, 0, NULL);
        return -1;
    }

    SSL_set_fd(ssl, sock);

    /* SNI: use the original hostname (not the resolved IP) */
    if (job->destination[0] != '\0') {
        SSL_set_tlsext_host_name(ssl, job->destination);
    }

    /* TLS handshake with timeout */
    rc = tls_do_handshake(ssl, sock, TLS_PROBE_HANDSHAKE_TIMEOUT_SEC);
    if (rc < 0) {
        ps_info("tls_probe: job '%s' TLS handshake failed", job->job_id);
        SSL_free(ssl);
        close(sock);
        publish_result(ctx, job->job_id, addr_str, port,
                       "tls_failed", NULL, NULL, NULL, 0, NULL);
        return 0;
    }

    /* ---- Extract TLS metadata ---- */

    /* TLS version */
    const char *tls_version = SSL_get_version(ssl);

    /* Certificate CN and SANs */
    char cert_cn[TLS_PROBE_CN_MAX] = {0};
    char san_list[TLS_PROBE_SAN_MAX][TLS_PROBE_SAN_LEN];
    int  san_count = 0;

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        extract_cert_cn(cert, cert_cn, sizeof(cert_cn));
        san_count = extract_cert_sans(cert, san_list, TLS_PROBE_SAN_MAX);
        X509_free(cert);
    } else {
        ps_debug("tls_probe: job '%s' — no peer certificate", job->job_id);
    }

    /* Negotiated ALPN */
    const unsigned char *alpn_data = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(ssl, &alpn_data, &alpn_len);

    char alpn_str[64] = {0};
    if (alpn_data && alpn_len > 0 && alpn_len < sizeof(alpn_str)) {
        memcpy(alpn_str, alpn_data, alpn_len);
        alpn_str[alpn_len] = '\0';
    }

    ps_info("tls_probe: job '%s' %s:%d → open ver=%s cn='%s' sans=%d alpn='%s'",
            job->job_id, addr_str, port,
            tls_version ? tls_version : "?",
            cert_cn,
            san_count,
            alpn_str[0] ? alpn_str : "(none)");

    publish_result(ctx, job->job_id, addr_str, port,
                   "open",
                   tls_version,
                   cert_cn[0] ? cert_cn : NULL,
                   san_count > 0 ? san_list : NULL,
                   san_count,
                   alpn_str[0] ? alpn_str : NULL);

    /* Clean up */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

const ps_module_t ps_tls_probe_module = {
    .name        = "tls_probe",
    .description = "TLS handshake inspection — cert, ALPN, and TLS version extraction",
    .version     = "1.0",
    .flags       = PS_MOD_ACTIVE,

    .init        = tls_init,
    .shutdown    = tls_shutdown,
    .on_packet   = NULL,
    .on_job      = tls_on_job,
    .on_response = NULL,
    .tick        = NULL,
};

#endif /* HAVE_OPENSSL */
