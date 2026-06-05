#ifndef PS_TLS_PROBE_H
#define PS_TLS_PROBE_H
/*
 * Shared TLS handshake + fingerprint + leaf-cert primitive.
 *
 * Factored out of src/cli/audit/tls.c so both the `audit tls` verb and the
 * recipe engine's TLS opcodes (TLS_UPGRADE / TLS_ENUM) drive one hardened
 * implementation. Library layer: self-contained TCP connect, no audit deps.
 */
#include <stddef.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

/* ---- low-level handshake (used by `audit tls` and ps_tls_probe) ---------- */

struct ps_tls_attempt {
    const SSL_METHOD *method;       /* NULL = TLS_client_method() */
    long              min_proto;    /* 0 = library default */
    long              max_proto;
    const char       *cipher_list;  /* NULL = default */
};

struct ps_tls_result {
    int             ok;
    int             protocol_version;     /* SSL_version() */
    char            cipher[64];
    int             cert_present;
    X509           *peer;                 /* owned; free with ps_tls_result_free */
    STACK_OF(X509) *chain;                /* borrowed from the SSL session */
    char            ja3_str[1024], ja3_md5[33];
    char            ja3s_str[512], ja3s_md5[33];
    char            ja4x[40], ja4[40], ja4s[40];
};

/* Connect to host:port and run a constrained TLS handshake, capturing the
 * negotiated session + fingerprints + peer cert. Returns 0 on a successful
 * handshake (out->ok==1), -1 otherwise. */
int  ps_tls_handshake(const char *host, uint16_t port,
                      const struct ps_tls_attempt *a, struct ps_tls_result *out);
void ps_tls_result_free(struct ps_tls_result *r);

/* ---- leaf-cert + format helpers (shared with the audit verb) ------------- */

int  ps_tls_cert_days_until_expiry(X509 *cert);   /* negative = expired */
int  ps_tls_hostname_matches(X509 *cert, const char *host);
int  ps_tls_weak_signature_alg(X509 *cert, char *out, size_t outsz);  /* 1 if weak */
void ps_tls_cert_sha256_hex(X509 *cert, char *out, size_t outsz);
void ps_tls_x509_name_cn(X509_NAME *n, char *out, size_t outsz);
void ps_tls_asn1_time_iso(const ASN1_TIME *t, char *out, size_t outsz);
void ps_tls_cert_sans_json(X509 *cert, char *out, size_t outsz);      /* [\"a\",..] */
int  ps_tls_json_str_escape(const char *src, char *dst, size_t dst_sz);
const char *ps_tls_proto_str(int ssl_version);

/* ---- recipe-engine API --------------------------------------------------- */

/* Map a label ("SSLv3","TLS1.0".."TLS1.3") to the OpenSSL *_VERSION macro,
 * or -1 if unknown. Inverse fills a stable label into out (>= 16 bytes). */
long ps_tls_proto_id(const char *label);
void ps_tls_proto_label(int ssl_version, char *out, size_t outsz);

/* Leaf-cert facts only (no chain / PKIX path). Fixed buffers, caller-owned. */
struct ps_tls_info {
    char version[16];
    char cipher[64];
    char ja4[40], ja4s[40], ja4x[40];
    char cert_subject_cn[256];
    char cert_issuer_cn[256];
    char cert_not_before[40];
    char cert_not_after[40];
    long cert_days_to_expiry;
    char cert_key_type[16];     /* RSA | EC | ED25519 | ... */
    int  cert_key_bits;
    int  cert_self_signed;      /* 0/1 */
    char cert_sig_alg[64];
    char cert_san[2048];        /* comma-joined dNSName/IP SANs */
};

struct ps_tls_probe_result { int ok; char version[16]; char cipher[64]; };

/* One constrained handshake to host:port for enumeration. starttls_mode in
 * {NULL,"smtp","imap","pop3","ftp","ldap"} runs a prelude first. Returns 0 if
 * the attempt completed (out->ok reflects handshake success), -1 on setup error. */
int ps_tls_probe(const char *host, int port,
                 const char *min_proto, const char *max_proto,
                 const char *cipher_list, const char *starttls_mode,
                 int timeout_ms, struct ps_tls_probe_result *out);

/* Wrap an already-connected fd in a TLS client session (verify NONE — leaf
 * facts only). On success returns a live SSL* (caller: SSL_free + close fd) and
 * fills *info; NULL on handshake failure. sni/alpn may be NULL. */
SSL *ps_tls_upgrade_fd(int fd, const char *sni, const char *const *alpn,
                       int timeout_ms, struct ps_tls_info *info);

#endif /* PS_TLS_PROBE_H */
