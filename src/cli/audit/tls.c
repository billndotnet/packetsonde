#include "audit_module.h"
#include "audit_common.h"
#include "../args.h"
#include "finding.h"
#include "ulid.h"

#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    /* TLS targets are always host:port (no implicit default port via the
     * cipher_list paths), so require an explicit port. ps_audit_parse_target
     * accepts a default but we pass 0 and reject post-parse if it stays 0. */
    *port = 0;
    if (ps_audit_parse_target(spec, host, host_sz, 0, port) != 0) return -1;
    if (*port == 0) return -1;
    return 0;
}

static int tcp_connect(const char *host, uint16_t port, int timeout_ms,
                       char *ip_out, size_t ip_out_sz) {
    return ps_audit_tcp_connect(host, port, timeout_ms, ip_out, ip_out_sz);
}

struct tls_attempt {
    const SSL_METHOD *method;
    long              min_proto;
    long              max_proto;
    const char       *cipher_list;
};

struct tls_result {
    int          ok;
    int          protocol_version;
    char         cipher[64];
    int          cert_present;
    X509        *peer;
    STACK_OF(X509) *chain;
    /* JA3 / JA3S fingerprints.
     * JA3  -- MD5 of "version,ciphers,extensions,curves,point_formats" from
     *         OUR ClientHello. Useful for defenders to recognise the scanner.
     * JA3S -- MD5 of "version,cipher,extensions" from the SERVER'S ServerHello.
     *         Useful for fingerprinting the server's TLS stack. */
    char         ja3_str  [1024];
    char         ja3_md5  [33];
    char         ja3s_str [512];
    char         ja3s_md5 [33];
    /* JA4X (FoxIO 2023) -- X.509 certificate fingerprint. Three SHA-256-12
     * hex hashes joined by '_':
     *   {issuer_OIDs_hash}_{subject_OIDs_hash}_{extension_OIDs_hash}
     * Useful for clustering hosts that share a cert *template* (same CA,
     * same template settings) regardless of CN / SAN content. */
    char         ja4x  [40];   /* 12+1+12+1+12+1 */
    /* JA4  -- client TLS fingerprint (FoxIO 2023).
     *   <q|t><ver><d|i><cc><ec><alpn>_<sha256-12 sorted ciphers>_
     *   <sha256-12 sorted exts (no SNI/ALPN) + sigalgs in original order>
     * JA4S -- server-side counterpart, computed from the ServerHello:
     *   <q|t><ver><ec><alpn>_<chosen cipher 4hex>_<sha256-12 exts in order> */
    char         ja4   [40];
    char         ja4s  [40];
};

/* TLS handshake bytes captured via SSL_CTX_set_msg_callback. We keep the
 * raw ClientHello + ServerHello around so post-handshake JA3/JA3S parsing
 * can walk them. */
struct hs_capture {
    uint8_t client_hello[4096];
    size_t  client_hello_len;
    uint8_t server_hello[4096];
    size_t  server_hello_len;
};

static void tls_result_free(struct tls_result *r) {
    if (r->peer) X509_free(r->peer);
}

/* GREASE values (RFC 8701) — these are sentinel values used to exercise
 * extensibility; standard JA3/JA3S excludes them so different runs of the
 * same client produce stable fingerprints. */
static int is_grease(uint16_t v) {
    /* GREASE pattern: 0x0a0a, 0x1a1a, ..., 0xfafa (low byte == high byte,
     * and low nibble == 0xa). */
    return (v & 0x0f0f) == 0x0a0a && ((v >> 8) & 0xff) == (v & 0xff);
}

static size_t append_u16_list(char *out, size_t outsz, size_t off,
                              const uint8_t *src, size_t n, int skip_grease) {
    int first = (off == 0 || out[off - 1] == ',');
    for (size_t i = 0; i + 1 < n; i += 2) {
        uint16_t v = ((uint16_t)src[i] << 8) | src[i + 1];
        if (skip_grease && is_grease(v)) continue;
        int w = snprintf(out + off, outsz - off, "%s%u", first ? "" : "-", v);
        if (w < 0 || (size_t)w >= outsz - off) return off;
        off += (size_t)w;
        first = 0;
    }
    return off;
}

/* SHA-256(input), first 12 hex chars in out[12+1]. Used by JA4X. */
static void sha256_hex12(const char *str, char out[13]) {
    unsigned char dig[32];
    unsigned int  dl = 0;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_DigestInit_ex(m, EVP_sha256(), NULL);
    EVP_DigestUpdate(m, str, strlen(str));
    EVP_DigestFinal_ex(m, dig, &dl);
    EVP_MD_CTX_free(m);
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 6; i++) {
        out[i * 2]     = H[dig[i] >> 4];
        out[i * 2 + 1] = H[dig[i] & 0x0f];
    }
    out[12] = '\0';
}

/* Build a comma-separated list of OID strings from an X509_NAME's entries
 * (in the order they appear in the cert -- this matters for the JA4X
 * hash). Truncated quietly if too long; the OID buffer is generous. */
static void x509_name_oids(X509_NAME *name, char *out, size_t outsz) {
    out[0] = '\0';
    size_t off = 0;
    int n = X509_NAME_entry_count(name);
    for (int i = 0; i < n; i++) {
        X509_NAME_ENTRY *e = X509_NAME_get_entry(name, i);
        if (!e) continue;
        ASN1_OBJECT *o = X509_NAME_ENTRY_get_object(e);
        char dot[128];
        int dl = OBJ_obj2txt(dot, sizeof(dot), o, 1); /* 1 = no name lookup */
        if (dl <= 0) continue;
        int w = snprintf(out + off, outsz - off, "%s%.*s",
                         i == 0 ? "" : ",", dl, dot);
        if (w < 0 || (size_t)w >= outsz - off) break;
        off += (size_t)w;
    }
}

/* Same shape, but for extension OIDs. */
static void x509_ext_oids(X509 *cert, char *out, size_t outsz) {
    out[0] = '\0';
    size_t off = 0;
    int n = X509_get_ext_count(cert);
    for (int i = 0; i < n; i++) {
        X509_EXTENSION *e = X509_get_ext(cert, i);
        if (!e) continue;
        ASN1_OBJECT *o = X509_EXTENSION_get_object(e);
        char dot[128];
        int dl = OBJ_obj2txt(dot, sizeof(dot), o, 1);
        if (dl <= 0) continue;
        int w = snprintf(out + off, outsz - off, "%s%.*s",
                         i == 0 ? "" : ",", dl, dot);
        if (w < 0 || (size_t)w >= outsz - off) break;
        off += (size_t)w;
    }
}

/* Compute JA4X = issuer_OIDs_hash _ subject_OIDs_hash _ extension_OIDs_hash. */
static void ja4x_from_cert(X509 *cert, char *out, size_t outsz) {
    out[0] = '\0';
    char issuer_oids[2048] = "";
    char subject_oids[2048] = "";
    char ext_oids   [2048] = "";
    x509_name_oids(X509_get_issuer_name(cert),  issuer_oids,  sizeof(issuer_oids));
    x509_name_oids(X509_get_subject_name(cert), subject_oids, sizeof(subject_oids));
    x509_ext_oids (cert,                        ext_oids,     sizeof(ext_oids));
    char ih[13], sh[13], eh[13];
    sha256_hex12(issuer_oids,  ih);
    sha256_hex12(subject_oids, sh);
    sha256_hex12(ext_oids,     eh);
    snprintf(out, outsz, "%s_%s_%s", ih, sh, eh);
}

static void md5_hex(const char *str, char *hex_out /* 33 bytes */) {
    unsigned char dig[16];
    unsigned int  dl = 0;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_DigestInit_ex(m, EVP_md5(), NULL);
    EVP_DigestUpdate(m, str, strlen(str));
    EVP_DigestFinal_ex(m, dig, &dl);
    EVP_MD_CTX_free(m);
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        hex_out[i * 2]     = H[dig[i] >> 4];
        hex_out[i * 2 + 1] = H[dig[i] & 0x0f];
    }
    hex_out[32] = '\0';
}

/* Parse a TLS handshake-message body (skipping the 1-byte type + 3-byte
 * length header that the openssl msg_callback strips on TLS 1.3 but not on
 * older paths). We accept both shapes and walk past the header if present. */
static const uint8_t *hs_body(const uint8_t *buf, size_t len, size_t *body_len) {
    if (len < 4) { *body_len = 0; return NULL; }
    /* If buf[0] looks like a handshake type (1=ClientHello, 2=ServerHello)
     * and the length bytes match, skip the header. */
    if ((buf[0] == 1 || buf[0] == 2) && len >= 4) {
        size_t l = ((size_t)buf[1] << 16) | ((size_t)buf[2] << 8) | buf[3];
        if (l + 4 == len) { *body_len = l; return buf + 4; }
    }
    *body_len = len;
    return buf;
}

static void ja3s_from_server_hello(const uint8_t *hs, size_t hs_len,
                                   char *out, size_t outsz) {
    size_t blen = 0;
    const uint8_t *b = hs_body(hs, hs_len, &blen);
    if (!b || blen < 38) { out[0] = '\0'; return; }
    /* ServerHello body: version(2) random(32) sid_len(1) sid(sid_len)
     *                   cipher(2) compression(1) ext_len(2) extensions */
    uint16_t version = ((uint16_t)b[0] << 8) | b[1];
    size_t p = 2 + 32;
    uint8_t sid_len = b[p++];
    if (p + sid_len + 3 > blen) { out[0] = '\0'; return; }
    p += sid_len;
    uint16_t cipher = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
    p += 1; /* compression */
    /* extensions block */
    size_t ext_off = 0;
    int n = snprintf(out, outsz, "%u,%u,", version, cipher);
    if (n < 0 || (size_t)n >= outsz) return;
    ext_off = (size_t)n;
    if (p + 2 <= blen) {
        uint16_t ext_len = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
        size_t end = p + ext_len;
        if (end > blen) end = blen;
        int first = 1;
        while (p + 4 <= end) {
            uint16_t et = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
            uint16_t el = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
            if (p + el > end) break;
            if (!is_grease(et)) {
                int w = snprintf(out + ext_off, outsz - ext_off,
                                 "%s%u", first ? "" : "-", et);
                if (w < 0 || (size_t)w >= outsz - ext_off) break;
                ext_off += (size_t)w;
                first = 0;
            }
            p += el;
        }
    }
    out[ext_off] = '\0';
}

static void ja3_from_client_hello(const uint8_t *hs, size_t hs_len,
                                  char *out, size_t outsz) {
    size_t blen = 0;
    const uint8_t *b = hs_body(hs, hs_len, &blen);
    if (!b || blen < 38) { out[0] = '\0'; return; }
    uint16_t version = ((uint16_t)b[0] << 8) | b[1];
    size_t p = 2 + 32;
    uint8_t sid_len = b[p++];
    if (p + sid_len + 2 > blen) { out[0] = '\0'; return; }
    p += sid_len;
    uint16_t cs_len = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
    if (p + cs_len + 1 > blen) { out[0] = '\0'; return; }
    const uint8_t *ciphers = b + p; size_t ciphers_n = cs_len;
    p += cs_len;
    uint8_t cm_len = b[p++];
    if (p + cm_len + 2 > blen) { out[0] = '\0'; return; }
    p += cm_len;
    uint16_t ext_len = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
    size_t ext_end = p + ext_len;
    if (ext_end > blen) ext_end = blen;

    /* Walk extensions to collect ext-type list, and pluck supported_groups
     * (10) and ec_point_formats (11) bodies. */
    const uint8_t *groups = NULL;     size_t groups_n = 0;
    const uint8_t *ecpf = NULL;       size_t ecpf_n = 0;
    /* We need to emit ext types in order, so do that first in a scratch buf. */
    char ext_list[512]; ext_list[0] = '\0'; size_t ext_off = 0;
    int first = 1;
    size_t q = p;
    while (q + 4 <= ext_end) {
        uint16_t et = ((uint16_t)b[q] << 8) | b[q + 1]; q += 2;
        uint16_t el = ((uint16_t)b[q] << 8) | b[q + 1]; q += 2;
        if (q + el > ext_end) break;
        if (!is_grease(et)) {
            int w = snprintf(ext_list + ext_off, sizeof(ext_list) - ext_off,
                             "%s%u", first ? "" : "-", et);
            if (w < 0 || (size_t)w >= sizeof(ext_list) - ext_off) break;
            ext_off += (size_t)w; first = 0;
        }
        if (et == 10 && el >= 2) {
            /* supported_groups: u16 list_len then u16 entries */
            groups = b + q + 2;
            groups_n = ((size_t)b[q] << 8 | b[q + 1]);
            if (groups_n + 2 > el) groups_n = el - 2;
        } else if (et == 11 && el >= 1) {
            /* ec_point_formats: u8 list_len then u8 entries */
            ecpf = b + q + 1;
            ecpf_n = b[q];
            if (ecpf_n + 1 > el) ecpf_n = el - 1;
        }
        q += el;
    }

    /* Build JA3 string: version,ciphers,extensions,curves,point_formats */
    int n = snprintf(out, outsz, "%u,", version);
    if (n < 0 || (size_t)n >= outsz) return;
    size_t off = (size_t)n;
    off = append_u16_list(out, outsz, off, ciphers, ciphers_n, 1);
    if (off + 1 >= outsz) return;
    out[off++] = ',';
    /* extensions list already built */
    int w = snprintf(out + off, outsz - off, "%s,", ext_list);
    if (w < 0 || (size_t)w >= outsz - off) return;
    off += (size_t)w;
    off = append_u16_list(out, outsz, off, groups, groups_n, 1);
    if (off + 1 >= outsz) return;
    out[off++] = ',';
    /* ec_point_formats are u8 — emit each as decimal */
    int pf_first = 1;
    for (size_t i = 0; i < ecpf_n; i++) {
        w = snprintf(out + off, outsz - off, "%s%u",
                     pf_first ? "" : "-", ecpf[i]);
        if (w < 0 || (size_t)w >= outsz - off) break;
        off += (size_t)w; pf_first = 0;
    }
    out[off] = '\0';
}

/* ----- JA4 / JA4S helpers ------------------------------------------------ */

static int u16_cmp(const void *a, const void *b) {
    uint16_t x = *(const uint16_t *)a, y = *(const uint16_t *)b;
    return (x > y) - (x < y);
}

/* Map a TLS version number to JA4's two-character version code. */
static void ja4_ver_chars(uint16_t v, char out[3]) {
    out[2] = '\0';
    switch (v) {
        case 0x0304: out[0] = '1'; out[1] = '3'; return; /* TLS 1.3 */
        case 0x0303: out[0] = '1'; out[1] = '2'; return; /* TLS 1.2 */
        case 0x0302: out[0] = '1'; out[1] = '1'; return; /* TLS 1.1 */
        case 0x0301: out[0] = '1'; out[1] = '0'; return; /* TLS 1.0 */
        case 0x0300: out[0] = 's'; out[1] = '3'; return; /* SSL 3.0 */
        case 0x0002: out[0] = 's'; out[1] = '2'; return; /* SSL 2.0 */
        case 0xfeff: out[0] = 'd'; out[1] = '1'; return; /* DTLS 1.0 */
        case 0xfefd: out[0] = 'd'; out[1] = '2'; return; /* DTLS 1.2 */
        case 0xfefc: out[0] = 'd'; out[1] = '3'; return; /* DTLS 1.3 */
        default:     out[0] = '0'; out[1] = '0'; return;
    }
}

/* Pick JA4's two ALPN characters from the first protocol in an ALPN extension
 * body. Body shape: u16 list_len, then [u8 proto_len][proto bytes]+. If the
 * first or last byte of the first protocol isn't ASCII alphanumeric, JA4
 * substitutes the high nibble of the first byte and the low nibble of the
 * last byte (so opaque protocols still produce a stable two-char tag). */
static int is_alnum_byte(uint8_t c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
static void ja4_alpn_chars(const uint8_t *ext_body, size_t ext_len, char out[3]) {
    out[0] = '0'; out[1] = '0'; out[2] = '\0';
    if (ext_len < 3) return;
    size_t list_len = ((size_t)ext_body[0] << 8) | ext_body[1];
    if (list_len + 2 > ext_len || list_len < 2) return;
    uint8_t proto_len = ext_body[2];
    if (proto_len < 1 || (size_t)proto_len + 3 > ext_len) return;
    const uint8_t *p = ext_body + 3;
    uint8_t first = p[0];
    uint8_t last  = p[proto_len - 1];
    if (is_alnum_byte(first) && is_alnum_byte(last)) {
        out[0] = (char)first;
        out[1] = (char)last;
    } else {
        static const char H[] = "0123456789abcdef";
        out[0] = H[(first >> 4) & 0x0f];
        out[1] = H[last & 0x0f];
    }
}

/* Build a comma-joined lowercase 4-hex CSV from a u16 array. */
static size_t u16s_csv4(const uint16_t *v, size_t n, char *out, size_t outsz) {
    size_t off = 0;
    for (size_t i = 0; i < n; i++) {
        int w = snprintf(out + off, outsz - off, "%s%04x", i ? "," : "", v[i]);
        if (w < 0 || (size_t)w >= outsz - off) break;
        off += (size_t)w;
    }
    out[off] = '\0';
    return off;
}

/* Compute JA4 from a captured ClientHello. */
static void ja4_from_client_hello(const uint8_t *hs, size_t hs_len,
                                  char *out, size_t outsz) {
    out[0] = '\0';
    size_t blen = 0;
    const uint8_t *b = hs_body(hs, hs_len, &blen);
    if (!b || blen < 38) return;

    uint16_t legacy_version = ((uint16_t)b[0] << 8) | b[1];
    size_t p = 2 + 32;
    uint8_t sid_len = b[p++];
    if (p + sid_len + 2 > blen) return;
    p += sid_len;
    uint16_t cs_len = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
    if (p + cs_len + 1 > blen) return;
    const uint8_t *ciphers_raw = b + p;
    size_t ciphers_raw_n = cs_len;
    p += cs_len;
    uint8_t cm_len = b[p++];
    if (p + cm_len + 2 > blen) return;
    p += cm_len;
    uint16_t ext_total = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
    size_t ext_end = p + ext_total;
    if (ext_end > blen) ext_end = blen;

    /* Collect non-GREASE extension types in order; pluck supported_versions,
     * signature_algorithms, ALPN, SNI presence. */
    uint16_t exts_all[128];   size_t exts_all_n = 0;
    uint16_t exts_hash[128];  size_t exts_hash_n = 0;  /* excludes SNI(0) + ALPN(16) */
    uint16_t sigalgs[64];     size_t sigalgs_n  = 0;
    int sni_present = 0;
    char alpn_cc[3] = {'0','0',0};
    uint16_t sv_max = 0; int sv_seen = 0;

    size_t q = p;
    while (q + 4 <= ext_end) {
        uint16_t et = ((uint16_t)b[q] << 8) | b[q + 1]; q += 2;
        uint16_t el = ((uint16_t)b[q] << 8) | b[q + 1]; q += 2;
        if (q + el > ext_end) break;
        const uint8_t *body = b + q;
        if (!is_grease(et)) {
            if (exts_all_n < 128) exts_all[exts_all_n++] = et;
            if (et != 0x0000 && et != 0x0010 && exts_hash_n < 128) {
                exts_hash[exts_hash_n++] = et;
            }
            if (et == 0x0000) sni_present = 1;
            if (et == 0x0010) ja4_alpn_chars(body, el, alpn_cc);
            if (et == 0x002b && el >= 1) {
                /* supported_versions in ClientHello: u8 list_len, then u16s */
                uint8_t llen = body[0];
                if ((size_t)llen + 1 <= el) {
                    for (size_t i = 0; i + 1 < llen; i += 2) {
                        uint16_t v = ((uint16_t)body[1 + i] << 8) | body[2 + i];
                        if (is_grease(v)) continue;
                        if (!sv_seen || v > sv_max) { sv_max = v; sv_seen = 1; }
                    }
                }
            }
            if (et == 0x000d && el >= 2) {
                /* signature_algorithms: u16 list_len, then u16 entries */
                size_t llen = ((size_t)body[0] << 8) | body[1];
                if (llen + 2 > el) llen = el - 2;
                for (size_t i = 0; i + 1 < llen && sigalgs_n < 64; i += 2) {
                    uint16_t v = ((uint16_t)body[2 + i] << 8) | body[3 + i];
                    if (is_grease(v)) continue;
                    sigalgs[sigalgs_n++] = v;
                }
            }
        }
        q += el;
    }

    /* Collect non-GREASE ciphers as u16 array. */
    uint16_t ciphers[128]; size_t ciphers_n = 0;
    for (size_t i = 0; i + 1 < ciphers_raw_n && ciphers_n < 128; i += 2) {
        uint16_t v = ((uint16_t)ciphers_raw[i] << 8) | ciphers_raw[i + 1];
        if (is_grease(v)) continue;
        ciphers[ciphers_n++] = v;
    }

    /* JA4_a: t<ver><d|i><cc 2d><ec 2d><alpn 2c>  (TCP transport — only kind
     * the audit speaks today; QUIC would flip to 'q' here.) */
    uint16_t real_ver = sv_seen ? sv_max : legacy_version;
    char ver_cc[3]; ja4_ver_chars(real_ver, ver_cc);
    size_t cc_d = ciphers_n   > 99 ? 99 : ciphers_n;
    size_t ec_d = exts_all_n  > 99 ? 99 : exts_all_n;

    char ja4_a[16];
    snprintf(ja4_a, sizeof(ja4_a), "t%s%c%02zu%02zu%s",
             ver_cc, sni_present ? 'd' : 'i', cc_d, ec_d, alpn_cc);

    /* JA4_b: sha256-12 of sorted-ciphers CSV (4-hex lowercase). */
    qsort(ciphers, ciphers_n, sizeof(ciphers[0]), u16_cmp);
    char ciphers_csv[8 * 128];
    u16s_csv4(ciphers, ciphers_n, ciphers_csv, sizeof(ciphers_csv));
    char hb[13]; sha256_hex12(ciphers_csv, hb);

    /* JA4_c: sha256-12 of "<sorted exts CSV>_<sigalgs CSV in original order>".
     * If no sigalgs were sent, the spec joins with just "" after the '_' — we
     * follow that and trail with the underscore. */
    qsort(exts_hash, exts_hash_n, sizeof(exts_hash[0]), u16_cmp);
    char exts_csv[8 * 128];
    u16s_csv4(exts_hash, exts_hash_n, exts_csv, sizeof(exts_csv));
    char sigs_csv[8 * 64];
    u16s_csv4(sigalgs, sigalgs_n, sigs_csv, sizeof(sigs_csv));
    char c_input[sizeof(exts_csv) + sizeof(sigs_csv) + 2];
    snprintf(c_input, sizeof(c_input), "%s_%s", exts_csv, sigs_csv);
    char hc[13]; sha256_hex12(c_input, hc);

    snprintf(out, outsz, "%s_%s_%s", ja4_a, hb, hc);
}

/* Compute JA4S from a captured ServerHello. */
static void ja4s_from_server_hello(const uint8_t *hs, size_t hs_len,
                                   char *out, size_t outsz) {
    out[0] = '\0';
    size_t blen = 0;
    const uint8_t *b = hs_body(hs, hs_len, &blen);
    if (!b || blen < 38) return;

    uint16_t legacy_version = ((uint16_t)b[0] << 8) | b[1];
    size_t p = 2 + 32;
    uint8_t sid_len = b[p++];
    if (p + sid_len + 3 > blen) return;
    p += sid_len;
    uint16_t cipher = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
    p += 1; /* compression */

    uint16_t exts[64]; size_t exts_n = 0;
    char alpn_cc[3] = {'0','0',0};
    uint16_t sv = 0; int sv_seen = 0;

    if (p + 2 <= blen) {
        uint16_t ext_len = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
        size_t end = p + ext_len;
        if (end > blen) end = blen;
        while (p + 4 <= end) {
            uint16_t et = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
            uint16_t el = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
            if (p + el > end) break;
            const uint8_t *body = b + p;
            if (!is_grease(et)) {
                if (exts_n < 64) exts[exts_n++] = et;
                if (et == 0x0010) ja4_alpn_chars(body, el, alpn_cc);
                if (et == 0x002b && el >= 2) {
                    /* In ServerHello, supported_versions is a single u16. */
                    sv = ((uint16_t)body[0] << 8) | body[1];
                    sv_seen = 1;
                }
            }
            p += el;
        }
    }

    uint16_t real_ver = sv_seen ? sv : legacy_version;
    char ver_cc[3]; ja4_ver_chars(real_ver, ver_cc);
    size_t ec_d = exts_n > 99 ? 99 : exts_n;

    char ja4s_a[12];
    snprintf(ja4s_a, sizeof(ja4s_a), "t%s%02zu%s", ver_cc, ec_d, alpn_cc);

    /* JA4S_c: SHA-256-12 over extensions in *original* order. */
    char exts_csv[8 * 64];
    u16s_csv4(exts, exts_n, exts_csv, sizeof(exts_csv));
    char hc[13]; sha256_hex12(exts_csv, hc);

    snprintf(out, outsz, "%s_%04x_%s", ja4s_a, cipher, hc);
}

static void msg_cb(int write_p, int version, int content_type,
                   const void *buf, size_t len, SSL *ssl, void *arg) {
    (void)version; (void)ssl;
    struct hs_capture *cap = arg;
    if (!cap || content_type != 22) return; /* SSL3_RT_HANDSHAKE = 22 */
    if (len < 4 || len > sizeof(cap->client_hello)) return;
    const uint8_t *b = buf;
    /* First byte is handshake_type; 1 = ClientHello, 2 = ServerHello. */
    if (write_p && b[0] == 1 && cap->client_hello_len == 0) {
        memcpy(cap->client_hello, b, len);
        cap->client_hello_len = len;
    } else if (!write_p && b[0] == 2 && cap->server_hello_len == 0) {
        memcpy(cap->server_hello, b, len);
        cap->server_hello_len = len;
    }
}

static int do_handshake(const char *host, uint16_t port,
                        const struct tls_attempt *a,
                        struct tls_result *out) {
    memset(out, 0, sizeof(*out));
    char ip[64] = "";
    int fd = tcp_connect(host, port, 4000, ip, sizeof(ip));
    if (fd < 0) return -1;

    SSL_CTX *ctx = SSL_CTX_new(a->method ? a->method : TLS_client_method());
    if (!ctx) { close(fd); return -1; }
    /* Permit ancient protocols / weak ciphers — this is an *audit* client. */
    SSL_CTX_set_security_level(ctx, 0);
    if (a->min_proto) SSL_CTX_set_min_proto_version(ctx, a->min_proto);
    if (a->max_proto) SSL_CTX_set_max_proto_version(ctx, a->max_proto);
    if (a->cipher_list) SSL_CTX_set_cipher_list(ctx, a->cipher_list);
    struct hs_capture cap; memset(&cap, 0, sizeof(cap));
    SSL_CTX_set_msg_callback(ctx, msg_cb);
    SSL_CTX_set_msg_callback_arg(ctx, &cap);
    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set_fd(ssl, fd);
    int rc = SSL_connect(ssl);
    if (rc == 1) {
        out->ok = 1;
        out->protocol_version = SSL_version(ssl);
        const char *cn = SSL_get_cipher_name(ssl);
        if (cn) snprintf(out->cipher, sizeof(out->cipher), "%s", cn);
        X509 *peer = SSL_get_peer_certificate(ssl);
        if (peer) {
            out->peer = peer; out->cert_present = 1;
            ja4x_from_cert(peer, out->ja4x, sizeof(out->ja4x));
        }
        out->chain = SSL_get_peer_cert_chain(ssl);
        if (cap.client_hello_len) {
            ja3_from_client_hello(cap.client_hello, cap.client_hello_len,
                                  out->ja3_str, sizeof(out->ja3_str));
            if (out->ja3_str[0]) md5_hex(out->ja3_str, out->ja3_md5);
            ja4_from_client_hello(cap.client_hello, cap.client_hello_len,
                                  out->ja4, sizeof(out->ja4));
        }
        if (cap.server_hello_len) {
            ja3s_from_server_hello(cap.server_hello, cap.server_hello_len,
                                   out->ja3s_str, sizeof(out->ja3s_str));
            if (out->ja3s_str[0]) md5_hex(out->ja3s_str, out->ja3s_md5);
            ja4s_from_server_hello(cap.server_hello, cap.server_hello_len,
                                   out->ja4s, sizeof(out->ja4s));
        }
    }
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return out->ok ? 0 : -1;
}

struct emit_ctx {
    const struct ps_audit_api *api;
    const char       *run_id;
    const char       *self_host;
    const char       *target_host;
    const char       *target_ip;
    uint16_t          target_port;
};

static void emit(struct emit_ctx *e,
                 const char *kind, enum ps_severity sev, enum ps_confidence conf,
                 const char *title, const char *evidence_json) {
    struct ps_finding f;
    ps_finding_init(&f, e->run_id, "cli.audit.tls", e->self_host, kind, sev, conf, title);
    if (e->target_ip && e->target_ip[0])
        ps_finding_set_target_ip(&f, e->target_ip, e->target_port);
    if (e->target_host && e->target_host[0])
        ps_finding_set_target_hostname(&f, e->target_host, e->target_port);
    if (evidence_json) ps_finding_set_evidence_json(&f, evidence_json);
    e->api->emit(&f);
}

static void check_protocol(struct emit_ctx *e, const char *target_host) {
    /* Permissive cipher list so we can negotiate against servers that only
     * offer legacy ciphers (the audit is precisely about finding those). */
    const char *cipher = "ALL:eNULL:@SECLEVEL=0";

    struct tls_attempt a10 = { TLS_client_method(), TLS1_VERSION, TLS1_VERSION, cipher };
    struct tls_result  r10;
    if (do_handshake(target_host, e->target_port, &a10, &r10) == 0) {
        emit(e, "tls.weak_protocol", PS_SEV_HIGH, PS_CONF_FIRM,
             "TLS 1.0 negotiated successfully", "{\"protocol\":\"TLSv1\"}");
    }
    tls_result_free(&r10);

    struct tls_attempt a11 = { TLS_client_method(), TLS1_1_VERSION, TLS1_1_VERSION, cipher };
    struct tls_result  r11;
    if (do_handshake(target_host, e->target_port, &a11, &r11) == 0) {
        emit(e, "tls.weak_protocol", PS_SEV_HIGH, PS_CONF_FIRM,
             "TLS 1.1 negotiated successfully", "{\"protocol\":\"TLSv1.1\"}");
    }
    tls_result_free(&r11);
}

static void check_ciphers(struct emit_ctx *e, const char *target_host) {
    /* Offer only weak families and require SECLEVEL=0 so OpenSSL parses them.
     * If the server negotiates any of these, the cipher really is weak. */
    struct tls_attempt aw = {
        TLS_client_method(), TLS1_VERSION, TLS1_2_VERSION,
        "DES:3DES:RC4:eNULL:EXP:MD5:@SECLEVEL=0"
    };
    struct tls_result  rw;
    if (do_handshake(target_host, e->target_port, &aw, &rw) == 0 && rw.cipher[0]) {
        char ev[160]; snprintf(ev, sizeof(ev), "{\"cipher\":\"%s\"}", rw.cipher);
        char title[160];
        snprintf(title, sizeof(title), "Server negotiates weak cipher: %s", rw.cipher);
        emit(e, "tls.weak_cipher", PS_SEV_HIGH, PS_CONF_FIRM, title, ev);
    }
    tls_result_free(&rw);
}

static int cert_days_until_expiry(X509 *cert) {
    const ASN1_TIME *na = X509_get0_notAfter(cert);
    int pday = 0, psec = 0;
    if (ASN1_TIME_diff(&pday, &psec, NULL, na) == 0) return -99999;
    return pday;
}

static int hostname_matches(X509 *cert, const char *host) {
    return X509_check_host(cert, host, 0, 0, NULL);
}

static int weak_signature_alg(X509 *cert, char *out, size_t outsz) {
    const X509_ALGOR *sig_alg = NULL;
    X509_get0_signature(NULL, &sig_alg, cert);
    int nid = OBJ_obj2nid(sig_alg->algorithm);
    const char *sn = OBJ_nid2sn(nid);
    if (sn) snprintf(out, outsz, "%s", sn);
    if (nid == NID_md5WithRSAEncryption  ||
        nid == NID_sha1WithRSAEncryption ||
        nid == NID_ecdsa_with_SHA1) {
        return 1;
    }
    return 0;
}

/* JSON-escape src into dst; returns 0 on success, -1 on overflow. */
static int json_str_escape(const char *src, char *dst, size_t dst_sz) {
    size_t o = 0;
    for (size_t i = 0; src[i]; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            if (o + 2 >= dst_sz) return -1;
            dst[o++] = '\\'; dst[o++] = (char)c;
        } else if (c < 0x20) {
            if (o + 6 >= dst_sz) return -1;
            o += (size_t)snprintf(dst + o, dst_sz - o, "\\u%04x", c);
        } else {
            if (o + 1 >= dst_sz) return -1;
            dst[o++] = (char)c;
        }
    }
    dst[o] = '\0';
    return 0;
}

static void cert_sha256_hex(X509 *cert, char *out, size_t outsz) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int  mdlen = 0;
    if (!X509_digest(cert, EVP_sha256(), md, &mdlen)) { out[0] = '\0'; return; }
    if (outsz < (size_t)mdlen * 2 + 1) { out[0] = '\0'; return; }
    static const char H[] = "0123456789abcdef";
    for (unsigned int i = 0; i < mdlen; i++) {
        out[i * 2]     = H[md[i] >> 4];
        out[i * 2 + 1] = H[md[i] & 0xf];
    }
    out[mdlen * 2] = '\0';
}

static void x509_name_cn(X509_NAME *n, char *out, size_t outsz) {
    out[0] = '\0';
    int idx = X509_NAME_get_index_by_NID(n, NID_commonName, -1);
    if (idx < 0) return;
    X509_NAME_ENTRY *e = X509_NAME_get_entry(n, idx);
    if (!e) return;
    ASN1_STRING *s = X509_NAME_ENTRY_get_data(e);
    if (!s) return;
    unsigned char *utf8 = NULL;
    int len = ASN1_STRING_to_UTF8(&utf8, s);
    if (len > 0 && utf8) {
        size_t k = (size_t)len < outsz - 1 ? (size_t)len : outsz - 1;
        memcpy(out, utf8, k);
        out[k] = '\0';
    }
    if (utf8) OPENSSL_free(utf8);
}

static void asn1_time_iso(const ASN1_TIME *t, char *out, size_t outsz) {
    out[0] = '\0';
    if (!t) return;
    BIO *b = BIO_new(BIO_s_mem());
    if (!b) return;
    if (ASN1_TIME_print(b, t)) {
        char buf[64] = "";
        int n = BIO_read(b, buf, sizeof(buf) - 1);
        if (n > 0) { buf[n] = '\0'; snprintf(out, outsz, "%s", buf); }
    }
    BIO_free(b);
}

/* Append up to N SANs as a JSON array fragment "[\"a\",\"b\"]". */
static void cert_sans_json(X509 *cert, char *out, size_t outsz) {
    out[0] = '\0';
    GENERAL_NAMES *gens = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (!gens) { snprintf(out, outsz, "[]"); return; }
    size_t o = 0;
    if (o + 1 >= outsz) goto done;
    out[o++] = '[';
    int first = 1;
    int count = sk_GENERAL_NAME_num(gens);
    for (int i = 0; i < count && i < 16; i++) {
        GENERAL_NAME *gn = sk_GENERAL_NAME_value(gens, i);
        if (gn->type != GEN_DNS && gn->type != GEN_IPADD) continue;
        char buf[256] = "";
        if (gn->type == GEN_DNS) {
            unsigned char *utf8 = NULL;
            int L = ASN1_STRING_to_UTF8(&utf8, gn->d.dNSName);
            if (L > 0 && utf8) {
                size_t k = (size_t)L < sizeof(buf) - 1 ? (size_t)L : sizeof(buf) - 1;
                memcpy(buf, utf8, k); buf[k] = '\0';
            }
            if (utf8) OPENSSL_free(utf8);
        } else if (gn->type == GEN_IPADD) {
            const unsigned char *ip = ASN1_STRING_get0_data(gn->d.iPAddress);
            int iplen = ASN1_STRING_length(gn->d.iPAddress);
            if (iplen == 4) snprintf(buf, sizeof(buf), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
        }
        if (!buf[0]) continue;
        char esc[512];
        if (json_str_escape(buf, esc, sizeof(esc)) != 0) continue;
        size_t need = strlen(esc) + 3 + (first ? 0 : 1);
        if (o + need >= outsz) break;
        if (!first) out[o++] = ',';
        out[o++] = '"';
        memcpy(out + o, esc, strlen(esc)); o += strlen(esc);
        out[o++] = '"';
        first = 0;
    }
    if (o + 1 < outsz) out[o++] = ']';
    out[o] = '\0';
done:
    GENERAL_NAMES_free(gens);
}

static const char *proto_str(int v) {
    switch (v) {
        case TLS1_VERSION:   return "TLSv1";
        case TLS1_1_VERSION: return "TLSv1.1";
        case TLS1_2_VERSION: return "TLSv1.2";
        case TLS1_3_VERSION: return "TLSv1.3";
        default: return "unknown";
    }
}

static void check_certificate(struct emit_ctx *e, const char *target_host) {
    struct tls_attempt a = { TLS_client_method(), 0, 0, "ALL:eNULL:@SECLEVEL=0" };
    struct tls_result  r;
    if (do_handshake(target_host, e->target_port, &a, &r) != 0 || !r.peer) {
        tls_result_free(&r);
        return;
    }

    /* Emit an info-severity tls.metadata finding with the full TLS posture.
     * Auditors get "what does this server look like" alongside any issues. */
    {
        char subj_cn[256] = "", issu_cn[256] = "";
        char not_before[64] = "", not_after[64] = "";
        char sha256[80] = "", sans[2048] = "";
        x509_name_cn(X509_get_subject_name(r.peer), subj_cn, sizeof(subj_cn));
        x509_name_cn(X509_get_issuer_name(r.peer),  issu_cn, sizeof(issu_cn));
        asn1_time_iso(X509_get0_notBefore(r.peer), not_before, sizeof(not_before));
        asn1_time_iso(X509_get0_notAfter(r.peer),  not_after,  sizeof(not_after));
        cert_sha256_hex(r.peer, sha256, sizeof(sha256));
        cert_sans_json(r.peer, sans, sizeof(sans));

        char subj_e[512], issu_e[512], nb_e[128], na_e[128];
        json_str_escape(subj_cn,    subj_e, sizeof(subj_e));
        json_str_escape(issu_cn,    issu_e, sizeof(issu_e));
        json_str_escape(not_before, nb_e,   sizeof(nb_e));
        json_str_escape(not_after,  na_e,   sizeof(na_e));

        char ev[4096];
        snprintf(ev, sizeof(ev),
            "{\"protocol\":\"%s\",\"cipher\":\"%s\","
            "\"subject_cn\":\"%s\",\"issuer_cn\":\"%s\","
            "\"not_before\":\"%s\",\"not_after\":\"%s\","
            "\"cert_sha256\":\"%s\",\"sans\":%s,"
            "\"ja3\":\"%s\",\"ja3_str\":\"%s\","
            "\"ja3s\":\"%s\",\"ja3s_str\":\"%s\","
            "\"ja4\":\"%s\",\"ja4s\":\"%s\","
            "\"ja4x\":\"%s\"}",
            proto_str(r.protocol_version), r.cipher,
            subj_e, issu_e, nb_e, na_e, sha256, sans,
            r.ja3_md5,  r.ja3_str,
            r.ja3s_md5, r.ja3s_str,
            r.ja4,      r.ja4s,
            r.ja4x);
        char title[320];
        snprintf(title, sizeof(title), "%s (%s) CN=%s",
                 proto_str(r.protocol_version), r.cipher,
                 subj_cn[0] ? subj_cn : "-");
        emit(e, "tls.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title, ev);
    }

    int days = cert_days_until_expiry(r.peer);
    if (days < 0) {
        char ev[64]; snprintf(ev, sizeof(ev), "{\"days_overdue\":%d}", -days);
        emit(e, "tls.expired_cert", PS_SEV_CRITICAL, PS_CONF_FIRM,
             "Certificate expired", ev);
    } else if (days < 30) {
        char ev[64]; snprintf(ev, sizeof(ev), "{\"days_remaining\":%d}", days);
        emit(e, "tls.expiring_cert", PS_SEV_MEDIUM, PS_CONF_FIRM,
             "Certificate expires within 30 days", ev);
    }

    if (!hostname_matches(r.peer, target_host)) {
        char ev[256]; snprintf(ev, sizeof(ev), "{\"hostname\":\"%s\"}", target_host);
        emit(e, "tls.hostname_mismatch", PS_SEV_HIGH, PS_CONF_FIRM,
             "Certificate does not match the requested hostname", ev);
    }

    char sig_name[64] = "";
    if (weak_signature_alg(r.peer, sig_name, sizeof(sig_name))) {
        char ev[128]; snprintf(ev, sizeof(ev), "{\"signature\":\"%s\"}", sig_name);
        emit(e, "tls.weak_signature", PS_SEV_HIGH, PS_CONF_FIRM,
             "Certificate uses a weak signature algorithm", ev);
    }

    X509_NAME *subj = X509_get_subject_name(r.peer);
    X509_NAME *issu = X509_get_issuer_name(r.peer);
    if (X509_NAME_cmp(subj, issu) == 0) {
        emit(e, "tls.self_signed", PS_SEV_MEDIUM, PS_CONF_FIRM,
             "Certificate is self-signed", NULL);
    }

    EVP_PKEY *pk = X509_get0_pubkey(r.peer);
    if (pk && EVP_PKEY_base_id(pk) == EVP_PKEY_RSA) {
        int bits = EVP_PKEY_bits(pk);
        if (bits < 2048) {
            char ev[64]; snprintf(ev, sizeof(ev), "{\"bits\":%d}", bits);
            emit(e, "tls.weak_key", PS_SEV_HIGH, PS_CONF_FIRM,
                 "RSA public key < 2048 bits", ev);
        }
    }

    tls_result_free(&r);
}

static int tls_run(int argc, char **argv,
                      const struct ps_args *opts,
                      const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit tls <host:port>\n");
        return 2;
    }
    const char *spec = argv[1];
    char  target_host[256];
    uint16_t target_port = 0;
    if (parse_target(spec, target_host, sizeof(target_host), &target_port) != 0) {
        fprintf(stderr, "packetsonde audit tls: bad target '%s' (expected host:port)\n", spec);
        return 2;
    }

    /* Skip loading the system openssl.cnf — modern distributions set
     * MinProtocol=TLSv1.2 and SECLEVEL=2 there, which would prevent the
     * audit from probing TLS 1.0/1.1 or weak-cipher servers. We make the
     * audit's policy explicit per-context instead. */
    OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);

    char self_host[256] = "";
    gethostname(self_host, sizeof(self_host));

    char run_id[PS_ULID_STRLEN + 1];
    ps_ulid_new(run_id, sizeof(run_id));

    struct timeval t_start;
    gettimeofday(&t_start, NULL);

    _Static_assert(PS_FMT_TEXT  == 1, "fmt mapping drift");
    _Static_assert(PS_FMT_JSON  == 2, "fmt mapping drift");
    _Static_assert(PS_FMT_JSONL == 3, "fmt mapping drift");
    _Static_assert(PS_FMT_QUIET == 4, "fmt mapping drift");

    /* Note: the worker pool / rate limiter previously held in this audit
     * has been removed. Under the plugin ABI, cancellation comes from the
     * dispatcher via api->cancelled(); rate limiting against a single
     * target is the dispatcher's concern. */
    (void)opts;

    char ip[64] = "";
    int probe_fd = tcp_connect(target_host, target_port, 4000, ip, sizeof(ip));
    if (probe_fd < 0) {
        fprintf(stderr, "packetsonde audit tls: cannot connect to %s:%u\n", target_host, target_port);
        return 1;
    }
    close(probe_fd);

    struct emit_ctx e;
    memset(&e, 0, sizeof(e));
    e.api = api; e.run_id = run_id; e.self_host = self_host;
    e.target_host = target_host; e.target_ip = ip; e.target_port = target_port;

    if (!api->cancelled()) check_protocol   (&e, target_host);
    if (!api->cancelled()) check_ciphers    (&e, target_host);
    if (!api->cancelled()) check_certificate(&e, target_host);

    struct timeval t_end;
    gettimeofday(&t_end, NULL);
    long dt_ms = (t_end.tv_sec - t_start.tv_sec) * 1000L
               + (t_end.tv_usec - t_start.tv_usec) / 1000L;
    (void)dt_ms;
    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "tls",
    .summary     = "Audit TLS server: protocol, cipher, cert hygiene",
    .run         = tls_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_tls_module(void) { return &MODULE; }
