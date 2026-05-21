#include "audit_module.h"
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
    const char *colon = strrchr(spec, ':');
    if (!colon) return -1;
    size_t hl = (size_t)(colon - spec);
    if (hl == 0 || hl >= host_sz) return -1;
    memcpy(host, spec, hl); host[hl] = '\0';
    long p = strtol(colon + 1, NULL, 10);
    if (p <= 0 || p > 65535) return -1;
    *port = (uint16_t)p;
    return 0;
}

static int tcp_connect(const char *host, uint16_t port, int timeout_ms,
                       char *ip_out, size_t ip_out_sz) {
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res); return -1;
    }
    if (ip_out && ip_out_sz) {
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        uint32_t a = sin->sin_addr.s_addr;
        snprintf(ip_out, ip_out_sz, "%u.%u.%u.%u",
                 (a >> 0) & 0xff, (a >> 8) & 0xff,
                 (a >> 16) & 0xff, (a >> 24) & 0xff);
    }
    freeaddrinfo(res);
    return fd;
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
    /* JA3 / JA3S fingerprints (legacy FoxIO format, MD5-based).
     * JA3  -- MD5 of "version,ciphers,extensions,curves,point_formats" from
     *         OUR ClientHello. Useful for defenders to recognise the scanner.
     * JA3S -- MD5 of "version,cipher,extensions" from the SERVER'S ServerHello.
     *         Useful for fingerprinting the server's TLS stack. */
    char         ja3_str  [1024];
    char         ja3_md5  [33];
    char         ja3s_str [512];
    char         ja3s_md5 [33];
    /* JA4 / JA4S fingerprints (FoxIO 2023, SHA-256-based, structured prefix).
     * Format:
     *   JA4  = "t{ver}{sni}{ncipher:02}{next:02}{alpn2}_{cipher_hash}_{ext_sigalg_hash}"
     *   JA4S = "t{ver}{nextNN}{alpn2}_{cipher_hex}_{ext_hash}"
     *
     * Each hash is the first 12 hex chars of SHA-256 over the canonical
     * comma-separated list. GREASE values are filtered. */
    char         ja4   [64];   /* "t13d1314h2_aaaaaaaaaaaa_bbbbbbbbbbbb" */
    char         ja4s  [64];   /* "t130200_1301_cccccccccccc" */
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

/* ---- JA4 + JA4S (FoxIO 2023, https://github.com/FoxIO-LLC/ja4) ----
 *
 * Newer fingerprinting scheme than JA3. Notable differences:
 *   - SHA-256 over comma-separated lists (truncated to first 12 hex chars).
 *   - Prefix is a human-readable summary (e.g. "t13d2010h2"):
 *       t/q   transport (TLS / QUIC)
 *       NN    TLS version (13 = TLS 1.3, 12 = TLS 1.2, 10 = TLS 1.0)
 *       d/i   SNI present / not (client only)
 *       NN    cipher count (client) -- always "00" client-side here
 *              since we don't emit a JA4 string -- or 4-hex chosen cipher
 *              (server)
 *       NN    extension count (skipping GREASE; on the server side this
 *              IS the chosen-cipher-aware count)
 *       XX    ALPN first/last char of the negotiated protocol, or "00"
 *   - Cipher and extension lists are SORTED ascending (a stable
 *     fingerprint even when servers permute the order).
 *
 * We compute JA4 (client) from our own ClientHello and JA4S (server) from
 * the ServerHello -- same source bytes as JA3/JA3S, different format. */

#include <openssl/sha.h>

static int cmp_u16(const void *a, const void *b) {
    uint16_t ia = *(const uint16_t *)a, ib = *(const uint16_t *)b;
    return (ia > ib) - (ia < ib);
}

static void sha256_hex12(const char *str, char out[13]) {
    unsigned char dig[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    unsigned int dl = 0;
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

/* Two chars representing the TLS version: "13"/"12"/"11"/"10".
 * For TLS 1.3 the legacy version field is 0x0303 but the *real* version
 * lives in the supported_versions extension (43). The caller decides
 * which value to feed in. */
static const char *ja4_ver(uint16_t v) {
    switch (v) {
        case 0x0304: return "13";   /* TLS 1.3 */
        case 0x0303: return "12";   /* TLS 1.2 */
        case 0x0302: return "11";   /* TLS 1.1 */
        case 0x0301: return "10";   /* TLS 1.0 */
        case 0x0300: return "s3";   /* SSL 3.0 */
        default:     return "00";
    }
}

/* Walk a list of u16 extension types in the wire order; if extension 43
 * (supported_versions) is present in the *client* hello, return its
 * highest non-GREASE version. */
static uint16_t client_supported_version(const uint8_t *b, size_t blen,
                                          size_t ext_start, size_t ext_end) {
    size_t q = ext_start;
    while (q + 4 <= ext_end) {
        uint16_t et = ((uint16_t)b[q] << 8) | b[q + 1]; q += 2;
        uint16_t el = ((uint16_t)b[q] << 8) | b[q + 1]; q += 2;
        if (q + el > ext_end) break;
        if (et == 43 && el >= 1) {
            uint8_t list_len = b[q];
            uint16_t best = 0;
            for (size_t i = 1; i + 1 < el && i + 2 <= 1 + list_len; i += 2) {
                uint16_t vv = ((uint16_t)b[q + i] << 8) | b[q + i + 1];
                if (!is_grease(vv) && vv > best) best = vv;
            }
            if (best) return best;
        }
        q += el;
    }
    return 0;
}

/* Find ALPN-selected protocol or first offered: extension 16. Returns the
 * two-char "alpn" field used by JA4 (first + last char of the first
 * non-GREASE protocol name), or "00" if absent. */
static void ja4_alpn_from_extensions(const uint8_t *b, size_t blen,
                                     size_t ext_start, size_t ext_end,
                                     char out[3]) {
    out[0] = '0'; out[1] = '0'; out[2] = '\0';
    size_t q = ext_start;
    while (q + 4 <= ext_end) {
        uint16_t et = ((uint16_t)b[q] << 8) | b[q + 1]; q += 2;
        uint16_t el = ((uint16_t)b[q] << 8) | b[q + 1]; q += 2;
        if (q + el > ext_end) break;
        if (et == 16 && el >= 3) {
            /* alpn ext body: u16 list_len, then [u8 plen, plen bytes]+ */
            size_t lp = q + 2;
            if (lp + 1 > q + el) { q += el; continue; }
            uint8_t plen = b[lp];
            if (lp + 1 + plen > q + el) { q += el; continue; }
            if (plen >= 1) {
                out[0] = (char)b[lp + 1];
                out[1] = (char)b[lp + plen];
                out[2] = '\0';
            }
            return;
        }
        q += el;
    }
}

static void ja4s_from_server_hello(const uint8_t *hs, size_t hs_len,
                                   char *out, size_t outsz) {
    out[0] = '\0';
    size_t blen = 0;
    const uint8_t *b = hs_body(hs, hs_len, &blen);
    if (!b || blen < 38) return;
    uint16_t legacy_ver = ((uint16_t)b[0] << 8) | b[1];
    size_t p = 2 + 32;
    uint8_t sid_len = b[p++];
    if (p + sid_len + 3 > blen) return;
    p += sid_len;
    uint16_t cipher = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
    p += 1; /* compression method */

    /* Extensions block: scan to record types (sorted), find ALPN, and
     * find the real version from supported_versions if present. */
    uint16_t real_ver = legacy_ver;
    uint16_t ext_types[64]; size_t ext_n = 0;
    char alpn[3] = "00";
    if (p + 2 <= blen) {
        uint16_t ext_len = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
        size_t end = p + ext_len;
        if (end > blen) end = blen;
        size_t q = p;
        while (q + 4 <= end) {
            uint16_t et = ((uint16_t)b[q] << 8) | b[q + 1]; q += 2;
            uint16_t el = ((uint16_t)b[q] << 8) | b[q + 1]; q += 2;
            if (q + el > end) break;
            if (!is_grease(et) && ext_n < 64) ext_types[ext_n++] = et;
            if (et == 43 && el >= 2) {
                /* server supported_versions: single u16 */
                real_ver = ((uint16_t)b[q] << 8) | b[q + 1];
            } else if (et == 16 && el >= 3) {
                size_t lp = q + 2;
                if (lp + 1 <= q + el) {
                    uint8_t plen = b[lp];
                    if (lp + 1 + plen <= q + el && plen >= 1) {
                        alpn[0] = (char)b[lp + 1];
                        alpn[1] = (char)b[lp + plen];
                    }
                }
            }
            q += el;
        }
    }

    /* JA4S prefix: t{ver}{ext_count:02}{alpn2}_{cipher_4hex}_{ext_hash12} */
    /* Build the canonical extension list (sorted, comma-separated). */
    qsort(ext_types, ext_n, sizeof(uint16_t), cmp_u16);
    char ext_csv[512]; size_t off = 0;
    ext_csv[0] = '\0';
    for (size_t i = 0; i < ext_n; i++) {
        int w = snprintf(ext_csv + off, sizeof(ext_csv) - off,
                         "%s%u", i ? "," : "", ext_types[i]);
        if (w < 0 || (size_t)w >= sizeof(ext_csv) - off) break;
        off += (size_t)w;
    }
    char ext_hash[13]; sha256_hex12(ext_csv, ext_hash);
    snprintf(out, outsz, "t%s%02zu%s_%04x_%s",
             ja4_ver(real_ver), ext_n, alpn, cipher, ext_hash);
}

static void ja4_from_client_hello(const uint8_t *hs, size_t hs_len,
                                  char *out, size_t outsz) {
    out[0] = '\0';
    size_t blen = 0;
    const uint8_t *b = hs_body(hs, hs_len, &blen);
    if (!b || blen < 38) return;
    uint16_t legacy_ver = ((uint16_t)b[0] << 8) | b[1];
    size_t p = 2 + 32;
    uint8_t sid_len = b[p++];
    if (p + sid_len + 2 > blen) return;
    p += sid_len;
    uint16_t cs_len = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
    if (p + cs_len + 1 > blen) return;
    const uint8_t *ciphers = b + p; size_t ciphers_n = cs_len;
    p += cs_len;
    uint8_t cm_len = b[p++];
    if (p + cm_len + 2 > blen) return;
    p += cm_len;
    uint16_t ext_len = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
    size_t ext_end = p + ext_len;
    if (ext_end > blen) ext_end = blen;

    /* Has SNI extension (0)? */
    int has_sni = 0;
    {
        size_t q = p;
        while (q + 4 <= ext_end) {
            uint16_t et = ((uint16_t)b[q] << 8) | b[q + 1];
            uint16_t el = ((uint16_t)b[q + 2] << 8) | b[q + 3];
            if (et == 0 && el > 0) { has_sni = 1; break; }
            q += 4 + el;
        }
    }

    /* Real TLS version from supported_versions, fall back to legacy. */
    uint16_t real_ver = client_supported_version(b, blen, p, ext_end);
    if (real_ver == 0) real_ver = legacy_ver;

    /* Collect non-GREASE ciphers; sort. */
    uint16_t ciph[256]; size_t cn = 0;
    for (size_t i = 0; i + 1 < ciphers_n && cn < 256; i += 2) {
        uint16_t c = ((uint16_t)ciphers[i] << 8) | ciphers[i + 1];
        if (!is_grease(c)) ciph[cn++] = c;
    }
    qsort(ciph, cn, sizeof(uint16_t), cmp_u16);

    /* Collect non-GREASE extension types (excluding SNI=0 and ALPN=16,
     * per the JA4 spec -- they're already encoded in the prefix). */
    uint16_t exts[256]; size_t en = 0;
    /* Also collect signature_algorithms (ext 13) body for the second hash. */
    const uint8_t *sig_algs = NULL; size_t sig_algs_n = 0;
    char alpn[3] = "00";
    size_t q = p;
    while (q + 4 <= ext_end) {
        uint16_t et = ((uint16_t)b[q] << 8) | b[q + 1]; q += 2;
        uint16_t el = ((uint16_t)b[q] << 8) | b[q + 1]; q += 2;
        if (q + el > ext_end) break;
        if (!is_grease(et) && et != 0 && et != 16 && en < 256) exts[en++] = et;
        if (et == 13 && el >= 2) {
            uint16_t sig_len = ((uint16_t)b[q] << 8) | b[q + 1];
            sig_algs = b + q + 2;
            sig_algs_n = sig_len;
            if (sig_algs_n + 2 > el) sig_algs_n = el - 2;
        } else if (et == 16 && el >= 3) {
            size_t lp = q + 2;
            if (lp + 1 <= q + el) {
                uint8_t plen = b[lp];
                if (lp + 1 + plen <= q + el && plen >= 1) {
                    alpn[0] = (char)b[lp + 1];
                    alpn[1] = (char)b[lp + plen];
                }
            }
        }
        q += el;
    }
    qsort(exts, en, sizeof(uint16_t), cmp_u16);

    /* Build the prefix: "t{ver}{sni}{nciph:02}{next:02}{alpn}" -- the
     * cipher/extension counts include all collected entries.
     *
     * Important: ext_count for JA4 is `en + 2` if SNI + ALPN are present
     * (they go back in the count even though they were excluded from the
     * extension hash). Strict spec compliance. */
    size_t ext_count = en + (has_sni ? 1 : 0) + (alpn[0] != '0' ? 1 : 0);
    char prefix[24];
    snprintf(prefix, sizeof(prefix), "t%s%c%02zu%02zu%s",
             ja4_ver(real_ver), has_sni ? 'd' : 'i',
             cn, ext_count, alpn);

    /* Cipher hash: SHA-256 over sorted cipher list, comma-separated 4-hex.
     * Spec uses lowercase hex. */
    char ciph_csv[2048]; size_t off = 0;
    ciph_csv[0] = '\0';
    for (size_t i = 0; i < cn; i++) {
        int w = snprintf(ciph_csv + off, sizeof(ciph_csv) - off,
                         "%s%04x", i ? "," : "", ciph[i]);
        if (w < 0 || (size_t)w >= sizeof(ciph_csv) - off) break;
        off += (size_t)w;
    }
    char ciph_hash[13]; sha256_hex12(ciph_csv, ciph_hash);

    /* Extension hash: SHA-256 over sorted ext list, then a comma, then
     * the signature_algorithms list IN WIRE ORDER (NOT sorted) as
     * 4-hex codes separated by commas. */
    char ext_csv[2048]; off = 0; ext_csv[0] = '\0';
    for (size_t i = 0; i < en; i++) {
        int w = snprintf(ext_csv + off, sizeof(ext_csv) - off,
                         "%s%04x", i ? "," : "", exts[i]);
        if (w < 0 || (size_t)w >= sizeof(ext_csv) - off) break;
        off += (size_t)w;
    }
    if (sig_algs_n > 0 && off + 1 < sizeof(ext_csv)) {
        ext_csv[off++] = '_';
        for (size_t i = 0; i + 1 < sig_algs_n; i += 2) {
            uint16_t sa = ((uint16_t)sig_algs[i] << 8) | sig_algs[i + 1];
            int w = snprintf(ext_csv + off, sizeof(ext_csv) - off,
                             "%s%04x", i ? "," : "", sa);
            if (w < 0 || (size_t)w >= sizeof(ext_csv) - off) break;
            off += (size_t)w;
        }
        ext_csv[off] = '\0';
    }
    char ext_hash[13]; sha256_hex12(ext_csv, ext_hash);

    snprintf(out, outsz, "%s_%s_%s", prefix, ciph_hash, ext_hash);
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
        if (peer) { out->peer = peer; out->cert_present = 1; }
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
            "\"ja4\":\"%s\",\"ja4s\":\"%s\"}",
            proto_str(r.protocol_version), r.cipher,
            subj_e, issu_e, nb_e, na_e, sha256, sans,
            r.ja3_md5,  r.ja3_str,
            r.ja3s_md5, r.ja3s_str,
            r.ja4, r.ja4s);
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
