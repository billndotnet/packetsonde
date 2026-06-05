/* Shared TLS handshake + fingerprint + leaf-cert primitive. See tls_probe.h.
 * Bodies factored from src/cli/audit/tls.c (unchanged logic). */
#include "tls_probe.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>

/* ---- self-contained TCP connect (no audit-lib dependency) ---------------- */

static int tp_tcp_connect(const char *host, int port, int timeout_ms) {
    char ports[16];
    snprintf(ports, sizeof(ports), "%d", port);
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, ports, &hints, &res) != 0) return -1;

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        int rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc == 0) { fcntl(fd, F_SETFL, fl); break; }
        if (errno == EINPROGRESS) {
            fd_set wf; FD_ZERO(&wf); FD_SET(fd, &wf);
            struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
            if (select(fd + 1, NULL, &wf, NULL, &tv) > 0) {
                int err = 0; socklen_t el = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
                if (err == 0) { fcntl(fd, F_SETFL, fl); break; }
            }
        }
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* ---- GREASE + small format helpers --------------------------------------- */

static int is_grease(uint16_t v) {
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
        off += (size_t)w; first = 0;
    }
    return off;
}

static void sha256_hex12(const char *str, char out[13]) {
    unsigned char dig[32]; unsigned int dl = 0;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_DigestInit_ex(m, EVP_sha256(), NULL);
    EVP_DigestUpdate(m, str, strlen(str));
    EVP_DigestFinal_ex(m, dig, &dl);
    EVP_MD_CTX_free(m);
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 6; i++) { out[i*2] = H[dig[i] >> 4]; out[i*2+1] = H[dig[i] & 0x0f]; }
    out[12] = '\0';
}

static void md5_hex(const char *str, char *hex_out /* 33 */) {
    unsigned char dig[16]; unsigned int dl = 0;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_DigestInit_ex(m, EVP_md5(), NULL);
    EVP_DigestUpdate(m, str, strlen(str));
    EVP_DigestFinal_ex(m, dig, &dl);
    EVP_MD_CTX_free(m);
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 16; i++) { hex_out[i*2] = H[dig[i] >> 4]; hex_out[i*2+1] = H[dig[i] & 0x0f]; }
    hex_out[32] = '\0';
}

static void x509_name_oids(X509_NAME *name, char *out, size_t outsz) {
    out[0] = '\0'; size_t off = 0;
    int n = X509_NAME_entry_count(name);
    for (int i = 0; i < n; i++) {
        X509_NAME_ENTRY *e = X509_NAME_get_entry(name, i);
        if (!e) continue;
        ASN1_OBJECT *o = X509_NAME_ENTRY_get_object(e);
        char dot[128];
        int dl = OBJ_obj2txt(dot, sizeof(dot), o, 1);
        if (dl <= 0) continue;
        int w = snprintf(out + off, outsz - off, "%s%.*s", i == 0 ? "" : ",", dl, dot);
        if (w < 0 || (size_t)w >= outsz - off) break;
        off += (size_t)w;
    }
}

static void x509_ext_oids(X509 *cert, char *out, size_t outsz) {
    out[0] = '\0'; size_t off = 0;
    int n = X509_get_ext_count(cert);
    for (int i = 0; i < n; i++) {
        X509_EXTENSION *e = X509_get_ext(cert, i);
        if (!e) continue;
        ASN1_OBJECT *o = X509_EXTENSION_get_object(e);
        char dot[128];
        int dl = OBJ_obj2txt(dot, sizeof(dot), o, 1);
        if (dl <= 0) continue;
        int w = snprintf(out + off, outsz - off, "%s%.*s", i == 0 ? "" : ",", dl, dot);
        if (w < 0 || (size_t)w >= outsz - off) break;
        off += (size_t)w;
    }
}

static void ja4x_from_cert(X509 *cert, char *out, size_t outsz) {
    out[0] = '\0';
    char io[2048] = "", so[2048] = "", eo[2048] = "";
    x509_name_oids(X509_get_issuer_name(cert),  io, sizeof(io));
    x509_name_oids(X509_get_subject_name(cert), so, sizeof(so));
    x509_ext_oids (cert,                        eo, sizeof(eo));
    char ih[13], sh[13], eh[13];
    sha256_hex12(io, ih); sha256_hex12(so, sh); sha256_hex12(eo, eh);
    snprintf(out, outsz, "%s_%s_%s", ih, sh, eh);
}

static const uint8_t *hs_body(const uint8_t *buf, size_t len, size_t *body_len) {
    if (len < 4) { *body_len = 0; return NULL; }
    if ((buf[0] == 1 || buf[0] == 2) && len >= 4) {
        size_t l = ((size_t)buf[1] << 16) | ((size_t)buf[2] << 8) | buf[3];
        if (l + 4 == len) { *body_len = l; return buf + 4; }
    }
    *body_len = len; return buf;
}

static void ja3s_from_server_hello(const uint8_t *hs, size_t hs_len, char *out, size_t outsz) {
    size_t blen = 0; const uint8_t *b = hs_body(hs, hs_len, &blen);
    if (!b || blen < 38) { out[0] = '\0'; return; }
    uint16_t version = ((uint16_t)b[0] << 8) | b[1];
    size_t p = 2 + 32; uint8_t sid_len = b[p++];
    if (p + sid_len + 3 > blen) { out[0] = '\0'; return; }
    p += sid_len;
    uint16_t cipher = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2; p += 1;
    int n = snprintf(out, outsz, "%u,%u,", version, cipher);
    if (n < 0 || (size_t)n >= outsz) return;
    size_t ext_off = (size_t)n;
    if (p + 2 <= blen) {
        uint16_t ext_len = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
        size_t end = p + ext_len; if (end > blen) end = blen;
        int first = 1;
        while (p + 4 <= end) {
            uint16_t et = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
            uint16_t el = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
            if (p + el > end) break;
            if (!is_grease(et)) {
                int w = snprintf(out + ext_off, outsz - ext_off, "%s%u", first ? "" : "-", et);
                if (w < 0 || (size_t)w >= outsz - ext_off) break;
                ext_off += (size_t)w; first = 0;
            }
            p += el;
        }
    }
    out[ext_off] = '\0';
}

static void ja3_from_client_hello(const uint8_t *hs, size_t hs_len, char *out, size_t outsz) {
    size_t blen = 0; const uint8_t *b = hs_body(hs, hs_len, &blen);
    if (!b || blen < 38) { out[0] = '\0'; return; }
    uint16_t version = ((uint16_t)b[0] << 8) | b[1];
    size_t p = 2 + 32; uint8_t sid_len = b[p++];
    if (p + sid_len + 2 > blen) { out[0] = '\0'; return; }
    p += sid_len;
    uint16_t cs_len = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
    if (p + cs_len + 1 > blen) { out[0] = '\0'; return; }
    const uint8_t *ciphers = b + p; size_t ciphers_n = cs_len; p += cs_len;
    uint8_t cm_len = b[p++];
    if (p + cm_len + 2 > blen) { out[0] = '\0'; return; }
    p += cm_len;
    uint16_t ext_len = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
    size_t ext_end = p + ext_len; if (ext_end > blen) ext_end = blen;
    const uint8_t *groups = NULL; size_t groups_n = 0;
    const uint8_t *ecpf = NULL;   size_t ecpf_n = 0;
    char ext_list[512]; ext_list[0] = '\0'; size_t ext_off = 0; int first = 1;
    size_t q = p;
    while (q + 4 <= ext_end) {
        uint16_t et = ((uint16_t)b[q] << 8) | b[q + 1]; q += 2;
        uint16_t el = ((uint16_t)b[q] << 8) | b[q + 1]; q += 2;
        if (q + el > ext_end) break;
        if (!is_grease(et)) {
            int w = snprintf(ext_list + ext_off, sizeof(ext_list) - ext_off, "%s%u", first ? "" : "-", et);
            if (w < 0 || (size_t)w >= sizeof(ext_list) - ext_off) break;
            ext_off += (size_t)w; first = 0;
        }
        if (et == 10 && el >= 2) { groups = b + q + 2; groups_n = ((size_t)b[q] << 8 | b[q + 1]); if (groups_n + 2 > el) groups_n = el - 2; }
        else if (et == 11 && el >= 1) { ecpf = b + q + 1; ecpf_n = b[q]; if (ecpf_n + 1 > el) ecpf_n = el - 1; }
        q += el;
    }
    int n = snprintf(out, outsz, "%u,", version);
    if (n < 0 || (size_t)n >= outsz) return;
    size_t off = (size_t)n;
    off = append_u16_list(out, outsz, off, ciphers, ciphers_n, 1);
    if (off + 1 >= outsz) return; out[off++] = ',';
    int w = snprintf(out + off, outsz - off, "%s,", ext_list);
    if (w < 0 || (size_t)w >= outsz - off) return; off += (size_t)w;
    off = append_u16_list(out, outsz, off, groups, groups_n, 1);
    if (off + 1 >= outsz) return; out[off++] = ',';
    int pf_first = 1;
    for (size_t i = 0; i < ecpf_n; i++) {
        w = snprintf(out + off, outsz - off, "%s%u", pf_first ? "" : "-", ecpf[i]);
        if (w < 0 || (size_t)w >= outsz - off) break;
        off += (size_t)w; pf_first = 0;
    }
    out[off] = '\0';
}

static int u16_cmp(const void *a, const void *b) {
    uint16_t x = *(const uint16_t *)a, y = *(const uint16_t *)b;
    return (x > y) - (x < y);
}

static void ja4_ver_chars(uint16_t v, char out[3]) {
    out[2] = '\0';
    switch (v) {
        case 0x0304: out[0]='1'; out[1]='3'; return;
        case 0x0303: out[0]='1'; out[1]='2'; return;
        case 0x0302: out[0]='1'; out[1]='1'; return;
        case 0x0301: out[0]='1'; out[1]='0'; return;
        case 0x0300: out[0]='s'; out[1]='3'; return;
        case 0x0002: out[0]='s'; out[1]='2'; return;
        case 0xfeff: out[0]='d'; out[1]='1'; return;
        case 0xfefd: out[0]='d'; out[1]='2'; return;
        case 0xfefc: out[0]='d'; out[1]='3'; return;
        default:     out[0]='0'; out[1]='0'; return;
    }
}

static int is_alnum_byte(uint8_t c) {
    return (c>='0'&&c<='9')||(c>='a'&&c<='z')||(c>='A'&&c<='Z');
}

static void ja4_alpn_chars(const uint8_t *ext_body, size_t ext_len, char out[3]) {
    out[0]='0'; out[1]='0'; out[2]='\0';
    if (ext_len < 3) return;
    size_t list_len = ((size_t)ext_body[0] << 8) | ext_body[1];
    if (list_len + 2 > ext_len || list_len < 2) return;
    uint8_t proto_len = ext_body[2];
    if (proto_len < 1 || (size_t)proto_len + 3 > ext_len) return;
    const uint8_t *p = ext_body + 3;
    uint8_t f = p[0], l = p[proto_len - 1];
    if (is_alnum_byte(f) && is_alnum_byte(l)) { out[0]=(char)f; out[1]=(char)l; }
    else { static const char H[]="0123456789abcdef"; out[0]=H[(f>>4)&0x0f]; out[1]=H[l&0x0f]; }
}

static size_t u16s_csv4(const uint16_t *v, size_t n, char *out, size_t outsz) {
    size_t off = 0;
    for (size_t i = 0; i < n; i++) {
        int w = snprintf(out + off, outsz - off, "%s%04x", i ? "," : "", v[i]);
        if (w < 0 || (size_t)w >= outsz - off) break;
        off += (size_t)w;
    }
    out[off] = '\0'; return off;
}

static void ja4_from_client_hello(const uint8_t *hs, size_t hs_len, char *out, size_t outsz) {
    out[0] = '\0';
    size_t blen = 0; const uint8_t *b = hs_body(hs, hs_len, &blen);
    if (!b || blen < 38) return;
    uint16_t legacy_version = ((uint16_t)b[0] << 8) | b[1];
    size_t p = 2 + 32; uint8_t sid_len = b[p++];
    if (p + sid_len + 2 > blen) return;
    p += sid_len;
    uint16_t cs_len = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
    if (p + cs_len + 1 > blen) return;
    const uint8_t *ciphers_raw = b + p; size_t ciphers_raw_n = cs_len; p += cs_len;
    uint8_t cm_len = b[p++];
    if (p + cm_len + 2 > blen) return;
    p += cm_len;
    uint16_t ext_total = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
    size_t ext_end = p + ext_total; if (ext_end > blen) ext_end = blen;
    uint16_t exts_all[128]; size_t exts_all_n = 0;
    uint16_t exts_hash[128]; size_t exts_hash_n = 0;
    uint16_t sigalgs[64]; size_t sigalgs_n = 0;
    int sni_present = 0; char alpn_cc[3] = {'0','0',0};
    uint16_t sv_max = 0; int sv_seen = 0;
    size_t q = p;
    while (q + 4 <= ext_end) {
        uint16_t et = ((uint16_t)b[q] << 8) | b[q + 1]; q += 2;
        uint16_t el = ((uint16_t)b[q] << 8) | b[q + 1]; q += 2;
        if (q + el > ext_end) break;
        const uint8_t *body = b + q;
        if (!is_grease(et)) {
            if (exts_all_n < 128) exts_all[exts_all_n++] = et;
            if (et != 0x0000 && et != 0x0010 && exts_hash_n < 128) exts_hash[exts_hash_n++] = et;
            if (et == 0x0000) sni_present = 1;
            if (et == 0x0010) ja4_alpn_chars(body, el, alpn_cc);
            if (et == 0x002b && el >= 1) {
                uint8_t llen = body[0];
                if ((size_t)llen + 1 <= el) for (size_t i = 0; i + 1 < llen; i += 2) {
                    uint16_t v = ((uint16_t)body[1+i] << 8) | body[2+i];
                    if (is_grease(v)) continue;
                    if (!sv_seen || v > sv_max) { sv_max = v; sv_seen = 1; }
                }
            }
            if (et == 0x000d && el >= 2) {
                size_t llen = ((size_t)body[0] << 8) | body[1];
                if (llen + 2 > el) llen = el - 2;
                for (size_t i = 0; i + 1 < llen && sigalgs_n < 64; i += 2) {
                    uint16_t v = ((uint16_t)body[2+i] << 8) | body[3+i];
                    if (is_grease(v)) continue;
                    sigalgs[sigalgs_n++] = v;
                }
            }
        }
        q += el;
    }
    uint16_t ciphers[128]; size_t ciphers_n = 0;
    for (size_t i = 0; i + 1 < ciphers_raw_n && ciphers_n < 128; i += 2) {
        uint16_t v = ((uint16_t)ciphers_raw[i] << 8) | ciphers_raw[i + 1];
        if (is_grease(v)) continue;
        ciphers[ciphers_n++] = v;
    }
    uint16_t real_ver = sv_seen ? sv_max : legacy_version;
    char ver_cc[3]; ja4_ver_chars(real_ver, ver_cc);
    size_t cc_d = ciphers_n > 99 ? 99 : ciphers_n;
    size_t ec_d = exts_all_n > 99 ? 99 : exts_all_n;
    char ja4_a[16];
    snprintf(ja4_a, sizeof(ja4_a), "t%s%c%02zu%02zu%s", ver_cc, sni_present ? 'd' : 'i', cc_d, ec_d, alpn_cc);
    qsort(ciphers, ciphers_n, sizeof(ciphers[0]), u16_cmp);
    char ciphers_csv[8 * 128]; u16s_csv4(ciphers, ciphers_n, ciphers_csv, sizeof(ciphers_csv));
    char hb[13]; sha256_hex12(ciphers_csv, hb);
    qsort(exts_hash, exts_hash_n, sizeof(exts_hash[0]), u16_cmp);
    char exts_csv[8 * 128]; u16s_csv4(exts_hash, exts_hash_n, exts_csv, sizeof(exts_csv));
    char sigs_csv[8 * 64]; u16s_csv4(sigalgs, sigalgs_n, sigs_csv, sizeof(sigs_csv));
    char c_input[sizeof(exts_csv) + sizeof(sigs_csv) + 2];
    snprintf(c_input, sizeof(c_input), "%s_%s", exts_csv, sigs_csv);
    char hc[13]; sha256_hex12(c_input, hc);
    snprintf(out, outsz, "%s_%s_%s", ja4_a, hb, hc);
}

static void ja4s_from_server_hello(const uint8_t *hs, size_t hs_len, char *out, size_t outsz) {
    out[0] = '\0';
    size_t blen = 0; const uint8_t *b = hs_body(hs, hs_len, &blen);
    if (!b || blen < 38) return;
    uint16_t legacy_version = ((uint16_t)b[0] << 8) | b[1];
    size_t p = 2 + 32; uint8_t sid_len = b[p++];
    if (p + sid_len + 3 > blen) return;
    p += sid_len;
    uint16_t cipher = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2; p += 1;
    uint16_t exts[64]; size_t exts_n = 0; char alpn_cc[3] = {'0','0',0};
    uint16_t sv = 0; int sv_seen = 0;
    if (p + 2 <= blen) {
        uint16_t ext_len = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
        size_t end = p + ext_len; if (end > blen) end = blen;
        while (p + 4 <= end) {
            uint16_t et = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
            uint16_t el = ((uint16_t)b[p] << 8) | b[p + 1]; p += 2;
            if (p + el > end) break;
            const uint8_t *body = b + p;
            if (!is_grease(et)) {
                if (exts_n < 64) exts[exts_n++] = et;
                if (et == 0x0010) ja4_alpn_chars(body, el, alpn_cc);
                if (et == 0x002b && el >= 2) { sv = ((uint16_t)body[0] << 8) | body[1]; sv_seen = 1; }
            }
            p += el;
        }
    }
    uint16_t real_ver = sv_seen ? sv : legacy_version;
    char ver_cc[3]; ja4_ver_chars(real_ver, ver_cc);
    size_t ec_d = exts_n > 99 ? 99 : exts_n;
    char ja4s_a[12]; snprintf(ja4s_a, sizeof(ja4s_a), "t%s%02zu%s", ver_cc, ec_d, alpn_cc);
    char exts_csv[8 * 64]; u16s_csv4(exts, exts_n, exts_csv, sizeof(exts_csv));
    char hc[13]; sha256_hex12(exts_csv, hc);
    snprintf(out, outsz, "%s_%04x_%s", ja4s_a, cipher, hc);
}

struct hs_capture {
    uint8_t client_hello[4096]; size_t client_hello_len;
    uint8_t server_hello[4096]; size_t server_hello_len;
};

static void msg_cb(int write_p, int version, int content_type,
                   const void *buf, size_t len, SSL *ssl, void *arg) {
    (void)version; (void)ssl;
    struct hs_capture *cap = arg;
    if (!cap || content_type != 22) return;
    if (len < 4 || len > sizeof(cap->client_hello)) return;
    const uint8_t *b = buf;
    if (write_p && b[0] == 1 && cap->client_hello_len == 0) { memcpy(cap->client_hello, b, len); cap->client_hello_len = len; }
    else if (!write_p && b[0] == 2 && cap->server_hello_len == 0) { memcpy(cap->server_hello, b, len); cap->server_hello_len = len; }
}

/* Build a CTX permissive enough to audit legacy servers (SECLEVEL 0). */
static SSL_CTX *audit_ctx(const SSL_METHOD *method, long minp, long maxp,
                          const char *cipher_list, struct hs_capture *cap) {
    SSL_CTX *ctx = SSL_CTX_new(method ? method : TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_security_level(ctx, 0);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    if (minp) SSL_CTX_set_min_proto_version(ctx, minp);
    if (maxp) SSL_CTX_set_max_proto_version(ctx, maxp);
    if (cipher_list) SSL_CTX_set_cipher_list(ctx, cipher_list);
    if (cap) { SSL_CTX_set_msg_callback(ctx, msg_cb); SSL_CTX_set_msg_callback_arg(ctx, cap); }
    return ctx;
}

static void fill_fingerprints(struct hs_capture *cap, SSL *ssl,
                              char *ja3_str, size_t ja3_str_sz, char *ja3_md5,
                              char *ja3s_str, size_t ja3s_str_sz, char *ja3s_md5,
                              char *ja4, size_t ja4_sz, char *ja4s, size_t ja4s_sz,
                              char *ja4x, size_t ja4x_sz) {
    X509 *peer = SSL_get_peer_certificate(ssl);
    if (peer && ja4x) { ja4x_from_cert(peer, ja4x, ja4x_sz); }
    if (peer) X509_free(peer);
    if (cap->client_hello_len) {
        if (ja3_str) { ja3_from_client_hello(cap->client_hello, cap->client_hello_len, ja3_str, ja3_str_sz); if (ja3_md5 && ja3_str[0]) md5_hex(ja3_str, ja3_md5); }
        if (ja4) ja4_from_client_hello(cap->client_hello, cap->client_hello_len, ja4, ja4_sz);
    }
    if (cap->server_hello_len) {
        if (ja3s_str) { ja3s_from_server_hello(cap->server_hello, cap->server_hello_len, ja3s_str, ja3s_str_sz); if (ja3s_md5 && ja3s_str[0]) md5_hex(ja3s_str, ja3s_md5); }
        if (ja4s) ja4s_from_server_hello(cap->server_hello, cap->server_hello_len, ja4s, ja4s_sz);
    }
}

/* ---- ps_tls_handshake (was do_handshake) --------------------------------- */

int ps_tls_handshake(const char *host, uint16_t port,
                     const struct ps_tls_attempt *a, struct ps_tls_result *out) {
    memset(out, 0, sizeof(*out));
    int fd = tp_tcp_connect(host, port, 4000);
    if (fd < 0) return -1;
    struct hs_capture cap; memset(&cap, 0, sizeof(cap));
    SSL_CTX *ctx = audit_ctx(a->method, a->min_proto, a->max_proto, a->cipher_list, &cap);
    if (!ctx) { close(fd); return -1; }
    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) == 1) {
        out->ok = 1;
        out->protocol_version = SSL_version(ssl);
        const char *cn = SSL_get_cipher_name(ssl);
        if (cn) snprintf(out->cipher, sizeof(out->cipher), "%s", cn);
        X509 *peer = SSL_get_peer_certificate(ssl);
        if (peer) { out->peer = peer; out->cert_present = 1; }
        out->chain = SSL_get_peer_cert_chain(ssl);
        fill_fingerprints(&cap, ssl,
                          out->ja3_str, sizeof(out->ja3_str), out->ja3_md5,
                          out->ja3s_str, sizeof(out->ja3s_str), out->ja3s_md5,
                          out->ja4, sizeof(out->ja4), out->ja4s, sizeof(out->ja4s),
                          out->ja4x, sizeof(out->ja4x));
    }
    SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
    return out->ok ? 0 : -1;
}

void ps_tls_result_free(struct ps_tls_result *r) { if (r->peer) X509_free(r->peer); }

/* ---- public leaf-cert + format helpers ----------------------------------- */

int ps_tls_cert_days_until_expiry(X509 *cert) {
    const ASN1_TIME *na = X509_get0_notAfter(cert);
    int pday = 0, psec = 0;
    if (ASN1_TIME_diff(&pday, &psec, NULL, na) == 0) return -99999;
    return pday;
}

int ps_tls_hostname_matches(X509 *cert, const char *host) {
    return X509_check_host(cert, host, 0, 0, NULL);
}

int ps_tls_weak_signature_alg(X509 *cert, char *out, size_t outsz) {
    const X509_ALGOR *sig_alg = NULL;
    X509_get0_signature(NULL, &sig_alg, cert);
    int nid = OBJ_obj2nid(sig_alg->algorithm);
    const char *sn = OBJ_nid2sn(nid);
    if (sn) snprintf(out, outsz, "%s", sn);
    return (nid == NID_md5WithRSAEncryption || nid == NID_sha1WithRSAEncryption || nid == NID_ecdsa_with_SHA1) ? 1 : 0;
}

void ps_tls_cert_sha256_hex(X509 *cert, char *out, size_t outsz) {
    unsigned char md[EVP_MAX_MD_SIZE]; unsigned int mdlen = 0;
    if (!X509_digest(cert, EVP_sha256(), md, &mdlen)) { out[0] = '\0'; return; }
    if (outsz < (size_t)mdlen * 2 + 1) { out[0] = '\0'; return; }
    static const char H[] = "0123456789abcdef";
    for (unsigned int i = 0; i < mdlen; i++) { out[i*2] = H[md[i] >> 4]; out[i*2+1] = H[md[i] & 0xf]; }
    out[mdlen * 2] = '\0';
}

void ps_tls_x509_name_cn(X509_NAME *n, char *out, size_t outsz) {
    out[0] = '\0';
    int idx = X509_NAME_get_index_by_NID(n, NID_commonName, -1);
    if (idx < 0) return;
    X509_NAME_ENTRY *e = X509_NAME_get_entry(n, idx);
    if (!e) return;
    ASN1_STRING *s = X509_NAME_ENTRY_get_data(e);
    if (!s) return;
    unsigned char *utf8 = NULL;
    int len = ASN1_STRING_to_UTF8(&utf8, s);
    if (len > 0 && utf8) { size_t k = (size_t)len < outsz - 1 ? (size_t)len : outsz - 1; memcpy(out, utf8, k); out[k] = '\0'; }
    if (utf8) OPENSSL_free(utf8);
}

void ps_tls_asn1_time_iso(const ASN1_TIME *t, char *out, size_t outsz) {
    out[0] = '\0';
    if (!t) return;
    BIO *b = BIO_new(BIO_s_mem());
    if (!b) return;
    if (ASN1_TIME_print(b, t)) { char buf[64] = ""; int n = BIO_read(b, buf, sizeof(buf) - 1); if (n > 0) { buf[n] = '\0'; snprintf(out, outsz, "%s", buf); } }
    BIO_free(b);
}

int ps_tls_json_str_escape(const char *src, char *dst, size_t dst_sz) {
    size_t o = 0;
    for (size_t i = 0; src[i]; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') { if (o + 2 >= dst_sz) return -1; dst[o++] = '\\'; dst[o++] = (char)c; }
        else if (c < 0x20) { if (o + 6 >= dst_sz) return -1; o += (size_t)snprintf(dst + o, dst_sz - o, "\\u%04x", c); }
        else { if (o + 1 >= dst_sz) return -1; dst[o++] = (char)c; }
    }
    dst[o] = '\0'; return 0;
}

void ps_tls_cert_sans_json(X509 *cert, char *out, size_t outsz) {
    out[0] = '\0';
    GENERAL_NAMES *gens = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (!gens) { snprintf(out, outsz, "[]"); return; }
    size_t o = 0;
    if (o + 1 >= outsz) { GENERAL_NAMES_free(gens); return; }
    out[o++] = '['; int first = 1;
    int count = sk_GENERAL_NAME_num(gens);
    for (int i = 0; i < count && i < 16; i++) {
        GENERAL_NAME *gn = sk_GENERAL_NAME_value(gens, i);
        if (gn->type != GEN_DNS && gn->type != GEN_IPADD) continue;
        char buf[256] = "";
        if (gn->type == GEN_DNS) {
            unsigned char *utf8 = NULL; int L = ASN1_STRING_to_UTF8(&utf8, gn->d.dNSName);
            if (L > 0 && utf8) { size_t k = (size_t)L < sizeof(buf) - 1 ? (size_t)L : sizeof(buf) - 1; memcpy(buf, utf8, k); buf[k] = '\0'; }
            if (utf8) OPENSSL_free(utf8);
        } else {
            const unsigned char *ip = ASN1_STRING_get0_data(gn->d.iPAddress);
            int iplen = ASN1_STRING_length(gn->d.iPAddress);
            if (iplen == 4) snprintf(buf, sizeof(buf), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
        }
        if (!buf[0]) continue;
        char esc[512];
        if (ps_tls_json_str_escape(buf, esc, sizeof(esc)) != 0) continue;
        size_t need = strlen(esc) + 3 + (first ? 0 : 1);
        if (o + need >= outsz) break;
        if (!first) out[o++] = ',';
        out[o++] = '"'; memcpy(out + o, esc, strlen(esc)); o += strlen(esc); out[o++] = '"';
        first = 0;
    }
    if (o + 1 < outsz) out[o++] = ']';
    out[o] = '\0';
    GENERAL_NAMES_free(gens);
}

const char *ps_tls_proto_str(int v) {
    switch (v) {
        case TLS1_VERSION:   return "TLSv1";
        case TLS1_1_VERSION: return "TLSv1.1";
        case TLS1_2_VERSION: return "TLSv1.2";
        case TLS1_3_VERSION: return "TLSv1.3";
        default: return "unknown";
    }
}

/* ---- proto label table --------------------------------------------------- */

long ps_tls_proto_id(const char *label) {
    if (!label) return 0;
    if (!strcmp(label, "SSLv3"))  return SSL3_VERSION;
    if (!strcmp(label, "TLS1.0")) return TLS1_VERSION;
    if (!strcmp(label, "TLS1.1")) return TLS1_1_VERSION;
    if (!strcmp(label, "TLS1.2")) return TLS1_2_VERSION;
    if (!strcmp(label, "TLS1.3")) return TLS1_3_VERSION;
    return -1;
}

void ps_tls_proto_label(int v, char *out, size_t outsz) {
    const char *s;
    switch (v) {
        case SSL3_VERSION:   s = "SSLv3";  break;
        case TLS1_VERSION:   s = "TLS1.0"; break;
        case TLS1_1_VERSION: s = "TLS1.1"; break;
        case TLS1_2_VERSION: s = "TLS1.2"; break;
        case TLS1_3_VERSION: s = "TLS1.3"; break;
        default: s = "unknown"; break;
    }
    snprintf(out, outsz, "%s", s);
}

/* STARTTLS prelude. NULL = no-op. Named modes implemented in Phase 2 (Task 8). */
static int starttls_prelude(int fd, const char *mode) {
    if (!mode || !mode[0]) return 0;
    (void)fd;
    return -1;
}

/* ---- ps_tls_probe (enumeration primitive) -------------------------------- */

int ps_tls_probe(const char *host, int port,
                 const char *min_proto, const char *max_proto,
                 const char *cipher_list, const char *starttls_mode,
                 int timeout_ms, struct ps_tls_probe_result *out) {
    memset(out, 0, sizeof(*out));
    long minp = min_proto ? ps_tls_proto_id(min_proto) : 0;
    long maxp = max_proto ? ps_tls_proto_id(max_proto) : 0;
    if (minp < 0 || maxp < 0) return -1;

    int fd = tp_tcp_connect(host, port, timeout_ms > 0 ? timeout_ms : 4000);
    if (fd < 0) return -1;
    if (starttls_prelude(fd, starttls_mode) != 0) { close(fd); return -1; }

    SSL_CTX *ctx = audit_ctx(NULL, minp, maxp, cipher_list, NULL);
    if (!ctx) { close(fd); return -1; }
    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) == 1) {
        out->ok = 1;
        ps_tls_proto_label(SSL_version(ssl), out->version, sizeof(out->version));
        const char *cn = SSL_get_cipher_name(ssl);
        if (cn) snprintf(out->cipher, sizeof(out->cipher), "%s", cn);
    }
    SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
    return 0;
}

/* ---- ps_tls_upgrade_fd (negotiated surfacing, continue-over-TLS) ---------- */

static void key_type_bits(X509 *cert, char *type, size_t tsz, int *bits) {
    type[0] = '\0'; *bits = 0;
    EVP_PKEY *pk = X509_get0_pubkey(cert);
    if (!pk) return;
    *bits = EVP_PKEY_bits(pk);
    switch (EVP_PKEY_base_id(pk)) {
        case EVP_PKEY_RSA:     snprintf(type, tsz, "RSA"); break;
        case EVP_PKEY_EC:      snprintf(type, tsz, "EC"); break;
        case EVP_PKEY_ED25519: snprintf(type, tsz, "ED25519"); break;
        case EVP_PKEY_ED448:   snprintf(type, tsz, "ED448"); break;
        default: snprintf(type, tsz, "%s", OBJ_nid2sn(EVP_PKEY_base_id(pk)) ? OBJ_nid2sn(EVP_PKEY_base_id(pk)) : "unknown"); break;
    }
}

/* Comma-join the JSON SAN array "[\"a\",\"b\"]" into "a,b". */
static void sans_csv(X509 *cert, char *out, size_t outsz) {
    char j[2048]; ps_tls_cert_sans_json(cert, j, sizeof(j));
    size_t o = 0; out[0] = '\0';
    for (size_t i = 0; j[i]; i++) {
        if (j[i] == '"' ) { /* copy until next quote */
            i++; while (j[i] && j[i] != '"' && o + 2 < outsz) out[o++] = j[i++];
            if (o + 1 < outsz) out[o++] = ',';
        }
    }
    if (o > 0 && out[o-1] == ',') o--;   /* trim trailing comma */
    out[o] = '\0';
}

SSL *ps_tls_upgrade_fd(int fd, const char *sni, const char *const *alpn,
                       int timeout_ms, struct ps_tls_info *info) {
    (void)timeout_ms;
    memset(info, 0, sizeof(*info));
    struct hs_capture cap; memset(&cap, 0, sizeof(cap));
    SSL_CTX *ctx = audit_ctx(NULL, 0, 0, NULL, &cap);
    if (!ctx) return NULL;
    if (alpn && alpn[0]) {
        /* build wire-format ALPN list */
        unsigned char wire[256]; size_t wo = 0;
        for (size_t i = 0; alpn[i] && wo < sizeof(wire); i++) {
            size_t l = strlen(alpn[i]); if (l > 255 || wo + 1 + l > sizeof(wire)) break;
            wire[wo++] = (unsigned char)l; memcpy(wire + wo, alpn[i], l); wo += l;
        }
        SSL_CTX_set_alpn_protos(ctx, wire, (unsigned)wo);
    }
    SSL *ssl = SSL_new(ctx);
    SSL_CTX_free(ctx);                 /* SSL holds its own ref */
    if (!ssl) return NULL;
    if (sni) SSL_set_tlsext_host_name(ssl, sni);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) { SSL_free(ssl); return NULL; }

    ps_tls_proto_label(SSL_version(ssl), info->version, sizeof(info->version));
    const char *cn = SSL_get_cipher_name(ssl);
    if (cn) snprintf(info->cipher, sizeof(info->cipher), "%s", cn);
    fill_fingerprints(&cap, ssl, NULL, 0, NULL, NULL, 0, NULL,
                      info->ja4, sizeof(info->ja4), info->ja4s, sizeof(info->ja4s),
                      info->ja4x, sizeof(info->ja4x));
    X509 *peer = SSL_get_peer_certificate(ssl);
    if (peer) {
        ps_tls_x509_name_cn(X509_get_subject_name(peer), info->cert_subject_cn, sizeof(info->cert_subject_cn));
        ps_tls_x509_name_cn(X509_get_issuer_name(peer),  info->cert_issuer_cn,  sizeof(info->cert_issuer_cn));
        ps_tls_asn1_time_iso(X509_get0_notBefore(peer), info->cert_not_before, sizeof(info->cert_not_before));
        ps_tls_asn1_time_iso(X509_get0_notAfter(peer),  info->cert_not_after,  sizeof(info->cert_not_after));
        info->cert_days_to_expiry = ps_tls_cert_days_until_expiry(peer);
        key_type_bits(peer, info->cert_key_type, sizeof(info->cert_key_type), &info->cert_key_bits);
        info->cert_self_signed = (X509_NAME_cmp(X509_get_subject_name(peer), X509_get_issuer_name(peer)) == 0) ? 1 : 0;
        ps_tls_weak_signature_alg(peer, info->cert_sig_alg, sizeof(info->cert_sig_alg));
        sans_csv(peer, info->cert_san, sizeof(info->cert_san));
        X509_free(peer);
    }
    return ssl;
}
