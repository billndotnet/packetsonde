#include "tls.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../signals.h"
#include "../util/fail_on.h"
#include "../workers/workers.h"
#include "../workers/limiter.h"
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
};

static void tls_result_free(struct tls_result *r) {
    if (r->peer) X509_free(r->peer);
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
    if (a->min_proto) SSL_CTX_set_min_proto_version(ctx, a->min_proto);
    if (a->max_proto) SSL_CTX_set_max_proto_version(ctx, a->max_proto);
    if (a->cipher_list) SSL_CTX_set_cipher_list(ctx, a->cipher_list);
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
    }
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return out->ok ? 0 : -1;
}

struct emit_ctx {
    struct ps_output *out;
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
    ps_output_emit(e->out, &f);
}

static void check_protocol(struct emit_ctx *e, const char *target_host) {
    struct tls_attempt a10 = { TLS_client_method(), TLS1_VERSION, TLS1_VERSION, NULL };
    struct tls_result  r10;
    if (do_handshake(target_host, e->target_port, &a10, &r10) == 0) {
        emit(e, "tls.weak_protocol", PS_SEV_HIGH, PS_CONF_FIRM,
             "TLS 1.0 negotiated successfully", "{\"protocol\":\"TLSv1\"}");
    }
    tls_result_free(&r10);

    struct tls_attempt a11 = { TLS_client_method(), TLS1_1_VERSION, TLS1_1_VERSION, NULL };
    struct tls_result  r11;
    if (do_handshake(target_host, e->target_port, &a11, &r11) == 0) {
        emit(e, "tls.weak_protocol", PS_SEV_HIGH, PS_CONF_FIRM,
             "TLS 1.1 negotiated successfully", "{\"protocol\":\"TLSv1.1\"}");
    }
    tls_result_free(&r11);
}

static void check_ciphers(struct emit_ctx *e, const char *target_host) {
    struct tls_attempt aw = {
        TLS_client_method(), TLS1_VERSION, TLS1_2_VERSION,
        "DES:3DES:RC4:NULL:EXP:MD5"
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

static void check_certificate(struct emit_ctx *e, const char *target_host) {
    struct tls_attempt a = { TLS_client_method(), 0, 0, NULL };
    struct tls_result  r;
    if (do_handshake(target_host, e->target_port, &a, &r) != 0 || !r.peer) {
        tls_result_free(&r);
        return;
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

int ps_audit_tls_run(int argc, char **argv, const struct ps_args *opts) {
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

    OPENSSL_init_ssl(0, NULL);

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

    struct ps_output_opts oopts;
    memset(&oopts, 0, sizeof(oopts));
    switch (opts->fmt) {
        case PS_FMT_TEXT:  oopts.fmt_force = PS_OFMT_TEXT;  break;
        case PS_FMT_JSON:  oopts.fmt_force = PS_OFMT_JSON;  break;
        case PS_FMT_JSONL: oopts.fmt_force = PS_OFMT_JSONL; break;
        case PS_FMT_QUIET: oopts.fmt_force = PS_OFMT_QUIET; break;
        default:           oopts.fmt_force = 0;             break;
    }
    oopts.color = opts->no_color ? 0 : 1;

    char append_path[512] = "";
    if (opts->auto_append) {
        const char *base = getenv("XDG_STATE_HOME");
        char default_base[400];
        if (!base || !base[0]) {
            const char *home = getenv("HOME");
            if (home && home[0]) {
                snprintf(default_base, sizeof(default_base), "%s/.local/state", home);
                base = default_base;
            } else {
                base = "/tmp";
            }
        }
        char dir[450];
        snprintf(dir, sizeof(dir), "%s/packetsonde", base);
        mkdir(base, 0755);
        mkdir(dir,  0755);
        struct timeval tv; gettimeofday(&tv, NULL);
        struct tm tm; gmtime_r(&tv.tv_sec, &tm);
        snprintf(append_path, sizeof(append_path),
                 "%s/findings-%04d-%02d-%02d.jsonl",
                 dir, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    }
    oopts.auto_append_path = append_path[0] ? append_path : NULL;

    struct ps_output out;
    ps_output_init(&out, &oopts);

    struct ps_limiter L;
    int rate = opts->rate_pps > 0 ? opts->rate_pps : 100;
    ps_limiter_init(&L, rate);

    struct ps_workers W;
    int concur = opts->concurrency > 0 ? opts->concurrency : 16;
    ps_workers_init(&W, concur, &L);
    ps_signals_install(&W);

    char ip[64] = "";
    int probe_fd = tcp_connect(target_host, target_port, 4000, ip, sizeof(ip));
    if (probe_fd < 0) {
        fprintf(stderr, "packetsonde audit tls: cannot connect to %s:%u\n", target_host, target_port);
        ps_workers_finish(&W); ps_workers_destroy(&W);
        ps_limiter_destroy(&L); ps_output_close(&out);
        return 1;
    }
    close(probe_fd);

    struct emit_ctx e;
    memset(&e, 0, sizeof(e));
    e.out = &out; e.run_id = run_id; e.self_host = self_host;
    e.target_host = target_host; e.target_ip = ip; e.target_port = target_port;

    if (!ps_workers_cancelled(&W)) check_protocol   (&e, target_host);
    if (!ps_workers_cancelled(&W)) check_ciphers    (&e, target_host);
    if (!ps_workers_cancelled(&W)) check_certificate(&e, target_host);

    ps_workers_finish(&W);
    ps_workers_destroy(&W);
    ps_limiter_destroy(&L);

    struct timeval t_end;
    gettimeofday(&t_end, NULL);
    long dt_ms = (t_end.tv_sec - t_start.tv_sec) * 1000L
               + (t_end.tv_usec - t_start.tv_usec) / 1000L;
    ps_output_summary(&out, run_id, dt_ms);

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
