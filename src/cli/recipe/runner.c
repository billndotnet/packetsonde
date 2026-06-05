/*
 * `packetsonde recipe run <file> <target> [target ...]`
 *
 * Loads a recipe (signed envelope or raw canonical JSON), then for each
 * target runs the engine with real socket I/O via audit_common and emits
 * findings through ps_audit_api -> ps_output.
 */

#include "../args.h"
#include "../audit/audit_common.h"
#include "../output/output.h"
#include "../runstate.h"
#include "audit_module.h"
#include "finding.h"
#include "recipe.h"
#include "tls_probe.h"
#include "ulid.h"

#include <openssl/ssl.h>

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* ---- runner-local output emitter --------------------------------------- */

static struct ps_output *g_run_out;
static atomic_int        g_run_cancel;

static void api_emit(struct ps_finding *f) {
    if (g_run_out) ps_output_emit(g_run_out, f);
}
static int api_cancelled(void) {
    return atomic_load(&g_run_cancel);
}
static const struct ps_audit_api API = { api_emit, api_cancelled };

/* ---- real-socket I/O backend -------------------------------------------- */

/* fd -> SSL* side-map: after tls_upgrade(conn), send/recv on that conn ride TLS. */
#define IO_TLS_MAX 16
struct io_ctx {
    int default_timeout_ms;
    struct { int fd; SSL *ssl; struct ps_tls_info info; } tls[IO_TLS_MAX];
    size_t tls_n;
};

static SSL *io_ssl_for(struct io_ctx *c, int conn) {
    for (size_t i = 0; i < c->tls_n; i++)
        if (c->tls[i].fd == conn && c->tls[i].ssl) return c->tls[i].ssl;
    return NULL;
}

static int io_connect_tcp(void *vc, const char *host, int port, int timeout_ms) {
    (void)vc;
    return ps_audit_tcp_connect(host, (uint16_t)port, timeout_ms, NULL, 0);
}
static int io_connect_udp(void *vc, const char *host, int port, int timeout_ms) {
    (void)vc;
    return ps_audit_udp_connect(host, (uint16_t)port, timeout_ms, NULL, 0);
}
static int io_send_all(void *vc, int conn, const uint8_t *buf, size_t n) {
    SSL *ssl = io_ssl_for(vc, conn);
    if (ssl) {
        size_t sent = 0;
        while (sent < n) {
            int w = SSL_write(ssl, buf + sent, (int)(n - sent));
            if (w <= 0) return -1;
            sent += (size_t)w;
        }
        return 0;
    }
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = send(conn, buf + sent, n - sent, 0);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}
static long io_recv_some(void *vc, int conn, uint8_t *buf, size_t cap) {
    SSL *ssl = io_ssl_for(vc, conn);
    if (ssl) {
        int r = SSL_read(ssl, buf, (int)cap);
        if (r > 0) return r;
        return (SSL_get_error(ssl, r) == SSL_ERROR_ZERO_RETURN) ? 0 : -1;
    }
    for (;;) {
        ssize_t r = recv(conn, buf, cap, 0);
        if (r >= 0) return (long)r;
        if (errno == EINTR) continue;
        return -1;
    }
}
static void io_close_conn(void *vc, int conn) {
    struct io_ctx *c = vc;
    for (size_t i = 0; i < c->tls_n; i++) {
        if (c->tls[i].fd == conn && c->tls[i].ssl) {
            SSL_shutdown(c->tls[i].ssl);
            SSL_free(c->tls[i].ssl);
            c->tls[i].ssl = NULL;
            break;
        }
    }
    if (conn >= 0) close(conn);
}

static int io_tls_upgrade(void *vc, int conn, const char *sni,
                          const char *const *alpn, int timeout_ms) {
    struct io_ctx *c = vc;
    if (c->tls_n >= IO_TLS_MAX) return -1;
    struct ps_tls_info info;
    SSL *ssl = ps_tls_upgrade_fd(conn, sni, alpn, timeout_ms, &info);
    if (!ssl) return -1;
    c->tls[c->tls_n].fd = conn;
    c->tls[c->tls_n].ssl = ssl;
    c->tls[c->tls_n].info = info;
    c->tls_n++;
    return 0;
}
static int io_tls_session(void *vc, int conn, struct ps_tls_info *out) {
    struct io_ctx *c = vc;
    for (size_t i = 0; i < c->tls_n; i++)
        if (c->tls[i].fd == conn && c->tls[i].ssl) { *out = c->tls[i].info; return 0; }
    return -1;
}
static int io_tls_probe(void *vc, const char *host, int port,
                        const char *min_proto, const char *max_proto,
                        const char *cipher_list, const char *starttls_mode,
                        int timeout_ms, struct ps_tls_probe_result *out) {
    (void)vc;
    return ps_tls_probe(host, port, min_proto, max_proto, cipher_list,
                        starttls_mode, timeout_ms, out);
}

/* ---- finding sink (engine -> ps_finding via api->emit) ------------------ */

struct sink_ctx {
    const char *run_id;
    const char *self_host;
    char        source[PS_FIND_SOURCE_MAX];   /* "cli.recipe.<name>" */
    const char *target_host;
    int         target_port;
    const char *target_ip;     /* optional; resolved at run start if available */
};

static enum ps_severity sev_from(const char *s) {
    if (!strcmp(s, "info"))     return PS_SEV_INFO;
    if (!strcmp(s, "low"))      return PS_SEV_LOW;
    if (!strcmp(s, "medium"))   return PS_SEV_MEDIUM;
    if (!strcmp(s, "high"))     return PS_SEV_HIGH;
    if (!strcmp(s, "critical")) return PS_SEV_CRITICAL;
    return PS_SEV_INFO;
}
static enum ps_confidence conf_from(const char *s) {
    if (!strcmp(s, "tentative")) return PS_CONF_TENTATIVE;
    if (!strcmp(s, "firm"))      return PS_CONF_FIRM;
    if (!strcmp(s, "confirmed")) return PS_CONF_CONFIRMED;
    return PS_CONF_FIRM;
}

static void sink_emit(void *ctx, const char *kind, const char *sev,
                      const char *conf, const char *title,
                      const char *evidence_json) {
    struct sink_ctx *s = ctx;
    struct ps_finding f;
    ps_finding_init(&f, s->run_id, s->source, s->self_host, kind,
                    sev_from(sev), conf_from(conf), title);
    if (s->target_ip && s->target_ip[0])
        ps_finding_set_target_ip(&f, s->target_ip, (uint16_t)s->target_port);
    ps_finding_set_target_hostname(&f, s->target_host, (uint16_t)s->target_port);
    if (evidence_json && evidence_json[0])
        ps_finding_set_evidence_json(&f, evidence_json);
    API.emit(&f);
}

/* ---- file load --------------------------------------------------------- */

static int slurp_file(const char *path, uint8_t **out_buf, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    long sz = ftell(fp);
    if (sz < 0 || sz > 4 * 1024 * 1024) { fclose(fp); return -1; }
    rewind(fp);
    uint8_t *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return -1; }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) { free(buf); fclose(fp); return -1; }
    fclose(fp);
    buf[sz] = '\0';
    *out_buf = buf;
    *out_len = (size_t)sz;
    return 0;
}

static int load_recipe(const uint8_t *bytes, size_t len,
                       struct ps_recipe **out_recipe,
                       struct ps_recipe_envelope *out_env,
                       int *out_signed,
                       char *errbuf, size_t errbuf_sz) {
    /* Sniff: an envelope has the "recipe_b64" key. */
    if (memmem(bytes, len, "\"recipe_b64\"", 12) != NULL) {
        char eerr[256] = "";
        int rc = ps_recipe_envelope_parse(bytes, len, out_env, eerr, sizeof(eerr));
        if (rc != 0) {
            snprintf(errbuf, errbuf_sz, "envelope parse: %s", eerr);
            return -1;
        }
        char perr[256] = "";
        *out_recipe = ps_recipe_parse_json(out_env->inner_json, out_env->inner_json_len,
                                           perr, sizeof(perr));
        if (!*out_recipe) {
            ps_recipe_envelope_free(out_env);
            snprintf(errbuf, errbuf_sz, "recipe parse: %s", perr);
            return -1;
        }
        *out_signed = 1;
        return 0;
    }
    /* Plain recipe JSON. */
    char perr[256] = "";
    *out_recipe = ps_recipe_parse_json(bytes, len, perr, sizeof(perr));
    if (!*out_recipe) {
        snprintf(errbuf, errbuf_sz, "recipe parse: %s", perr);
        return -1;
    }
    *out_signed = 0;
    return 0;
}

static void usage(void) {
    fprintf(stderr,
        "Usage: packetsonde recipe run <file> <target> [target ...]\n"
        "\n"
        "  <file>     signed envelope (.signed.json) or raw canonical recipe JSON.\n"
        "  <target>   host:port; if omitted, the recipe's default_port is used.\n");
}

int ps_recipe_runner_main(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }
    const char *file = argv[1];
    if (argc < 3) { usage(); return 2; }

    uint8_t *bytes = NULL;
    size_t   bytes_n = 0;
    if (slurp_file(file, &bytes, &bytes_n) != 0) {
        fprintf(stderr, "packetsonde recipe run: cannot read '%s'\n", file);
        return 1;
    }

    struct ps_recipe *recipe = NULL;
    struct ps_recipe_envelope env;
    int is_signed = 0;
    char err[256] = "";
    if (load_recipe(bytes, bytes_n, &recipe, &env, &is_signed, err, sizeof(err)) != 0) {
        fprintf(stderr, "packetsonde recipe run: %s\n", err);
        free(bytes);
        return 1;
    }

    if (is_signed) {
        int sig_ok = ps_recipe_envelope_verify_sig(&env);
        if (!sig_ok) {
            fprintf(stderr,
                "packetsonde recipe run: signature INVALID. Local CLI runs accept\n"
                "  unverifiable envelopes, but the agent path will reject this.\n");
        }
        /* Keystore/authorization-flag check is the agent's job; local run
         * is for authoring + smoke testing. */
    }

    /* Output pipeline (shared with `audit`). */
    struct ps_output_opts oopts; memset(&oopts, 0, sizeof(oopts));
    switch (opts->fmt) {
        case PS_FMT_TEXT:  oopts.fmt_force = PS_OFMT_TEXT;  break;
        case PS_FMT_JSON:  oopts.fmt_force = PS_OFMT_JSON;  break;
        case PS_FMT_JSONL: oopts.fmt_force = PS_OFMT_JSONL; break;
        case PS_FMT_QUIET: oopts.fmt_force = PS_OFMT_QUIET; break;
        default:           oopts.fmt_force = 0;             break;
    }
    oopts.color = opts->no_color ? 0 : 1;
    struct ps_output out;
    ps_output_init(&out, &oopts);
    g_run_out = &out;
    atomic_store(&g_run_cancel, 0);

    char self_host[128] = "";
    gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1];
    ps_ulid_new(run_id, sizeof(run_id));

    struct io_ctx ioc = { .default_timeout_ms = 5000 };
    struct ps_recipe_io io_api = {
        .ctx = &ioc,
        .connect_tcp = io_connect_tcp,
        .connect_udp = io_connect_udp,
        .send_all    = io_send_all,
        .recv_some   = io_recv_some,
        .close_conn  = io_close_conn,
        .tls_upgrade = io_tls_upgrade,
        .tls_session = io_tls_session,
        .tls_probe   = io_tls_probe,
    };

    int exit_rc = 0;
    for (int ai = 2; ai < argc; ai++) {
        const char *spec = argv[ai];
        char host[256]; uint16_t port = 0;
        if (ps_audit_parse_target(spec, host, sizeof(host),
                                  (uint16_t)recipe->default_port, &port) != 0
            || port == 0) {
            fprintf(stderr, "packetsonde recipe run: bad target '%s'\n", spec);
            exit_rc = 2;
            continue;
        }

        struct sink_ctx sctx;
        memset(&sctx, 0, sizeof(sctx));
        sctx.run_id = run_id;
        sctx.self_host = self_host;
        snprintf(sctx.source, sizeof(sctx.source), "cli.recipe.%s",
                 recipe->name ? recipe->name : "anon");
        sctx.target_host = host;
        sctx.target_port = (int)port;

        struct ps_recipe_sink sink_api = { .ctx = &sctx, .emit = sink_emit };
        struct ps_recipe_target target = { .host = host, .port = (int)port };
        char rerr[256] = "";
        int rc = ps_recipe_run(recipe, &target, &io_api, &sink_api, rerr, sizeof(rerr));
        if (rc != 0) {
            fprintf(stderr, "packetsonde recipe run: %s on %s:%u — %s\n",
                    recipe->name ? recipe->name : "?", host, port, rerr);
            if (exit_rc == 0) exit_rc = 1;
        }
        if (api_cancelled()) break;
    }

    ps_output_snapshot(&out, &g_last_run_counts);
    g_run_out = NULL;
    ps_output_close(&out);

    ps_recipe_free(recipe);
    if (is_signed) ps_recipe_envelope_free(&env);
    free(bytes);
    return exit_rc;
}
