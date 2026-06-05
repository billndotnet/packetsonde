#ifndef PS_RECIPE_H
#define PS_RECIPE_H

/*
 * Recipe framework — v1 (spec: docs/specs/2026-06-01-recipe-framework.md).
 *
 * A recipe is a signed, declarative audit description. Wire form is JSON;
 * authors write YAML and `recipe build` produces the canonical JSON that
 * gets signed and pushed. The agent only ever sees signed JSON.
 *
 * This header covers the engine's read-side: envelope verification,
 * recipe parsing into an in-memory tree, plus the opcode + binding types
 * the interpreter (recipe_engine.c, separate file) walks. No networking
 * lives here.
 *
 * Memory model: every parse allocates a single arena owned by the
 * `ps_recipe` it returns. `ps_recipe_free` releases the whole arena.
 * Callers never free child strings / steps individually.
 */

#include <stddef.h>
#include <stdint.h>

#define PS_RECIPE_SCHEMA_V1 1
#define PS_RECIPE_SCHEMA_V2 2     /* TLS-aware engine (TLS_UPGRADE / TLS_ENUM) */
#define PS_RECIPE_SCHEMA_MAX 2    /* highest schema this build executes */

/* Opcode set. v1 = 1..8 (frozen); schema-2 adds the TLS opcodes. */
enum ps_recipe_op {
    PS_OP_CONNECT_TCP = 1,
    PS_OP_CONNECT_UDP,
    PS_OP_SEND,
    PS_OP_RECV,
    PS_OP_CLOSE,
    PS_OP_MATCH,
    PS_OP_IF,
    PS_OP_EMIT,
    PS_OP_TLS_UPGRADE,   /* schema 2 */
    PS_OP_TLS_ENUM,      /* schema 2 */
};

/* Binding types — see spec §4. */
enum ps_recipe_bt {
    PS_BT_NONE = 0,
    PS_BT_CONN,
    PS_BT_BYTES,
    PS_BT_STRING,
    PS_BT_INT,
    PS_BT_BOOL,
    PS_BT_STRLIST,       /* schema 2: ordered list of strings */
};

/* Severity / confidence — mirror the finding.h enums but kept as their
 * canonical strings here; the engine maps to ps_severity at emit time. */

/* A capture inside a `match` step: regex group named `name` produces a
 * binding of declared type `as` (string or int). */
struct ps_recipe_capture {
    const char           *name;
    enum ps_recipe_bt     as;
};

/* `recv.until` discriminator. */
enum ps_recipe_until {
    PS_UNTIL_NEWLINE = 1,
    PS_UNTIL_N_BYTES,
    PS_UNTIL_REGEX,
};

/* `if.cond` discriminator. */
enum ps_recipe_cond {
    PS_COND_EQUALS = 1,
    PS_COND_EXISTS,
    PS_COND_MATCHES,
    PS_COND_ANY_MATCHES,   /* schema 2: any element of a strlist matches regex */
    PS_COND_ANY_IN,        /* schema 2: any element of a strlist is in a set */
};

/* A reference resolves at run time to a typed value. `text` may be a
 * literal string ("a:b") or a reference template ("$target.host:$port").
 * `kind` says whether resolution is needed. */
enum ps_recipe_ref_kind {
    PS_REF_LITERAL = 0,   /* text used as-is */
    PS_REF_TEMPLATE,      /* contains $name / $target.* — substituted at run time */
};

struct ps_recipe_ref {
    enum ps_recipe_ref_kind  kind;
    const char              *text;
};

struct ps_recipe_step {
    enum ps_recipe_op  op;
    const char        *out;           /* output binding name (NULL if none) */
    enum ps_recipe_bt  out_type;      /* derived from op */

    /* Per-op fields — only the union member matching `op` is valid. */
    union {
        struct {
            struct ps_recipe_ref host;
            struct ps_recipe_ref port;       /* int-typed at validate time */
            int                  timeout_ms;
        } connect;
        struct {
            const char *conn;                /* binding name */
            const uint8_t *bytes;            /* literal bytes (may contain NULs) */
            size_t      bytes_len;
            int         bytes_is_template;   /* if 1, treat as UTF-8 template */
            const char *template_text;       /* set when is_template */
        } send;
        struct {
            const char *conn;
            enum ps_recipe_until until;
            int         n_bytes;             /* PS_UNTIL_N_BYTES */
            const char *regex;               /* PS_UNTIL_REGEX */
            int         max_bytes;
        } recv;
        struct {
            const char *conn;
        } close;
        struct {
            const char *in;                  /* binding name (scalar in mode) */
            const char *any;                 /* schema 2: strlist binding (any mode) */
            const char *regex;
            struct ps_recipe_capture *captures;
            size_t                    captures_n;
        } match;
        struct {
            enum ps_recipe_cond cond;
            const char *binding;             /* left side, always a binding */
            const char *literal;             /* right side for equals/matches */
            const char *list;                /* schema 2: strlist for any_matches/any_in */
            const char *regex;               /* schema 2: any_matches pattern */
            const char **set;                /* schema 2: any_in membership set */
            size_t      set_n;
            struct ps_recipe_step **then;    /* substep array */
            size_t                  then_n;
        } if_;
        struct {
            const char *kind;                /* finding kind (e.g. "vnc.metadata") */
            const char *severity;            /* "info"|"low"|"medium"|"high"|"critical" */
            const char *confidence;          /* "tentative"|"firm"|"confirmed" */
            const char *title;               /* template */
            /* evidence fields: each is (key, value-ref, declared-type). */
            struct ps_recipe_emit_field *fields;
            size_t                       fields_n;
        } emit;
        struct {                             /* schema 2 */
            const char          *conn;       /* conn binding to wrap in TLS */
            struct ps_recipe_ref sni;
            const char         **alpn;       /* NULL-terminated; may be NULL */
            int                  timeout_ms;
        } tls_upgrade;
        struct {                             /* schema 2 */
            struct ps_recipe_ref host;
            struct ps_recipe_ref port;
            const char         **protocols;  /* labels; NULL => default full set */
            size_t               protocols_n;
            const char          *starttls;   /* named mode or NULL */
            int                  timeout_ms;
        } tls_enum;
    } u;
};

struct ps_recipe_emit_field {
    const char           *key;
    struct ps_recipe_ref  value;
    enum ps_recipe_bt     as;
};

struct ps_recipe_budgets {
    int max_steps;
    int max_recv_bytes;
    int max_targets;
    int max_wallclock_ms;
    int max_tls_probes;       /* schema 2: cap on TLS handshakes per run */
};

struct ps_recipe {
    /* Arena that owns every string / struct hanging off this recipe.
     * Opaque to the caller — use ps_recipe_free. */
    void                       *_arena;

    int                         schema;       /* must be PS_RECIPE_SCHEMA_V1 */
    const char                 *name;
    int                         version;      /* author-specified recipe version */
    const char                 *description;  /* optional, may be NULL */
    const char                 *kind_prefix;  /* used to validate emit.kind */
    int                         default_port; /* 0 if unset */
    struct ps_recipe_budgets    budgets;

    struct ps_recipe_step     **steps;
    size_t                      steps_n;
};

/* Parse canonical JSON bytes into a recipe. On failure returns NULL and
 * fills `errbuf` (if non-NULL) with a one-line reason. */
struct ps_recipe *ps_recipe_parse_json(const uint8_t *json, size_t json_len,
                                       char *errbuf, size_t errbuf_sz);

/* Free a parsed recipe and everything hanging off it. NULL-safe. */
void ps_recipe_free(struct ps_recipe *r);

/* --- Envelope (spec §6) --------------------------------------------------- */

struct ps_recipe_envelope {
    /* Set on success. The inner_json buffer is part of an arena owned by
     * the envelope; it stays valid until ps_recipe_envelope_free. */
    int         schema;
    const uint8_t *inner_json;
    size_t         inner_json_len;
    uint8_t        recipe_sha256[32];
    uint8_t        author_pub[32];
    int64_t        signed_at_ms;
    uint8_t        signature[64];

    void          *_arena;
};

struct ps_keypair;  /* keystore.h */

/* Emit a signed envelope JSON for `recipe_bytes` (signed as-given) into `out`
 * (NUL-terminated). Computes SHA-256 of the bytes, Ed25519-signs
 * sha256‖author_pub‖signed_at_ms(BE) with `kp`, and writes the envelope object.
 * Returns the JSON length, or -1 on sign failure / output overflow. */
int ps_recipe_envelope_build(const uint8_t *recipe_bytes, size_t recipe_len,
                             const struct ps_keypair *kp, int64_t signed_at_ms,
                             char *out, size_t out_cap);

/* Parse a signed envelope from JSON. Verifies that recipe_sha256 matches
 * the actual SHA-256 of the inner recipe bytes; does NOT verify the
 * signature (use ps_recipe_envelope_verify_sig for that, separately —
 * useful for inspection tooling that wants to display info on a recipe
 * with an unknown / unauthorized key). Returns 0 on success, sets
 * errbuf on failure. */
int ps_recipe_envelope_parse(const uint8_t *json, size_t json_len,
                             struct ps_recipe_envelope *out,
                             char *errbuf, size_t errbuf_sz);

/* Verify the Ed25519 signature over the canonical 72-byte input
 *   recipe_sha256 (32) || author_pub (32) || signed_at_ms (8 BE).
 * Returns 1 if valid, 0 otherwise. Caller is responsible for separately
 * deciding whether `author_pub` is *trusted* (keystore lookup). */
int ps_recipe_envelope_verify_sig(const struct ps_recipe_envelope *env);

void ps_recipe_envelope_free(struct ps_recipe_envelope *env);

/* --- Engine (spec §11) ---------------------------------------------------- */

/* The target a recipe is being run against. Resolved by the caller from
 * a `host:port` argv string or from the dispatch frame's target list. */
struct ps_recipe_target {
    const char *host;
    int         port;
};

/* I/O backend. `connect_tcp` / `connect_udp` return a non-negative
 * connection handle (the engine treats it opaquely) or -1 on failure.
 * `recv_some` is a single best-effort read into `buf` of up to `cap`
 * bytes; the engine implements the per-step `until` semantics by calling
 * it in a loop. Returns >0 bytes read, 0 on EOF, -1 on error. */
/* Full definitions in tls_probe.h; forward-declared here so recipe.h consumers
 * don't pull in OpenSSL. The TLS callbacks may be NULL for schema-1-only backends. */
struct ps_tls_info;
struct ps_tls_probe_result;

struct ps_recipe_io {
    void *ctx;
    int    (*connect_tcp)(void *ctx, const char *host, int port, int timeout_ms);
    int    (*connect_udp)(void *ctx, const char *host, int port, int timeout_ms);
    int    (*send_all)   (void *ctx, int conn, const uint8_t *buf, size_t n);
    long   (*recv_some)  (void *ctx, int conn, uint8_t *buf, size_t cap);
    void   (*close_conn) (void *ctx, int conn);
    /* schema 2 — TLS. After tls_upgrade(conn) succeeds, send_all/recv_some on
     * that conn ride the encrypted channel. */
    int    (*tls_upgrade)(void *ctx, int conn, const char *sni,
                          const char *const *alpn, int timeout_ms);
    int    (*tls_session)(void *ctx, int conn, struct ps_tls_info *out);
    int    (*tls_probe)  (void *ctx, const char *host, int port,
                          const char *min_proto, const char *max_proto,
                          const char *cipher_list, const char *starttls_mode,
                          int timeout_ms, struct ps_tls_probe_result *out);
};

/* Findings sink. `evidence_json` is a complete JSON object (`{...}`) or
 * the empty string when the recipe's `emit` had no evidence fields. */
struct ps_recipe_sink {
    void *ctx;
    void  (*emit)(void *ctx,
                  const char *kind,
                  const char *severity,
                  const char *confidence,
                  const char *title,
                  const char *evidence_json);
};

/* Run a recipe against one target. Returns 0 on clean completion, -1 on
 * any failure (parse mismatch, I/O error, budget breach, regex compile
 * error). On non-zero return, `errbuf` (if provided) is filled with a
 * one-line diagnostic. Findings already emitted before the failure remain
 * delivered through `sink`. */
int ps_recipe_run(const struct ps_recipe *r,
                  const struct ps_recipe_target *target,
                  const struct ps_recipe_io *io,
                  const struct ps_recipe_sink *sink,
                  char *errbuf, size_t errbuf_sz);

#endif
