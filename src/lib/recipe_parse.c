#include "recipe.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * Arena allocator
 *
 * Every string and struct produced by a parse hangs off a single arena;
 * ps_recipe_free / ps_recipe_envelope_free destroys it in one call. The
 * arena chains 4 KiB pages and never reallocates a live allocation, so
 * returned pointers remain valid for the arena's lifetime.
 * ========================================================================= */

struct arena_page {
    struct arena_page *next;
    size_t             cap;
    size_t             used;
    /* page payload follows in the same allocation */
};

struct arena {
    struct arena_page *head;
};

#define ARENA_PAGE_BYTES 4096

static void *arena_alloc(struct arena *a, size_t n) {
    /* Align to 8. */
    n = (n + 7u) & ~(size_t)7u;
    struct arena_page *p = a->head;
    if (!p || p->used + n > p->cap) {
        size_t cap = ARENA_PAGE_BYTES;
        if (n > cap) cap = n;
        struct arena_page *np = malloc(sizeof(*np) + cap);
        if (!np) return NULL;
        np->next = a->head;
        np->cap  = cap;
        np->used = 0;
        a->head = np;
        p = np;
    }
    void *out = (char *)(p + 1) + p->used;
    p->used += n;
    return out;
}

static char *arena_strndup(struct arena *a, const char *s, size_t n) {
    char *out = arena_alloc(a, n + 1);
    if (!out) return NULL;
    memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

static void arena_destroy(struct arena *a) {
    struct arena_page *p = a->head;
    while (p) {
        struct arena_page *next = p->next;
        free(p);
        p = next;
    }
    a->head = NULL;
}

/* =========================================================================
 * Minimal JSON value parser
 *
 * Just what recipes need: object/array/string/int/bool/null. No floats,
 * no scientific notation, no surrogate pairs. Strict input — anything
 * else fails the parse rather than getting silently coerced.
 * ========================================================================= */

enum jv_kind { JV_NULL, JV_BOOL, JV_INT, JV_STR, JV_ARR, JV_OBJ };

struct jv {
    enum jv_kind kind;
    union {
        int      b;
        int64_t  i;
        struct { char *s; size_t n; } str;
        struct { struct jv **items; size_t n; } arr;
        struct {
            char **keys;
            struct jv **values;
            size_t n;
        } obj;
    } u;
};

struct jp {
    const uint8_t *src;
    size_t         len;
    size_t         pos;
    struct arena  *a;
    char          *err;       /* points to a buffer the caller owns */
    size_t         err_sz;
    int            schema;     /* recipe schema; gates schema-2 opcodes */
};

static void jp_err(struct jp *p, const char *fmt, ...) {
    if (!p->err || p->err_sz == 0) return;
    if (p->err[0] != '\0') return;  /* keep first error */
    va_list ap; va_start(ap, fmt);
    vsnprintf(p->err, p->err_sz, fmt, ap);
    va_end(ap);
}

static void jp_skip_ws(struct jp *p) {
    while (p->pos < p->len) {
        uint8_t c = p->src[p->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') p->pos++;
        else break;
    }
}

static int jp_expect(struct jp *p, char c) {
    jp_skip_ws(p);
    if (p->pos >= p->len || p->src[p->pos] != (uint8_t)c) {
        jp_err(p, "expected '%c' at offset %zu", c, p->pos);
        return -1;
    }
    p->pos++;
    return 0;
}

static struct jv *jv_new(struct jp *p, enum jv_kind k) {
    struct jv *v = arena_alloc(p->a, sizeof(*v));
    if (!v) { jp_err(p, "oom"); return NULL; }
    memset(v, 0, sizeof(*v));
    v->kind = k;
    return v;
}

static int parse_string(struct jp *p, char **out_s, size_t *out_n) {
    jp_skip_ws(p);
    if (p->pos >= p->len || p->src[p->pos] != '"') {
        jp_err(p, "expected string at offset %zu", p->pos);
        return -1;
    }
    p->pos++;
    /* Two-pass: first compute decoded length and validate. */
    size_t start = p->pos;
    size_t out_len = 0;
    while (p->pos < p->len) {
        uint8_t c = p->src[p->pos];
        if (c == '"') break;
        if (c == '\\') {
            if (p->pos + 1 >= p->len) { jp_err(p, "bad escape"); return -1; }
            uint8_t e = p->src[p->pos + 1];
            switch (e) {
                case '"': case '\\': case '/':
                case 'b': case 'f': case 'n': case 'r': case 't':
                    out_len++; p->pos += 2; break;
                default:
                    /* No \uXXXX in v1 — keep parser tiny; recipes don't need it. */
                    jp_err(p, "unsupported escape '\\%c'", e);
                    return -1;
            }
        } else if (c < 0x20) {
            jp_err(p, "control byte 0x%02x in string", c);
            return -1;
        } else {
            out_len++; p->pos++;
        }
    }
    if (p->pos >= p->len) { jp_err(p, "unterminated string"); return -1; }
    /* Allocate and decode. */
    char *buf = arena_alloc(p->a, out_len + 1);
    if (!buf) { jp_err(p, "oom"); return -1; }
    size_t i = start, w = 0;
    while (i < p->pos) {
        uint8_t c = p->src[i];
        if (c == '\\') {
            uint8_t e = p->src[i + 1];
            switch (e) {
                case '"':  buf[w++] = '"';  break;
                case '\\': buf[w++] = '\\'; break;
                case '/':  buf[w++] = '/';  break;
                case 'b':  buf[w++] = '\b'; break;
                case 'f':  buf[w++] = '\f'; break;
                case 'n':  buf[w++] = '\n'; break;
                case 'r':  buf[w++] = '\r'; break;
                case 't':  buf[w++] = '\t'; break;
            }
            i += 2;
        } else {
            buf[w++] = (char)c;
            i++;
        }
    }
    buf[out_len] = '\0';
    p->pos++; /* closing quote */
    *out_s = buf;
    *out_n = out_len;
    return 0;
}

static int parse_int(struct jp *p, int64_t *out) {
    jp_skip_ws(p);
    size_t start = p->pos;
    int neg = 0;
    if (p->pos < p->len && p->src[p->pos] == '-') { neg = 1; p->pos++; }
    if (p->pos >= p->len || !isdigit(p->src[p->pos])) {
        jp_err(p, "expected integer at offset %zu", start);
        return -1;
    }
    int64_t v = 0;
    while (p->pos < p->len && isdigit(p->src[p->pos])) {
        v = v * 10 + (p->src[p->pos] - '0');
        p->pos++;
    }
    if (p->pos < p->len && (p->src[p->pos] == '.' || p->src[p->pos] == 'e' || p->src[p->pos] == 'E')) {
        jp_err(p, "non-integer number at offset %zu", start);
        return -1;
    }
    *out = neg ? -v : v;
    return 0;
}

static struct jv *parse_value(struct jp *p);

static struct jv *parse_object(struct jp *p) {
    if (jp_expect(p, '{') != 0) return NULL;
    struct jv *v = jv_new(p, JV_OBJ);
    if (!v) return NULL;
    /* Grow keys/values arrays in powers of two. */
    size_t cap = 0;
    jp_skip_ws(p);
    if (p->pos < p->len && p->src[p->pos] == '}') { p->pos++; return v; }
    for (;;) {
        char  *key  = NULL; size_t key_n = 0;
        if (parse_string(p, &key, &key_n) != 0) return NULL;
        if (jp_expect(p, ':') != 0) return NULL;
        struct jv *val = parse_value(p);
        if (!val) return NULL;
        if (v->u.obj.n == cap) {
            size_t nc = cap ? cap * 2 : 4;
            char **nk = arena_alloc(p->a, nc * sizeof(*nk));
            struct jv **nv = arena_alloc(p->a, nc * sizeof(*nv));
            if (!nk || !nv) { jp_err(p, "oom"); return NULL; }
            if (cap) {
                memcpy(nk, v->u.obj.keys,   cap * sizeof(*nk));
                memcpy(nv, v->u.obj.values, cap * sizeof(*nv));
            }
            v->u.obj.keys = nk;
            v->u.obj.values = nv;
            cap = nc;
        }
        v->u.obj.keys[v->u.obj.n]   = key;
        v->u.obj.values[v->u.obj.n] = val;
        v->u.obj.n++;
        jp_skip_ws(p);
        if (p->pos < p->len && p->src[p->pos] == ',') { p->pos++; continue; }
        if (jp_expect(p, '}') != 0) return NULL;
        return v;
    }
}

static struct jv *parse_array(struct jp *p) {
    if (jp_expect(p, '[') != 0) return NULL;
    struct jv *v = jv_new(p, JV_ARR);
    if (!v) return NULL;
    size_t cap = 0;
    jp_skip_ws(p);
    if (p->pos < p->len && p->src[p->pos] == ']') { p->pos++; return v; }
    for (;;) {
        struct jv *item = parse_value(p);
        if (!item) return NULL;
        if (v->u.arr.n == cap) {
            size_t nc = cap ? cap * 2 : 4;
            struct jv **ni = arena_alloc(p->a, nc * sizeof(*ni));
            if (!ni) { jp_err(p, "oom"); return NULL; }
            if (cap) memcpy(ni, v->u.arr.items, cap * sizeof(*ni));
            v->u.arr.items = ni;
            cap = nc;
        }
        v->u.arr.items[v->u.arr.n++] = item;
        jp_skip_ws(p);
        if (p->pos < p->len && p->src[p->pos] == ',') { p->pos++; continue; }
        if (jp_expect(p, ']') != 0) return NULL;
        return v;
    }
}

static struct jv *parse_value(struct jp *p) {
    jp_skip_ws(p);
    if (p->pos >= p->len) { jp_err(p, "unexpected end of input"); return NULL; }
    uint8_t c = p->src[p->pos];
    if (c == '{') return parse_object(p);
    if (c == '[') return parse_array(p);
    if (c == '"') {
        struct jv *v = jv_new(p, JV_STR);
        if (!v) return NULL;
        if (parse_string(p, &v->u.str.s, &v->u.str.n) != 0) return NULL;
        return v;
    }
    if (c == 't' || c == 'f') {
        if (c == 't' && p->pos + 4 <= p->len && memcmp(p->src + p->pos, "true",  4) == 0) {
            p->pos += 4;
            struct jv *v = jv_new(p, JV_BOOL); if (!v) return NULL; v->u.b = 1; return v;
        }
        if (c == 'f' && p->pos + 5 <= p->len && memcmp(p->src + p->pos, "false", 5) == 0) {
            p->pos += 5;
            struct jv *v = jv_new(p, JV_BOOL); if (!v) return NULL; v->u.b = 0; return v;
        }
        jp_err(p, "bad literal at offset %zu", p->pos);
        return NULL;
    }
    if (c == 'n') {
        if (p->pos + 4 <= p->len && memcmp(p->src + p->pos, "null", 4) == 0) {
            p->pos += 4;
            return jv_new(p, JV_NULL);
        }
        jp_err(p, "bad literal at offset %zu", p->pos);
        return NULL;
    }
    if (c == '-' || isdigit(c)) {
        struct jv *v = jv_new(p, JV_INT); if (!v) return NULL;
        if (parse_int(p, &v->u.i) != 0) return NULL;
        return v;
    }
    jp_err(p, "unexpected '%c' at offset %zu", (char)c, p->pos);
    return NULL;
}

/* Convenience accessors. */
static struct jv *jv_obj_get(const struct jv *o, const char *key) {
    if (!o || o->kind != JV_OBJ) return NULL;
    for (size_t i = 0; i < o->u.obj.n; i++) {
        if (strcmp(o->u.obj.keys[i], key) == 0) return o->u.obj.values[i];
    }
    return NULL;
}

/* =========================================================================
 * Recipe schema walker
 *
 * Walks a parsed jv tree into a ps_recipe with build-time validation per
 * spec §4 §5. Maintains a binding-type table so $references can be
 * type-checked before any networking happens.
 * ========================================================================= */

#define BT_MAX 64

struct bt_entry {
    const char       *name;
    enum ps_recipe_bt type;
};
struct bt_table {
    struct bt_entry e[BT_MAX];
    size_t          n;
};

static int bt_declare(struct bt_table *t, const char *name, enum ps_recipe_bt ty,
                      char *err, size_t err_sz) {
    if (!name) return 0;
    for (size_t i = 0; i < t->n; i++) {
        if (strcmp(t->e[i].name, name) == 0) {
            snprintf(err, err_sz, "binding '%s' redeclared", name);
            return -1;
        }
    }
    if (t->n >= BT_MAX) {
        snprintf(err, err_sz, "binding table overflow (max %d)", BT_MAX);
        return -1;
    }
    t->e[t->n].name = name;
    t->e[t->n].type = ty;
    t->n++;
    return 0;
}

static enum ps_recipe_bt bt_lookup(const struct bt_table *t, const char *name) {
    for (size_t i = 0; i < t->n; i++) {
        if (strcmp(t->e[i].name, name) == 0) return t->e[i].type;
    }
    return PS_BT_NONE;
}

/* A "$target.host" / "$target.port" reference is always resolvable; other
 * $name references must match a declared binding. The check looks for any
 * '$' in the text and validates each name. Type checking against an
 * expected type happens at the call site.
 *
 * On error, returns -1 and fills err. */
static int validate_template_refs(const char *text, const struct bt_table *t,
                                  char *err, size_t err_sz) {
    const char *p = text;
    while (p && *p) {
        if (*p != '$') { p++; continue; }
        /* `$$` is a literal `$`. */
        if (p[1] == '$') { p += 2; continue; }
        const char *start = ++p;
        /* Accept the two fixed dotted tokens `target.host` / `target.port`
         * as special cases; otherwise a binding identifier is
         * [A-Za-z_][A-Za-z0-9_]*. Dots are NOT part of plain identifiers —
         * `$major.$minor` must split at the dot. */
        if (strncmp(p, "target.host", 11) == 0) { p += 11; continue; }
        if (strncmp(p, "target.port", 11) == 0) { p += 11; continue; }
        while (*p && (isalnum((unsigned char)*p) || *p == '_')) p++;
        size_t n = (size_t)(p - start);
        if (n == 0) {
            snprintf(err, err_sz, "lone '$' in template");
            return -1;
        }
        /* Otherwise must be a declared binding. */
        char namebuf[64];
        if (n >= sizeof(namebuf)) {
            snprintf(err, err_sz, "binding name too long in template");
            return -1;
        }
        memcpy(namebuf, start, n); namebuf[n] = '\0';
        if (bt_lookup(t, namebuf) == PS_BT_NONE) {
            snprintf(err, err_sz, "unknown binding '$%s' in template", namebuf);
            return -1;
        }
    }
    return 0;
}

static int build_ref(struct jp *p, struct ps_recipe_ref *out,
                     const char *text, char *err, size_t err_sz,
                     const struct bt_table *t) {
    (void)p;
    out->text = text;
    if (strchr(text, '$') != NULL) {
        out->kind = PS_REF_TEMPLATE;
        if (validate_template_refs(text, t, err, err_sz) != 0) return -1;
    } else {
        out->kind = PS_REF_LITERAL;
    }
    return 0;
}

static enum ps_recipe_bt bt_from_string(const char *s) {
    if (!s) return PS_BT_NONE;
    if (!strcmp(s, "string"))  return PS_BT_STRING;
    if (!strcmp(s, "int"))     return PS_BT_INT;
    if (!strcmp(s, "bool"))    return PS_BT_BOOL;
    if (!strcmp(s, "bytes"))   return PS_BT_BYTES;
    if (!strcmp(s, "strlist")) return PS_BT_STRLIST;
    return PS_BT_NONE;
}

static int expect_string(const struct jv *o, const char *key, const char **out,
                         char *err, size_t err_sz, const char *ctx) {
    struct jv *v = jv_obj_get(o, key);
    if (!v || v->kind != JV_STR) {
        snprintf(err, err_sz, "%s: missing or non-string '%s'", ctx, key);
        return -1;
    }
    *out = v->u.str.s;
    return 0;
}

static int expect_int(const struct jv *o, const char *key, int *out,
                      char *err, size_t err_sz, const char *ctx) {
    struct jv *v = jv_obj_get(o, key);
    if (!v || v->kind != JV_INT) {
        snprintf(err, err_sz, "%s: missing or non-integer '%s'", ctx, key);
        return -1;
    }
    if (v->u.i < INT32_MIN || v->u.i > INT32_MAX) {
        snprintf(err, err_sz, "%s: '%s' out of int32 range", ctx, key);
        return -1;
    }
    *out = (int)v->u.i;
    return 0;
}

static int opt_int(const struct jv *o, const char *key, int *out) {
    struct jv *v = jv_obj_get(o, key);
    if (!v) return 0;
    if (v->kind != JV_INT) return -1;
    if (v->u.i < INT32_MIN || v->u.i > INT32_MAX) return -1;
    *out = (int)v->u.i;
    return 0;
}

static int opt_string(const struct jv *o, const char *key, const char **out) {
    struct jv *v = jv_obj_get(o, key);
    if (!v) return 0;
    if (v->kind != JV_STR) return -1;
    *out = v->u.str.s;
    return 0;
}

static int validate_kind_prefix(const char *kind, const char *prefix,
                                char *err, size_t err_sz) {
    size_t pl = strlen(prefix);
    if (strncmp(kind, prefix, pl) != 0 || kind[pl] != '.') {
        snprintf(err, err_sz, "emit.kind '%s' must start with '%s.'", kind, prefix);
        return -1;
    }
    return 0;
}

static int is_severity(const char *s) {
    return s && (!strcmp(s, "info") || !strcmp(s, "low") || !strcmp(s, "medium")
                 || !strcmp(s, "high") || !strcmp(s, "critical"));
}
static int is_confidence(const char *s) {
    return s && (!strcmp(s, "tentative") || !strcmp(s, "firm") || !strcmp(s, "confirmed"));
}

/* Build a single step. Records new bindings into `t`. */
static struct ps_recipe_step *build_step(struct jp *p, const struct jv *o,
                                         struct bt_table *t,
                                         const char *kind_prefix,
                                         char *err, size_t err_sz);

static int build_steps_array(struct jp *p, const struct jv *arr,
                             struct ps_recipe_step ***out_steps, size_t *out_n,
                             struct bt_table *t,
                             const char *kind_prefix,
                             char *err, size_t err_sz) {
    if (arr->kind != JV_ARR) {
        snprintf(err, err_sz, "steps must be an array");
        return -1;
    }
    struct ps_recipe_step **arr_out =
        arena_alloc(p->a, arr->u.arr.n * sizeof(*arr_out));
    if (!arr_out && arr->u.arr.n) {
        snprintf(err, err_sz, "oom");
        return -1;
    }
    for (size_t i = 0; i < arr->u.arr.n; i++) {
        struct ps_recipe_step *s = build_step(p, arr->u.arr.items[i], t,
                                              kind_prefix, err, err_sz);
        if (!s) return -1;
        arr_out[i] = s;
    }
    *out_steps = arr_out;
    *out_n = arr->u.arr.n;
    return 0;
}

static struct ps_recipe_step *build_step(struct jp *p, const struct jv *o,
                                         struct bt_table *t,
                                         const char *kind_prefix,
                                         char *err, size_t err_sz) {
    if (o->kind != JV_OBJ) {
        snprintf(err, err_sz, "step must be an object");
        return NULL;
    }
    const char *op_s = NULL;
    if (expect_string(o, "op", &op_s, err, err_sz, "step") != 0) return NULL;

    struct ps_recipe_step *s = arena_alloc(p->a, sizeof(*s));
    if (!s) { snprintf(err, err_sz, "oom"); return NULL; }
    memset(s, 0, sizeof(*s));

    /* Optional `out` binding name (used by ops that produce bindings). */
    (void)opt_string(o, "out", &s->out);

    if (!strcmp(op_s, "connect_tcp") || !strcmp(op_s, "connect_udp")) {
        s->op = (!strcmp(op_s, "connect_tcp")) ? PS_OP_CONNECT_TCP : PS_OP_CONNECT_UDP;
        s->out_type = PS_BT_CONN;
        const char *host_s = NULL, *port_s = NULL;
        if (expect_string(o, "host", &host_s, err, err_sz, op_s) != 0) return NULL;
        /* port may be either int literal or template string; accept both. */
        struct jv *port_v = jv_obj_get(o, "port");
        char port_buf[32];
        if (!port_v) {
            snprintf(err, err_sz, "%s: missing 'port'", op_s); return NULL;
        }
        if (port_v->kind == JV_INT) {
            snprintf(port_buf, sizeof(port_buf), "%lld", (long long)port_v->u.i);
            port_s = arena_strndup(p->a, port_buf, strlen(port_buf));
            if (!port_s) { snprintf(err, err_sz, "oom"); return NULL; }
        } else if (port_v->kind == JV_STR) {
            port_s = port_v->u.str.s;
        } else {
            snprintf(err, err_sz, "%s: 'port' must be int or template string", op_s);
            return NULL;
        }
        if (expect_int(o, "timeout_ms", &s->u.connect.timeout_ms, err, err_sz, op_s) != 0)
            return NULL;
        if (build_ref(p, &s->u.connect.host, host_s, err, err_sz, t) != 0) return NULL;
        if (build_ref(p, &s->u.connect.port, port_s, err, err_sz, t) != 0) return NULL;
        if (!s->out) {
            snprintf(err, err_sz, "%s: missing 'out' binding", op_s);
            return NULL;
        }
        if (bt_declare(t, s->out, PS_BT_CONN, err, err_sz) != 0) return NULL;
        return s;
    }

    if (!strcmp(op_s, "send")) {
        s->op = PS_OP_SEND;
        if (expect_string(o, "conn", &s->u.send.conn, err, err_sz, "send") != 0) return NULL;
        if (bt_lookup(t, s->u.send.conn) != PS_BT_CONN) {
            snprintf(err, err_sz, "send: 'conn' must reference a conn binding"); return NULL;
        }
        /* bytes: string template OR object {"hex": "..."} */
        struct jv *b = jv_obj_get(o, "bytes");
        if (!b) { snprintf(err, err_sz, "send: missing 'bytes'"); return NULL; }
        if (b->kind == JV_STR) {
            s->u.send.bytes_is_template = 1;
            s->u.send.template_text = b->u.str.s;
            if (validate_template_refs(b->u.str.s, t, err, err_sz) != 0) return NULL;
        } else if (b->kind == JV_OBJ) {
            const char *hex = NULL;
            if (expect_string(b, "hex", &hex, err, err_sz, "send.bytes") != 0) return NULL;
            size_t hn = strlen(hex);
            if (hn % 2) { snprintf(err, err_sz, "send.bytes.hex: odd length"); return NULL; }
            uint8_t *buf = arena_alloc(p->a, hn / 2);
            if (!buf && hn) { snprintf(err, err_sz, "oom"); return NULL; }
            for (size_t i = 0; i < hn; i += 2) {
                int hi = hex[i], lo = hex[i + 1];
                int hv = (hi <= '9') ? hi - '0' : (hi | 0x20) - 'a' + 10;
                int lv = (lo <= '9') ? lo - '0' : (lo | 0x20) - 'a' + 10;
                if (hv < 0 || hv > 15 || lv < 0 || lv > 15) {
                    snprintf(err, err_sz, "send.bytes.hex: non-hex char"); return NULL;
                }
                buf[i / 2] = (uint8_t)((hv << 4) | lv);
            }
            s->u.send.bytes = buf;
            s->u.send.bytes_len = hn / 2;
        } else {
            snprintf(err, err_sz, "send.bytes: must be string template or {hex}");
            return NULL;
        }
        return s;
    }

    if (!strcmp(op_s, "recv")) {
        s->op = PS_OP_RECV;
        s->out_type = PS_BT_BYTES;
        if (expect_string(o, "conn", &s->u.recv.conn, err, err_sz, "recv") != 0) return NULL;
        if (bt_lookup(t, s->u.recv.conn) != PS_BT_CONN) {
            snprintf(err, err_sz, "recv: 'conn' must reference a conn binding"); return NULL;
        }
        const char *u = NULL;
        if (expect_string(o, "until", &u, err, err_sz, "recv") != 0) return NULL;
        if (!strcmp(u, "newline")) s->u.recv.until = PS_UNTIL_NEWLINE;
        else if (!strcmp(u, "n_bytes")) {
            s->u.recv.until = PS_UNTIL_N_BYTES;
            if (expect_int(o, "n_bytes", &s->u.recv.n_bytes, err, err_sz, "recv") != 0)
                return NULL;
        } else if (!strcmp(u, "regex")) {
            s->u.recv.until = PS_UNTIL_REGEX;
            if (expect_string(o, "regex", &s->u.recv.regex, err, err_sz, "recv") != 0)
                return NULL;
        } else {
            snprintf(err, err_sz, "recv.until: must be newline|n_bytes|regex"); return NULL;
        }
        if (expect_int(o, "max_bytes", &s->u.recv.max_bytes, err, err_sz, "recv") != 0)
            return NULL;
        if (!s->out) { snprintf(err, err_sz, "recv: missing 'out' binding"); return NULL; }
        if (bt_declare(t, s->out, PS_BT_BYTES, err, err_sz) != 0) return NULL;
        return s;
    }

    if (!strcmp(op_s, "close")) {
        s->op = PS_OP_CLOSE;
        if (expect_string(o, "conn", &s->u.close.conn, err, err_sz, "close") != 0) return NULL;
        if (bt_lookup(t, s->u.close.conn) != PS_BT_CONN) {
            snprintf(err, err_sz, "close: 'conn' must reference a conn binding"); return NULL;
        }
        return s;
    }

    if (!strcmp(op_s, "match")) {
        s->op = PS_OP_MATCH;
        /* schema 2: `any` mode matches the regex against any element of a strlist,
         * binding `out` (the first hit). Mutually exclusive with `in`. */
        if (jv_obj_get(o, "any")) {
            if (p->schema < PS_RECIPE_SCHEMA_V2) { snprintf(err, err_sz, "match.any requires schema 2"); return NULL; }
            if (expect_string(o, "any", &s->u.match.any, err, err_sz, "match") != 0) return NULL;
            if (bt_lookup(t, s->u.match.any) != PS_BT_STRLIST) {
                snprintf(err, err_sz, "match.any: '%s' must reference a strlist binding", s->u.match.any); return NULL;
            }
            if (expect_string(o, "regex", &s->u.match.regex, err, err_sz, "match") != 0) return NULL;
            if (s->out) { s->out_type = PS_BT_STRING; if (bt_declare(t, s->out, PS_BT_STRING, err, err_sz) != 0) return NULL; }
            return s;
        }
        if (expect_string(o, "in", &s->u.match.in, err, err_sz, "match") != 0) return NULL;
        enum ps_recipe_bt in_ty = bt_lookup(t, s->u.match.in);
        if (in_ty != PS_BT_BYTES && in_ty != PS_BT_STRING) {
            snprintf(err, err_sz, "match: 'in' must reference bytes or string binding");
            return NULL;
        }
        if (expect_string(o, "regex", &s->u.match.regex, err, err_sz, "match") != 0) return NULL;
        struct jv *cap = jv_obj_get(o, "captures");
        if (cap) {
            if (cap->kind != JV_ARR) {
                snprintf(err, err_sz, "match.captures: must be array"); return NULL;
            }
            struct ps_recipe_capture *cs =
                arena_alloc(p->a, cap->u.arr.n * sizeof(*cs));
            if (!cs && cap->u.arr.n) { snprintf(err, err_sz, "oom"); return NULL; }
            for (size_t i = 0; i < cap->u.arr.n; i++) {
                struct jv *ci = cap->u.arr.items[i];
                if (ci->kind != JV_OBJ) {
                    snprintf(err, err_sz, "match.captures[%zu]: must be object", i);
                    return NULL;
                }
                const char *nm = NULL, *as = NULL;
                if (expect_string(ci, "name", &nm, err, err_sz, "match.captures") != 0) return NULL;
                if (expect_string(ci, "as",   &as, err, err_sz, "match.captures") != 0) return NULL;
                enum ps_recipe_bt at = bt_from_string(as);
                if (at != PS_BT_STRING && at != PS_BT_INT) {
                    snprintf(err, err_sz, "match.captures[%zu].as: must be string|int", i);
                    return NULL;
                }
                cs[i].name = nm; cs[i].as = at;
                if (bt_declare(t, nm, at, err, err_sz) != 0) return NULL;
            }
            s->u.match.captures = cs;
            s->u.match.captures_n = cap->u.arr.n;
        }
        return s;
    }

    if (!strcmp(op_s, "emit")) {
        s->op = PS_OP_EMIT;
        if (expect_string(o, "kind",       &s->u.emit.kind,       err, err_sz, "emit") != 0) return NULL;
        if (expect_string(o, "severity",   &s->u.emit.severity,   err, err_sz, "emit") != 0) return NULL;
        if (expect_string(o, "confidence", &s->u.emit.confidence, err, err_sz, "emit") != 0) return NULL;
        if (expect_string(o, "title",      &s->u.emit.title,      err, err_sz, "emit") != 0) return NULL;
        if (!is_severity(s->u.emit.severity)) {
            snprintf(err, err_sz, "emit.severity: bad value '%s'", s->u.emit.severity);
            return NULL;
        }
        if (!is_confidence(s->u.emit.confidence)) {
            snprintf(err, err_sz, "emit.confidence: bad value '%s'", s->u.emit.confidence);
            return NULL;
        }
        if (validate_kind_prefix(s->u.emit.kind, kind_prefix, err, err_sz) != 0) return NULL;
        if (validate_template_refs(s->u.emit.title, t, err, err_sz) != 0) return NULL;
        struct jv *ev = jv_obj_get(o, "evidence");
        if (ev) {
            if (ev->kind != JV_OBJ) {
                snprintf(err, err_sz, "emit.evidence: must be object"); return NULL;
            }
            struct ps_recipe_emit_field *fs =
                arena_alloc(p->a, ev->u.obj.n * sizeof(*fs));
            if (!fs && ev->u.obj.n) { snprintf(err, err_sz, "oom"); return NULL; }
            for (size_t i = 0; i < ev->u.obj.n; i++) {
                struct jv *fv = ev->u.obj.values[i];
                /* Each value is either a string (template, default type string)
                 * or an object {"value": "...", "as": "int|bool|string"}. */
                fs[i].key = ev->u.obj.keys[i];
                if (fv->kind == JV_STR) {
                    fs[i].as = PS_BT_STRING;
                    if (build_ref(p, &fs[i].value, fv->u.str.s, err, err_sz, t) != 0)
                        return NULL;
                } else if (fv->kind == JV_OBJ) {
                    const char *as = NULL, *val = NULL;
                    if (expect_string(fv, "value", &val, err, err_sz, "emit.evidence") != 0) return NULL;
                    if (expect_string(fv, "as",    &as,  err, err_sz, "emit.evidence") != 0) return NULL;
                    enum ps_recipe_bt at = bt_from_string(as);
                    if (at == PS_BT_NONE || at == PS_BT_CONN) {
                        snprintf(err, err_sz, "emit.evidence.%s.as: invalid '%s'",
                                 ev->u.obj.keys[i], as);
                        return NULL;
                    }
                    fs[i].as = at;
                    if (build_ref(p, &fs[i].value, val, err, err_sz, t) != 0) return NULL;
                } else {
                    snprintf(err, err_sz, "emit.evidence.%s: must be string or object",
                             ev->u.obj.keys[i]);
                    return NULL;
                }
            }
            s->u.emit.fields = fs;
            s->u.emit.fields_n = ev->u.obj.n;
        }
        return s;
    }

    if (!strcmp(op_s, "if")) {
        s->op = PS_OP_IF;
        const char *c = NULL;
        if (expect_string(o, "cond", &c, err, err_sz, "if") != 0) return NULL;
        if      (!strcmp(c, "equals"))      s->u.if_.cond = PS_COND_EQUALS;
        else if (!strcmp(c, "exists"))      s->u.if_.cond = PS_COND_EXISTS;
        else if (!strcmp(c, "matches"))     s->u.if_.cond = PS_COND_MATCHES;
        else if (!strcmp(c, "any_matches")) s->u.if_.cond = PS_COND_ANY_MATCHES;
        else if (!strcmp(c, "any_in"))      s->u.if_.cond = PS_COND_ANY_IN;
        else { snprintf(err, err_sz, "if.cond: bad value '%s'", c); return NULL; }

        if (s->u.if_.cond == PS_COND_ANY_MATCHES || s->u.if_.cond == PS_COND_ANY_IN) {
            if (p->schema < PS_RECIPE_SCHEMA_V2) { snprintf(err, err_sz, "if.%s requires schema 2", c); return NULL; }
            if (expect_string(o, "list", &s->u.if_.list, err, err_sz, "if") != 0) return NULL;
            if (bt_lookup(t, s->u.if_.list) != PS_BT_STRLIST) {
                snprintf(err, err_sz, "if.%s: 'list' must reference a strlist binding", c); return NULL;
            }
            if (s->u.if_.cond == PS_COND_ANY_MATCHES) {
                if (expect_string(o, "regex", &s->u.if_.regex, err, err_sz, "if") != 0) return NULL;
            } else {
                struct jv *setv = jv_obj_get(o, "set");
                if (!setv || setv->kind != JV_ARR) { snprintf(err, err_sz, "if.any_in: 'set' must be an array"); return NULL; }
                const char **set = arena_alloc(p->a, (setv->u.arr.n ? setv->u.arr.n : 1) * sizeof(*set));
                if (!set) { snprintf(err, err_sz, "oom"); return NULL; }
                for (size_t i = 0; i < setv->u.arr.n; i++) {
                    struct jv *it = setv->u.arr.items[i];
                    if (it->kind != JV_STR) { snprintf(err, err_sz, "if.any_in.set[%zu]: must be a string", i); return NULL; }
                    set[i] = it->u.str.s;
                }
                s->u.if_.set = set; s->u.if_.set_n = setv->u.arr.n;
            }
        } else {
            if (expect_string(o, "binding", &s->u.if_.binding, err, err_sz, "if") != 0) return NULL;
            if (bt_lookup(t, s->u.if_.binding) == PS_BT_NONE) {
                snprintf(err, err_sz, "if: unknown binding '%s'", s->u.if_.binding); return NULL;
            }
            if (s->u.if_.cond != PS_COND_EXISTS) {
                if (expect_string(o, "literal", &s->u.if_.literal, err, err_sz, "if") != 0) return NULL;
            }
        }
        struct jv *thenv = jv_obj_get(o, "then");
        if (!thenv) { snprintf(err, err_sz, "if: missing 'then'"); return NULL; }
        if (build_steps_array(p, thenv, &s->u.if_.then, &s->u.if_.then_n,
                              t, kind_prefix, err, err_sz) != 0) return NULL;
        return s;
    }

    if (!strcmp(op_s, "tls_upgrade")) {
        if (p->schema < PS_RECIPE_SCHEMA_V2) { snprintf(err, err_sz, "tls_upgrade requires schema 2"); return NULL; }
        s->op = PS_OP_TLS_UPGRADE;
        if (expect_string(o, "conn", &s->u.tls_upgrade.conn, err, err_sz, "tls_upgrade") != 0) return NULL;
        if (bt_lookup(t, s->u.tls_upgrade.conn) != PS_BT_CONN) {
            snprintf(err, err_sz, "tls_upgrade: 'conn' must reference a conn binding"); return NULL;
        }
        const char *sni = NULL;
        if (expect_string(o, "sni", &sni, err, err_sz, "tls_upgrade") != 0) return NULL;
        if (build_ref(p, &s->u.tls_upgrade.sni, sni, err, err_sz, t) != 0) return NULL;
        (void)opt_int(o, "timeout_ms", &s->u.tls_upgrade.timeout_ms);
        struct jv *alpnv = jv_obj_get(o, "alpn");
        if (alpnv) {
            if (alpnv->kind != JV_ARR) { snprintf(err, err_sz, "tls_upgrade.alpn: must be an array"); return NULL; }
            const char **al = arena_alloc(p->a, (alpnv->u.arr.n + 1) * sizeof(*al));
            if (!al) { snprintf(err, err_sz, "oom"); return NULL; }
            for (size_t i = 0; i < alpnv->u.arr.n; i++) {
                struct jv *it = alpnv->u.arr.items[i];
                if (it->kind != JV_STR) { snprintf(err, err_sz, "tls_upgrade.alpn[%zu]: must be a string", i); return NULL; }
                al[i] = it->u.str.s;
            }
            al[alpnv->u.arr.n] = NULL;
            s->u.tls_upgrade.alpn = al;
        }
        static const struct { const char *n; enum ps_recipe_bt t; } TLSB[] = {
            {"tls_version", PS_BT_STRING}, {"tls_cipher", PS_BT_STRING}, {"tls_ja4", PS_BT_STRING},
            {"tls_ja4s", PS_BT_STRING}, {"tls_ja4x", PS_BT_STRING}, {"cert_subject_cn", PS_BT_STRING},
            {"cert_issuer_cn", PS_BT_STRING}, {"cert_not_after", PS_BT_STRING}, {"cert_sig_alg", PS_BT_STRING},
            {"cert_key_type", PS_BT_STRING}, {"cert_san", PS_BT_STRING}, {"cert_self_signed", PS_BT_STRING},
            {"cert_days_to_expiry", PS_BT_INT}, {"cert_key_bits", PS_BT_INT},
        };
        for (size_t i = 0; i < sizeof(TLSB) / sizeof(TLSB[0]); i++)
            if (bt_declare(t, TLSB[i].n, TLSB[i].t, err, err_sz) != 0) return NULL;
        return s;
    }

    if (!strcmp(op_s, "tls_enum")) {
        if (p->schema < PS_RECIPE_SCHEMA_V2) { snprintf(err, err_sz, "tls_enum requires schema 2"); return NULL; }
        s->op = PS_OP_TLS_ENUM;
        const char *host_s = NULL, *port_s = NULL;
        if (expect_string(o, "host", &host_s, err, err_sz, "tls_enum") != 0) return NULL;
        struct jv *pv = jv_obj_get(o, "port");
        char pb[32];
        if (!pv) { snprintf(err, err_sz, "tls_enum: missing 'port'"); return NULL; }
        if (pv->kind == JV_INT) {
            snprintf(pb, sizeof(pb), "%lld", (long long)pv->u.i);
            port_s = arena_strndup(p->a, pb, strlen(pb));
            if (!port_s) { snprintf(err, err_sz, "oom"); return NULL; }
        } else if (pv->kind == JV_STR) { port_s = pv->u.str.s; }
        else { snprintf(err, err_sz, "tls_enum: 'port' must be int or template string"); return NULL; }
        if (build_ref(p, &s->u.tls_enum.host, host_s, err, err_sz, t) != 0) return NULL;
        if (build_ref(p, &s->u.tls_enum.port, port_s, err, err_sz, t) != 0) return NULL;
        (void)opt_int(o, "timeout_ms", &s->u.tls_enum.timeout_ms);
        struct jv *pr = jv_obj_get(o, "protocols");
        if (pr) {
            if (pr->kind != JV_ARR) { snprintf(err, err_sz, "tls_enum.protocols: must be an array"); return NULL; }
            const char **ps = arena_alloc(p->a, (pr->u.arr.n ? pr->u.arr.n : 1) * sizeof(*ps));
            if (!ps) { snprintf(err, err_sz, "oom"); return NULL; }
            for (size_t i = 0; i < pr->u.arr.n; i++) {
                struct jv *it = pr->u.arr.items[i];
                if (it->kind != JV_STR) { snprintf(err, err_sz, "tls_enum.protocols[%zu]: must be a string", i); return NULL; }
                const char *L = it->u.str.s;
                if (strcmp(L, "SSLv3") && strcmp(L, "TLS1.0") && strcmp(L, "TLS1.1") &&
                    strcmp(L, "TLS1.2") && strcmp(L, "TLS1.3")) {
                    snprintf(err, err_sz, "tls_enum: bad protocol '%s'", L); return NULL;
                }
                ps[i] = L;
            }
            s->u.tls_enum.protocols = ps; s->u.tls_enum.protocols_n = pr->u.arr.n;
        }
        const char *st = NULL;
        if (opt_string(o, "starttls", &st) == 0 && st) {
            if (strcmp(st, "smtp") && strcmp(st, "imap") && strcmp(st, "pop3") &&
                strcmp(st, "ftp") && strcmp(st, "ldap")) {
                snprintf(err, err_sz, "tls_enum.starttls: bad mode '%s'", st); return NULL;
            }
            s->u.tls_enum.starttls = st;
        }
        if (bt_declare(t, "tls_accepted_protocols", PS_BT_STRLIST, err, err_sz) != 0) return NULL;
        if (bt_declare(t, "tls_accepted_ciphers",  PS_BT_STRLIST, err, err_sz) != 0) return NULL;
        return s;
    }

    snprintf(err, err_sz, "unknown opcode '%s'", op_s);
    return NULL;
}

/* Default budgets per spec §8. */
static void default_budgets(struct ps_recipe_budgets *b) {
    b->max_steps        = 200;
    b->max_recv_bytes   = 65536;
    b->max_targets      = 1024;
    b->max_wallclock_ms = 30000;
    b->max_tls_probes   = 200;
}

struct ps_recipe *ps_recipe_parse_json(const uint8_t *json, size_t json_len,
                                       char *errbuf, size_t errbuf_sz) {
    if (errbuf && errbuf_sz) errbuf[0] = '\0';
    char local_err[256] = "";
    char *err = errbuf ? errbuf : local_err;
    size_t err_sz = errbuf ? errbuf_sz : sizeof(local_err);

    struct arena *a = calloc(1, sizeof(*a));
    if (!a) { snprintf(err, err_sz, "oom"); return NULL; }
    struct jp p = { .src = json, .len = json_len, .pos = 0, .a = a,
                    .err = err, .err_sz = err_sz };
    struct jv *root = parse_value(&p);
    if (!root) { arena_destroy(a); free(a); return NULL; }
    if (root->kind != JV_OBJ) {
        snprintf(err, err_sz, "recipe root must be object");
        arena_destroy(a); free(a); return NULL;
    }

    struct ps_recipe *r = arena_alloc(a, sizeof(*r));
    if (!r) { snprintf(err, err_sz, "oom"); arena_destroy(a); free(a); return NULL; }
    memset(r, 0, sizeof(*r));
    r->_arena = a;
    default_budgets(&r->budgets);

    if (expect_int(root, "schema", &r->schema, err, err_sz, "recipe") != 0) goto fail;
    if (r->schema < PS_RECIPE_SCHEMA_V1 || r->schema > PS_RECIPE_SCHEMA_MAX) {
        snprintf(err, err_sz, "unsupported schema %d", r->schema); goto fail;
    }
    p.schema = r->schema;   /* gate schema-2 opcodes during step building */
    if (expect_string(root, "name", &r->name, err, err_sz, "recipe") != 0) goto fail;
    if (expect_int(root, "version", &r->version, err, err_sz, "recipe") != 0) goto fail;
    (void)opt_string(root, "description", &r->description);
    if (expect_string(root, "kind_prefix", &r->kind_prefix, err, err_sz, "recipe") != 0) goto fail;
    (void)opt_int(root, "default_port", &r->default_port);

    struct jv *bj = jv_obj_get(root, "budgets");
    if (bj) {
        (void)opt_int(bj, "max_steps",        &r->budgets.max_steps);
        (void)opt_int(bj, "max_recv_bytes",   &r->budgets.max_recv_bytes);
        (void)opt_int(bj, "max_targets",      &r->budgets.max_targets);
        (void)opt_int(bj, "max_wallclock_ms", &r->budgets.max_wallclock_ms);
        (void)opt_int(bj, "max_tls_probes",   &r->budgets.max_tls_probes);
    }

    struct jv *steps = jv_obj_get(root, "steps");
    if (!steps) { snprintf(err, err_sz, "recipe: missing 'steps'"); goto fail; }
    struct bt_table tab = {0};
    if (build_steps_array(&p, steps, &r->steps, &r->steps_n, &tab,
                          r->kind_prefix, err, err_sz) != 0) goto fail;

    return r;

fail:
    arena_destroy(a); free(a);
    return NULL;
}

void ps_recipe_free(struct ps_recipe *r) {
    if (!r) return;
    struct arena *a = r->_arena;
    if (a) { arena_destroy(a); free(a); }
}

/* =========================================================================
 * Envelope parse (spec §6) — defined here so it can share the JSON parser.
 * Signature verification lives in recipe_verify.c.
 * ========================================================================= */

/* base64 decode using OpenSSL's EVP_DecodeBlock (returns padded length;
 * caller must subtract trailing '=' padding accounted in the input). */
#include <openssl/evp.h>
#include <openssl/sha.h>

static int b64_decode(const char *in, size_t in_len, uint8_t *out, size_t *out_len) {
    /* Output cap: in_len * 3 / 4. */
    size_t cap = (in_len / 4) * 3;
    if (cap == 0 && in_len > 0) return -1;
    int n = EVP_DecodeBlock(out, (const unsigned char *)in, (int)in_len);
    if (n < 0) return -1;
    /* Adjust for padding. */
    size_t pad = 0;
    if (in_len >= 1 && in[in_len - 1] == '=') pad++;
    if (in_len >= 2 && in[in_len - 2] == '=') pad++;
    if ((size_t)n < pad) return -1;
    *out_len = (size_t)n - pad;
    return 0;
}

int ps_recipe_envelope_parse(const uint8_t *json, size_t json_len,
                             struct ps_recipe_envelope *out,
                             char *errbuf, size_t errbuf_sz) {
    if (errbuf && errbuf_sz) errbuf[0] = '\0';
    char local_err[256] = "";
    char *err = errbuf ? errbuf : local_err;
    size_t err_sz = errbuf ? errbuf_sz : sizeof(local_err);
    memset(out, 0, sizeof(*out));

    struct arena *a = calloc(1, sizeof(*a));
    if (!a) { snprintf(err, err_sz, "oom"); return -1; }
    struct jp p = { .src = json, .len = json_len, .pos = 0, .a = a,
                    .err = err, .err_sz = err_sz };
    struct jv *root = parse_value(&p);
    if (!root || root->kind != JV_OBJ) {
        if (root && err[0] == '\0')
            snprintf(err, err_sz, "envelope root must be object");
        arena_destroy(a); free(a); return -1;
    }
    if (expect_int(root, "schema", &out->schema, err, err_sz, "envelope") != 0) goto fail;
    if (out->schema != 1) { snprintf(err, err_sz, "unsupported envelope schema"); goto fail; }

    const char *recipe_b64 = NULL, *sha_hex = NULL, *pub_b64 = NULL, *sig_b64 = NULL;
    if (expect_string(root, "recipe_b64",    &recipe_b64, err, err_sz, "envelope") != 0) goto fail;
    if (expect_string(root, "recipe_sha256", &sha_hex,    err, err_sz, "envelope") != 0) goto fail;
    if (expect_string(root, "author_pub",    &pub_b64,    err, err_sz, "envelope") != 0) goto fail;
    if (expect_string(root, "signature",     &sig_b64,    err, err_sz, "envelope") != 0) goto fail;
    int64_t sm = 0;
    {
        struct jv *v = jv_obj_get(root, "signed_at_ms");
        if (!v || v->kind != JV_INT) {
            snprintf(err, err_sz, "envelope: missing or non-integer 'signed_at_ms'");
            goto fail;
        }
        sm = v->u.i;
    }
    out->signed_at_ms = sm;

    /* SHA-256 hex (64 chars). */
    size_t sl = strlen(sha_hex);
    if (sl != 64) { snprintf(err, err_sz, "envelope: bad recipe_sha256 length"); goto fail; }
    for (size_t i = 0; i < 32; i++) {
        int hi = sha_hex[i * 2], lo = sha_hex[i * 2 + 1];
        int hv = (hi <= '9') ? hi - '0' : (hi | 0x20) - 'a' + 10;
        int lv = (lo <= '9') ? lo - '0' : (lo | 0x20) - 'a' + 10;
        if (hv < 0 || hv > 15 || lv < 0 || lv > 15) {
            snprintf(err, err_sz, "envelope: non-hex in recipe_sha256"); goto fail;
        }
        out->recipe_sha256[i] = (uint8_t)((hv << 4) | lv);
    }

    /* base64 fields. EVP_DecodeBlock writes in multiples of 3, so it can emit up
     * to 2 padding bytes past the logical length; decode into temp buffers sized
     * for that and copy the exact bytes out (the fixed struct fields are adjacent —
     * decoding straight into them overflows into the next field). */
    size_t n;
    uint8_t pub_tmp[48], sig_tmp[72];
    if (b64_decode(pub_b64, strlen(pub_b64), pub_tmp, &n) != 0 || n != 32) {
        snprintf(err, err_sz, "envelope: bad author_pub base64"); goto fail;
    }
    memcpy(out->author_pub, pub_tmp, 32);
    if (b64_decode(sig_b64, strlen(sig_b64), sig_tmp, &n) != 0 || n != 64) {
        snprintf(err, err_sz, "envelope: bad signature base64"); goto fail;
    }
    memcpy(out->signature, sig_tmp, 64);
    /* recipe_b64 → arena buffer. */
    size_t rb_len = strlen(recipe_b64);
    uint8_t *inner = arena_alloc(a, rb_len); /* upper bound */
    if (!inner) { snprintf(err, err_sz, "oom"); goto fail; }
    size_t inner_n = 0;
    if (b64_decode(recipe_b64, rb_len, inner, &inner_n) != 0) {
        snprintf(err, err_sz, "envelope: bad recipe_b64"); goto fail;
    }
    /* Recompute SHA-256 over the inner bytes; must match the declared hash. */
    uint8_t calc[32];
    SHA256(inner, inner_n, calc);
    if (memcmp(calc, out->recipe_sha256, 32) != 0) {
        snprintf(err, err_sz, "envelope: recipe_sha256 mismatch"); goto fail;
    }
    out->inner_json = inner;
    out->inner_json_len = inner_n;
    out->_arena = a;
    return 0;

fail:
    arena_destroy(a); free(a);
    return -1;
}

void ps_recipe_envelope_free(struct ps_recipe_envelope *env) {
    if (!env) return;
    struct arena *a = env->_arena;
    if (a) { arena_destroy(a); free(a); }
    memset(env, 0, sizeof(*env));
}
