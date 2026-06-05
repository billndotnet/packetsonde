#include "recipe.h"
#include "tls_probe.h"

#include <ctype.h>
#include <regex.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/*
 * Recipe interpreter — spec §11.
 *
 * Walks the parsed recipe step by step against a target. All I/O is
 * dispatched through the caller-supplied `ps_recipe_io` callbacks, so
 * the engine has no socket dependency: production calls into TCP/UDP,
 * tests call into an in-memory mock.
 *
 * Budgets (§8) are enforced live: every recv accumulates against
 * max_recv_bytes, every step increments max_steps, and a single wall
 * clock check after each step covers max_wallclock_ms.
 */

/* ---- private runtime arena (same shape as recipe_parse.c) -------------- */

struct rt_page {
    struct rt_page *next;
    size_t          cap;
    size_t          used;
};

struct rt_arena {
    struct rt_page *head;
};

static void *rt_alloc(struct rt_arena *a, size_t n) {
    n = (n + 7u) & ~(size_t)7u;
    struct rt_page *p = a->head;
    if (!p || p->used + n > p->cap) {
        size_t cap = 4096;
        if (n > cap) cap = n;
        struct rt_page *np = malloc(sizeof(*np) + cap);
        if (!np) return NULL;
        np->next = a->head; np->cap = cap; np->used = 0;
        a->head = np; p = np;
    }
    void *out = (char *)(p + 1) + p->used;
    p->used += n;
    return out;
}

static char *rt_strdup_n(struct rt_arena *a, const char *s, size_t n) {
    char *out = rt_alloc(a, n + 1);
    if (!out) return NULL;
    memcpy(out, s, n); out[n] = '\0';
    return out;
}

static void rt_arena_destroy(struct rt_arena *a) {
    struct rt_page *p = a->head;
    while (p) { struct rt_page *next = p->next; free(p); p = next; }
    a->head = NULL;
}

/* ---- runtime binding table ---------------------------------------------- */

#define RT_BINDINGS_MAX 64

struct rt_binding {
    const char       *name;
    enum ps_recipe_bt type;
    union {
        int            conn;
        struct { uint8_t *b; size_t n; } bytes;
        const char    *s;     /* arena-owned */
        int64_t        i;
        int            boolv;
        struct { const char **items; size_t n; } strlist;  /* arena-owned */
    } u;
};

struct rt {
    struct rt_arena         arena;
    struct rt_binding       bs[RT_BINDINGS_MAX];
    size_t                  bsn;

    const struct ps_recipe        *r;
    const struct ps_recipe_target *t;
    const struct ps_recipe_io     *io;
    const struct ps_recipe_sink   *sink;

    /* Budget bookkeeping. */
    int      steps_done;
    int      tls_probes_done;
    size_t   recv_bytes_total;
    int64_t  start_ms;

    char    *err;
    size_t   err_sz;
};

static int64_t now_ms(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + (int64_t)tv.tv_usec / 1000;
}

static void rt_err(struct rt *rt, const char *fmt, ...) {
    if (!rt->err || rt->err_sz == 0) return;
    if (rt->err[0] != '\0') return;
    va_list ap; va_start(ap, fmt);
    vsnprintf(rt->err, rt->err_sz, fmt, ap);
    va_end(ap);
}

static struct rt_binding *rt_lookup(struct rt *rt, const char *name) {
    if (!name) return NULL;
    for (size_t i = 0; i < rt->bsn; i++) {
        if (strcmp(rt->bs[i].name, name) == 0) return &rt->bs[i];
    }
    return NULL;
}

static struct rt_binding *rt_bind_new(struct rt *rt, const char *name,
                                      enum ps_recipe_bt ty) {
    if (rt->bsn >= RT_BINDINGS_MAX) {
        rt_err(rt, "binding table overflow");
        return NULL;
    }
    struct rt_binding *b = &rt->bs[rt->bsn++];
    b->name = name;
    b->type = ty;
    return b;
}

/* Budget gates ----------------------------------------------------------- */

static int budget_step(struct rt *rt) {
    rt->steps_done++;
    if (rt->steps_done > rt->r->budgets.max_steps) {
        rt_err(rt, "budget: max_steps exceeded (%d)", rt->r->budgets.max_steps);
        return -1;
    }
    if (now_ms() - rt->start_ms > rt->r->budgets.max_wallclock_ms) {
        rt_err(rt, "budget: max_wallclock_ms exceeded (%d)",
               rt->r->budgets.max_wallclock_ms);
        return -1;
    }
    return 0;
}

/* Counts one TLS handshake (upgrade or enumeration probe). */
static int budget_tls(struct rt *rt) {
    rt->tls_probes_done++;
    if (rt->tls_probes_done > rt->r->budgets.max_tls_probes) {
        rt_err(rt, "budget: max_tls_probes exceeded (%d)", rt->r->budgets.max_tls_probes);
        return -1;
    }
    return 0;
}

static const char *rt_strdup(struct rt *rt, const char *s) {
    return rt_strdup_n(&rt->arena, s, strlen(s));
}

static int bind_str(struct rt *rt, const char *name, const char *val) {
    struct rt_binding *b = rt_bind_new(rt, name, PS_BT_STRING);
    if (!b) return -1;
    b->u.s = rt_strdup(rt, val);
    return b->u.s ? 0 : -1;
}

static int bind_int(struct rt *rt, const char *name, int64_t val) {
    struct rt_binding *b = rt_bind_new(rt, name, PS_BT_INT);
    if (!b) return -1;
    b->u.i = val;
    return 0;
}

/* Copy a stack array of (arena-owned) strings into an arena-owned strlist binding. */
static int bind_strlist(struct rt *rt, const char *name, const char **items, size_t n) {
    struct rt_binding *b = rt_bind_new(rt, name, PS_BT_STRLIST);
    if (!b) return -1;
    const char **arr = rt_alloc(&rt->arena, (n ? n : 1) * sizeof(*arr));
    if (!arr) { rt_err(rt, "oom in strlist"); return -1; }
    for (size_t i = 0; i < n; i++) arr[i] = items[i];
    b->u.strlist.items = arr;
    b->u.strlist.n = n;
    return 0;
}

/* ---- template expansion ------------------------------------------------- */

/* Render a binding's value into a heap string in the runtime arena.
 * Returns NULL on type/lookup failure. */
static const char *render_binding(struct rt *rt, const char *name) {
    if (strcmp(name, "target.host") == 0) return rt->t->host;
    if (strcmp(name, "target.port") == 0) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d", rt->t->port);
        return rt_strdup_n(&rt->arena, buf, strlen(buf));
    }
    struct rt_binding *b = rt_lookup(rt, name);
    if (!b) { rt_err(rt, "render: unknown binding '%s'", name); return NULL; }
    char buf[64];
    switch (b->type) {
        case PS_BT_STRING: return b->u.s;
        case PS_BT_INT:
            snprintf(buf, sizeof(buf), "%lld", (long long)b->u.i);
            return rt_strdup_n(&rt->arena, buf, strlen(buf));
        case PS_BT_BOOL:
            return b->u.boolv ? "true" : "false";
        case PS_BT_BYTES:
            /* Render as raw bytes — assume printable. */
            return rt_strdup_n(&rt->arena, (const char *)b->u.bytes.b, b->u.bytes.n);
        case PS_BT_STRLIST: {
            /* Comma-join the items for evidence/templates. */
            size_t total = 1;
            for (size_t i = 0; i < b->u.strlist.n; i++) total += strlen(b->u.strlist.items[i]) + 1;
            char *out = rt_alloc(&rt->arena, total);
            if (!out) { rt_err(rt, "oom in strlist render"); return NULL; }
            size_t o = 0;
            for (size_t i = 0; i < b->u.strlist.n; i++) {
                if (i) out[o++] = ',';
                size_t l = strlen(b->u.strlist.items[i]);
                memcpy(out + o, b->u.strlist.items[i], l); o += l;
            }
            out[o] = '\0';
            return out;
        }
        default:
            rt_err(rt, "render: binding '%s' has non-stringable type", name);
            return NULL;
    }
}

/* Expand $name / $target.host / $target.port references in `tmpl` into
 * an arena-allocated string. */
static const char *expand_template(struct rt *rt, const char *tmpl) {
    if (!tmpl) return "";
    if (strchr(tmpl, '$') == NULL) return tmpl;

    char *out = NULL; size_t outlen = 0, outcap = 0;
    const char *p = tmpl;

    #define APPEND(src, n) do {                                       \
        if (outlen + (n) + 1 > outcap) {                              \
            size_t nc = outcap ? outcap * 2 : 64;                     \
            while (nc < outlen + (n) + 1) nc *= 2;                    \
            char *nb = rt_alloc(&rt->arena, nc);                      \
            if (!nb) { rt_err(rt, "oom in template"); return NULL; }  \
            if (outlen) memcpy(nb, out, outlen);                      \
            out = nb; outcap = nc;                                    \
        }                                                             \
        memcpy(out + outlen, (src), (n));                             \
        outlen += (n);                                                \
        out[outlen] = '\0';                                           \
    } while (0)

    while (*p) {
        if (*p != '$') { APPEND(p, 1); p++; continue; }
        if (p[1] == '$') { APPEND("$", 1); p += 2; continue; }
        const char *start = ++p;
        const char *name_end;
        if (strncmp(p, "target.host", 11) == 0) { p += 11; name_end = p; }
        else if (strncmp(p, "target.port", 11) == 0) { p += 11; name_end = p; }
        else {
            while (*p && (isalnum((unsigned char)*p) || *p == '_')) p++;
            name_end = p;
        }
        size_t nlen = (size_t)(name_end - start);
        if (nlen == 0) { rt_err(rt, "lone $ in template"); return NULL; }
        char namebuf[64];
        if (nlen >= sizeof(namebuf)) { rt_err(rt, "binding name too long"); return NULL; }
        memcpy(namebuf, start, nlen); namebuf[nlen] = '\0';
        const char *val = render_binding(rt, namebuf);
        if (!val) return NULL;
        size_t vl = strlen(val);
        APPEND(val, vl);
    }
    #undef APPEND
    return out ? out : "";
}

/* Resolve a ref to a typed value used by `emit` evidence (and templates
 * that should remain typed, e.g. `port:int`). */
static int resolve_as_int(struct rt *rt, const struct ps_recipe_ref *ref, int64_t *out) {
    /* If text is exactly a $name, look up the binding directly so we keep
     * the int. Otherwise expand template, then atoi. */
    if (ref->kind == PS_REF_LITERAL) {
        /* Literal — parse as integer. */
        char *end; long long v = strtoll(ref->text, &end, 10);
        if (*end != '\0') { rt_err(rt, "value '%s' not an integer", ref->text); return -1; }
        *out = (int64_t)v;
        return 0;
    }
    /* Template — common case is "$something". Resolve directly if so. */
    if (ref->text[0] == '$') {
        const char *name = ref->text + 1;
        if (strcmp(name, "target.port") == 0) { *out = rt->t->port; return 0; }
        /* Fixed-token "target.host" can't be an int. */
        struct rt_binding *b = rt_lookup(rt, name);
        if (b && b->type == PS_BT_INT) { *out = b->u.i; return 0; }
    }
    /* Fallback: expand to string, atoi. */
    const char *s = expand_template(rt, ref->text);
    if (!s) return -1;
    char *end; long long v = strtoll(s, &end, 10);
    if (*end != '\0') { rt_err(rt, "expanded '%s' not an integer", s); return -1; }
    *out = (int64_t)v;
    return 0;
}

static int resolve_as_bool(struct rt *rt, const struct ps_recipe_ref *ref, int *out) {
    const char *s = expand_template(rt, ref->text);
    if (!s) return -1;
    if (!strcmp(s, "true"))  { *out = 1; return 0; }
    if (!strcmp(s, "false")) { *out = 0; return 0; }
    rt_err(rt, "value '%s' not a boolean", s);
    return -1;
}

/* ---- JSON escape into a caller-managed buffer --------------------------- */

static int json_append_string(char *out, size_t cap, size_t *off, const char *s) {
    size_t o = *off;
    if (o + 1 >= cap) return -1;
    out[o++] = '"';
    for (size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        const char *esc = NULL;
        char ub[8];
        switch (c) {
            case '"':  esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\n': esc = "\\n";  break;
            case '\r': esc = "\\r";  break;
            case '\t': esc = "\\t";  break;
            case '\b': esc = "\\b";  break;
            case '\f': esc = "\\f";  break;
            default:
                if (c < 0x20) {
                    snprintf(ub, sizeof(ub), "\\u%04x", c);
                    esc = ub;
                }
        }
        if (esc) {
            size_t el = strlen(esc);
            if (o + el >= cap) return -1;
            memcpy(out + o, esc, el); o += el;
        } else {
            if (o + 1 >= cap) return -1;
            out[o++] = (char)c;
        }
    }
    if (o + 1 >= cap) return -1;
    out[o++] = '"';
    out[o] = '\0';
    *off = o;
    return 0;
}

/* Build emit evidence JSON from the recipe's typed field list. */
static int build_evidence_json(struct rt *rt, const struct ps_recipe_step *s,
                               char *out, size_t cap) {
    if (s->u.emit.fields_n == 0) { out[0] = '\0'; return 0; }
    size_t off = 0;
    if (off + 1 >= cap) return -1;
    out[off++] = '{';
    for (size_t i = 0; i < s->u.emit.fields_n; i++) {
        const struct ps_recipe_emit_field *f = &s->u.emit.fields[i];
        if (i > 0) {
            if (off + 1 >= cap) return -1;
            out[off++] = ',';
        }
        if (json_append_string(out, cap, &off, f->key) != 0) return -1;
        if (off + 1 >= cap) return -1;
        out[off++] = ':';
        switch (f->as) {
            case PS_BT_INT: {
                int64_t v;
                if (resolve_as_int(rt, &f->value, &v) != 0) return -1;
                int w = snprintf(out + off, cap - off, "%lld", (long long)v);
                if (w < 0 || (size_t)w >= cap - off) return -1;
                off += (size_t)w;
                break;
            }
            case PS_BT_BOOL: {
                int v;
                if (resolve_as_bool(rt, &f->value, &v) != 0) return -1;
                const char *lit = v ? "true" : "false";
                size_t l = strlen(lit);
                if (off + l >= cap) return -1;
                memcpy(out + off, lit, l); off += l;
                break;
            }
            case PS_BT_STRING:
            default: {
                const char *expanded = expand_template(rt, f->value.text);
                if (!expanded) return -1;
                if (json_append_string(out, cap, &off, expanded) != 0) return -1;
                break;
            }
        }
    }
    if (off + 1 >= cap) return -1;
    out[off++] = '}';
    out[off] = '\0';
    return 0;
}

/* ---- per-step handlers -------------------------------------------------- */

static int run_steps(struct rt *rt, struct ps_recipe_step *const *steps, size_t n);

static int do_connect(struct rt *rt, const struct ps_recipe_step *s) {
    const char *host = expand_template(rt, s->u.connect.host.text);
    if (!host) return -1;
    int64_t port;
    if (resolve_as_int(rt, &s->u.connect.port, &port) != 0) return -1;
    if (port <= 0 || port > 65535) { rt_err(rt, "connect: port out of range"); return -1; }
    int fd;
    if (s->op == PS_OP_CONNECT_TCP) {
        if (!rt->io->connect_tcp) { rt_err(rt, "io.connect_tcp not provided"); return -1; }
        fd = rt->io->connect_tcp(rt->io->ctx, host, (int)port, s->u.connect.timeout_ms);
    } else {
        if (!rt->io->connect_udp) { rt_err(rt, "io.connect_udp not provided"); return -1; }
        fd = rt->io->connect_udp(rt->io->ctx, host, (int)port, s->u.connect.timeout_ms);
    }
    if (fd < 0) { rt_err(rt, "connect %s:%d failed", host, (int)port); return -1; }
    struct rt_binding *b = rt_bind_new(rt, s->out, PS_BT_CONN);
    if (!b) return -1;
    b->u.conn = fd;
    return 0;
}

static int do_send(struct rt *rt, const struct ps_recipe_step *s) {
    struct rt_binding *cb = rt_lookup(rt, s->u.send.conn);
    if (!cb || cb->type != PS_BT_CONN) { rt_err(rt, "send: bad conn binding"); return -1; }
    const uint8_t *buf; size_t n;
    if (s->u.send.bytes_is_template) {
        const char *expanded = expand_template(rt, s->u.send.template_text);
        if (!expanded) return -1;
        buf = (const uint8_t *)expanded;
        n = strlen(expanded);
    } else {
        buf = s->u.send.bytes;
        n = s->u.send.bytes_len;
    }
    if (!rt->io->send_all) { rt_err(rt, "io.send_all not provided"); return -1; }
    if (rt->io->send_all(rt->io->ctx, cb->u.conn, buf, n) != 0) {
        rt_err(rt, "send failed (%zu bytes)", n);
        return -1;
    }
    return 0;
}

static int do_recv(struct rt *rt, const struct ps_recipe_step *s) {
    struct rt_binding *cb = rt_lookup(rt, s->u.recv.conn);
    if (!cb || cb->type != PS_BT_CONN) { rt_err(rt, "recv: bad conn binding"); return -1; }
    int cap = s->u.recv.max_bytes;
    if (cap <= 0 || cap > rt->r->budgets.max_recv_bytes) {
        rt_err(rt, "recv: max_bytes %d out of range", cap); return -1;
    }
    if (rt->recv_bytes_total + (size_t)cap > (size_t)rt->r->budgets.max_recv_bytes) {
        rt_err(rt, "budget: max_recv_bytes exceeded");
        return -1;
    }
    uint8_t *buf = rt_alloc(&rt->arena, (size_t)cap + 1);
    if (!buf) { rt_err(rt, "oom in recv"); return -1; }
    size_t got = 0;
    if (!rt->io->recv_some) { rt_err(rt, "io.recv_some not provided"); return -1; }
    /* Loop until the `until` condition fires or we hit max_bytes / EOF. */
    while (got < (size_t)cap) {
        long r = rt->io->recv_some(rt->io->ctx, cb->u.conn, buf + got, (size_t)cap - got);
        if (r < 0) { rt_err(rt, "recv I/O error"); return -1; }
        if (r == 0) break; /* EOF */
        got += (size_t)r;
        if (s->u.recv.until == PS_UNTIL_NEWLINE) {
            int found = 0;
            for (size_t i = got - (size_t)r; i < got; i++) {
                if (buf[i] == '\n') { found = 1; got = i + 1; break; }
            }
            if (found) break;
        } else if (s->u.recv.until == PS_UNTIL_N_BYTES) {
            if (got >= (size_t)s->u.recv.n_bytes) {
                got = (size_t)s->u.recv.n_bytes;
                break;
            }
        }
        /* PS_UNTIL_REGEX: caps at max_bytes; engine doesn't probe mid-stream
         * in v1 (regex-until is a step #3 follow-on). */
    }
    rt->recv_bytes_total += got;
    buf[got] = '\0';
    struct rt_binding *b = rt_bind_new(rt, s->out, PS_BT_BYTES);
    if (!b) return -1;
    b->u.bytes.b = buf;
    b->u.bytes.n = got;
    return 0;
}

static int do_close(struct rt *rt, const struct ps_recipe_step *s) {
    struct rt_binding *cb = rt_lookup(rt, s->u.close.conn);
    if (!cb || cb->type != PS_BT_CONN) { rt_err(rt, "close: bad conn binding"); return -1; }
    if (rt->io->close_conn) rt->io->close_conn(rt->io->ctx, cb->u.conn);
    cb->u.conn = -1;
    return 0;
}

static int do_match(struct rt *rt, const struct ps_recipe_step *s) {
    /* schema 2: match `any` element of a strlist against the regex. Binds `out`
     * (the first matching element) so downstream `if exists` can gate on it. */
    if (s->u.match.any) {
        struct rt_binding *lb = rt_lookup(rt, s->u.match.any);
        if (!lb || lb->type != PS_BT_STRLIST) { rt_err(rt, "match.any: '%s' not a strlist", s->u.match.any); return -1; }
        regex_t re;
        if (regcomp(&re, s->u.match.regex, REG_EXTENDED) != 0) { rt_err(rt, "match: regex compile failed"); return -1; }
        const char *hit = NULL;
        for (size_t i = 0; i < lb->u.strlist.n; i++) {
            if (regexec(&re, lb->u.strlist.items[i], 0, NULL, 0) == 0) { hit = lb->u.strlist.items[i]; break; }
        }
        regfree(&re);
        if (hit && s->out) return bind_str(rt, s->out, hit);
        return 0;
    }

    struct rt_binding *ib = rt_lookup(rt, s->u.match.in);
    if (!ib) { rt_err(rt, "match: unknown binding '%s'", s->u.match.in); return -1; }
    const char *hay; size_t hay_n;
    if (ib->type == PS_BT_BYTES) { hay = (const char *)ib->u.bytes.b; hay_n = ib->u.bytes.n; }
    else if (ib->type == PS_BT_STRING) { hay = ib->u.s; hay_n = strlen(hay); }
    else { rt_err(rt, "match: 'in' must be bytes or string"); return -1; }

    /* POSIX regex requires NUL-terminated input. The recv path already
     * appends a trailing NUL; tolerate embedded NULs by treating the
     * haystack as truncated at the first NUL. */
    (void)hay_n;
    regex_t re;
    if (regcomp(&re, s->u.match.regex, REG_EXTENDED) != 0) {
        rt_err(rt, "match: regex compile failed");
        return -1;
    }
    size_t ng = s->u.match.captures_n + 1;
    regmatch_t *mv = calloc(ng, sizeof(*mv));
    if (!mv) { regfree(&re); rt_err(rt, "oom"); return -1; }
    int rc = regexec(&re, hay, ng, mv, 0);
    if (rc != 0) {
        /* No match → captures unset. v1 leaves bindings undeclared; the
         * recipe author should gate downstream usage with `if exists`. */
        free(mv); regfree(&re);
        return 0;
    }
    for (size_t i = 0; i < s->u.match.captures_n; i++) {
        const struct ps_recipe_capture *c = &s->u.match.captures[i];
        regmatch_t m = mv[i + 1];
        if (m.rm_so < 0) { rt_err(rt, "match: capture '%s' not matched", c->name); free(mv); regfree(&re); return -1; }
        size_t len = (size_t)(m.rm_eo - m.rm_so);
        const char *p = hay + m.rm_so;
        struct rt_binding *b = rt_bind_new(rt, c->name, c->as);
        if (!b) { free(mv); regfree(&re); return -1; }
        if (c->as == PS_BT_INT) {
            char buf[32];
            if (len >= sizeof(buf)) { rt_err(rt, "match: int capture too long"); free(mv); regfree(&re); return -1; }
            memcpy(buf, p, len); buf[len] = '\0';
            b->u.i = strtoll(buf, NULL, 10);
        } else {
            b->u.s = rt_strdup_n(&rt->arena, p, len);
            if (!b->u.s) { rt_err(rt, "oom"); free(mv); regfree(&re); return -1; }
        }
    }
    free(mv); regfree(&re);
    return 0;
}

static int do_emit(struct rt *rt, const struct ps_recipe_step *s) {
    const char *title = expand_template(rt, s->u.emit.title);
    if (!title) return -1;
    char ev[8192];
    if (build_evidence_json(rt, s, ev, sizeof(ev)) != 0) {
        rt_err(rt, "emit: evidence overflow");
        return -1;
    }
    if (rt->sink && rt->sink->emit) {
        rt->sink->emit(rt->sink->ctx,
                       s->u.emit.kind, s->u.emit.severity, s->u.emit.confidence,
                       title, ev);
    }
    return 0;
}

static int do_if(struct rt *rt, const struct ps_recipe_step *s) {
    /* any_matches/any_in use `list`, not `binding` (which is NULL for them). */
    struct rt_binding *b = s->u.if_.binding ? rt_lookup(rt, s->u.if_.binding) : NULL;
    int taken = 0;
    switch (s->u.if_.cond) {
        case PS_COND_EXISTS:
            taken = (b != NULL);
            break;
        case PS_COND_EQUALS: {
            if (!b) { taken = 0; break; }
            const char *cur = NULL;
            char numbuf[32];
            if (b->type == PS_BT_STRING) cur = b->u.s;
            else if (b->type == PS_BT_INT) {
                snprintf(numbuf, sizeof(numbuf), "%lld", (long long)b->u.i);
                cur = numbuf;
            } else if (b->type == PS_BT_BYTES) cur = (const char *)b->u.bytes.b;
            else cur = "";
            taken = (strcmp(cur, s->u.if_.literal) == 0);
            break;
        }
        case PS_COND_MATCHES: {
            if (!b) { taken = 0; break; }
            const char *hay = (b->type == PS_BT_STRING) ? b->u.s
                            : (b->type == PS_BT_BYTES) ? (const char *)b->u.bytes.b
                            : "";
            regex_t re;
            if (regcomp(&re, s->u.if_.literal, REG_EXTENDED) != 0) {
                rt_err(rt, "if.matches: regex compile failed"); return -1;
            }
            taken = (regexec(&re, hay, 0, NULL, 0) == 0);
            regfree(&re);
            break;
        }
        case PS_COND_ANY_MATCHES: {
            struct rt_binding *lb = rt_lookup(rt, s->u.if_.list);
            if (!lb || lb->type != PS_BT_STRLIST) { taken = 0; break; }
            regex_t re;
            if (regcomp(&re, s->u.if_.regex, REG_EXTENDED) != 0) { rt_err(rt, "if.any_matches: regex compile failed"); return -1; }
            for (size_t i = 0; i < lb->u.strlist.n && !taken; i++)
                if (regexec(&re, lb->u.strlist.items[i], 0, NULL, 0) == 0) taken = 1;
            regfree(&re);
            break;
        }
        case PS_COND_ANY_IN: {
            struct rt_binding *lb = rt_lookup(rt, s->u.if_.list);
            if (!lb || lb->type != PS_BT_STRLIST) { taken = 0; break; }
            for (size_t i = 0; i < lb->u.strlist.n && !taken; i++)
                for (size_t j = 0; j < s->u.if_.set_n; j++)
                    if (strcmp(lb->u.strlist.items[i], s->u.if_.set[j]) == 0) { taken = 1; break; }
            break;
        }
    }
    if (taken) return run_steps(rt, s->u.if_.then, s->u.if_.then_n);
    return 0;
}

/* schema 2: wrap the current conn in TLS, surface the negotiated session +
 * leaf-cert facts as bindings (underscore names — the v1 template grammar
 * doesn't allow dots in $refs). On handshake failure, bindings stay unset. */
static int do_tls_upgrade(struct rt *rt, const struct ps_recipe_step *s) {
    struct rt_binding *cb = rt_lookup(rt, s->u.tls_upgrade.conn);
    if (!cb || cb->type != PS_BT_CONN) { rt_err(rt, "tls_upgrade: bad conn binding"); return -1; }
    if (!rt->io->tls_upgrade || !rt->io->tls_session) { rt_err(rt, "io.tls_upgrade not provided"); return -1; }
    if (budget_tls(rt) != 0) return -1;
    const char *sni = expand_template(rt, s->u.tls_upgrade.sni.text);
    if (!sni) return -1;
    if (rt->io->tls_upgrade(rt->io->ctx, cb->u.conn, sni, s->u.tls_upgrade.alpn,
                            s->u.tls_upgrade.timeout_ms) != 0)
        return 0;
    struct ps_tls_info info;
    if (rt->io->tls_session(rt->io->ctx, cb->u.conn, &info) != 0) { rt_err(rt, "tls_session failed"); return -1; }
    if (bind_str(rt, "tls_version", info.version) != 0) return -1;
    if (bind_str(rt, "tls_cipher", info.cipher) != 0) return -1;
    bind_str(rt, "tls_ja4", info.ja4);
    bind_str(rt, "tls_ja4s", info.ja4s);
    bind_str(rt, "tls_ja4x", info.ja4x);
    bind_str(rt, "cert_subject_cn", info.cert_subject_cn);
    bind_str(rt, "cert_issuer_cn", info.cert_issuer_cn);
    bind_str(rt, "cert_not_after", info.cert_not_after);
    bind_str(rt, "cert_sig_alg", info.cert_sig_alg);
    bind_str(rt, "cert_key_type", info.cert_key_type);
    bind_str(rt, "cert_san", info.cert_san);
    bind_str(rt, "cert_self_signed", info.cert_self_signed ? "1" : "0");
    bind_int(rt, "cert_days_to_expiry", info.cert_days_to_expiry);
    bind_int(rt, "cert_key_bits", info.cert_key_bits);
    return 0;
}

static const char *PS_DEFAULT_PROTOS[] = { "SSLv3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3" };

/* schema 2: enumerate accepted protocols/ciphers by cipher peeling. */
static int do_tls_enum(struct rt *rt, const struct ps_recipe_step *s) {
    if (!rt->io->tls_probe) { rt_err(rt, "io.tls_probe not provided"); return -1; }
    const char *host = expand_template(rt, s->u.tls_enum.host.text);
    if (!host) return -1;
    int64_t port;
    if (resolve_as_int(rt, &s->u.tls_enum.port, &port) != 0) return -1;
    const char **protos = s->u.tls_enum.protocols;
    size_t protos_n = s->u.tls_enum.protocols_n;
    if (!protos || protos_n == 0) { protos = PS_DEFAULT_PROTOS; protos_n = 5; }
    const char *starttls = s->u.tls_enum.starttls;
    int timeout = s->u.tls_enum.timeout_ms;

    const char *acc_protos[16];  size_t acc_protos_n = 0;
    const char *acc_ciphers[256]; size_t acc_ciphers_n = 0;

    for (size_t pi = 0; pi < protos_n; pi++) {
        const char *proto = protos[pi];
        char excl[2048]; snprintf(excl, sizeof(excl), "ALL:COMPLEMENTOFALL:@SECLEVEL=0");
        char last[128] = ""; int proto_added = 0;
        for (;;) {
            if (budget_tls(rt) != 0) return -1;
            struct ps_tls_probe_result res;
            if (rt->io->tls_probe(rt->io->ctx, host, (int)port, proto, proto,
                                  excl, starttls, timeout, &res) != 0) break;
            if (!res.ok || res.cipher[0] == '\0') break;
            if (strcmp(res.cipher, last) == 0) break;   /* no progress (TLS1.3 fixed suites) */
            if (!proto_added && acc_protos_n < 16) { acc_protos[acc_protos_n++] = rt_strdup(rt, proto); proto_added = 1; }
            if (acc_ciphers_n < 256) {
                char pc[200]; snprintf(pc, sizeof(pc), "%s:%s", proto, res.cipher);
                acc_ciphers[acc_ciphers_n++] = rt_strdup(rt, pc);
            }
            snprintf(last, sizeof(last), "%s", res.cipher);
            size_t l = strlen(excl);
            snprintf(excl + l, sizeof(excl) - l, ":!%s", res.cipher);
        }
    }
    if (bind_strlist(rt, "tls_accepted_protocols", acc_protos, acc_protos_n) != 0) return -1;
    if (bind_strlist(rt, "tls_accepted_ciphers", acc_ciphers, acc_ciphers_n) != 0) return -1;
    return 0;
}

static int run_steps(struct rt *rt, struct ps_recipe_step *const *steps, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (budget_step(rt) != 0) return -1;
        const struct ps_recipe_step *s = steps[i];
        int rc;
        switch (s->op) {
            case PS_OP_CONNECT_TCP:
            case PS_OP_CONNECT_UDP: rc = do_connect(rt, s); break;
            case PS_OP_SEND:        rc = do_send(rt, s);    break;
            case PS_OP_RECV:        rc = do_recv(rt, s);    break;
            case PS_OP_CLOSE:       rc = do_close(rt, s);   break;
            case PS_OP_MATCH:       rc = do_match(rt, s);   break;
            case PS_OP_EMIT:        rc = do_emit(rt, s);    break;
            case PS_OP_IF:          rc = do_if(rt, s);      break;
            case PS_OP_TLS_UPGRADE: rc = do_tls_upgrade(rt, s); break;
            case PS_OP_TLS_ENUM:    rc = do_tls_enum(rt, s);    break;
            default: rt_err(rt, "unknown op %d", s->op); return -1;
        }
        if (rc != 0) return -1;
    }
    return 0;
}

int ps_recipe_run(const struct ps_recipe *r,
                  const struct ps_recipe_target *target,
                  const struct ps_recipe_io *io,
                  const struct ps_recipe_sink *sink,
                  char *errbuf, size_t errbuf_sz) {
    if (errbuf && errbuf_sz) errbuf[0] = '\0';
    if (!r || !target || !io) return -1;

    struct rt rt = {0};
    rt.r = r; rt.t = target; rt.io = io; rt.sink = sink;
    rt.err = errbuf; rt.err_sz = errbuf_sz;
    rt.start_ms = now_ms();

    int rc = run_steps(&rt, r->steps, r->steps_n);

    /* Close any conns the recipe left open — frees the fd and, for upgraded
     * conns, the TLS session. do_close zeroes conn to -1, so this only hits
     * still-open ones. */
    if (rt.io && rt.io->close_conn) {
        for (size_t i = 0; i < rt.bsn; i++)
            if (rt.bs[i].type == PS_BT_CONN && rt.bs[i].u.conn >= 0)
                rt.io->close_conn(rt.io->ctx, rt.bs[i].u.conn);
    }

    rt_arena_destroy(&rt.arena);
    return rc;
}
