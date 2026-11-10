/* Observation dedupe: see obs_dedupe.h for the key format, the window
 * semantics and the summary event. */
#include "obs_dedupe.h"
#include "iso8601.h"
#include "json_extract.h"
#include "log.h"

#include <ctype.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

extern char **environ;

#define DEDUPE_MAX_DEPTH 32

/* ================================================================== */
/* Canonical key                                                       */
/* ================================================================== */

struct sb { char *b; size_t len, cap, lim; int err; };

static void sb_init(struct sb *s, size_t lim) { s->b = NULL; s->len = s->cap = 0; s->lim = lim; s->err = 0; }
static void sb_free(struct sb *s) { free(s->b); s->b = NULL; s->len = s->cap = 0; }
static void sb_put(struct sb *s, const char *p, size_t n) {
    if (s->err) return;
    if (s->len + n + 1 > s->lim) { s->err = 1; return; }
    if (s->len + n + 1 > s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 64;
        while (nc < s->len + n + 1) nc *= 2;
        if (nc > s->lim) nc = s->lim;
        char *nb = realloc(s->b, nc);
        if (!nb) { s->err = 1; return; }
        s->b = nb; s->cap = nc;
    }
    memcpy(s->b + s->len, p, n);
    s->len += n;
    s->b[s->len] = 0;
}
static void sb_c(struct sb *s, char c) { sb_put(s, &c, 1); }
static void sb_s(struct sb *s, const char *z) { sb_put(s, z, strlen(z)); }

struct parser { const char *p, *end; int err; };

static void skip_ws(struct parser *P) {
    while (P->p < P->end && (*P->p == ' ' || *P->p == '\t' || *P->p == '\n' || *P->p == '\r')) P->p++;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int read_u4(struct parser *P, unsigned *out) {
    if (P->end - P->p < 4) return -1;
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        int h = hexval(P->p[i]);
        if (h < 0) return -1;
        v = v * 16 + (unsigned)h;
    }
    P->p += 4;
    *out = v;
    return 0;
}
static void put_utf8(struct sb *s, unsigned cp) {
    char b[4];
    if (cp < 0x80) { b[0] = (char)cp; sb_put(s, b, 1); }
    else if (cp < 0x800) { b[0] = (char)(0xC0 | (cp >> 6)); b[1] = (char)(0x80 | (cp & 0x3F)); sb_put(s, b, 2); }
    else if (cp < 0x10000) {
        b[0] = (char)(0xE0 | (cp >> 12)); b[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        b[2] = (char)(0x80 | (cp & 0x3F)); sb_put(s, b, 3);
    } else {
        b[0] = (char)(0xF0 | (cp >> 18)); b[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        b[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); b[3] = (char)(0x80 | (cp & 0x3F)); sb_put(s, b, 4);
    }
}

/* Parse a JSON string at P->p (on the opening quote) into decoded UTF-8. */
static int parse_string(struct parser *P, struct sb *dec) {
    if (P->p >= P->end || *P->p != '"') return -1;
    P->p++;
    while (P->p < P->end) {
        unsigned char c = (unsigned char)*P->p;
        if (c == '"') { P->p++; if (!dec->b) sb_put(dec, "", 0); return dec->err ? -1 : 0; }
        if (c < 0x20) return -1;
        if (c != '\\') { sb_put(dec, P->p, 1); P->p++; continue; }
        P->p++;
        if (P->p >= P->end) return -1;
        char e = *P->p++;
        switch (e) {
        case '"': sb_c(dec, '"'); break;
        case '\\': sb_c(dec, '\\'); break;
        case '/': sb_c(dec, '/'); break;
        case 'b': sb_c(dec, '\b'); break;
        case 'f': sb_c(dec, '\f'); break;
        case 'n': sb_c(dec, '\n'); break;
        case 'r': sb_c(dec, '\r'); break;
        case 't': sb_c(dec, '\t'); break;
        case 'u': {
            unsigned cp;
            if (read_u4(P, &cp) < 0) return -1;
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                unsigned lo;
                if (P->end - P->p < 6 || P->p[0] != '\\' || P->p[1] != 'u') return -1;
                P->p += 2;
                if (read_u4(P, &lo) < 0 || lo < 0xDC00 || lo > 0xDFFF) return -1;
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                return -1;   /* lone low surrogate */
            }
            put_utf8(dec, cp);
            break;
        }
        default: return -1;
        }
    }
    return -1;
}

/* Canonical (Python json.dumps(ensure_ascii=False)) form of decoded text. */
static void emit_string(struct sb *out, const char *s, size_t n) {
    sb_c(out, '"');
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':  sb_put(out, "\\\"", 2); break;
        case '\\': sb_put(out, "\\\\", 2); break;
        case '\b': sb_put(out, "\\b", 2); break;
        case '\f': sb_put(out, "\\f", 2); break;
        case '\n': sb_put(out, "\\n", 2); break;
        case '\r': sb_put(out, "\\r", 2); break;
        case '\t': sb_put(out, "\\t", 2); break;
        default:
            if (c < 0x20) { char u[8]; snprintf(u, sizeof u, "\\u%04x", c); sb_put(out, u, 6); }
            else sb_put(out, (const char *)&s[i], 1);
        }
    }
    sb_c(out, '"');
}

/* Python repr(float) of the token's value. */
static int emit_float(struct sb *out, const char *tok, size_t n) {
    char t[400];
    if (n >= sizeof t) return -1;
    memcpy(t, tok, n); t[n] = 0;
    double x = strtod(t, NULL);
    if (!isfinite(x)) return -1;
    char buf[64];
    for (int prec = 1; prec <= 17; prec++) {
        snprintf(buf, sizeof buf, "%.*e", prec - 1, x);
        if (strtod(buf, NULL) == x) break;
    }
    /* buf: [-]d[.ddd]e[+-]XX */
    const char *q = buf;
    int neg = 0;
    if (*q == '-') { neg = 1; q++; }
    char digits[32]; int nd = 0;
    while (*q && *q != 'e') { if (isdigit((unsigned char)*q)) digits[nd++] = *q; q++; }
    while (nd > 1 && digits[nd - 1] == '0') nd--;
    digits[nd] = 0;
    int e = (*q == 'e') ? atoi(q + 1) : 0;
    int decpt = e + 1;
    if (neg) sb_c(out, '-');
    if (decpt > -4 && decpt <= 16) {
        if (decpt <= 0) {
            sb_s(out, "0.");
            for (int i = 0; i < -decpt; i++) sb_c(out, '0');
            sb_put(out, digits, (size_t)nd);
        } else if (decpt >= nd) {
            sb_put(out, digits, (size_t)nd);
            for (int i = 0; i < decpt - nd; i++) sb_c(out, '0');
            sb_s(out, ".0");
        } else {
            sb_put(out, digits, (size_t)decpt);
            sb_c(out, '.');
            sb_put(out, digits + decpt, (size_t)(nd - decpt));
        }
    } else {
        sb_c(out, digits[0]);
        if (nd > 1) { sb_c(out, '.'); sb_put(out, digits + 1, (size_t)(nd - 1)); }
        char ex[16];
        snprintf(ex, sizeof ex, "e%c%02d", decpt - 1 < 0 ? '-' : '+', abs(decpt - 1));
        sb_s(out, ex);
    }
    return 0;
}

static int parse_number(struct parser *P, struct sb *out) {
    const char *s = P->p;
    int is_int = 1;
    if (P->p < P->end && *P->p == '-') P->p++;
    if (P->p >= P->end || !isdigit((unsigned char)*P->p)) return -1;
    if (*P->p == '0') P->p++;
    else while (P->p < P->end && isdigit((unsigned char)*P->p)) P->p++;
    if (P->p < P->end && *P->p == '.') {
        is_int = 0; P->p++;
        if (P->p >= P->end || !isdigit((unsigned char)*P->p)) return -1;
        while (P->p < P->end && isdigit((unsigned char)*P->p)) P->p++;
    }
    if (P->p < P->end && (*P->p == 'e' || *P->p == 'E')) {
        is_int = 0; P->p++;
        if (P->p < P->end && (*P->p == '+' || *P->p == '-')) P->p++;
        if (P->p >= P->end || !isdigit((unsigned char)*P->p)) return -1;
        while (P->p < P->end && isdigit((unsigned char)*P->p)) P->p++;
    }
    size_t n = (size_t)(P->p - s);
    if (is_int) {
        if (n == 2 && s[0] == '-' && s[1] == '0') sb_c(out, '0');
        else sb_put(out, s, n);
        return 0;
    }
    return emit_float(out, s, n);
}

static const char *const VOLATILE[] = {
    "ts", "seen_at", "first_seen", "last_seen", "count", "seq", "id",
    "timestamp", "observed_at", "ttl", NULL
};
static int is_volatile(const char *k, size_t n) {
    for (int i = 0; VOLATILE[i]; i++)
        if (strlen(VOLATILE[i]) == n && memcmp(VOLATILE[i], k, n) == 0) return 1;
    return 0;
}

/* Sort fields of an answers element: Python str() of name / type / data. */
struct sortkey { struct sb f[3]; int is_object; };
static const char *const SORT_FIELDS[3] = { "name", "type", "data" };

struct member { struct sb k; struct sb v; };

static int canon_value(struct parser *P, struct sb *out, int depth,
                       const char *member, size_t member_len, struct sortkey *sk);

static int cmp_member(const void *a, const void *b) {
    const struct member *x = a, *y = b;
    size_t n = x->k.len < y->k.len ? x->k.len : y->k.len;
    int c = memcmp(x->k.b, y->k.b, n);
    if (c) return c;
    return (x->k.len > y->k.len) - (x->k.len < y->k.len);
}

static int canon_object(struct parser *P, struct sb *out, int depth, struct sortkey *sk) {
    P->p++;   /* '{' */
    struct member *m = NULL;
    int nm = 0, cap = 0, rc = -1;
    skip_ws(P);
    if (P->p < P->end && *P->p == '}') { P->p++; goto emit; }
    for (;;) {
        skip_ws(P);
        struct member cur;
        sb_init(&cur.k, PS_DEDUPE_KEY_MAX);
        sb_init(&cur.v, PS_DEDUPE_KEY_MAX);
        if (parse_string(P, &cur.k) < 0) { sb_free(&cur.k); goto out; }
        skip_ws(P);
        if (P->p >= P->end || *P->p != ':') { sb_free(&cur.k); goto out; }
        P->p++;
        skip_ws(P);
        /* str() forms of name/type/data for an answers sort, if asked */
        struct sb *strform = NULL;
        if (sk) for (int i = 0; i < 3; i++)
            if (cur.k.len == strlen(SORT_FIELDS[i]) && memcmp(cur.k.b, SORT_FIELDS[i], cur.k.len) == 0) {
                strform = &sk->f[i];
                strform->len = 0; if (strform->b) strform->b[0] = 0;
                sb_put(strform, "", 0);
            }
        if (strform && P->p < P->end && *P->p == '"') {
            struct parser save = *P;
            if (parse_string(P, strform) < 0) { sb_free(&cur.k); goto out; }
            *P = save;
        }
        if (canon_value(P, &cur.v, depth + 1, cur.k.b, cur.k.len, NULL) < 0) {
            sb_free(&cur.k); sb_free(&cur.v); goto out;
        }
        if (strform && cur.v.len && cur.v.b[0] != '"') {
            const char *t = cur.v.b;
            if (strcmp(t, "true") == 0) t = "True";
            else if (strcmp(t, "false") == 0) t = "False";
            else if (strcmp(t, "null") == 0) t = "None";
            sb_s(strform, t);
        }
        if (is_volatile(cur.k.b, cur.k.len)) {
            if (strform) { strform->len = 0; strform->b[0] = 0; }
            sb_free(&cur.k); sb_free(&cur.v);
        } else {
            int dup = -1;
            for (int i = 0; i < nm; i++)
                if (m[i].k.len == cur.k.len && memcmp(m[i].k.b, cur.k.b, cur.k.len) == 0) { dup = i; break; }
            if (dup >= 0) {
                sb_free(&m[dup].k); sb_free(&m[dup].v);
                m[dup] = cur;
            } else {
                if (nm == cap) {
                    int nc = cap ? cap * 2 : 8;
                    struct member *nmv = realloc(m, (size_t)nc * sizeof *m);
                    if (!nmv) { sb_free(&cur.k); sb_free(&cur.v); goto out; }
                    m = nmv; cap = nc;
                }
                m[nm++] = cur;
            }
        }
        skip_ws(P);
        if (P->p < P->end && *P->p == ',') { P->p++; continue; }
        if (P->p < P->end && *P->p == '}') { P->p++; break; }
        goto out;
    }
emit:
    if (nm > 1) qsort(m, (size_t)nm, sizeof *m, cmp_member);
    sb_c(out, '{');
    for (int i = 0; i < nm; i++) {
        if (i) sb_c(out, ',');
        emit_string(out, m[i].k.b, m[i].k.len);
        sb_c(out, ':');
        sb_put(out, m[i].v.b, m[i].v.len);
    }
    sb_c(out, '}');
    if (sk) sk->is_object = 1;
    rc = out->err ? -1 : 0;
out:
    for (int i = 0; i < nm; i++) { sb_free(&m[i].k); sb_free(&m[i].v); }
    free(m);
    return rc;
}

struct elem { struct sb text; struct sortkey sk; int idx; };

static int cmp_sb(const struct sb *a, const struct sb *b) {
    size_t n = a->len < b->len ? a->len : b->len;
    int c = n ? memcmp(a->b, b->b, n) : 0;
    if (c) return c;
    return (a->len > b->len) - (a->len < b->len);
}
static int cmp_elem(const void *a, const void *b) {
    const struct elem *x = a, *y = b;
    for (int i = 0; i < 3; i++) {
        int c = cmp_sb(&x->sk.f[i], &y->sk.f[i]);
        if (c) return c;
    }
    return x->idx - y->idx;   /* stable */
}

static int canon_array(struct parser *P, struct sb *out, int depth, int answers) {
    P->p++;   /* '[' */
    struct elem *e = NULL;
    int ne = 0, cap = 0, rc = -1;
    skip_ws(P);
    if (P->p < P->end && *P->p == ']') { P->p++; goto emit; }
    for (;;) {
        skip_ws(P);
        if (ne == cap) {
            int nc = cap ? cap * 2 : 8;
            struct elem *n2 = realloc(e, (size_t)nc * sizeof *e);
            if (!n2) goto out;
            e = n2; cap = nc;
        }
        struct elem *cur = &e[ne];
        memset(cur, 0, sizeof *cur);
        sb_init(&cur->text, PS_DEDUPE_KEY_MAX);
        for (int i = 0; i < 3; i++) sb_init(&cur->sk.f[i], PS_DEDUPE_KEY_MAX);
        cur->idx = ne;
        ne++;
        if (canon_value(P, &cur->text, depth + 1, NULL, 0, answers ? &cur->sk : NULL) < 0) goto out;
        skip_ws(P);
        if (P->p < P->end && *P->p == ',') { P->p++; continue; }
        if (P->p < P->end && *P->p == ']') { P->p++; break; }
        goto out;
    }
emit:
    if (answers && ne > 1) {
        int all_obj = 1;
        for (int i = 0; i < ne; i++) if (!e[i].sk.is_object) all_obj = 0;
        if (all_obj) qsort(e, (size_t)ne, sizeof *e, cmp_elem);
    }
    sb_c(out, '[');
    for (int i = 0; i < ne; i++) {
        if (i) sb_c(out, ',');
        sb_put(out, e[i].text.b, e[i].text.len);
    }
    sb_c(out, ']');
    rc = out->err ? -1 : 0;
out:
    for (int i = 0; i < ne; i++) {
        sb_free(&e[i].text);
        for (int j = 0; j < 3; j++) sb_free(&e[i].sk.f[j]);
    }
    free(e);
    return rc;
}

static int canon_value(struct parser *P, struct sb *out, int depth,
                       const char *member, size_t member_len, struct sortkey *sk) {
    if (depth > DEDUPE_MAX_DEPTH) return -1;
    skip_ws(P);
    if (P->p >= P->end) return -1;
    char c = *P->p;
    if (c == '{') return canon_object(P, out, depth, sk);
    if (c == '[') {
        int answers = member && member_len == 7 && memcmp(member, "answers", 7) == 0;
        return canon_array(P, out, depth, answers);
    }
    if (c == '"') {
        struct sb dec;
        sb_init(&dec, PS_DEDUPE_KEY_MAX);
        int rc = parse_string(P, &dec);
        if (rc == 0) emit_string(out, dec.b, dec.len);
        sb_free(&dec);
        return rc < 0 || out->err ? -1 : 0;
    }
    if (c == '-' || isdigit((unsigned char)c)) return parse_number(P, out);
    static const char *const lit[] = { "true", "false", "null" };
    for (int i = 0; i < 3; i++) {
        size_t n = strlen(lit[i]);
        if ((size_t)(P->end - P->p) >= n && memcmp(P->p, lit[i], n) == 0) {
            P->p += n;
            sb_put(out, lit[i], n);
            return out->err ? -1 : 0;
        }
    }
    return -1;
}

int ps_obs_dedupe_key_n(const char *kind, const char *obs, size_t obs_len,
                        char out_key[PS_DEDUPE_KEY_MAX]) {
    if (out_key) out_key[0] = 0;
    if (!kind || !obs || !out_key) return -1;
    struct sb out;
    sb_init(&out, PS_DEDUPE_KEY_MAX);
    sb_s(&out, kind);
    sb_c(&out, '|');
    struct parser P = { obs, obs + obs_len, 0 };
    int rc = canon_value(&P, &out, 0, NULL, 0, NULL);
    if (rc == 0) { skip_ws(&P); if (P.p != P.end) rc = -1; }
    if (rc == 0 && !out.err) {
        memcpy(out_key, out.b, out.len + 1);
        rc = (int)out.len;
    } else {
        rc = -1;
    }
    sb_free(&out);
    return rc;
}

int ps_obs_dedupe_key(const char *kind, const char *obs, char out_key[PS_DEDUPE_KEY_MAX]) {
    return ps_obs_dedupe_key_n(kind, obs, obs ? strlen(obs) : 0, out_key);
}

/* ================================================================== */
/* Summary event                                                       */
/* ================================================================== */

static void fmt_secs(char *b, size_t cap, int64_t ms) {
    if (ms < 0) ms = 0;
    long long w = (long long)(ms / 1000);
    int f = (int)(ms % 1000);
    if (f == 0) { snprintf(b, cap, "%lld", w); return; }
    snprintf(b, cap, "%lld.%03d", w, f);
    size_t n = strlen(b);
    while (b[n - 1] == '0') b[--n] = 0;
}
static void fmt_iso(char *b, size_t cap, int64_t ms) {
    if (ms < 0) ms = 0;
    if (ps_iso8601_utc((uint64_t)ms * 1000u, b, cap) == 0) snprintf(b, cap, "1970-01-01T00:00:00Z");
}

static size_t write_summary(char *out, size_t lim, const char *kind,
                            const char *obs, size_t obs_len,
                            const struct ps_obs_dedupe_stats *st,
                            int64_t pairs[][2], int npairs, int coarse,
                            const char *key_hex) {
    char since[32], first[32], last[32], gmin[32], gmax[32], gmean[32];
    fmt_iso(since, sizeof since, st->since_ms);
    fmt_iso(first, sizeof first, st->first_ms);
    fmt_iso(last, sizeof last, st->last_ms);
    fmt_secs(gmin, sizeof gmin, st->gap_min_ms);
    fmt_secs(gmax, sizeof gmax, st->gap_max_ms);
    int64_t span = st->last_ms - st->since_ms;
    if (span < 0) span = 0;
    int64_t mean = st->n ? (2 * span + (int64_t)st->n) / (2 * (int64_t)st->n) : 0;
    fmt_secs(gmean, sizeof gmean, mean);

    size_t off = 0;
    int n;
#define APPEND(...) do { \
        n = snprintf(out + off, lim - off, __VA_ARGS__); \
        if (n < 0 || (size_t)n >= lim - off) return 0; \
        off += (size_t)n; \
    } while (0)
    if (key_hex) {
        APPEND("{\"kind\":\"%s\",\"ts\":\"%s\",\"observation\":{\"key_sha256\":\"%s\"},", kind, last, key_hex);
    } else {
        APPEND("{\"kind\":\"%s\",\"ts\":\"%s\",\"observation\":%.*s,", kind, last, (int)obs_len, obs);
    }
    APPEND("\"dedupe\":{\"since\":\"%s\",\"first\":\"%s\",\"last\":\"%s\",\"n\":%lu,"
           "\"gap_min\":%s,\"gap_max\":%s,\"gap_mean\":%s,\"seen\":[",
           since, first, last, (unsigned long)st->n, gmin, gmax, gmean);
    for (int i = 0; i < npairs; i++)
        APPEND("%s[%lld,%lld]", i ? "," : "", (long long)pairs[i][0], (long long)pairs[i][1]);
    APPEND("]");
    if (coarse) APPEND(",\"seen_coarse\":true");
    if (key_hex) APPEND(",\"truncated\":true");
    APPEND("}}");
#undef APPEND
    return off;
}

size_t ps_obs_dedupe_build_summary(char *out, size_t cap, const char *kind,
                                   const char *obs, size_t obs_len,
                                   const struct ps_obs_dedupe_stats *st,
                                   const char *key_hex) {
    if (!out || !cap || !kind || !obs || !st) return 0;
    size_t lim = cap < PS_OBS_ITEM_MAX ? cap : PS_OBS_ITEM_MAX;
    int64_t pairs[PS_DEDUPE_SEEN_MAX][2];
    int np = st->npairs < 0 ? 0 : (st->npairs > PS_DEDUPE_SEEN_MAX ? PS_DEDUPE_SEEN_MAX : st->npairs);
    memcpy(pairs, st->seen, (size_t)np * sizeof pairs[0]);
    int coarse = st->coarse;
    for (;;) {
        size_t n = write_summary(out, lim, kind, obs, obs_len, st, pairs, np, coarse, NULL);
        if (n) return n;
        if (np <= 1) break;
        /* merge neighbouring runs: counts and span stay exact */
        int k = 0;
        for (int i = 0; i < np; i += 2) {
            pairs[k][0] = pairs[i][0];
            pairs[k][1] = pairs[i][1] + (i + 1 < np ? pairs[i + 1][1] : 0);
            k++;
        }
        np = k;
        coarse = 1;
    }
    if (key_hex) {
        size_t n = write_summary(out, lim, kind, obs, obs_len, st, pairs, np, coarse, key_hex);
        if (n) return n;
    }
    out[0] = 0;
    return 0;
}

/* ================================================================== */
/* Table                                                               */
/* ================================================================== */

struct entry {
    int      used;
    unsigned char dig[32];
    unsigned char subj[32];
    int      has_subj;
    char     kind[64];
    char    *obs;
    size_t   obs_len;
    int64_t  window_ms;
    int64_t  prev_ms;     /* time of the latest sighting (sent or repeat) */
    int64_t  cur_gap_s;   /* rounded gap of the current run */
    uint64_t tick;        /* LRU */
    struct ps_obs_dedupe_stats st;
};

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static struct entry   *g_tab;
static int             g_max;
static int             g_used;
static int             g_on;
static uint64_t        g_tick;
static struct ps_obs_dedupe_cfg g_cfg;
static struct ps_obs_dedupe_counters g_ctr;
/* Summaries closed during an offer, waiting for the next flush. */
static char           *g_stage[PS_DEDUPE_STAGE_MAX + PS_DEDUPE_RESTAGE_MAX];
static int             g_nstage;

void ps_obs_dedupe_cfg_defaults(struct ps_obs_dedupe_cfg *c) {
    memset(c, 0, sizeof *c);
    c->window_s = -1;
    c->table_max = PS_DEDUPE_TABLE_DEFAULT;
}

void ps_obs_dedupe_cfg_from_env(struct ps_obs_dedupe_cfg *c) {
    ps_obs_dedupe_cfg_defaults(c);
    const char *v = getenv("PS_CENTRAL_DEDUPE_WINDOW_S");
    if (v && v[0]) c->window_s = atoi(v) < 0 ? -1 : atoi(v);
    v = getenv("PS_CENTRAL_DEDUPE_TABLE_MAX");
    if (v && v[0] && atoi(v) > 0) c->table_max = atoi(v);
    static const char pre[] = "PS_CENTRAL_DEDUPE_WINDOW_";
    for (char **e = environ; e && *e; e++) {
        if (strncmp(*e, pre, sizeof pre - 1) != 0) continue;
        const char *name = *e + sizeof pre - 1;
        const char *eq = strchr(name, '=');
        if (!eq || eq == name) continue;
        size_t nl = (size_t)(eq - name);
        if (nl == 1 && name[0] == 'S') continue;
        if (nl >= sizeof c->kinds[0].kind || c->n_kinds >= PS_DEDUPE_KIND_WINDOWS) continue;
        struct ps_obs_dedupe_kind_window *kw = &c->kinds[c->n_kinds++];
        for (size_t i = 0; i < nl; i++) kw->kind[i] = (char)tolower((unsigned char)name[i]);
        kw->kind[nl] = 0;
        kw->window_s = atoi(eq + 1) < 0 ? 0 : atoi(eq + 1);
    }
}

static int kind_matches(const char *want, const char *kind) {
    if (strcasecmp(want, kind) == 0) return 1;
    size_t n = strlen(kind);
    if (strlen(want) == n) {
        size_t i;
        for (i = 0; i < n; i++) {
            char a = (char)tolower((unsigned char)want[i]);
            char b = (char)tolower((unsigned char)(kind[i] == '.' ? '_' : kind[i]));
            if (a != b) break;
        }
        if (i == n) return 1;
    }
    const char *dot = strrchr(kind, '.');
    return dot && strcasecmp(want, dot + 1) == 0;
}

static int window_for_locked(const char *kind) {
    if (!g_on || !kind) return 0;
    if (g_cfg.window_s == 0) return 0;
    for (int i = 0; i < g_cfg.n_kinds && i < PS_DEDUPE_KIND_WINDOWS; i++)
        if (kind_matches(g_cfg.kinds[i].kind, kind))
            return g_cfg.kinds[i].window_s > 0 ? g_cfg.kinds[i].window_s : 0;
    if (g_cfg.window_s > 0) return g_cfg.window_s;
    if (strcmp(kind, "discovery.dns") == 0) return 300;
    return 900;
}

int ps_obs_dedupe_window_for(const char *kind) {
    pthread_mutex_lock(&g_mu);
    int w = window_for_locked(kind);
    pthread_mutex_unlock(&g_mu);
    return w;
}

static void free_table_locked(void) {
    for (int i = 0; i < g_nstage; i++) free(g_stage[i]);
    g_nstage = 0;
    if (g_tab) for (int i = 0; i < g_max; i++) free(g_tab[i].obs);
    free(g_tab);
    g_tab = NULL;
    g_max = g_used = 0;
    g_on = 0;
}

int ps_obs_dedupe_init(const struct ps_obs_dedupe_cfg *cfg) {
    pthread_mutex_lock(&g_mu);
    free_table_locked();
    if (cfg) g_cfg = *cfg; else ps_obs_dedupe_cfg_defaults(&g_cfg);
    if (g_cfg.n_kinds > PS_DEDUPE_KIND_WINDOWS) g_cfg.n_kinds = PS_DEDUPE_KIND_WINDOWS;
    g_max = g_cfg.table_max > 0 ? g_cfg.table_max : PS_DEDUPE_TABLE_DEFAULT;
    memset(&g_ctr, 0, sizeof g_ctr);
    g_tick = 0;
    int rc = 0;
    g_tab = calloc((size_t)g_max, sizeof *g_tab);
    if (!g_tab) { g_max = 0; rc = -1; }
    else g_on = 1;
    pthread_mutex_unlock(&g_mu);
    return rc;
}

void ps_obs_dedupe_shutdown(void) {
    pthread_mutex_lock(&g_mu);
    free_table_locked();
    pthread_mutex_unlock(&g_mu);
}

static void sha256(const void *p, size_t n, unsigned char out[32]) {
    unsigned int len = 0;
    if (EVP_Digest(p, n, out, &len, EVP_sha256(), NULL) != 1 || len != 32)
        memset(out, 0, 32);
}
static void to_hex(const unsigned char d[32], char out[65]) {
    for (int i = 0; i < 32; i++) snprintf(out + 2 * i, 3, "%02x", d[i]);
}

/* Neighbor subject: the thing whose content may change (ip on an interface,
 * per protocol and message type). Other kinds have none. */
static int neighbor_subject(const char *kind, const char *obs, unsigned char out[32]) {
    if (strcmp(kind, "discovery.neighbor") != 0) return 0;
    char ip[128], ifn[128], proto[32], ndp[32];
    if (ps_json_extract_string(obs, "ip", ip, sizeof ip) < 0) return 0;
    if (ps_json_extract_string(obs, "interface", ifn, sizeof ifn) < 0) ifn[0] = 0;
    if (ps_json_extract_string(obs, "proto", proto, sizeof proto) < 0) proto[0] = 0;
    if (ps_json_extract_string(obs, "ndp_type", ndp, sizeof ndp) < 0) ndp[0] = 0;
    char s[512];
    int n = snprintf(s, sizeof s, "%s|%s|%s|%s|%s", kind, ip, ifn, proto, ndp);
    if (n < 0 || (size_t)n >= sizeof s) return 0;
    sha256(s, (size_t)n, out);
    return 1;
}

/* Build the entry's summary into out (lim bytes). Returns length, 0 if no
 * repeats or it could not be built. */
static size_t summarise_locked(struct entry *e, char *out, size_t lim) {
    if (e->st.n == 0) return 0;
    char hex[65];
    to_hex(e->dig, hex);
    size_t n = ps_obs_dedupe_build_summary(out, lim, e->kind, e->obs, e->obs_len, &e->st, hex);
    if (n == 0) {
        ps_warn("dedupe: could not build a summary for %s (%lu repeats)", e->kind,
                (unsigned long)e->st.n);
        return 0;
    }
    g_ctr.summaries++;
    g_ctr.summary_repeats += e->st.n;
    if (strstr(out + (n > 40 ? n - 40 : 0), "\"truncated\":true")) g_ctr.truncated++;
    return n;
}

static void drop_locked(struct entry *e) {
    free(e->obs);
    memset(e, 0, sizeof *e);
    g_used--;
}

/* Close an entry during an offer: its summary (if it has repeats) goes to
 * the emit hook, or to the staging list that the next flush returns first,
 * and the entry is removed. Returns -1 (entry left untouched) when the
 * staging list is full: the caller must then keep the entry, so no repeat
 * count is ever dropped. */
static int close_locked(struct entry *e) {
    if (e->st.n == 0) { drop_locked(e); return 0; }
    static char ev[PS_OBS_ITEM_MAX];
    if (g_cfg.emit) {
        size_t n = summarise_locked(e, ev, sizeof ev);
        if (n) g_cfg.emit(ev, n, g_cfg.emit_user);
        drop_locked(e);
        return 0;
    }
    if (g_nstage >= PS_DEDUPE_STAGE_MAX) { g_ctr.stage_full++; return -1; }
    size_t n = summarise_locked(e, ev, sizeof ev);
    if (n) {
        char *copy = malloc(n + 1);
        if (!copy) {   /* undo the accounting; keep the entry */
            g_ctr.summaries--;
            g_ctr.summary_repeats -= e->st.n;
            g_ctr.stage_full++;
            return -1;
        }
        memcpy(copy, ev, n + 1);
        g_stage[g_nstage++] = copy;
    }
    drop_locked(e);
    return 0;
}

static void account_locked(struct entry *e, int64_t now) {
    struct ps_obs_dedupe_stats *st = &e->st;
    int64_t t = now < e->prev_ms ? e->prev_ms : now;   /* clock step back: zero gap */
    int64_t gap = t - e->prev_ms;
    int64_t g = (gap + 500) / 1000;
    int64_t off = (e->prev_ms - st->since_ms + 500) / 1000;
    if (st->n == 0) {
        st->first_ms = t;
        st->gap_min_ms = st->gap_max_ms = gap;
    } else {
        if (gap < st->gap_min_ms) st->gap_min_ms = gap;
        if (gap > st->gap_max_ms) st->gap_max_ms = gap;
    }
    st->n++;
    st->last_ms = t;
    if (st->npairs > 0 && g == e->cur_gap_s) {
        st->seen[st->npairs - 1][1]++;
    } else if (st->npairs < PS_DEDUPE_SEEN_MAX) {
        st->seen[st->npairs][0] = off;
        st->seen[st->npairs][1] = 1;
        st->npairs++;
        e->cur_gap_s = g;
    } else {
        st->seen[st->npairs - 1][1]++;
        st->coarse = 1;
    }
    e->prev_ms = t;
}

enum ps_dedupe_action ps_obs_dedupe_offer_n(const char *kind, const char *obs,
                                            size_t obs_len, int64_t now_ms) {
    if (!kind || !obs) return PS_DEDUPE_SEND;
    pthread_mutex_lock(&g_mu);
    g_ctr.offered++;
    int w = window_for_locked(kind);
    pthread_mutex_unlock(&g_mu);
    if (w <= 0) goto send_unlocked;

    char *key = malloc(PS_DEDUPE_KEY_MAX);
    if (!key) goto send_unlocked;
    int klen = (strlen(kind) < sizeof ((struct entry *)0)->kind)
             ? ps_obs_dedupe_key_n(kind, obs, obs_len, key) : -1;
    unsigned char dig[32], subj[32];
    if (klen >= 0) sha256(key, (size_t)klen, dig);
    free(key);
    if (klen < 0) {
        pthread_mutex_lock(&g_mu);
        g_ctr.unkeyed++;
        pthread_mutex_unlock(&g_mu);
        goto send_unlocked;
    }
    int has_subj = 0;
    {
        /* subject extraction needs a NUL-terminated copy */
        char *z = malloc(obs_len + 1);
        if (z) { memcpy(z, obs, obs_len); z[obs_len] = 0; has_subj = neighbor_subject(kind, z, subj); free(z); }
    }

    pthread_mutex_lock(&g_mu);
    if (!g_on) { pthread_mutex_unlock(&g_mu); goto send_unlocked; }
    struct entry *hit = NULL;
    for (int i = 0; i < g_max; i++)
        if (g_tab[i].used && memcmp(g_tab[i].dig, dig, 32) == 0) { hit = &g_tab[i]; break; }
    if (hit) {
        if (now_ms < hit->st.since_ms + hit->window_ms) {
            account_locked(hit, now_ms);
            hit->tick = ++g_tick;
            g_ctr.suppressed++;
            pthread_mutex_unlock(&g_mu);
            return PS_DEDUPE_SUPPRESS;
        }
        /* window over: its summary first, then a new sighting. If the
         * summary cannot be staged now, keep counting into the old entry:
         * the next flush emits it (its window has ended). */
        if (close_locked(hit) < 0) {
            account_locked(hit, now_ms);
            hit->tick = ++g_tick;
            g_ctr.suppressed++;
            pthread_mutex_unlock(&g_mu);
            return PS_DEDUPE_SUPPRESS;
        }
    }
    if (has_subj) {
        for (int i = 0; i < g_max; i++) {
            struct entry *e = &g_tab[i];
            /* staging full: leave it open, its window end flushes it */
            if (e->used && e->has_subj && memcmp(e->subj, subj, 32) == 0 &&
                close_locked(e) == 0)
                g_ctr.closed++;
        }
    }
    if (g_used >= g_max) {
        struct entry *lru = NULL;
        for (int i = 0; i < g_max; i++)
            if (g_tab[i].used && (!lru || g_tab[i].tick < lru->tick)) lru = &g_tab[i];
        /* staging full: the new sighting is sent but not tracked */
        if (lru && close_locked(lru) == 0) g_ctr.evicted++;
    }
    struct entry *slot = NULL;
    for (int i = 0; i < g_max; i++) if (!g_tab[i].used) { slot = &g_tab[i]; break; }
    char *copy = slot ? malloc(obs_len + 1) : NULL;
    if (slot && copy) {
        memcpy(copy, obs, obs_len);
        copy[obs_len] = 0;
        memset(slot, 0, sizeof *slot);
        slot->used = 1;
        memcpy(slot->dig, dig, 32);
        if (has_subj) { memcpy(slot->subj, subj, 32); slot->has_subj = 1; }
        snprintf(slot->kind, sizeof slot->kind, "%s", kind);
        slot->obs = copy;
        slot->obs_len = obs_len;
        slot->window_ms = (int64_t)w * 1000;
        slot->st.since_ms = now_ms;
        slot->prev_ms = now_ms;
        slot->tick = ++g_tick;
        g_used++;
    } else {
        free(copy);
    }
    g_ctr.sent++;
    pthread_mutex_unlock(&g_mu);
    return PS_DEDUPE_SEND;

send_unlocked:
    pthread_mutex_lock(&g_mu);
    g_ctr.sent++;
    pthread_mutex_unlock(&g_mu);
    return PS_DEDUPE_SEND;
}

enum ps_dedupe_action ps_obs_dedupe_offer(const char *kind, const char *obs, int64_t now_ms) {
    return ps_obs_dedupe_offer_n(kind, obs, obs ? strlen(obs) : 0, now_ms);
}

int ps_obs_dedupe_flush(int64_t now_ms, int force, char out_items[][PS_OBS_ITEM_MAX], int max) {
    int k = 0;
    pthread_mutex_lock(&g_mu);
    if (g_on && out_items && max > 0) {
        /* staged summaries first, in the order they were closed */
        int take = g_nstage < max ? g_nstage : max;
        for (int i = 0; i < take; i++) {
            snprintf(out_items[k++], PS_OBS_ITEM_MAX, "%s", g_stage[i]);
            free(g_stage[i]);
        }
        memmove(g_stage, g_stage + take, (size_t)(g_nstage - take) * sizeof g_stage[0]);
        g_nstage -= take;
        for (int i = 0; k < max && i < g_max; i++) {
            struct entry *e = &g_tab[i];
            if (!e->used) continue;
            if (!force && now_ms < e->st.since_ms + e->window_ms) continue;
            if (e->st.n > 0) {
                if (k >= max) break;
                if (summarise_locked(e, out_items[k], PS_OBS_ITEM_MAX)) k++;
            }
            drop_locked(e);
        }
    }
    pthread_mutex_unlock(&g_mu);
    return k;
}

void ps_obs_dedupe_get_counters(struct ps_obs_dedupe_counters *out) {
    pthread_mutex_lock(&g_mu);
    *out = g_ctr;
    pthread_mutex_unlock(&g_mu);
}

int ps_obs_dedupe_restage(const char **items, int n) {
    int took = 0;
    pthread_mutex_lock(&g_mu);
    if (g_on && items && n > 0) {
        int room = PS_DEDUPE_STAGE_MAX + PS_DEDUPE_RESTAGE_MAX - g_nstage;
        int k = n < room ? n : room;
        char *tmp[PS_DEDUPE_STAGE_MAX + PS_DEDUPE_RESTAGE_MAX];
        for (int i = 0; i < k; i++) {
            tmp[took] = strdup(items[i]);
            if (tmp[took]) took++;
        }
        memmove(g_stage + took, g_stage, (size_t)g_nstage * sizeof g_stage[0]);
        memcpy(g_stage, tmp, (size_t)took * sizeof g_stage[0]);
        g_nstage += took;
    }
    pthread_mutex_unlock(&g_mu);
    if (took < n) ps_warn("dedupe: %d undelivered summaries could not be re-staged", n - took);
    return took;
}

int ps_obs_dedupe_staged(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_nstage;
    pthread_mutex_unlock(&g_mu);
    return n;
}

int ps_obs_dedupe_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_used;
    pthread_mutex_unlock(&g_mu);
    return n;
}
