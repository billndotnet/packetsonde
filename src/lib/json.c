#include "json.h"
#include <stdio.h>
#include <string.h>

static void emit(struct ps_json *j, const char *s, size_t n)
{
    if (j->error) return;
    if (j->len + n >= j->cap) { j->error = 1; return; }
    memcpy(j->buf + j->len, s, n);
    j->len += n;
}

static void emit_str(struct ps_json *j, const char *s) { emit(j, s, strlen(s)); }

static void maybe_comma(struct ps_json *j)
{
    if (j->needs_comma) emit_str(j, ",");
    j->needs_comma = 0;
}

static void emit_quoted(struct ps_json *j, const char *s)
{
    emit_str(j, "\"");
    for (const char *p = s; *p; p++) {
        switch (*p) {
        case '"':  emit_str(j, "\\\""); break;
        case '\\': emit_str(j, "\\\\"); break;
        case '\n': emit_str(j, "\\n");  break;
        case '\t': emit_str(j, "\\t");  break;
        case '\r': emit_str(j, "\\r");  break;
        default:
            if ((unsigned char)*p < 0x20) {
                char esc[8];
                snprintf(esc, sizeof(esc), "\\u%04x", (unsigned char)*p);
                emit_str(j, esc);
            } else {
                emit(j, p, 1);
            }
        }
    }
    emit_str(j, "\"");
}

void ps_json_init(struct ps_json *j, char *buf, size_t cap)
{
    j->buf = buf; j->cap = cap; j->len = 0;
    j->depth = 0; j->needs_comma = 0; j->error = 0;
}

void ps_json_object_begin(struct ps_json *j)  { maybe_comma(j); emit_str(j, "{"); j->needs_comma = 0; j->depth++; }
void ps_json_object_end(struct ps_json *j)    { emit_str(j, "}"); j->depth--; j->needs_comma = 1; }
void ps_json_key_object_begin(struct ps_json *j, const char *key) { maybe_comma(j); emit_quoted(j, key); emit_str(j, ":{"); j->needs_comma = 0; j->depth++; }
void ps_json_array_begin(struct ps_json *j, const char *key) { maybe_comma(j); emit_quoted(j, key); emit_str(j, ":["); j->needs_comma = 0; }
void ps_json_array_end(struct ps_json *j)     { emit_str(j, "]"); j->needs_comma = 1; }

void ps_json_key_string(struct ps_json *j, const char *key, const char *val)
{
    maybe_comma(j); emit_quoted(j, key); emit_str(j, ":"); emit_quoted(j, val); j->needs_comma = 1;
}

void ps_json_key_int(struct ps_json *j, const char *key, int64_t val)
{
    maybe_comma(j); emit_quoted(j, key);
    char num[32]; snprintf(num, sizeof(num), ":%lld", (long long)val);
    emit_str(j, num); j->needs_comma = 1;
}

void ps_json_key_double(struct ps_json *j, const char *key, double val)
{
    maybe_comma(j); emit_quoted(j, key);
    char num[64]; snprintf(num, sizeof(num), ":%.3f", val);
    emit_str(j, num); j->needs_comma = 1;
}

void ps_json_key_bool(struct ps_json *j, const char *key, int val)
{
    maybe_comma(j); emit_quoted(j, key);
    emit_str(j, val ? ":true" : ":false"); j->needs_comma = 1;
}

void ps_json_key_null(struct ps_json *j, const char *key)
{
    maybe_comma(j); emit_quoted(j, key);
    emit_str(j, ":null"); j->needs_comma = 1;
}

void ps_json_array_string(struct ps_json *j, const char *val)
{
    maybe_comma(j); emit_quoted(j, val); j->needs_comma = 1;
}

void ps_json_array_double(struct ps_json *j, double val)
{
    maybe_comma(j);
    char num[64]; snprintf(num, sizeof(num), "%.3f", val);
    emit_str(j, num); j->needs_comma = 1;
}

int ps_json_finish(struct ps_json *j)
{
    if (j->error || j->len >= j->cap) return -1;
    j->buf[j->len] = '\0';
    return (int)j->len;
}
