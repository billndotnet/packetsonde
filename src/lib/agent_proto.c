#include "agent_proto.h"
#include "json_extract.h"

#include <string.h>
#include <sys/types.h>

int ps_ap_hello_recipe_schema(const uint8_t *payload, size_t len) {
    char tmp[1024];
    if (len >= sizeof(tmp)) len = sizeof(tmp) - 1;
    memcpy(tmp, payload, len);
    tmp[len] = '\0';
    long v;
    if (ps_json_extract_int(tmp, "max_recipe_schema", &v) == 0 && v >= 1) return (int)v;
    return 1;   /* agents/clients predating the field speak recipe schema 1 only */
}

static int io_read_all(const struct ps_ap_io *io, void *buf, size_t n) {
    uint8_t *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = io->read(io->ctx, p + got, n - got);
        if (r == 0) return PS_AP_ERR_EOF;
        if (r < 0)  return PS_AP_ERR_IO;
        got += (size_t)r;
    }
    return PS_AP_OK;
}

static int io_write_all(const struct ps_ap_io *io, const void *buf, size_t n) {
    const uint8_t *p = buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = io->write(io->ctx, p + sent, n - sent);
        if (w <= 0) return PS_AP_ERR_IO;
        sent += (size_t)w;
    }
    return PS_AP_OK;
}

int ps_ap_read_frame(const struct ps_ap_io *io,
                     uint8_t *out_buf, size_t out_buf_cap,
                     size_t *out_len) {
    uint8_t hdr[4];
    int rc = io_read_all(io, hdr, 4);
    if (rc != PS_AP_OK) return rc;
    uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                   ((uint32_t)hdr[2] <<  8) |  (uint32_t)hdr[3];
    if (len > PS_AGENT_FRAME_MAX) return PS_AP_ERR_OVERSIZE;
    if (len > out_buf_cap)        return PS_AP_ERR_SHORT;
    rc = io_read_all(io, out_buf, len);
    if (rc != PS_AP_OK) return rc;
    /* Sanity: leading char must be '{' for a JSON object. We don't fully
     * parse; we only enforce the protocol invariant that payloads are JSON
     * objects so a malformed peer cannot DOS us with non-JSON garbage. */
    if (len < 2 || out_buf[0] != '{') return PS_AP_ERR_BAD_JSON;
    *out_len = len;
    return PS_AP_OK;
}

int ps_ap_write_frame(const struct ps_ap_io *io,
                      const void *payload, size_t len) {
    if (len > PS_AGENT_FRAME_MAX) return PS_AP_ERR_OVERSIZE;
    uint8_t hdr[4];
    hdr[0] = (uint8_t)((len >> 24) & 0xff);
    hdr[1] = (uint8_t)((len >> 16) & 0xff);
    hdr[2] = (uint8_t)((len >>  8) & 0xff);
    hdr[3] = (uint8_t)(len & 0xff);
    int rc = io_write_all(io, hdr, 4);
    if (rc != PS_AP_OK) return rc;
    return io_write_all(io, payload, len);
}

/* Find ' "type"  :  "value"' inside the payload object. Conservative scan:
 * we walk the top-level object, skipping balanced quoted strings, until we
 * find a key literal "type", then read the following string value. */

static int is_ws(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

static const uint8_t *skip_ws(const uint8_t *p, const uint8_t *end) {
    while (p < end && is_ws((char)*p)) p++;
    return p;
}

static const uint8_t *skip_string(const uint8_t *p, const uint8_t *end) {
    /* p points at the opening '"'. Walk until the closing '"', honoring
     * backslash escapes. */
    if (p >= end || *p != '"') return NULL;
    p++;
    while (p < end) {
        if (*p == '\\') {
            p++;
            if (p >= end) return NULL;
            p++;
            continue;
        }
        if (*p == '"') return p + 1; /* one past the closing quote */
        p++;
    }
    return NULL;
}

/* Skip one JSON value (string/object/array/number/literal). Best-effort
 * for non-string values -- we just walk past balanced braces/brackets and
 * quoted strings. Sufficient for finding the next top-level key. */
static const uint8_t *skip_value(const uint8_t *p, const uint8_t *end) {
    p = skip_ws(p, end);
    if (p >= end) return NULL;
    if (*p == '"') return skip_string(p, end);
    if (*p == '{' || *p == '[') {
        char open = (char)*p, close = (open == '{') ? '}' : ']';
        int depth = 1; p++;
        while (p < end && depth > 0) {
            if (*p == '"') { p = skip_string(p, end); if (!p) return NULL; continue; }
            if (*p == open)  depth++;
            else if (*p == close) depth--;
            p++;
        }
        return depth == 0 ? p : NULL;
    }
    /* number / true / false / null -- walk until comma/closing brace */
    while (p < end && *p != ',' && *p != '}' && !is_ws((char)*p)) p++;
    return p;
}

int ps_ap_frame_type(const uint8_t *payload, size_t len,
                     char *out, size_t out_cap) {
    if (out_cap == 0) return -1;
    out[0] = '\0';
    const uint8_t *p = payload;
    const uint8_t *end = payload + len;
    p = skip_ws(p, end);
    if (p >= end || *p != '{') return -1;
    p++;
    while (p < end) {
        p = skip_ws(p, end);
        if (p >= end) return -1;
        if (*p == '}') return -1;
        if (*p != '"') return -1;
        /* Read key */
        const uint8_t *key_start = p + 1;
        const uint8_t *key_end_quote = skip_string(p, end);
        if (!key_end_quote) return -1;
        size_t key_len = (size_t)(key_end_quote - 1 - key_start);
        p = skip_ws(key_end_quote, end);
        if (p >= end || *p != ':') return -1;
        p = skip_ws(p + 1, end);
        if (p >= end) return -1;
        if (key_len == 4 && memcmp(key_start, "type", 4) == 0) {
            if (*p != '"') return -1;
            const uint8_t *vs = p + 1;
            const uint8_t *vend = skip_string(p, end);
            if (!vend) return -1;
            size_t vlen = (size_t)(vend - 1 - vs);
            if (vlen >= out_cap) vlen = out_cap - 1;
            memcpy(out, vs, vlen);
            out[vlen] = '\0';
            return 0;
        }
        /* Skip this value, then expect comma or end. */
        const uint8_t *vend = skip_value(p, end);
        if (!vend) return -1;
        p = skip_ws(vend, end);
        if (p < end && *p == ',') p++;
    }
    return -1;
}
