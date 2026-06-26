#include "remote_session.h"

#include "via_connect.h"

#include "agent_proto.h"
#include "agent_transport.h"
#include "../output/output.h"
#include "finding.h"
#include "recipe.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../args.h"

/* Build the request frame:
 *   {"type":"<type>","kind":"<kind>","args":["a","b",...]}
 * Each arg is shell-escape-free (we just pass the verb's argv through).
 * JSON-string-escape each arg minimally. */
static int build_request(char *out, size_t outsz,
                         const char *type, const char *kind,
                         int argc, char **argv,
                         const char *const *via_chain, int via_count) {
    size_t off = 0;
    int n = snprintf(out + off, outsz - off,
                     "{\"type\":\"%s\",\"kind\":\"%s\",\"args\":[", type, kind);
    if (n < 0 || (size_t)n >= outsz - off) return -1;
    off += (size_t)n;
    for (int i = 0; i < argc; i++) {
        if (i > 0 && off + 1 < outsz) out[off++] = ',';
        if (off + 1 >= outsz) return -1;
        out[off++] = '"';
        for (const char *p = argv[i]; *p; p++) {
            if (off + 2 >= outsz) return -1;
            unsigned char c = (unsigned char)*p;
            if (c == '"' || c == '\\') { out[off++] = '\\'; out[off++] = (char)c; }
            else if (c >= 0x20 && c < 0x7f) out[off++] = (char)c;
            else { /* drop non-printable for safety */ }
        }
        if (off + 1 >= outsz) return -1;
        out[off++] = '"';
    }
    if (off + 1 >= outsz) return -1;
    out[off++] = ']';
    /* Optional via_chain: the *remaining* hops after this one. The
     * receiving agent runs `packetsonde --via via_chain[0] ...` so the
     * forwarded request keeps shrinking by one hop per layer. */
    if (via_count > 0) {
        int w = snprintf(out + off, outsz - off, ",\"via_chain\":[");
        if (w < 0 || (size_t)w >= outsz - off) return -1;
        off += (size_t)w;
        for (int i = 0; i < via_count; i++) {
            if (i > 0 && off + 1 < outsz) out[off++] = ',';
            if (off + 1 >= outsz) return -1;
            out[off++] = '"';
            for (const char *p = via_chain[i]; *p; p++) {
                if (off + 2 >= outsz) return -1;
                unsigned char c = (unsigned char)*p;
                if (c == '"' || c == '\\') { out[off++] = '\\'; out[off++] = (char)c; }
                else if (c >= 0x20 && c < 0x7f) out[off++] = (char)c;
            }
            if (off + 1 >= outsz) return -1;
            out[off++] = '"';
        }
        if (off + 1 >= outsz) return -1;
        out[off++] = ']';
    }
    if (off + 1 >= outsz) return -1;
    out[off++] = '}';
    out[off]   = '\0';
    return (int)off;
}

/* Extract the severity field from a v:1 JSONL finding line so the
 * passthrough emitter can credit the right --fail-on counter. Returns
 * a PS_SEV_* value or -1 if not found. */
static int parse_severity_from_jsonl(const uint8_t *buf, size_t len) {
    const char *key = "\"severity\":\"";
    const size_t klen = 12;
    for (size_t i = 0; i + klen < len; i++) {
        if (memcmp(buf + i, key, klen) != 0) continue;
        const uint8_t *v = buf + i + klen;
        size_t vlen = 0;
        while (v + vlen < buf + len && v[vlen] != '"') vlen++;
        if      (vlen == 4 && memcmp(v, "info",     4) == 0) return PS_SEV_INFO;
        else if (vlen == 3 && memcmp(v, "low",      3) == 0) return PS_SEV_LOW;
        else if (vlen == 6 && memcmp(v, "medium",   6) == 0) return PS_SEV_MEDIUM;
        else if (vlen == 4 && memcmp(v, "high",     4) == 0) return PS_SEV_HIGH;
        else if (vlen == 8 && memcmp(v, "critical", 8) == 0) return PS_SEV_CRITICAL;
        return -1;
    }
    return -1;
}

/* Lift a "finding" frame's payload onto our local emitter. The payload
 * is already JSON in the v:1 schema, so we feed it to ps_output via
 * the JSON-passthrough path. We splice in a via_agent field before the
 * closing brace if one isn't already present.
 *
 * In the simplest implementation we just print the JSON line to stdout
 * directly when fmt is JSONL -- preserves the exact wire byte sequence
 * the agent sent and avoids re-parsing the finding record. */
static void emit_finding_passthrough(struct ps_output *out,
                                     const char *agent_name,
                                     const uint8_t *frame, size_t frame_len) {
    /* Extract the "payload" object via a minimal scanner: find ':"payload"' --
     * actually it's a key, so find "payload" followed by ':'. Find the
     * matching object start '{' and the matching close brace at the same
     * nesting depth. */
    const uint8_t *p = frame;
    const uint8_t *end = frame + frame_len;
    const char *key = "\"payload\"";
    const uint8_t *q = NULL;
    for (const uint8_t *s = p; s + 9 <= end; s++) {
        if (memcmp(s, key, 9) == 0) { q = s + 9; break; }
    }
    if (!q) return;
    while (q < end && (*q == ' ' || *q == ':' || *q == '\t')) q++;
    if (q >= end || *q != '{') return;
    int depth = 0;
    const uint8_t *start = q;
    while (q < end) {
        if (*q == '"') {
            /* skip a quoted string with escapes */
            q++;
            while (q < end && *q != '"') {
                if (*q == '\\' && q + 1 < end) q += 2;
                else q++;
            }
            if (q < end) q++;
            continue;
        }
        if (*q == '{') depth++;
        else if (*q == '}') { depth--; if (depth == 0) { q++; break; } }
        q++;
    }
    if (depth != 0) return;
    size_t obj_len = (size_t)(q - start);

    int sev = parse_severity_from_jsonl(start, obj_len);

    /* JSON-escape agent_name so a stray quote/backslash in a local
     * agents.toml entry can't corrupt the JSONL stream. */
    char esc[2 * 64 + 4]; /* PS_AGENT_NAME_MAX = 64, worst-case doubled */
    size_t eo = 0;
    for (const char *pn = agent_name; *pn && eo + 2 < sizeof(esc); pn++) {
        unsigned char c = (unsigned char)*pn;
        if (c == '"' || c == '\\') { esc[eo++] = '\\'; esc[eo++] = (char)c; }
        else if (c >= 0x20 && c < 0x7f) esc[eo++] = (char)c;
    }
    esc[eo] = '\0';

    /* Find an existing via_agent inside the payload object so we can
     * promote it from string to array when this hop adds itself.
     *
     * Single-hop case (no via_agent present): we splice
     *   ,"via_agent":"<name>"}  -- string form, unchanged from v1.6 for
     *   backwards compatibility with existing consumers that expect a
     *   scalar via_agent.
     *
     * Multi-hop case (via_agent already there):
     *   - if it's a string "X", rewrite to ["X","<name>"]
     *   - if it's an array [...], insert ,"<name>" before the closing ]
     *
     * Searching is a conservative substring scan -- the payload itself is
     * a flat finding record, no nested via_agent occurrences expected. */
    const char *vkey = "\"via_agent\"";
    const size_t vkey_len = 11;
    const uint8_t *va = NULL;
    for (const uint8_t *s = start; s + vkey_len <= start + obj_len; s++) {
        if (memcmp(s, vkey, vkey_len) == 0) { va = s + vkey_len; break; }
    }

    char buf[8192];
    int n;

    if (!va) {
        /* No existing via_agent -- splice as string. */
        if (obj_len + eo + 32 >= sizeof(buf)) return;
        memcpy(buf, start, obj_len - 1); /* drop closing } */
        n = snprintf(buf + obj_len - 1, sizeof(buf) - (obj_len - 1),
                     ",\"via_agent\":\"%s\"}", esc);
        if (n < 0) return;
        size_t bo = obj_len - 1 + (size_t)n;
        if (bo + 1 >= sizeof(buf)) return;
        buf[bo++] = '\n';
        ps_output_emit_raw_jsonl(out, sev, buf, bo);
        return;
    }

    /* Walk past ':' and whitespace to the value. */
    while (va < start + obj_len && (*va == ' ' || *va == ':' || *va == '\t')) va++;
    if (va >= start + obj_len) return;

    if (*va == '"') {
        /* String form. Find the closing quote (skipping escapes), capture
         * the string content, then rewrite the entire ,"via_agent":"X"
         * fragment as ,"via_agent":["X","<name>"]. */
        const uint8_t *vstart = va + 1;
        const uint8_t *vend   = vstart;
        while (vend < start + obj_len && *vend != '"') {
            if (*vend == '\\' && vend + 1 < start + obj_len) vend += 2;
            else vend++;
        }
        if (vend >= start + obj_len) return;
        /* Region to replace: from the ',' (or '{') before vkey through
         * the closing '"' of the existing value. Find the start. */
        const uint8_t *region_start = (const uint8_t *)memmem(
            start, (size_t)(va - start), vkey, vkey_len);
        if (!region_start) return;
        /* Step backward to swallow any preceding comma. */
        if (region_start > start && *(region_start - 1) == ',') region_start--;
        size_t prefix_len = (size_t)(region_start - start);
        size_t suffix_off = (size_t)(vend + 1 - start);
        size_t suffix_len = obj_len - suffix_off;

        size_t old_value_len = (size_t)(vend - vstart);
        if (old_value_len + eo + 64 >= sizeof(buf)) return;

        memcpy(buf, start, prefix_len);
        size_t bo = prefix_len;
        /* Always emit with a leading comma; if we're replacing the very
         * first field (prefix ends in '{'), use no comma. */
        const char *sep = (bo > 0 && buf[bo - 1] == '{') ? "" : ",";
        int w = snprintf(buf + bo, sizeof(buf) - bo,
                         "%s\"via_agent\":[\"%.*s\",\"%s\"]",
                         sep, (int)old_value_len, vstart, esc);
        if (w < 0 || (size_t)w >= sizeof(buf) - bo) return;
        bo += (size_t)w;
        if (bo + suffix_len >= sizeof(buf)) return;
        memcpy(buf + bo, start + suffix_off, suffix_len);
        bo += suffix_len;
        if (bo + 1 >= sizeof(buf)) return;
        buf[bo++] = '\n';
        ps_output_emit_raw_jsonl(out, sev, buf, bo);
        return;
    }

    if (*va == '[') {
        /* Array form. Find the matching ']' (no nested arrays expected in
         * the via_agent value -- it's a flat string list). Insert
         * ,"<name>" just before it. */
        const uint8_t *aend = va + 1;
        while (aend < start + obj_len && *aend != ']') {
            if (*aend == '"') {
                aend++;
                while (aend < start + obj_len && *aend != '"') {
                    if (*aend == '\\' && aend + 1 < start + obj_len) aend += 2;
                    else aend++;
                }
                if (aend < start + obj_len) aend++;
                continue;
            }
            aend++;
        }
        if (aend >= start + obj_len) return;
        size_t insert_off = (size_t)(aend - start);
        if (obj_len + eo + 8 >= sizeof(buf)) return;
        memcpy(buf, start, insert_off);
        size_t bo = insert_off;
        /* If the array is empty, no leading comma. Look back one char. */
        const char *sep = (bo > 0 && buf[bo - 1] == '[') ? "" : ",";
        int w = snprintf(buf + bo, sizeof(buf) - bo, "%s\"%s\"", sep, esc);
        if (w < 0 || (size_t)w >= sizeof(buf) - bo) return;
        bo += (size_t)w;
        memcpy(buf + bo, start + insert_off, obj_len - insert_off);
        bo += obj_len - insert_off;
        if (bo + 1 >= sizeof(buf)) return;
        buf[bo++] = '\n';
        ps_output_emit_raw_jsonl(out, sev, buf, bo);
        return;
    }

    /* Unknown shape -- give up silently, finding stays as the agent sent
     * it. Caller will not see this hop's name, but the data is intact. */
    (void)out; (void)n;
}

int ps_remote_run(const char *type, const char *kind, int argc, char **argv,
                  const struct ps_args *opts, struct ps_output *out) {
    struct ps_at_ctx tctx; SSL *ssl = NULL; struct ps_ap_io io;
    if (ps_via_connect(opts->via, &tctx, &ssl, &io) != 0) return 1;

    char req[4096];
    /* opts->via_chain[0] is the hop we just connected to; the remaining
     * hops travel in the request so the receiving agent can forward. */
    const char *const *next_chain = (opts->via_count > 1)
        ? &opts->via_chain[1] : NULL;
    int next_count = (opts->via_count > 1) ? (opts->via_count - 1) : 0;
    int rn = build_request(req, sizeof(req), type, kind, argc, argv,
                           next_chain, next_count);
    if (rn < 0 || ps_ap_write_frame(&io, req, (size_t)rn) != PS_AP_OK) {
        fprintf(stderr, "--via: %s request write failed\n", type);
        ps_at_close(ssl); ps_at_ctx_destroy(&tctx);
        return 1;
    }

    /* Stream frames until bye/error/eof. */
    int run_rc = 0;
    for (;;) {
        uint8_t fbuf[64 * 1024]; size_t flen = 0;
        int frc = ps_ap_read_frame(&io, fbuf, sizeof(fbuf), &flen);
        if (frc == PS_AP_ERR_EOF) break;
        if (frc != PS_AP_OK) {
            fprintf(stderr, "--via: read error (%d)\n", frc);
            run_rc = 1; break;
        }
        char ftype[32];
        if (ps_ap_frame_type(fbuf, flen, ftype, sizeof(ftype)) != 0) continue;
        if (strcmp(ftype, "finding") == 0) {
            emit_finding_passthrough(out, opts->via, fbuf, flen);
        } else if (strcmp(ftype, "log") == 0) {
            /* Log lines are agent-side diagnostics; forward to stderr. */
            fwrite(fbuf, 1, flen, stderr);
            fputc('\n', stderr);
        } else if (strcmp(ftype, "error") == 0) {
            fwrite(fbuf, 1, flen, stderr);
            fputc('\n', stderr);
            run_rc = 1;
        } else if (strcmp(ftype, "bye") == 0) {
            break;
        } else if (strcmp(ftype, "hello") == 0) {
            /* agent's hello -- could validate features here */
        }
    }

    ps_at_close(ssl);
    ps_at_ctx_destroy(&tctx);
    return run_rc;
}
