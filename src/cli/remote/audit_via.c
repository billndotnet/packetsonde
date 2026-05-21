#include "audit_via.h"

#include "agent_proto.h"
#include "agent_transport.h"
#include "keystore.h"
#include "../registry/agents.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Split "host:port" into host + port. Returns 0 on success. */
static int split_addr(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    const char *colon = strrchr(spec, ':');
    if (!colon) return -1;
    size_t hl = (size_t)(colon - spec);
    if (hl == 0 || hl >= host_sz) return -1;
    memcpy(host, spec, hl); host[hl] = '\0';
    long p = atol(colon + 1);
    if (p <= 0 || p > 65535) return -1;
    *port = (uint16_t)p;
    return 0;
}

/* Build the audit request frame:
 *   {"type":"audit","kind":"<kind>","args":["a","b",...]}
 * Each arg is shell-escape-free (we just pass the verb's argv through).
 * JSON-string-escape each arg minimally. */
static int build_audit_request(char *out, size_t outsz,
                               int argc, char **argv) {
    size_t off = 0;
    int n = snprintf(out + off, outsz - off,
                     "{\"type\":\"audit\",\"kind\":\"%s\",\"args\":[", argv[0]);
    if (n < 0 || (size_t)n >= outsz - off) return -1;
    off += (size_t)n;
    for (int i = 1; i < argc; i++) {
        if (i > 1 && off + 1 < outsz) out[off++] = ',';
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
    if (off + 3 >= outsz) return -1;
    out[off++] = ']';
    out[off++] = '}';
    out[off]   = '\0';
    return (int)off;
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
    /* Splice via_agent before the closing brace. */
    /* Build: <obj_without_closing>,"via_agent":"<name>"} */
    char buf[8192];
    if (obj_len + strlen(agent_name) + 32 >= sizeof(buf)) return;
    memcpy(buf, start, obj_len - 1); /* drop closing } */
    int n = snprintf(buf + obj_len - 1, sizeof(buf) - (obj_len - 1),
                     ",\"via_agent\":\"%s\"}", agent_name);
    if (n < 0) return;
    (void)out;
    /* JSONL passthrough: one line on stdout. Matches the emitter's JSONL
     * format. */
    fwrite(buf, 1, obj_len - 1 + (size_t)n, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

int ps_audit_via_run(int argc, char **argv,
                     const struct ps_args *opts,
                     struct ps_output *out) {
    /* Resolve the agent. */
    struct ps_agents A;
    if (ps_agents_load(&A, ps_agents_default_path()) != 0 || A.count == 0) {
        fprintf(stderr, "--via: no agents registered (see 'packetsonde config show')\n");
        return 1;
    }
    const struct ps_agent *ag = ps_agents_find(&A, opts->via);
    if (!ag) {
        fprintf(stderr, "--via: unknown agent '%s'\n", opts->via);
        ps_agents_destroy(&A);
        return 1;
    }
    char host[256]; uint16_t port = 0;
    if (split_addr(ag->address, host, sizeof(host), &port) != 0) {
        fprintf(stderr, "--via: agent '%s' has bad address '%s'\n",
                ag->name, ag->address);
        ps_agents_destroy(&A);
        return 1;
    }
    if (!ag->key_fingerprint[0]) {
        fprintf(stderr, "--via: agent '%s' has no key_fingerprint in registry\n",
                ag->name);
        ps_agents_destroy(&A);
        return 1;
    }
    /* Strip optional sha256: prefix from the pin -- agents.toml may use
     * either form. */
    const char *pin = ag->key_fingerprint;
    if (strncmp(pin, "sha256:", 7) == 0) pin += 7;

    /* Load our CLI key. */
    char kdir[1024];
    if (ps_keystore_default_dir(kdir, sizeof(kdir)) != 0) {
        ps_agents_destroy(&A); return 1;
    }
    struct ps_keypair kp;
    if (ps_keystore_load(kdir, "default", &kp) != 0) {
        fprintf(stderr, "--via: no CLI key 'default' in %s\n"
                        "  (run: packetsonde key generate)\n", kdir);
        ps_agents_destroy(&A); return 1;
    }
    int has_sec = 0;
    for (size_t i = 0; i < PS_KEYSTORE_SECKEY_SIZE; i++)
        if (kp.seckey[i]) { has_sec = 1; break; }
    if (!has_sec) {
        fprintf(stderr, "--via: CLI key is pubkey-only\n");
        ps_agents_destroy(&A); return 1;
    }

    /* Open the mTLS channel. */
    struct ps_at_ctx tctx;
    if (ps_at_ctx_init(&tctx, PS_AT_CLIENT, &kp, pin) != 0) {
        fprintf(stderr, "--via: TLS context init failed\n");
        ps_agents_destroy(&A); return 1;
    }
    SSL *ssl = ps_at_connect(&tctx, host, port);
    if (!ssl) {
        fprintf(stderr, "--via: cannot connect to agent '%s' at %s:%u "
                        "(network unreachable, refused, or fingerprint mismatch)\n",
                ag->name, host, port);
        ps_at_ctx_destroy(&tctx); ps_agents_destroy(&A); return 1;
    }
    struct ps_ap_io io; ps_at_make_io(ssl, &io);

    /* Hello + audit request. */
    char self_fpr[PS_KEYSTORE_FPR_HEX_SIZE];
    ps_keystore_fingerprint(kp.pubkey, self_fpr);
    char hello[256];
    int hn = snprintf(hello, sizeof(hello),
                      "{\"type\":\"hello\",\"v\":%d,\"client_fingerprint\":\"sha256:%s\"}",
                      PS_AGENT_PROTO_VERSION, self_fpr);
    if (hn < 0 || ps_ap_write_frame(&io, hello, (size_t)hn) != PS_AP_OK) {
        fprintf(stderr, "--via: hello write failed\n");
        ps_at_close(ssl); ps_at_ctx_destroy(&tctx); ps_agents_destroy(&A);
        return 1;
    }
    char req[4096];
    int rn = build_audit_request(req, sizeof(req), argc, argv);
    if (rn < 0 || ps_ap_write_frame(&io, req, (size_t)rn) != PS_AP_OK) {
        fprintf(stderr, "--via: audit request write failed\n");
        ps_at_close(ssl); ps_at_ctx_destroy(&tctx); ps_agents_destroy(&A);
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
        char type[32];
        if (ps_ap_frame_type(fbuf, flen, type, sizeof(type)) != 0) continue;
        if (strcmp(type, "finding") == 0) {
            emit_finding_passthrough(out, ag->name, fbuf, flen);
        } else if (strcmp(type, "log") == 0) {
            /* Log lines are agent-side diagnostics; forward to stderr. */
            fwrite(fbuf, 1, flen, stderr);
            fputc('\n', stderr);
        } else if (strcmp(type, "error") == 0) {
            fwrite(fbuf, 1, flen, stderr);
            fputc('\n', stderr);
            run_rc = 1;
        } else if (strcmp(type, "bye") == 0) {
            break;
        } else if (strcmp(type, "hello") == 0) {
            /* agent's hello -- could validate features here */
        }
    }

    ps_at_close(ssl);
    ps_at_ctx_destroy(&tctx);
    ps_agents_destroy(&A);
    return run_rc;
}
