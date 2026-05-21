#include "audit_via.h"

#include "agent_proto.h"
#include "agent_transport.h"
#include "discovery.h"
#include "keystore.h"
#include "../registry/agents.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

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
                               int argc, char **argv,
                               const char *const *via_chain, int via_count) {
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
        fwrite(buf, 1, obj_len - 1 + (size_t)n, stdout);
        fputc('\n', stdout);
        fflush(stdout);
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
        fwrite(buf, 1, bo, stdout);
        fputc('\n', stdout);
        fflush(stdout);
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
        fwrite(buf, 1, bo, stdout);
        fputc('\n', stdout);
        fflush(stdout);
        return;
    }

    /* Unknown shape -- give up silently, finding stays as the agent sent
     * it. Caller will not see this hop's name, but the data is intact. */
    (void)out; (void)n;
}

/* Send a signed broadcast knock and wait for a reply from the agent whose
 * pubkey matches `pin`. On success fills *out_ip and *out_port with the
 * agent's session-window listener. Returns 0 on success. */
static int knock_for_session(const struct ps_keypair *kp, const char *pin,
                              const char *bcast, char *out_ip, size_t ip_cap,
                              uint16_t *out_port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    struct sockaddr_in la; memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET; la.sin_addr.s_addr = htonl(INADDR_ANY); la.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&la, sizeof(la)) != 0) { close(fd); return -1; }

    struct ps_discovery_probe p = {0};
    p.version = PS_DISCOVERY_VERSION;
    p.flags = PS_DISCOVERY_FLAG_REQUEST_SESSION;
    p.max_skew_ms = PS_DISCOVERY_DEFAULT_SKEW_MS;
    p.timestamp_ms = ps_discovery_now_ms();
    ps_discovery_random(p.nonce, PS_DISCOVERY_NONCE_SIZE);
    memcpy(p.pubkey, kp->pubkey, PS_DISCOVERY_PUBKEY_SIZE);
    if (ps_discovery_probe_sign(&p, kp->seckey) != 0) { close(fd); return -1; }

    uint8_t wire[PS_DISCOVERY_PROBE_SIZE];
    ps_discovery_probe_pack(&p, wire);
    /* The agent dst port doesn't matter -- its pcap listener catches by
     * broadcast MAC + magic. Pick a random high port so we blend with
     * ad-hoc UDP traffic. */
    uint8_t cp[2]; ps_discovery_random(cp, 2);
    uint16_t cover = (uint16_t)(32768 + ((cp[0] << 8 | cp[1]) & 0x7fff));
    struct sockaddr_in to; memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(cover);
    if (inet_aton(bcast, &to.sin_addr) == 0) { close(fd); return -1; }
    if (sendto(fd, wire, sizeof(wire), 0,
               (struct sockaddr *)&to, sizeof(to)) != (ssize_t)sizeof(wire)) {
        close(fd); return -1;
    }

    struct timeval tv = { 3, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    for (int tries = 0; tries < 8; tries++) {
        uint8_t rbuf[PS_DISCOVERY_REPLY_SIZE * 2];
        struct sockaddr_in from; socklen_t flen = sizeof(from);
        ssize_t n = recvfrom(fd, rbuf, sizeof(rbuf), 0,
                             (struct sockaddr *)&from, &flen);
        if (n <= 0) break;
        if (n != PS_DISCOVERY_REPLY_SIZE) continue;
        struct ps_discovery_reply r;
        if (ps_discovery_reply_unpack(&r, rbuf) != 0) continue;
        if (memcmp(r.nonce, p.nonce, PS_DISCOVERY_NONCE_SIZE) != 0) continue;
        if (!ps_discovery_reply_verify(&r)) continue;
        /* Compare the agent's pubkey to the pin. */
        char fpr[PS_KEYSTORE_FPR_HEX_SIZE];
        ps_keystore_fingerprint(r.agent_pub, fpr);
        if (strcmp(fpr, pin) != 0) continue;
        /* v4-mapped reply ip. */
        if (memcmp(r.listen_ip, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) != 0) continue;
        snprintf(out_ip, ip_cap, "%u.%u.%u.%u",
                 r.listen_ip[12], r.listen_ip[13],
                 r.listen_ip[14], r.listen_ip[15]);
        *out_port = r.listen_port;
        close(fd);
        return 0;
    }
    close(fd);
    return -1;
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
    char host[256] = ""; uint16_t port = 0;
    if (!ag->knock) {
        if (split_addr(ag->address, host, sizeof(host), &port) != 0) {
            fprintf(stderr, "--via: agent '%s' has bad address '%s'\n",
                    ag->name, ag->address);
            ps_agents_destroy(&A);
            return 1;
        }
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

    /* Knock-mode: replace (host, port) with the ephemeral session window
     * advertised by the agent in its discovery reply. */
    if (ag->knock) {
        const char *bcast = ag->broadcast[0] ? ag->broadcast : "255.255.255.255";
        if (knock_for_session(&kp, pin, bcast, host, sizeof(host), &port) != 0) {
            fprintf(stderr, "--via: knock failed (no reply from authorized agent on %s)\n",
                    bcast);
            ps_agents_destroy(&A); return 1;
        }
    }

    /* Open the mTLS channel. SIGPIPE block is opt-in now (#11) so the
     * library can be embedded without surprise. We want it set for any
     * --via run so a half-closed peer doesn't kill us mid-stream. */
    ps_at_block_sigpipe();
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
    /* opts->via_chain[0] is the hop we just connected to; the remaining
     * hops travel in the request so the receiving agent can forward. */
    const char *const *next_chain = (opts->via_count > 1)
        ? &opts->via_chain[1] : NULL;
    int next_count = (opts->via_count > 1) ? (opts->via_count - 1) : 0;
    int rn = build_audit_request(req, sizeof(req), argc, argv,
                                 next_chain, next_count);
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
