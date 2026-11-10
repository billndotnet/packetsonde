#include "reporter.h"
#include "http_client.h"
#include "keystore.h"
#include "json.h"
#include "log.h"
#include <openssl/evp.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int ps_reporter_extract_ts(const char *event_json, char *out, size_t cap) {
    const char *k = strstr(event_json, "\"ts\":\"");
    if (!k) return -1;
    k += 6;
    const char *end = strchr(k, '"');
    if (!end) return -1;
    size_t len = (size_t)(end - k);
    if (len >= cap) len = cap - 1;
    memcpy(out, k, len); out[len] = 0;
    return 0;
}

int ps_reporter_build_payload(char *buf, size_t cap, const char *agent_id,
                              const char *ts, const char *event_json) {
    /* Order/escaping irrelevant — central verifies these exact bytes, then parses.
     * agent_id/ts are controlled (ids + ISO timestamps); event_json is embedded raw. */
    int n = snprintf(buf, cap,
        "{\"origin_agent_id\":\"%s\",\"ts\":\"%s\",\"event\":%s}",
        agent_id, ts, event_json);
    if (n < 0 || (size_t)n >= cap) return -1;
    return n;
}

static int b64(const uint8_t *in, size_t n, char *out, size_t cap) {
    int len = EVP_EncodeBlock((unsigned char *)out, in, (int)n);
    return (len < 0 || (size_t)len >= cap) ? -1 : len;
}

/* Rate-limited warnings: the first occurrence of each reason is logged, then at
 * most one per PS_REPORT_WARN_INTERVAL seconds carrying the count suppressed in
 * between. Sizes and indices only; observation contents are never logged. */
#define PS_REPORT_WARN_INTERVAL 60
enum warn_reason {
    W_PAYLOAD, W_SIGN, W_B64, W_ENVELOPE, W_TOO_BIG, W_KEY, W_POST, W_STATUS, W_NREASONS
};
static const char *const WARN_NAME[W_NREASONS] = {
    "payload_too_large", "sign_failed", "b64_failed", "envelope_too_large",
    "exceeds_batch_buffer", "key_load_failed", "post_failed", "http_status",
};
static struct { time_t last; unsigned long suppressed; } g_warn[W_NREASONS];
static pthread_mutex_t g_warn_mu = PTHREAD_MUTEX_INITIALIZER;

static void report_warn(enum warn_reason r, const char *fmt, ...) {
    time_t now = time(NULL);
    unsigned long sup;
    pthread_mutex_lock(&g_warn_mu);
    if (g_warn[r].last != 0 && now - g_warn[r].last < PS_REPORT_WARN_INTERVAL) {
        g_warn[r].suppressed++;
        pthread_mutex_unlock(&g_warn_mu);
        return;
    }
    sup = g_warn[r].suppressed;
    g_warn[r].suppressed = 0;
    g_warn[r].last = now;
    pthread_mutex_unlock(&g_warn_mu);

    char msg[384];
    va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    if (sup) ps_warn("reporter: %s: %s (%lu more since last report)", WARN_NAME[r], msg, sup);
    else     ps_warn("reporter: %s: %s", WARN_NAME[r], msg);
}

/* Builds the array for event_jsons[0..n) into out. `base` is the index of
 * event_jsons[0] in the caller's batch, for diagnostics only. */
static int build_envelopes(const struct ps_central_config *cc,
                           const char **event_jsons, size_t n, size_t base,
                           char *out, size_t cap, struct ps_envelope_stats *st) {
    struct ps_envelope_stats local;
    if (!st) st = &local;
    memset(st, 0, sizeof *st);
    if (!out || cap < 3) return -1;   /* room for "[]" + NUL */

    const char *keydir = (cc->key_dir && cc->key_dir[0]) ? cc->key_dir : "/etc/packetsonded/keys";
    struct ps_keypair kp;
    if (ps_keystore_load(keydir, "agent", &kp) != 0) {
        report_warn(W_KEY, "cannot load the agent signing key; %zu item(s) not built", n);
        return -1;
    }

    char host[256];
    const char *agent_id = (cc->agent_id && cc->agent_id[0]) ? cc->agent_id
                          : (gethostname(host, sizeof host) == 0 ? host : "unknown");

    /* "[ {…}, … ]" — each envelope's payload embedded as an escaped string via
     * ps_json so the signed bytes are correctly quoted. Room for "]\0" is
     * reserved throughout, so the array is always closed and never overruns. */
    char payload[16384];
    char env[20000];
    size_t o = 0;
    out[o++] = '[';
    size_t i;
    for (i = 0; i < n; i++) {
        size_t ilen = strlen(event_jsons[i]);
        char ts[40];
        if (ps_reporter_extract_ts(event_jsons[i], ts, sizeof ts) != 0)
            snprintf(ts, sizeof ts, "1970-01-01T00:00:00Z");
        int plen = ps_reporter_build_payload(payload, sizeof payload, agent_id, ts, event_jsons[i]);
        if (plen < 0) {
            report_warn(W_PAYLOAD, "item %zu skipped (item %zu bytes, payload buffer %zu)",
                        base + i, ilen, sizeof payload);
            st->skipped++; continue;
        }
        uint8_t sig[64];
        if (ps_keystore_sign(&kp, (const uint8_t*)payload, (size_t)plen, sig) != 0) {
            report_warn(W_SIGN, "item %zu skipped (payload %d bytes)", base + i, plen);
            st->skipped++; continue;
        }
        char sig_b64[128];
        if (b64(sig, 64, sig_b64, sizeof sig_b64) < 0) {
            report_warn(W_B64, "item %zu skipped", base + i);
            st->skipped++; continue;
        }

        struct ps_json j; ps_json_init(&j, env, sizeof env);
        ps_json_object_begin(&j);
        ps_json_key_int(&j, "envelope_v", 1);
        ps_json_key_string(&j, "origin_agent_id", agent_id);
        ps_json_key_string(&j, "payload", payload);
        ps_json_key_string(&j, "ed25519_sig", sig_b64);
        ps_json_object_end(&j);
        int elen = ps_json_finish(&j);
        if (elen < 0) {
            report_warn(W_ENVELOPE, "item %zu skipped (item %zu bytes, payload %d bytes, "
                        "escaped envelope exceeds %zu)", base + i, ilen, plen, sizeof env);
            st->skipped++; continue;
        }

        size_t need = (size_t)elen + (st->emitted ? 1 : 0);
        if (o + need + 2 > cap) {
            if (st->emitted == 0) {
                /* Cannot fit even in an otherwise empty array: never will. */
                report_warn(W_TOO_BIG, "item %zu skipped (envelope %d bytes, batch buffer %zu)",
                            base + i, elen, cap);
                st->skipped++; continue;
            }
            break;   /* full: leave item i and the rest for the caller's next chunk */
        }
        if (st->emitted) out[o++] = ',';
        memcpy(out + o, env, (size_t)elen); o += (size_t)elen;
        st->emitted++;
    }
    st->consumed = i;
    out[o++] = ']';
    out[o] = 0;
    return (int)o;
}

int ps_reporter_build_envelopes_ex(const struct ps_central_config *cc,
                                   const char **event_jsons, size_t n,
                                   char *out, size_t cap,
                                   struct ps_envelope_stats *st) {
    return build_envelopes(cc, event_jsons, n, 0, out, cap, st);
}

int ps_reporter_build_envelopes(const struct ps_central_config *cc,
                                const char **event_jsons, size_t n,
                                char *out, size_t cap) {
    struct ps_envelope_stats st;
    int rc = build_envelopes(cc, event_jsons, n, 0, out, cap, &st);
    if (rc >= 0 && st.consumed < n)
        report_warn(W_TOO_BIG, "%zu of %zu item(s) did not fit the %zu-byte array and were left out",
                    n - st.consumed, n, cap);
    return rc;
}

#define PS_REPORT_BATCH_CAP 262144   /* bytes of envelope array per POST */

/* Shared: sign + POST {envelopes:[…]} to `endpoint_path` under the host. Items
 * whose envelope cannot be built are skipped; when the envelopes outgrow one
 * POST the rest go in further POSTs, so nothing is silently truncated. */
static int ps_report_to(const struct ps_central_config *cc, const char *base_url,
                        const char *endpoint_path,
                        const char **event_jsons, size_t n,
                        struct ps_report_result *out) {
    struct ps_report_result res;
    memset(&res, 0, sizeof res);
    res.total = (int)n;
    int rc = 0;

    static const char pre[] = "{\"envelopes\":";
    const size_t prelen = sizeof pre - 1;
    char *body = NULL;

    if (!cc || !cc->url || !cc->url[0]) { res.unsent = (int)n; rc = -1; goto out; }
    body = malloc(prelen + PS_REPORT_BATCH_CAP + 2);
    if (!body) { res.unsent = (int)n; rc = -1; goto out; }
    memcpy(body, pre, prelen);

    char url[640];
    snprintf(url, sizeof url, "%s%s",
             (base_url && base_url[0]) ? base_url : cc->url, endpoint_path);
    struct ps_http_opts opts = { cc->verify, cc->ca_cert, 15 };

    size_t off = 0;
    while (off < n) {
        struct ps_envelope_stats st;
        int alen = build_envelopes(cc, event_jsons + off, n - off, off,
                                   body + prelen, PS_REPORT_BATCH_CAP, &st);
        if (alen < 0 || st.consumed == 0) {   /* key unusable: nothing more can be built */
            res.unsent += (int)(n - off); res.retryable += (int)(n - off); rc = -1; break;
        }
        res.skipped += (int)st.skipped;
        off += st.consumed;
        if (st.emitted == 0) continue;
        body[prelen + (size_t)alen] = '}';
        body[prelen + (size_t)alen + 1] = 0;
        size_t blen = prelen + (size_t)alen + 1;

        int status = 0; char resp[8192]; resp[0] = 0;
        res.posts++;
        if (ps_http_request("POST", url, body, &opts, &status, resp, sizeof resp) != 0) {
            report_warn(W_POST, "POST of %zu envelope(s), %zu-byte body failed at %s",
                        st.emitted, blen, ps_http_last_error());
            /* central is unreachable: do not keep signing and dialling */
            res.unsent += (int)st.emitted + (int)(n - off);
            res.retryable += (int)st.emitted + (int)(n - off);
            rc = -1; break;
        }
        res.http_status = status;
        if (status < 200 || status > 299) {
            report_warn(W_STATUS, "POST of %zu envelope(s), %zu-byte body answered HTTP %d",
                        st.emitted, blen, status);
            res.unsent += (int)st.emitted;
            if (status >= 500 || status == 429) res.retryable += (int)st.emitted;
            continue;
        }
        const char *a = strstr(resp, "\"accepted\":");
        res.accepted += a ? atoi(a + 11) : 0;
    }
out:
    free(body);
    res.rejected = res.total - res.accepted;
    if (out) *out = res;
    return rc;
}

int ps_report_events(const struct ps_central_config *cc, const char *base_url,
                     const char **event_jsons, size_t n, struct ps_report_result *out) {
    return ps_report_to(cc, base_url, "/api/v1/packetsonde/events", event_jsons, n, out);
}

int ps_report_observations(const struct ps_central_config *cc, const char *base_url,
                           const char **event_jsons, size_t n, struct ps_report_result *out) {
    return ps_report_to(cc, base_url, "/api/v1/packetsonde/observations", event_jsons, n, out);
}

int ps_report_findings(const struct ps_central_config *cc, const char *base_url,
                       const struct ps_finding *findings, size_t n,
                       struct ps_report_result *out) {
    const char **events = calloc(n, sizeof(char*));
    char *blob = malloc(n * 8192);
    if (!events || !blob) { free(events); free(blob); return -1; }
    size_t ok = 0;
    for (size_t i = 0; i < n; i++) {
        char *slot = blob + i * 8192;
        int len = ps_finding_to_json(&findings[i], slot, 8192);
        if (len < 0) continue;
        if (len > 0 && slot[len-1] == '\n') slot[len-1] = 0;  /* drop trailing newline */
        events[ok++] = slot;
    }
    int rc = ps_report_events(cc, base_url, events, ok, out);
    free(events); free(blob);
    return rc;
}
