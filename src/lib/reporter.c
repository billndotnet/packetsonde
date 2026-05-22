#include "reporter.h"
#include "http_client.h"
#include "keystore.h"
#include "json.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int ps_report_events(const struct ps_central_config *cc, const char *base_url,
                     const char **event_jsons, size_t n, struct ps_report_result *out) {
    if (!cc || !cc->url || !cc->url[0]) return -1;
    const char *keydir = (cc->key_dir && cc->key_dir[0]) ? cc->key_dir : "/etc/packetsonded/keys";
    struct ps_keypair kp;
    if (ps_keystore_load(keydir, "agent", &kp) != 0) return -1;

    char host[256];
    const char *agent_id = (cc->agent_id && cc->agent_id[0]) ? cc->agent_id
                          : (gethostname(host, sizeof host) == 0 ? host : "unknown");

    /* Assemble {"envelopes":[ {…}, … ]}. payload is embedded as an escaped string
     * via ps_json so we get correct JSON-string quoting around the signed bytes. */
    static char body[262144];   /* 256 KiB batch cap */
    size_t bo = 0;
    bo += (size_t)snprintf(body + bo, sizeof body - bo, "{\"envelopes\":[");
    for (size_t i = 0; i < n; i++) {
        char ts[40];
        if (ps_reporter_extract_ts(event_jsons[i], ts, sizeof ts) != 0)
            snprintf(ts, sizeof ts, "1970-01-01T00:00:00Z");
        char payload[16384];
        if (ps_reporter_build_payload(payload, sizeof payload, agent_id, ts, event_jsons[i]) < 0)
            continue;
        uint8_t sig[64];
        if (ps_keystore_sign(&kp, (const uint8_t*)payload, strlen(payload), sig) != 0) return -1;
        char sig_b64[128];
        if (b64(sig, 64, sig_b64, sizeof sig_b64) < 0) return -1;

        char env[20000]; struct ps_json j; ps_json_init(&j, env, sizeof env);
        ps_json_object_begin(&j);
        ps_json_key_int(&j, "envelope_v", 1);
        ps_json_key_string(&j, "origin_agent_id", agent_id);
        ps_json_key_string(&j, "payload", payload);
        ps_json_key_string(&j, "ed25519_sig", sig_b64);
        ps_json_object_end(&j);
        if (ps_json_finish(&j) < 0) return -1;

        bo += (size_t)snprintf(body + bo, sizeof body - bo, "%s%s", i ? "," : "", env);
        if (bo >= sizeof body - 64) break;  /* batch full; caller can chunk */
    }
    bo += (size_t)snprintf(body + bo, sizeof body - bo, "]}");

    char url[640];
    snprintf(url, sizeof url, "%s/api/v1/packetsonde/events",
             (base_url && base_url[0]) ? base_url : cc->url);
    struct ps_http_opts opts = { cc->verify, cc->ca_cert, 15 };
    int status = 0; char resp[8192];
    if (ps_http_request("POST", url, body, &opts, &status, resp, sizeof resp) != 0) return -1;

    if (out) {
        out->http_status = status;
        out->total = (int)n;
        const char *a = strstr(resp, "\"accepted\":");
        out->accepted = a ? atoi(a + 11) : 0;
        out->rejected = out->total - out->accepted;
    }
    return 0;
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
