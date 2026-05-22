#include "collect.h"
#include "json_extract.h"
#include "keystore.h"
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

/* base64-decode; returns decoded length or -1. */
static int b64dec(const char *in, uint8_t *out, size_t outcap) {
    size_t inlen = strlen(in);
    if (inlen == 0 || inlen % 4 != 0 || outcap < inlen / 4 * 3) return -1;
    int n = EVP_DecodeBlock(out, (const unsigned char*)in, (int)inlen);
    if (n < 0) return -1;
    if (inlen >= 1 && in[inlen-1] == '=') n--;
    if (inlen >= 2 && in[inlen-2] == '=') n--;
    return n;
}

/* True if `msg` is signed by any of the pubkeys (sig is base64). */
static int verified_by_any(const uint8_t (*pks)[32], size_t npk,
                           const uint8_t *msg, size_t msglen, const char *sig_b64) {
    uint8_t sig[80];
    int sl = b64dec(sig_b64, sig, sizeof sig);
    if (sl != 64) return 0;
    for (size_t i = 0; i < npk; i++)
        if (ps_keystore_verify(pks[i], msg, msglen, sig) == 1) return 1;
    return 0;
}

int ps_collect_process(const char *envelope_json, const uint8_t (*pubkeys)[32], size_t npk,
                       const char *received_ts, char *out, size_t cap,
                       struct ps_collect_result *res) {
    char payload[16384], sig_b64[128], outer_id[256] = "";
    if (ps_json_extract_string(envelope_json, "payload", payload, sizeof payload) < 0) return -1;
    if (ps_json_extract_string(envelope_json, "ed25519_sig", sig_b64, sizeof sig_b64) < 0) return -1;
    ps_json_extract_string(envelope_json, "origin_agent_id", outer_id, sizeof outer_id);

    int verified = verified_by_any(pubkeys, npk, (const uint8_t*)payload, strlen(payload), sig_b64);

    char inner_id[256] = "", ts[64] = "";
    ps_json_extract_string(payload, "origin_agent_id", inner_id, sizeof inner_id);
    ps_json_extract_string(payload, "ts", ts, sizeof ts);
    if (inner_id[0] && outer_id[0] && strcmp(inner_id, outer_id) != 0) verified = 0;

    /* event is a nested object: substring from "event": to its matching closing brace. */
    const char *ev = strstr(payload, "\"event\":");
    const char *obj = ev ? strchr(ev, '{') : NULL;
    char event_obj[16384] = "{}";
    if (obj) {
        int depth = 0; const char *c = obj;
        for (; *c; c++) { if (*c=='{') depth++; else if (*c=='}') { depth--; if (depth==0) { c++; break; } } }
        size_t len = (size_t)(c - obj);
        if (len < sizeof event_obj) { memcpy(event_obj, obj, len); event_obj[len] = 0; }
    }

    int has_relay = (strstr(envelope_json, "\"relay_path\":") != NULL);
    int chain_ok = 1;
    if (has_relay) {
        const char *rp = strstr(envelope_json, "\"relay_path\":");
        char rf[256] = "", rts[64] = "", rsig[128] = "";
        ps_json_extract_string(rp, "received_from", rf, sizeof rf);
        ps_json_extract_string(rp, "ts", rts, sizeof rts);
        ps_json_extract_string(rp, "sig", rsig, sizeof rsig);
        char attest[512];
        snprintf(attest, sizeof attest, "%s|%s|%s", sig_b64, rf, rts);
        chain_ok = verified_by_any(pubkeys, npk, (const uint8_t*)attest, strlen(attest), rsig);
    }

    res->verified = verified;
    res->has_relay = has_relay;
    res->relay_chain_verified = has_relay ? chain_ok : 1;

    size_t elen = strlen(event_obj);
    if (elen < 2 || event_obj[elen-1] != '}') return -1;
    event_obj[elen-1] = 0;  /* drop closing brace */
    const char *sep = (elen > 2) ? "," : "";
    int n = snprintf(out, cap,
        "%s%s\"agent_id\":\"%s\",\"verified\":%s,\"relay_chain_verified\":%s,"
        "\"transport\":\"%s\",\"received_ts\":\"%s\"}",
        event_obj, sep,
        inner_id[0] ? inner_id : (outer_id[0] ? outer_id : "unknown"),
        verified ? "true" : "false",
        res->relay_chain_verified ? "true" : "false",
        has_relay ? "relay" : "direct",
        received_ts ? received_ts : "");
    if (n < 0 || (size_t)n >= cap) return -1;
    return n;
}
