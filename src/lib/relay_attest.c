#include "relay_attest.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int ps_relay_attest_string(const char *env_sig_b64, const char *received_from,
                           const char *ts, char *out, size_t cap) {
    int n = snprintf(out, cap, "%s|%s|%s", env_sig_b64, received_from, ts);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

static void iso_now(char *out, size_t cap) {
    time_t t = time(NULL); struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static int b64(const unsigned char *in, size_t n, char *out, size_t cap) {
    int len = EVP_EncodeBlock((unsigned char *)out, in, (int)n);
    return (len < 0 || (size_t)len >= cap) ? -1 : len;
}

int ps_relay_attest_entry(const struct ps_keypair *kp, const char *self_agent_id,
                          const char *env_sig_b64, const char *received_from,
                          char *out, size_t cap) {
    char ts[40]; iso_now(ts, sizeof ts);
    char s[512];
    if (ps_relay_attest_string(env_sig_b64, received_from, ts, s, sizeof s) < 0) return -1;
    unsigned char sig[64];
    if (ps_keystore_sign(kp, (const unsigned char *)s, strlen(s), sig) != 0) return -1;
    char sig_b64[128];
    if (b64(sig, 64, sig_b64, sizeof sig_b64) < 0) return -1;
    int n = snprintf(out, cap,
        "{\"relay_agent_id\":\"%s\",\"received_from\":\"%s\",\"ts\":\"%s\",\"sig\":\"%s\"}",
        self_agent_id, received_from, ts, sig_b64);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}
