#include "registration.h"
#include "json.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static int b64(const uint8_t *in, size_t n, char *out, size_t cap) {
    int len = EVP_EncodeBlock((unsigned char *)out, in, (int)n);
    return (len < 0 || (size_t)len >= cap) ? -1 : len;
}

int ps_reg_build_payload(char *buf, size_t cap, const struct ps_reg_input *in) {
    char pub_b64[64];
    if (b64(in->pubkey, 32, pub_b64, sizeof pub_b64) < 0) return -1;
    struct ps_json j; ps_json_init(&j, buf, cap);
    ps_json_object_begin(&j);
    ps_json_key_string(&j, "agent_id", in->agent_id);
    ps_json_key_string(&j, "pubkey", pub_b64);
    ps_json_key_string(&j, "binary_checksum", in->binary_checksum);
    ps_json_key_string(&j, "deployment_mode", in->deployment_mode);
    ps_json_key_string(&j, "provenance", in->provenance);
    ps_json_key_string(&j, "ip_address", in->ip_address ? in->ip_address : "");
    ps_json_object_end(&j);
    int len = ps_json_finish(&j);   /* returns byte count on success, -1 on error */
    if (len < 0) return -1;
    return len;
}

int ps_sha256_file(const char *path, char *out_hex) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    if (!c) { fclose(f); return -1; }
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    unsigned char chunk[8192]; size_t r;
    while ((r = fread(chunk, 1, sizeof chunk, f)) > 0) EVP_DigestUpdate(c, chunk, r);
    fclose(f);
    unsigned char md[EVP_MAX_MD_SIZE]; unsigned int mdlen = 0;
    EVP_DigestFinal_ex(c, md, &mdlen);
    EVP_MD_CTX_free(c);
    for (unsigned i = 0; i < mdlen; i++) sprintf(out_hex + i*2, "%02x", md[i]);
    out_hex[mdlen*2] = 0;
    return 0;
}

int ps_reg_marker_read(const char *path, char *agent_id_out, size_t cap) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256]; int found = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "agent_id=", 9) == 0) {
            char *v = line + 9; v[strcspn(v, "\r\n")] = 0;
            snprintf(agent_id_out, cap, "%s", v); found = 0;
        }
    }
    fclose(f);
    return found;
}

int ps_reg_marker_write(const char *path, const char *agent_id, const char *status) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "agent_id=%s\nstatus=%s\n", agent_id, status);
    fclose(f);
    return 0;
}
