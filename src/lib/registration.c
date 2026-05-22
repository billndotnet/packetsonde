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

#include "http_client.h"
#include "keystore.h"
#include <unistd.h>
#include <limits.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PS_REG_MARKER "/etc/packetsonded/registered"

static void self_exe_path(char *out, size_t cap) {
    ssize_t n = readlink("/proc/self/exe", out, cap - 1);
    if (n > 0) { out[n] = 0; return; }
    snprintf(out, cap, "%s", "/usr/local/bin/packetsonded");  /* fallback */
}

/* Minimal primary-v4 detection: UDP-connect a far address, read local sockname.
 * No packets are sent (connect on UDP just sets the route/local addr). */
static void primary_ipv4(char *out, size_t cap) {
    out[0] = 0;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    struct sockaddr_in to; memset(&to, 0, sizeof to);
    to.sin_family = AF_INET; to.sin_port = htons(53);
    inet_pton(AF_INET, "10.255.255.255", &to.sin_addr);
    if (connect(s, (struct sockaddr*)&to, sizeof to) == 0) {
        struct sockaddr_in me; socklen_t ml = sizeof me;
        if (getsockname(s, (struct sockaddr*)&me, &ml) == 0)
            inet_ntop(AF_INET, &me.sin_addr, out, cap);
    }
    close(s);
}

enum ps_reg_result ps_register(const struct ps_central_config *cc,
                               const char *provenance, int force) {
    if (!cc || !cc->url || !cc->url[0]) return PS_REG_LOCAL_ERR;   /* central disabled */

    char marker_id[128];
    if (!force && ps_reg_marker_read(PS_REG_MARKER, marker_id, sizeof marker_id) == 0)
        return PS_REG_ALREADY;

    const char *keydir = (cc->key_dir && cc->key_dir[0]) ? cc->key_dir
                                                         : "/etc/packetsonded/keys";
    struct ps_keypair kp;
    if (ps_keystore_load(keydir, "agent", &kp) != 0) {
        if (ps_keystore_generate(&kp) != 0) return PS_REG_LOCAL_ERR;
        if (ps_keystore_save(keydir, "agent", &kp) != 0) return PS_REG_LOCAL_ERR;
    }

    char exe[PATH_MAX]; self_exe_path(exe, sizeof exe);
    char checksum[65];
    if (ps_sha256_file(exe, checksum) != 0) return PS_REG_LOCAL_ERR;

    char host[256];
    const char *agent_id = (cc->agent_id && cc->agent_id[0]) ? cc->agent_id
                          : (gethostname(host, sizeof host) == 0 ? host : "unknown");

    char ip[64]; primary_ipv4(ip, sizeof ip);

    char payload[1024];
    struct ps_reg_input in = { agent_id, kp.pubkey, checksum,
                               cc->deployment_mode ? cc->deployment_mode : "host",
                               provenance, ip };
    if (ps_reg_build_payload(payload, sizeof payload, &in) < 0) return PS_REG_LOCAL_ERR;

    char url[640];
    snprintf(url, sizeof url, "%s/api/v1/packetsonde/register", cc->url);
    struct ps_http_opts opts = { cc->verify, cc->ca_cert, 10 };
    int status = 0; char resp[2048];
    if (ps_http_request("POST", url, payload, &opts, &status, resp, sizeof resp) != 0)
        return PS_REG_HTTP_ERR;
    if (status != 201 && status != 200 && status != 409) return PS_REG_HTTP_ERR;

    ps_reg_marker_write(PS_REG_MARKER, agent_id, status == 409 ? "exists" : "pending");
    return PS_REG_OK;
}
