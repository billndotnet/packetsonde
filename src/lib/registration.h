#ifndef PS_REGISTRATION_H
#define PS_REGISTRATION_H
#include <stddef.h>
#include <stdint.h>

struct ps_config;  /* forward decl; from config.h */

struct ps_reg_input {
    const char *agent_id;
    const uint8_t *pubkey;        /* 32 bytes */
    const char *binary_checksum;
    const char *deployment_mode;
    const char *provenance;
    const char *ip_address;
};

enum ps_reg_result { PS_REG_OK, PS_REG_ALREADY, PS_REG_HTTP_ERR, PS_REG_LOCAL_ERR };

int ps_reg_build_payload(char *buf, size_t cap, const struct ps_reg_input *in);
int ps_sha256_file(const char *path, char *out_hex /* >= 65 */);
int ps_reg_marker_read(const char *path, char *agent_id_out, size_t cap);
int ps_reg_marker_write(const char *path, const char *agent_id, const char *status);

enum ps_reg_result ps_register(const struct ps_config *cfg,
                               const char *provenance, int force);
#endif
