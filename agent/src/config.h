#ifndef PS_CONFIG_H
#define PS_CONFIG_H

#include <stddef.h>

#define PS_CONFIG_MAX_SECTIONS  32
#define PS_CONFIG_MAX_KEYS      64
#define PS_CONFIG_MAX_LINE      1024

struct ps_config_entry {
    char section[64];
    char key[64];
    char value[512];
};

struct ps_config {
    struct ps_config_entry entries[PS_CONFIG_MAX_SECTIONS * PS_CONFIG_MAX_KEYS];
    int count;
};

int ps_config_parse_file(struct ps_config *cfg, const char *path);
int ps_config_parse_string(struct ps_config *cfg, const char *text);
const char *ps_config_get(const struct ps_config *cfg, const char *section, const char *key);
int ps_config_get_int(const struct ps_config *cfg, const char *section, const char *key, int def);
int ps_config_get_bool(const struct ps_config *cfg, const char *section, const char *key, int def);
void ps_config_free(struct ps_config *cfg);

#endif
