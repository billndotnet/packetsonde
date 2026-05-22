#ifndef PS_CLI_CONFIG_UTIL_H
#define PS_CLI_CONFIG_UTIL_H
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* ps_config preserves wrapping double-quotes on values (config_to_env strips them
 * for the agent's env path; direct ps_config_get callers must). Copies v into buf,
 * stripping a single layer of surrounding double-quotes. Returns buf, or NULL if v
 * is NULL. */
static inline const char *ps_cli_unq(const char *v, char *buf, size_t cap) {
    if (!v) return NULL;
    size_t n = strlen(v);
    if (n >= 2 && v[0] == '"' && v[n - 1] == '"') {
        size_t inner = n - 2; if (inner >= cap) inner = cap - 1;
        memcpy(buf, v + 1, inner); buf[inner] = 0;
    } else {
        snprintf(buf, cap, "%s", v);
    }
    return buf;
}

#endif
