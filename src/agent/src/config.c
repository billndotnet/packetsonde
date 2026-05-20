#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static int parse_line(struct ps_config *cfg, char *current_section, const char *line)
{
    char buf[PS_CONFIG_MAX_LINE];
    snprintf(buf, sizeof(buf), "%s", line);
    char *s = trim(buf);

    if (*s == '\0' || *s == '#' || *s == ';') return 0;

    if (*s == '[') {
        char *end = strchr(s, ']');
        if (!end) return -1;
        *end = '\0';
        snprintf(current_section, 64, "%s", trim(s + 1));
        return 0;
    }

    char *eq = strchr(s, '=');
    if (!eq) return -1;
    *eq = '\0';
    char *key = trim(s);
    char *val = trim(eq + 1);

    if (cfg->count >= PS_CONFIG_MAX_SECTIONS * PS_CONFIG_MAX_KEYS) return -1;

    struct ps_config_entry *e = &cfg->entries[cfg->count++];
    snprintf(e->section, sizeof(e->section), "%s", current_section);
    snprintf(e->key, sizeof(e->key), "%s", key);
    snprintf(e->value, sizeof(e->value), "%s", val);
    return 0;
}

static int parse_lines(struct ps_config *cfg, const char *text)
{
    cfg->count = 0;
    char current_section[64] = "";
    char line[PS_CONFIG_MAX_LINE];
    const char *p = text;

    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, p, len);
        line[len] = '\0';
        if (parse_line(cfg, current_section, line) < 0) return -1;
        p += len;
        if (*p == '\n') p++;
    }
    return 0;
}

int ps_config_parse_string(struct ps_config *cfg, const char *text) { return parse_lines(cfg, text); }

int ps_config_parse_file(struct ps_config *cfg, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0 || size > 1024 * 1024) { fclose(f); return -1; }
    char *buf = malloc((size_t)size + 1);
    if (!buf) { fclose(f); return -1; }
    size_t nread = fread(buf, 1, (size_t)size, f);
    buf[nread] = '\0';
    fclose(f);
    int rc = parse_lines(cfg, buf);
    free(buf);
    return rc;
}

const char *ps_config_get(const struct ps_config *cfg, const char *section, const char *key)
{
    for (int i = 0; i < cfg->count; i++) {
        if (strcmp(cfg->entries[i].section, section) == 0 &&
            strcmp(cfg->entries[i].key, key) == 0)
            return cfg->entries[i].value;
    }
    return NULL;
}

int ps_config_get_int(const struct ps_config *cfg, const char *section, const char *key, int def)
{
    const char *v = ps_config_get(cfg, section, key);
    if (!v) return def;
    return (int)strtol(v, NULL, 0);
}

int ps_config_get_bool(const struct ps_config *cfg, const char *section, const char *key, int def)
{
    const char *v = ps_config_get(cfg, section, key);
    if (!v) return def;
    return (strcmp(v, "true") == 0 || strcmp(v, "yes") == 0 || strcmp(v, "1") == 0);
}

void ps_config_free(struct ps_config *cfg) { cfg->count = 0; }
