#include "agents.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *ltrim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}
static void rtrim(char *s) {
    size_t L = strlen(s);
    while (L && isspace((unsigned char)s[L-1])) s[--L] = '\0';
}

static int ps_agents_push(struct ps_agents *A, const struct ps_agent *a) {
    if (A->count == A->cap) {
        size_t nc = A->cap ? A->cap * 2 : 4;
        struct ps_agent *g = realloc(A->items, nc * sizeof(*g));
        if (!g) return -1;
        A->items = g; A->cap = nc;
    }
    A->items[A->count++] = *a;
    return 0;
}

static int strip_quotes(char *v) {
    size_t L = strlen(v);
    if (L >= 2 && v[0] == '"' && v[L-1] == '"') {
        memmove(v, v + 1, L - 2);
        v[L - 2] = '\0';
        return 0;
    }
    return -1;
}

int ps_agents_load(struct ps_agents *A, const char *path) {
    memset(A, 0, sizeof(*A));
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[1024];
    struct ps_agent cur; memset(&cur, 0, sizeof(cur));
    int in_block = 0;

    while (fgets(line, sizeof(line), f)) {
        char *s = ltrim(line);
        if (*s == '#' || *s == '\0' || *s == '\n') continue;
        rtrim(s);
        if (*s == '[') {
            if (in_block && cur.name[0]) ps_agents_push(A, &cur);
            memset(&cur, 0, sizeof(cur));
            in_block = 0;
            if (strncmp(s, "[agents.", 8) != 0) continue;
            const char *name_start = s + 8;
            const char *rb = strchr(name_start, ']');
            if (!rb) continue;
            size_t nl = (size_t)(rb - name_start);
            if (nl == 0 || nl >= sizeof(cur.name)) continue;
            memcpy(cur.name, name_start, nl);
            cur.name[nl] = '\0';
            in_block = 1;
            continue;
        }
        if (!in_block) continue;
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = ltrim(s); rtrim(key);
        char *val = ltrim(eq + 1); rtrim(val);
        if (strip_quotes(val) != 0) continue;
        if      (!strcmp(key, "address"))         strncpy(cur.address,         val, sizeof(cur.address)         - 1);
        else if (!strcmp(key, "key_fingerprint")) strncpy(cur.key_fingerprint, val, sizeof(cur.key_fingerprint) - 1);
        else if (!strcmp(key, "tags"))            strncpy(cur.tags,            val, sizeof(cur.tags)            - 1);
    }
    if (in_block && cur.name[0]) ps_agents_push(A, &cur);
    fclose(f);
    return 0;
}

const struct ps_agent *ps_agents_find(const struct ps_agents *A, const char *name) {
    for (size_t i = 0; i < A->count; i++) {
        if (strcmp(A->items[i].name, name) == 0) return &A->items[i];
    }
    return NULL;
}

void ps_agents_destroy(struct ps_agents *A) {
    free(A->items);
    memset(A, 0, sizeof(*A));
}

const char *ps_agents_default_path(void) {
    static char path[512];
    const char *cfg = getenv("XDG_CONFIG_HOME");
    if (cfg && cfg[0]) {
        snprintf(path, sizeof(path), "%s/packetsonde/agents.toml", cfg);
    } else {
        const char *home = getenv("HOME");
        if (home && home[0]) {
            snprintf(path, sizeof(path), "%s/.config/packetsonde/agents.toml", home);
        } else {
            snprintf(path, sizeof(path), "/etc/packetsonde/agents.toml");
        }
    }
    return path;
}
