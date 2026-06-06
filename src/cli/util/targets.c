#include "targets.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

int ps_cidr_parse(const char *spec, struct ps_cidr *out) {
    if (!spec || !out) return -1;
    memset(out, 0, sizeof(*out));
    char buf[64];
    size_t n = strlen(spec);
    if (n >= sizeof(buf)) return -1;
    memcpy(buf, spec, n + 1);
    char *slash = strchr(buf, '/');
    int prefix = -1;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) return -1;
    }
    struct in_addr ia;
    if (inet_pton(AF_INET, buf, &ia) != 1) return -1;
    uint32_t addr = ntohl(ia.s_addr);
    if (prefix < 0) {
        out->base   = addr;
        out->count  = 1;
        out->prefix = -1;
        return 0;
    }
    uint32_t mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
    out->base   = addr & mask;
    out->count  = prefix == 32 ? 1 : (1u << (32 - prefix));
    out->prefix = prefix;
    return 0;
}

int ps_cidr_addr(const struct ps_cidr *c, uint32_t idx, char *out, size_t outsz) {
    if (idx >= c->count) return -1;
    uint32_t a = c->base + idx;
    struct in_addr ia; ia.s_addr = htonl(a);
    if (!inet_ntop(AF_INET, &ia, out, (socklen_t)outsz)) return -1;
    return 0;
}

static int port_add(struct ps_portset *p, int v) {
    if (v <= 0 || v > 65535) return -1;
    if (p->count == p->cap) {
        size_t newcap = p->cap ? p->cap * 2 : 64;
        uint16_t *grow = realloc(p->ports, newcap * sizeof(*grow));
        if (!grow) return -1;
        p->ports = grow; p->cap = newcap;
    }
    p->ports[p->count++] = (uint16_t)v;
    return 0;
}

int ps_ports_parse(const char *spec, struct ps_portset *out) {
    if (!spec || !out) return -1;
    memset(out, 0, sizeof(*out));
    const char *p = spec;
    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;
        char *end;
        long a = strtol(p, &end, 10);
        if (end == p) goto fail;
        if (*end == '-') {
            long b = strtol(end + 1, &end, 10);
            if (b < a) goto fail;
            for (long v = a; v <= b; v++) {
                if (port_add(out, (int)v) != 0) goto fail;
            }
        } else {
            if (port_add(out, (int)a) != 0) goto fail;
        }
        p = end;
    }
    if (out->count == 0) goto fail;
    return 0;
fail:
    ps_ports_destroy(out);
    return -1;
}

void ps_ports_destroy(struct ps_portset *p) {
    free(p->ports);
    p->ports = NULL; p->count = 0; p->cap = 0;
}
