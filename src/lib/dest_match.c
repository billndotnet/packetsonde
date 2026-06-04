#include "dest_match.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* split "ip:port" (v4) -> ip + port strings. For "[v6]:port" the ip keeps the
 * brackets; CIDR is not attempted on v6. port may be empty. */
static void split_raddr(const char *raddr, char *ip, size_t ipc, char *port, size_t pc) {
    const char *colon = strrchr(raddr, ':');
    if (colon) {
        size_t n = (size_t)(colon - raddr); if (n >= ipc) n = ipc - 1;
        memcpy(ip, raddr, n); ip[n] = 0;
        snprintf(port, pc, "%s", colon + 1);
    } else { snprintf(ip, ipc, "%s", raddr); port[0] = 0; }
}

static int v4_to_u32(const char *ip, unsigned *out) {
    unsigned a,b,c,d;
    if (sscanf(ip, "%u.%u.%u.%u", &a,&b,&c,&d) != 4) return -1;
    if (a>255||b>255||c>255||d>255) return -1;
    *out = (a<<24)|(b<<16)|(c<<8)|d; return 0;
}

int ps_dest_match(const char *entry, const char *raddr) {
    if (!entry || !raddr) return 0;
    char rip[64], rport[16]; split_raddr(raddr, rip, sizeof rip, rport, sizeof rport);

    char e[128]; snprintf(e, sizeof e, "%s", entry);
    char *eport = NULL;
    char *slash = strchr(e, '/');
    char *ecolon = strrchr(e, ':');
    if (ecolon && (!slash || ecolon > slash)) { *ecolon = 0; eport = ecolon + 1; }
    if (eport && strcmp(eport, rport) != 0) return 0;      /* port specified and differs */

    if (e[0] == 0) return 1;                               /* ":port" form -> host wildcard, port matched */
    slash = strchr(e, '/');
    if (slash) {                                           /* v4 CIDR */
        *slash = 0; int bits = atoi(slash + 1);
        unsigned net, rip32;
        if (v4_to_u32(e, &net) != 0 || v4_to_u32(rip, &rip32) != 0) return 0;
        if (bits <= 0) return 1; if (bits > 32) bits = 32;
        unsigned mask = bits == 32 ? 0xFFFFFFFFu : ~((1u << (32 - bits)) - 1);
        return (net & mask) == (rip32 & mask);
    }
    return strcmp(e, rip) == 0;                            /* host (exact ip) */
}

int ps_destset_covered(const struct ps_baseline_set *s, const char *raddr) {
    for (int i = 0; i < s->n; i++) if (ps_dest_match(s->path[i], raddr)) return 1;
    return 0;
}

int ps_dest_generalize(const char *raddr, const char *form, char *out, size_t cap) {
    if (!raddr || !form) return -1;
    char ip[64], port[16]; split_raddr(raddr, ip, sizeof ip, port, sizeof port);
    if (!strcmp(form, "exact")) { snprintf(out, cap, "%s", raddr); return 0; }
    if (!strcmp(form, "host"))  { snprintf(out, cap, "%s", ip); return 0; }
    if (!strcmp(form, "port"))  { snprintf(out, cap, ":%s", port); return 0; }
    if (!strncmp(form, "cidr/", 5)) {
        int bits = atoi(form + 5); if (bits < 0) bits = 0; if (bits > 32) bits = 32;
        unsigned u; if (v4_to_u32(ip, &u) != 0) return -1;
        unsigned mask = bits == 0 ? 0 : (bits == 32 ? 0xFFFFFFFFu : ~((1u << (32 - bits)) - 1));
        unsigned net = u & mask;
        snprintf(out, cap, "%u.%u.%u.%u/%d", (net>>24)&255,(net>>16)&255,(net>>8)&255,net&255, bits);
        return 0;
    }
    return -1;
}
