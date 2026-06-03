#include "sock_parse.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Decode a "HEXADDR:HEXPORT" token into "a.b.c.d:port" (v4, 8 hex addr chars)
 * or "[v6]:port" (32 hex addr chars). Little-endian addr bytes, per kernel. */
static void decode_addr(const char *tok, char *out, size_t cap) {
    const char *colon = strchr(tok, ':');
    if (!colon) { snprintf(out, cap, "?"); return; }
    size_t alen = (size_t)(colon - tok);
    unsigned port = (unsigned)strtoul(colon + 1, NULL, 16);
    if (alen == 8) {
        /* 8-char hex = 4 bytes in little-endian order. Read pairs and reverse for display. */
        unsigned long d = strtoul((char[]){tok[0],tok[1],0}, NULL, 16);
        unsigned long c = strtoul((char[]){tok[2],tok[3],0}, NULL, 16);
        unsigned long b = strtoul((char[]){tok[4],tok[5],0}, NULL, 16);
        unsigned long a = strtoul((char[]){tok[6],tok[7],0}, NULL, 16);
        snprintf(out, cap, "%lu.%lu.%lu.%lu:%u", a, b, c, d, port);
    } else {
        /* v6: emit colon-grouped hex of the 32-char field, big enough for context */
        char hex[40]; size_t n = alen < sizeof hex - 1 ? alen : sizeof hex - 1;
        memcpy(hex, tok, n); hex[n] = 0;
        snprintf(out, cap, "[%s]:%u", hex, port);
    }
}

static const char *tcp_state(const char *st_hex) {
    static const char *S[] = {"","ESTABLISHED","SYN_SENT","SYN_RECV","FIN_WAIT1",
        "FIN_WAIT2","TIME_WAIT","CLOSE","CLOSE_WAIT","LAST_ACK","LISTEN","CLOSING"};
    unsigned v = (unsigned)strtoul(st_hex, NULL, 16);
    return (v < sizeof S / sizeof S[0]) ? S[v] : "";
}

int ps_sock_parse_procnet(const char *proto, const char *buf,
                          struct ps_sock_ep *out, int max) {
    if (!proto || !buf) return -1;
    int is_tcp = strcmp(proto, "tcp") == 0;
    int count = 0;
    const char *line = buf;
    /* skip header line */
    line = strchr(line, '\n');
    if (!line) return 0;
    line++;
    while (*line && count < max) {
        char local[64] = "", rem[64] = "", st[8] = "";
        unsigned long inode = 0;
        /* fields: "  N: LOCAL REM ST tx:rx tr:when retr uid timeout inode ..." */
        char sl[16];
        int got = sscanf(line, "%15[^:]: %63s %63s %7s %*s %*s %*s %*u %*u %lu",
                         sl, local, rem, st, &inode);
        if (got >= 5 && inode > 0) {
            struct ps_sock_ep *e = &out[count++];
            memset(e, 0, sizeof *e);
            e->inode = inode;
            snprintf(e->proto, sizeof e->proto, "%s", proto);
            decode_addr(local, e->laddr, sizeof e->laddr);
            decode_addr(rem, e->raddr, sizeof e->raddr);
            if (is_tcp) snprintf(e->state, sizeof e->state, "%s", tcp_state(st));
        }
        line = strchr(line, '\n');
        if (!line) break;
        line++;
    }
    return count;
}

int ps_sock_find_by_inode(const struct ps_sock_ep *eps, int n,
                          unsigned long inode, struct ps_sock_ep *out) {
    for (int i = 0; i < n; i++) {
        if (eps[i].inode == inode) { *out = eps[i]; return 0; }
    }
    return -1;
}
