#ifndef PS_SOCK_PARSE_H
#define PS_SOCK_PARSE_H
#include <stddef.h>

struct ps_sock_ep {
    unsigned long inode;
    char proto[4];     /* "tcp"|"udp" */
    char laddr[64];    /* "ip:port" */
    char raddr[64];
    char state[16];    /* "ESTABLISHED" etc, or "" for udp */
};

/* Parse /proc/net/{tcp,tcp6,udp,udp6} text. `proto` is "tcp" or "udp"; the
 * tcp6/udp6 hex-address width is auto-detected per line. Returns count, or -1. */
int ps_sock_parse_procnet(const char *proto, const char *buf,
                          struct ps_sock_ep *out, int max);

/* Copy the first entry whose inode matches into *out. 0 on hit, -1 if none. */
int ps_sock_find_by_inode(const struct ps_sock_ep *eps, int n,
                          unsigned long inode, struct ps_sock_ep *out);
#endif /* PS_SOCK_PARSE_H */
