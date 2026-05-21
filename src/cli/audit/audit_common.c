#include "audit_common.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int ps_audit_parse_target(const char *spec,
                          char *host, size_t host_sz,
                          uint16_t default_port,
                          uint16_t *out_port) {
    if (!spec || !host || host_sz == 0 || !out_port) return -1;
    *out_port = default_port;

    /* IPv6 in brackets: [addr] or [addr]:port */
    if (spec[0] == '[') {
        const char *rb = strchr(spec, ']');
        if (!rb) return -1;
        size_t hl = (size_t)(rb - spec - 1);
        if (hl == 0 || hl >= host_sz) return -1;
        memcpy(host, spec + 1, hl); host[hl] = '\0';
        if (rb[1] == '\0') return 0;
        if (rb[1] != ':')  return -1;
        long p = strtol(rb + 2, NULL, 10);
        if (p <= 0 || p > 65535) return -1;
        *out_port = (uint16_t)p;
        return 0;
    }

    /* Hostname or v4 with optional :port. We use strrchr so a stray
     * colon in a bare v6 literal doesn't confuse us -- callers wanting
     * v6 + port must bracket. A bare "::1" is treated as a hostname
     * (no port split). */
    if (strchr(spec, ':') != strrchr(spec, ':')) {
        /* multiple colons -> assume bare v6 literal, no port */
        size_t hl = strlen(spec);
        if (hl == 0 || hl >= host_sz) return -1;
        memcpy(host, spec, hl); host[hl] = '\0';
        return 0;
    }

    const char *colon = strrchr(spec, ':');
    size_t hl = colon ? (size_t)(colon - spec) : strlen(spec);
    if (hl == 0 || hl >= host_sz) return -1;
    memcpy(host, spec, hl); host[hl] = '\0';
    if (colon) {
        long p = strtol(colon + 1, NULL, 10);
        if (p <= 0 || p > 65535) return -1;
        *out_port = (uint16_t)p;
    }
    return 0;
}

int ps_audit_tcp_connect(const char *host, uint16_t port, int timeout_ms,
                         char *out_ip, size_t out_ip_sz) {
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;     /* v4 + v6; closes #5 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;

    int fd = -1;
    for (struct addrinfo *r = res; r; r = r->ai_next) {
        fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd < 0) continue;
        if (timeout_ms > 0) {
            struct timeval tv;
            tv.tv_sec  = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }
        if (connect(fd, r->ai_addr, r->ai_addrlen) == 0) {
            if (out_ip && out_ip_sz > 0) {
                if (r->ai_family == AF_INET) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)r->ai_addr;
                    inet_ntop(AF_INET, &sin->sin_addr, out_ip, (socklen_t)out_ip_sz);
                } else if (r->ai_family == AF_INET6) {
                    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)r->ai_addr;
                    inet_ntop(AF_INET6, &s6->sin6_addr, out_ip, (socklen_t)out_ip_sz);
                } else {
                    out_ip[0] = '\0';
                }
            }
            break;
        }
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int ps_audit_udp_connect(const char *host, uint16_t port, int timeout_ms,
                         char *out_ip, size_t out_ip_sz) {
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;

    int fd = -1;
    for (struct addrinfo *r = res; r; r = r->ai_next) {
        fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd < 0) continue;
        if (timeout_ms > 0) {
            struct timeval tv;
            tv.tv_sec  = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }
        /* connect() on a DGRAM socket fixes the peer so send/recv work
         * without an explicit address, and lets ICMP port-unreachable
         * surface as ECONNREFUSED on the next recv. */
        if (connect(fd, r->ai_addr, r->ai_addrlen) == 0) {
            if (out_ip && out_ip_sz > 0) {
                if (r->ai_family == AF_INET) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)r->ai_addr;
                    inet_ntop(AF_INET, &sin->sin_addr, out_ip, (socklen_t)out_ip_sz);
                } else if (r->ai_family == AF_INET6) {
                    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)r->ai_addr;
                    inet_ntop(AF_INET6, &s6->sin6_addr, out_ip, (socklen_t)out_ip_sz);
                } else {
                    out_ip[0] = '\0';
                }
            }
            break;
        }
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}
