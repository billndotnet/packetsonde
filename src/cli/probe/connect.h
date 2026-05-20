#ifndef PS_PROBE_CONNECT_H
#define PS_PROBE_CONNECT_H

#include <stddef.h>
#include <stdint.h>

int ps_tcp_open_check(const char *host, uint16_t port, int timeout_ms,
                      char *ip_out, size_t ip_out_sz);

#endif
