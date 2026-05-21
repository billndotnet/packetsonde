#ifndef PS_AUDIT_COMMON_H
#define PS_AUDIT_COMMON_H

/*
 * Shared helpers for audit modules.
 *
 * Every audit kind used to copy-paste its own parse_target and its own
 * AF_INET-only tcp_connect. That duplication was about ~380 lines of
 * identical code, and the AF_INET hardcode silently skipped any target
 * that resolved to an AAAA record only. Both issues are fixed here by
 * giving all audits one shared implementation.
 *
 * Stays in src/cli/audit/ rather than src/lib/ because it's CLI-specific
 * (uses the audit_module ABI; lib doesn't know about that).
 */

#include <stddef.h>
#include <stdint.h>

/*
 * Parse "host[:port]" into host + port.
 *
 *   spec         "example.com", "example.com:443", "[::1]:443", "[::1]"
 *   host         buffer for the hostname (square brackets stripped for v6)
 *   host_sz      sizeof(host)
 *   default_port port to fill in if `spec` omits it
 *   out_port     receives the port (default or parsed)
 *
 * Returns 0 on success, -1 on malformed input.
 *
 * IPv6 literals must be square-bracketed when paired with a port
 * ("[::1]:443"); a bare "::1" is accepted as a hostname with default port.
 */
int ps_audit_parse_target(const char *spec,
                          char *host, size_t host_sz,
                          uint16_t default_port,
                          uint16_t *out_port);

/*
 * Open a TCP connection to host:port. Accepts both IPv4 and IPv6
 * (AF_UNSPEC); the first address that connects wins.
 *
 *   host           hostname or numeric address
 *   port           dst port
 *   timeout_ms     send/recv timeout for SO_RCVTIMEO / SO_SNDTIMEO
 *   out_ip         optional buffer for the textual peer IP (NULL to skip)
 *   out_ip_sz      sizeof(out_ip), ignored if out_ip is NULL
 *
 * Returns a connected socket fd on success, -1 on any failure. The
 * caller closes the fd.
 */
int ps_audit_tcp_connect(const char *host, uint16_t port, int timeout_ms,
                         char *out_ip, size_t out_ip_sz);

/*
 * Same shape, UDP. Returns a connected DGRAM socket (so send/recv work
 * without an explicit address) suitable for protocols like NTP, SNMP
 * that are request-response over a single (src, dst) tuple.
 *
 * Accepts both IPv4 and IPv6 (AF_UNSPEC). The connect on a DGRAM
 * socket is what makes the kernel surface ICMP port-unreachable as
 * ECONNREFUSED on subsequent recv -- useful for "is anything
 * listening?" probes.
 *
 * Returns the fd on success, -1 on any failure. Caller closes.
 */
int ps_audit_udp_connect(const char *host, uint16_t port, int timeout_ms,
                         char *out_ip, size_t out_ip_sz);

#endif
