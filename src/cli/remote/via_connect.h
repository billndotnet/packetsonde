#ifndef PS_VIA_CONNECT_H
#define PS_VIA_CONNECT_H
#include "agent_transport.h"
#include "agent_proto.h"
#include <openssl/ssl.h>

/* Connect to a registered via-agent over mTLS and exchange the client hello.
 * On success returns 0 with *ctx_out/*ssl_out/*io_out filled and owned by the
 * caller (ps_at_close(*ssl_out) then ps_at_ctx_destroy(ctx_out)). Returns -1 on
 * any failure (prints a diagnostic + cleans up internally). Defined in audit_via.c. */
int ps_via_connect(const char *agent_name, struct ps_at_ctx *ctx_out,
                   SSL **ssl_out, struct ps_ap_io *io_out);
#endif
