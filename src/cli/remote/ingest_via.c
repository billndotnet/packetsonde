#include "ingest_via.h"
#include "via_connect.h"
#include "agent_proto.h"
#include "agent_transport.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int ps_ingest_via(const char *relay_agent, const char *envelopes_array,
                  struct ps_report_result *out) {
    struct ps_at_ctx ctx; SSL *ssl = NULL; struct ps_ap_io io;
    if (ps_via_connect(relay_agent, &ctx, &ssl, &io) != 0) return -1;

    static char frame[262144];
    int fn = snprintf(frame, sizeof frame,
                      "{\"type\":\"ingest\",\"envelopes\":%s}", envelopes_array);
    int rc = -1;
    if (fn > 0 && (size_t)fn < sizeof frame &&
        ps_ap_write_frame(&io, frame, (size_t)fn) == PS_AP_OK) {
        uint8_t buf[8192]; size_t blen = 0;
        if (ps_ap_read_frame(&io, buf, sizeof buf, &blen) == PS_AP_OK) {
            size_t z = blen < sizeof buf ? blen : sizeof buf - 1;
            buf[z] = 0;
            if (out) {
                const char *a = strstr((char *)buf, "\"accepted\":");
                out->accepted = a ? atoi(a + 11) : 0;
                out->http_status = 200;
            }
            rc = 0;
        }
    }
    ps_at_close(ssl);
    ps_at_ctx_destroy(&ctx);
    return rc;
}
