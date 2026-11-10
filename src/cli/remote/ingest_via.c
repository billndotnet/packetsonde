#include "ingest_via.h"
#include "via_connect.h"
#include "agent_proto.h"
#include "agent_transport.h"
#include "json_extract.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define INGEST_PREFIX "{\"type\":\"ingest\",\"envelopes\":"

int ps_ingest_build_frame(const char *envelopes_array, char **frame, size_t *len) {
    *frame = NULL;
    size_t need = strlen(INGEST_PREFIX) + strlen(envelopes_array) + 1;   /* + '}' */
    *len = need;
    if (need > PS_AGENT_FRAME_MAX) return -1;
    char *f = malloc(need + 1);
    if (!f) { *len = 0; return -1; }
    snprintf(f, need + 1, "%s%s}", INGEST_PREFIX, envelopes_array);
    *frame = f;
    return 0;
}

int ps_ingest_exchange(const struct ps_ap_io *io, const char *frame, size_t len,
                       struct ps_report_result *out, char *why, size_t why_cap) {
    snprintf(why, why_cap, "%s", "");
    if (ps_ap_write_frame(io, frame, len) != PS_AP_OK) {
        snprintf(why, why_cap, "send to relay failed");
        return -1;
    }
    uint8_t buf[8192]; size_t blen = 0;
    int rrc;
    /* Read frames until the relay answers, skipping its hello. */
    while ((rrc = ps_ap_read_frame(io, buf, sizeof buf - 1, &blen)) == PS_AP_OK) {
        char type[32];
        if (ps_ap_frame_type(buf, blen, type, sizeof type) != 0) continue;
        if (strcmp(type, PS_AP_MSG_HELLO) == 0) continue;
        buf[blen] = 0;
        if (strcmp(type, PS_AP_MSG_ERROR) == 0) {
            char msg[256];
            if (ps_json_extract_string((char *)buf, "message", msg, sizeof msg) < 0)
                snprintf(msg, sizeof msg, "unspecified error");
            snprintf(why, why_cap, "relay refused the batch: %s", msg);
            return -1;
        }
        if (strcmp(type, PS_AP_MSG_ACK) != 0) continue;
        long a = 0, rj = 0;
        if (ps_json_extract_int((char *)buf, "accepted", &a) != 0) a = 0;
        if (ps_json_extract_int((char *)buf, "rejected", &rj) != 0) rj = 0;
        if (ps_json_extract_string((char *)buf, "detail", why, why_cap) < 0 && why_cap)
            why[0] = 0;
        if (out) {
            out->accepted = (int)a;
            out->rejected = (int)rj;
            out->http_status = 200;
        }
        return 0;
    }
    snprintf(why, why_cap, rrc == PS_AP_ERR_EOF ? "relay closed the session without an ack"
                                                : "no valid ack from relay");
    return -1;
}

int ps_ingest_via(const char *relay_agent, const char *envelopes_array,
                  struct ps_report_result *out) {
    char *frame; size_t flen;
    if (ps_ingest_build_frame(envelopes_array, &frame, &flen) != 0) {
        if (flen)
            fprintf(stderr, "ingest via %s: batch needs a %zu-byte frame, over the %u-byte "
                            "protocol limit; not sent\n",
                    relay_agent, flen, (unsigned)PS_AGENT_FRAME_MAX);
        else
            fprintf(stderr, "ingest via %s: out of memory\n", relay_agent);
        return -1;
    }

    struct ps_at_ctx ctx; SSL *ssl = NULL; struct ps_ap_io io;
    if (ps_via_connect(relay_agent, &ctx, &ssl, &io) != 0) { free(frame); return -1; }

    char why[256];
    int rc = ps_ingest_exchange(&io, frame, flen, out, why, sizeof why);
    if (rc != 0)
        fprintf(stderr, "ingest via %s: %s\n", relay_agent, why);
    else if (why[0])
        fprintf(stderr, "ingest via %s: relay: %s\n", relay_agent, why);
    free(frame);
    ps_at_close(ssl);
    ps_at_ctx_destroy(&ctx);
    return rc;
}
