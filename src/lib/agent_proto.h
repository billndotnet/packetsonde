#ifndef PS_AGENT_PROTO_H
#define PS_AGENT_PROTO_H

/*
 * Agent network protocol -- wire framing + message types.
 *
 * The protocol is length-prefixed JSON messages inside an authenticated +
 * encrypted transport (added in a sibling commit). This header defines the
 * transport-independent layer: frame I/O against an opaque byte pipe and
 * the canonical message-type taxonomy.
 *
 * Frame format on the wire:
 *
 *   uint32_t length    -- BE, length of the JSON payload (excluding this header)
 *   uint8_t  json[]    -- UTF-8 JSON object, MUST contain a "type" string field
 *
 * Maximum frame size is PS_AGENT_FRAME_MAX (1 MiB by default). Anything larger
 * is a protocol violation and yields PS_AP_ERR_OVERSIZE.
 *
 * Message types (see PS_AP_MSG_*):
 *
 *   hello   -- initial handshake. Carries protocol version + features.
 *   audit   -- CLI -> agent. Requests `audit <kind> <args...>`.
 *   finding -- agent -> CLI. One JSONL finding record per frame (same v:1
 *              schema as local).
 *   log     -- agent -> CLI. Informational; level + msg.
 *   error   -- either direction. message + numeric code; usually closes.
 *   bye     -- either direction. graceful close; carries an exit status.
 *
 * The agent's CLI sees finding frames as if the audit had run locally:
 * each frame's `host` field is the agent's host and an extra `via_agent`
 * field is filled in.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define PS_AGENT_PROTO_VERSION    1
#define PS_AGENT_FRAME_MAX        (1024U * 1024U)

/* Message-type tags as canonical lowercase strings. */
#define PS_AP_MSG_HELLO   "hello"
#define PS_AP_MSG_AUDIT   "audit"
#define PS_AP_MSG_FINDING "finding"
#define PS_AP_MSG_LOG     "log"
#define PS_AP_MSG_ERROR   "error"
#define PS_AP_MSG_BYE     "bye"

/* Frame I/O errors. */
enum {
    PS_AP_OK              =  0,
    PS_AP_ERR_EOF         = -1,   /* peer closed cleanly */
    PS_AP_ERR_IO          = -2,   /* read/write failed mid-frame */
    PS_AP_ERR_OVERSIZE    = -3,   /* length header exceeds PS_AGENT_FRAME_MAX */
    PS_AP_ERR_SHORT       = -4,   /* caller buffer too small */
    PS_AP_ERR_BAD_JSON    = -5,   /* payload isn't a JSON object or missing "type" */
};

/* I/O is delegated to caller-supplied callbacks so the same framing code
 * works against a plain fd, an SSL*, an in-memory buffer (for tests), or
 * anything else with a sensible read/write semantic. Callbacks must return:
 *   > 0  : that many bytes read/written
 *   = 0  : peer closed (read only)
 *   < 0  : I/O error
 * Callbacks should keep going until n bytes have been transferred OR an
 * error/EOF condition has occurred (the framing code does not retry). */
typedef ssize_t (*ps_ap_read_fn) (void *io_ctx, void *buf, size_t n);
typedef ssize_t (*ps_ap_write_fn)(void *io_ctx, const void *buf, size_t n);

struct ps_ap_io {
    ps_ap_read_fn  read;
    ps_ap_write_fn write;
    void          *ctx;
};

/* Read one frame into out_buf. On success, *out_len holds the JSON byte
 * count and the buffer holds raw UTF-8 (NOT null-terminated). Returns
 * PS_AP_OK or one of the PS_AP_ERR_* codes. */
int  ps_ap_read_frame (const struct ps_ap_io *io,
                       uint8_t *out_buf, size_t out_buf_cap,
                       size_t *out_len);

/* Write one frame; payload is the raw JSON bytes. Returns PS_AP_OK or
 * PS_AP_ERR_IO / PS_AP_ERR_OVERSIZE. */
int  ps_ap_write_frame(const struct ps_ap_io *io,
                       const void *payload, size_t len);

/* Extract the "type" field from a frame payload without a full JSON
 * parse. Returns 0 on success and writes up to `out_cap-1` bytes plus a
 * NUL. Returns -1 if no "type" field is found. Conservative scanner --
 * tolerates leading whitespace, expects a string value. */
int  ps_ap_frame_type(const uint8_t *payload, size_t len,
                      char *out, size_t out_cap);

#endif
