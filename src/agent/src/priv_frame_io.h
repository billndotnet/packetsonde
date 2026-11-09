#ifndef PS_PRIV_FRAME_IO_H
#define PS_PRIV_FRAME_IO_H

/*
 * Lossy frame writer for the priv worker -> brain stream.
 *
 * The brain socket is an AF_UNIX SOCK_STREAM socketpair, so the wire has no
 * message boundaries of its own: the 8-byte ps_priv_msg header is the only
 * framing. Async data frames (PACKET_DATA, RAW_RESPONSE) are droppable when
 * the brain is backed up, but a frame may only be dropped whole.
 *
 * The caller must serialise calls on one fd (priv_worker holds g_write_mu)
 * so frames are never interleaved.
 */

#include <stddef.h>
#include <stdint.h>

/* Default bound on finishing a frame whose first bytes are already queued. */
#define PS_PRIV_FRAME_FINISH_TIMEOUT_MS 2000

enum {
    PS_FRAME_BROKEN  = -1,  /* stream unusable: framing lost or hard error */
    PS_FRAME_DROPPED =  0,  /* nothing written, the frame was discarded    */
    PS_FRAME_SENT    =  1,  /* the whole frame is in the stream            */
};

struct ps_frame_stats {
    unsigned long sent;     /* frames written whole                         */
    unsigned long dropped;  /* frames dropped before their first byte       */
    unsigned long partial;  /* frames whose first write was short           */
};

/*
 * Write one frame (header + payload, n bytes) to a non-blocking fd with a
 * single write(). The frame counts as sent only if write() took all of it;
 * anything else is reported as dropped. stats may be NULL.
 *
 * finish_timeout_ms is reserved and currently unused.
 */
int ps_priv_write_frame_lossy(int fd, const uint8_t *buf, size_t n,
                              int finish_timeout_ms,
                              struct ps_frame_stats *stats);

#endif /* PS_PRIV_FRAME_IO_H */
