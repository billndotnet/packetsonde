#ifndef PS_PRIV_FRAME_IO_H
#define PS_PRIV_FRAME_IO_H

/*
 * Frame writer for the priv worker -> brain stream.
 *
 * The brain socket is an AF_UNIX SOCK_STREAM socketpair, so the wire has no
 * message boundaries of its own: the 8-byte ps_priv_msg header is the only
 * framing. Async data frames (PACKET_DATA, RAW_RESPONSE) may be dropped when
 * the brain is backed up, but only whole: a frame whose first byte is in the
 * stream must be finished before any other byte is written.
 *
 * The writer never waits for a data frame. When the socket takes only part
 * of a frame, the unsent remainder (at most one frame) is copied into the
 * writer's own buffer, and the caller finishes it from its poll loop
 * (ps_frame_writer_flush on POLLOUT). Until it is finished, every new data
 * frame is dropped whole. A reader that stalls for any length of time
 * therefore costs dropped frames, never a corrupted stream, a blocked writer
 * or a restart. Frames that must not be lost (command responses) are written
 * with ps_frame_writer_send_all, which finishes any pending remainder first.
 *
 * The caller must serialise calls on one writer (priv_worker holds
 * g_write_mu) so frames are never interleaved.
 */

#include <stddef.h>
#include <stdint.h>

enum {
    PS_FRAME_BROKEN  = -1,  /* stream unusable: the peer is gone or a hard error */
    PS_FRAME_DROPPED =  0,  /* nothing written, the frame was discarded whole    */
    PS_FRAME_SENT    =  1,  /* the whole frame is in the stream                  */
    PS_FRAME_QUEUED  =  2,  /* the frame has started; its remainder is buffered  */
};

struct ps_frame_stats {
    unsigned long sent;     /* data frames committed to the stream (incl. queued) */
    unsigned long dropped;  /* data frames dropped whole                         */
    unsigned long partial;  /* data frames whose first write was short (queued)  */
    unsigned long dropped_pending; /* of dropped: a remainder was still pending  */
};

struct ps_frame_writer {
    int      fd;            /* non-blocking stream socket                     */
    uint8_t *tail;          /* caller-provided buffer for one frame remainder */
    size_t   tail_cap;
    size_t   tail_off;      /* tail[tail_off, tail_len) is still to be sent   */
    size_t   tail_len;
    int      broken;        /* sticky: once set, every call fails             */
    struct ps_frame_stats stats;
};

/* tail/tail_cap: storage for the unsent part of at most one frame; frames
 * longer than tail_cap are refused (dropped) rather than risk a remainder
 * that does not fit. */
void ps_frame_writer_init(struct ps_frame_writer *w, int fd,
                          uint8_t *tail, size_t tail_cap);

/* 1 while a frame remainder is waiting to be written (poll for POLLOUT). */
int ps_frame_writer_pending(const struct ps_frame_writer *w);

/* Write as much of the pending remainder as the socket takes now, without
 * waiting. Returns 1 when nothing is pending any more, 0 when some is still
 * pending, PS_FRAME_BROKEN on a hard error. */
int ps_frame_writer_flush(struct ps_frame_writer *w);

/* Data frame (header + payload, n bytes), never waiting:
 *   - a remainder is still pending, or the socket takes nothing,
 *     or n > tail_cap                       -> PS_FRAME_DROPPED
 *   - the whole frame is taken             -> PS_FRAME_SENT
 *   - part of it is taken                  -> PS_FRAME_QUEUED (the rest is
 *     copied; `buf` may be reused at once)
 *   - hard error (peer gone, ...)          -> PS_FRAME_BROKEN */
int ps_frame_writer_send_lossy(struct ps_frame_writer *w,
                               const uint8_t *buf, size_t n);

/* Frame that must not be dropped (a command response): finish any pending
 * remainder, then write the whole frame, waiting for the socket as long as
 * needed (timeout_ms < 0) or at most timeout_ms in total. PS_FRAME_SENT, or
 * PS_FRAME_BROKEN on a hard error or timeout (errno ETIMEDOUT); after a
 * timeout part of a frame may be in the stream, so the writer is broken. */
int ps_frame_writer_send_all(struct ps_frame_writer *w,
                             const uint8_t *buf, size_t n, int timeout_ms);

#endif /* PS_PRIV_FRAME_IO_H */
