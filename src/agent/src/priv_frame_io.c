#include "priv_frame_io.h"

#include <unistd.h>

int ps_priv_write_frame_lossy(int fd, const uint8_t *buf, size_t n,
                              int finish_timeout_ms,
                              struct ps_frame_stats *stats)
{
    (void)finish_timeout_ms;
    ssize_t r = write(fd, buf, n);
    if (r == (ssize_t)n) {
        if (stats) stats->sent++;
        return PS_FRAME_SENT;
    }
    if (stats) {
        if (r > 0) stats->partial++;
        stats->dropped++;
    }
    return PS_FRAME_DROPPED;
}
