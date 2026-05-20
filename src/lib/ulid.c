#include "ulid.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

static const char CROCKFORD[33] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_last_ms = 0;
static uint8_t  g_last_rand[10] = {0};

static int read_random(uint8_t *out, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, out + got, n - got);
        if (r <= 0) { close(fd); return -1; }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}

/* Increment an 80-bit big-endian counter in place. Used for the
 * monotonic-within-the-same-ms guarantee. */
static void inc80(uint8_t *r) {
    for (int i = 9; i >= 0; i--) {
        if (++r[i] != 0) return;
    }
}

int ps_ulid_new(char *buf, size_t bufsz) {
    if (!buf || bufsz < PS_ULID_STRLEN + 1) return -1;

    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) return -1;
    uint64_t ms = (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000);

    pthread_mutex_lock(&g_lock);
    uint8_t r[10];
    if (ms == g_last_ms) {
        memcpy(r, g_last_rand, 10);
        inc80(r);
    } else {
        if (read_random(r, 10) != 0) {
            pthread_mutex_unlock(&g_lock);
            return -1;
        }
    }
    g_last_ms = ms;
    memcpy(g_last_rand, r, 10);
    pthread_mutex_unlock(&g_lock);

    /* Timestamp: 48 bits → 10 base32 chars. */
    uint64_t t = ms & 0xFFFFFFFFFFFFULL;
    for (int i = 9; i >= 0; i--) {
        buf[i] = CROCKFORD[t & 0x1F];
        t >>= 5;
    }

    /* Randomness: 80 bits → 16 base32 chars. Treat r as one big number
     * split into a 16-bit high half and a 64-bit low half; shift the
     * combined value right 5 bits at a time, emitting from the back. */
    uint64_t lo = 0;
    for (int i = 2; i < 10; i++) lo = (lo << 8) | r[i];
    uint64_t hi = ((uint64_t)r[0] << 8) | r[1];

    for (int i = 15; i >= 0; i--) {
        uint32_t five = (uint32_t)(lo & 0x1F);
        uint64_t carry = (hi & 0x1F);
        lo = (lo >> 5) | (carry << 59);
        hi = (hi >> 5);
        buf[10 + i] = CROCKFORD[five];
    }
    buf[PS_ULID_STRLEN] = '\0';
    return 0;
}
