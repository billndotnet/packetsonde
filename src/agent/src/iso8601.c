#include "iso8601.h"

#include <time.h>

size_t ps_iso8601_utc(uint64_t usec, char *buf, size_t cap) {
    if (cap < 21) return 0;
    time_t secs = (time_t)(usec / 1000000ULL);
    struct tm tm_utc;
    if (gmtime_r(&secs, &tm_utc) == NULL) return 0;
    size_t n = strftime(buf, cap, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    return n; /* 20 on success, 0 if cap too small */
}
