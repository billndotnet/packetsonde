#ifndef PS_ISO8601_H
#define PS_ISO8601_H

#include <stdint.h>
#include <stddef.h>

/* Format `usec` (microseconds since Unix epoch, UTC) into `buf` as
 * "YYYY-MM-DDTHH:MM:SSZ" (20 chars + NUL). `cap` must be >= 21.
 * Returns the string length, or 0 if cap too small / gmtime failed. */
size_t ps_iso8601_utc(uint64_t usec, char *buf, size_t cap);

#endif /* PS_ISO8601_H */
