#ifndef PS_ULID_H
#define PS_ULID_H

#include <stddef.h>

/* ULID: 26-char Crockford base32 string (no NUL). */
#define PS_ULID_STRLEN 26

/* Generate a new ULID into buf. buf must be >= PS_ULID_STRLEN+1.
 * Writes a NUL-terminated string. Returns 0 on success, -1 on failure
 * (bad buf size, RNG error). Thread-safe; monotonic within the same
 * millisecond for a single process. */
int ps_ulid_new(char *buf, size_t bufsz);

#endif
