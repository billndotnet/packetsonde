#ifndef PS_EXE_SLUG_H
#define PS_EXE_SLUG_H
#include <stddef.h>
/* Sanitize an exe path to a filename slug: leading '/' dropped, each run of
 * non-[A-Za-z0-9._-] chars -> a single '-'. Returns 0, or -1 on empty input. */
int ps_exe_slug(const char *exe, char *out, size_t cap);
#endif
