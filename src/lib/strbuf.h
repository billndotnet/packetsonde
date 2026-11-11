#ifndef PS_STRBUF_H
#define PS_STRBUF_H

#include <stdarg.h>
#include <stddef.h>

/* Bounded string building into a caller-owned buffer.
 *
 * ps_appendf formats at buf + *off, keeping the content within limit - 1
 * bytes (limit counts the terminating NUL; pass a value no larger than the
 * buffer). On success *off advances and 0 is returned. An encoding error, a
 * result that would not fit, or *off already at or past limit leaves the
 * buffer content and *off as they were and returns -1: nothing partial is
 * ever kept, so a caller can stop at the first failure and still close what
 * it has built. Callers that must always close a structure pass a limit
 * below the buffer size to keep room for the closing bytes. */
int ps_appendf(char *buf, size_t limit, size_t *off, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
int ps_vappendf(char *buf, size_t limit, size_t *off, const char *fmt, va_list ap)
    __attribute__((format(printf, 4, 0)));

/* 1 if `tok` equals one whole entry of `list`, where entries are separated by
 * any run of the bytes in `seps`; 0 otherwise (also for a NULL or empty
 * `tok` or `list`). Comparison is exact: no prefix or substring matches. */
int ps_list_has_token(const char *list, const char *seps, const char *tok);

#endif
