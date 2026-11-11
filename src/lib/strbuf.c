#include "strbuf.h"

#include <stdio.h>
#include <string.h>

int ps_vappendf(char *buf, size_t limit, size_t *off, const char *fmt, va_list ap)
{
    if (!buf || !off || *off >= limit) return -1;
    size_t room = limit - *off;
    int n = vsnprintf(buf + *off, room, fmt, ap);
    if (n < 0 || (size_t)n >= room) { buf[*off] = '\0'; return -1; }
    *off += (size_t)n;
    return 0;
}

int ps_appendf(char *buf, size_t limit, size_t *off, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int rc = ps_vappendf(buf, limit, off, fmt, ap);
    va_end(ap);
    return rc;
}

int ps_list_has_token(const char *list, const char *seps, const char *tok)
{
    if (!list || !seps || !tok || !tok[0]) return 0;
    size_t tl = strlen(tok);
    const char *p = list;
    for (;;) {
        p += strspn(p, seps);
        if (!*p) return 0;
        size_t n = strcspn(p, seps);
        if (n == tl && memcmp(p, tok, n) == 0) return 1;
        p += n;
    }
}
