#include "exe_slug.h"
#include <string.h>

static int ok(char c) {
    return (c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c=='-';
}
int ps_exe_slug(const char *exe, char *out, size_t cap) {
    if (!exe || !*exe || cap < 2) return -1;
    size_t o = 0; int prev_dash = 1;   /* prev_dash=1 suppresses a leading '-' */
    for (const char *p = exe; *p && o < cap - 1; p++) {
        if (ok(*p)) { out[o++] = *p; prev_dash = 0; }
        else if (!prev_dash) { out[o++] = '-'; prev_dash = 1; }
    }
    while (o > 0 && out[o-1] == '-') o--;   /* trim trailing '-' */
    out[o] = 0;
    return o > 0 ? 0 : -1;
}
