#include "json_extract.h"
#include <string.h>
#include <stdio.h>

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int ps_json_extract_string(const char *json, const char *key, char *out, size_t cap) {
    if (!json || !key || !out || cap == 0) return -1;
    char needle[128];
    int nl = snprintf(needle, sizeof needle, "\"%s\":", key);
    if (nl < 0 || (size_t)nl >= sizeof needle) return -1;
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += nl;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return -1;       /* not a string value */
    p++;                            /* past opening quote */

    size_t o = 0;
    while (*p) {
        unsigned char c = (unsigned char)*p;
        if (c == '"') {             /* unescaped closing quote -> done */
            out[o] = '\0';
            return (int)o;
        }
        if (c == '\\') {
            p++;
            char e = *p;
            char dec;
            switch (e) {
                case '"':  dec = '"';  break;
                case '\\': dec = '\\'; break;
                case '/':  dec = '/';  break;
                case 'n':  dec = '\n'; break;
                case 'r':  dec = '\r'; break;
                case 't':  dec = '\t'; break;
                case 'b':  dec = '\b'; break;
                case 'f':  dec = '\f'; break;
                case 'u': {
                    if (!p[1] || !p[2] || !p[3] || !p[4]) return -1;
                    int h1 = hexval(p[1]), h2 = hexval(p[2]), h3 = hexval(p[3]), h4 = hexval(p[4]);
                    if (h1 < 0 || h2 < 0 || h3 < 0 || h4 < 0) return -1;
                    unsigned cp = (unsigned)((h1 << 12) | (h2 << 8) | (h3 << 4) | h4);
                    p += 4;
                    /* ps_json only \u-escapes control chars (< 0x20), so cp fits one byte. */
                    dec = (char)(cp & 0xff);
                    break;
                }
                default: return -1;  /* invalid escape */
            }
            if (o + 1 >= cap) return -1;
            out[o++] = dec;
            p++;
            continue;
        }
        if (o + 1 >= cap) return -1;
        out[o++] = (char)c;
        p++;
    }
    return -1;  /* unterminated string */
}
