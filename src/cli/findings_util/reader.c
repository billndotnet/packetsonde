#include "reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int extract_str(const char *line, const char *key, char *out, size_t outsz) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    const char *p = strstr(line, pattern);
    if (!p) { if (outsz) out[0] = '\0'; return 0; }
    p += strlen(pattern);
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < outsz) {
        if (*p == '\\' && p[1]) { out[i++] = p[1]; p += 2; continue; }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 1;
}

static long extract_num(const char *line, const char *key) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    const char *p = strstr(line, pattern);
    if (!p) return -1;
    p += strlen(pattern);
    return strtol(p, NULL, 10);
}

static enum ps_severity parse_sev(const char *s) {
    if (!strcmp(s, "info"))     return PS_SEV_INFO;
    if (!strcmp(s, "low"))      return PS_SEV_LOW;
    if (!strcmp(s, "medium"))   return PS_SEV_MEDIUM;
    if (!strcmp(s, "high"))     return PS_SEV_HIGH;
    if (!strcmp(s, "critical")) return PS_SEV_CRITICAL;
    return PS_SEV_INFO;
}

int ps_finding_parse_line(const char *line, struct ps_finding_lite *out) {
    if (!line || !out) return -1;
    memset(out, 0, sizeof(*out));
    if (!extract_str(line, "id",      out->id,     sizeof(out->id)))     return -1;
    extract_str    (line, "run_id",  out->run_id, sizeof(out->run_id));
    extract_str    (line, "source",  out->source, sizeof(out->source));
    if (!extract_str(line, "kind",    out->kind,   sizeof(out->kind)))   return -1;
    extract_str    (line, "title",   out->title,  sizeof(out->title));
    char sev_buf[16] = "";
    extract_str(line, "severity", sev_buf, sizeof(sev_buf));
    out->severity = parse_sev(sev_buf);

    char ip[64] = "", hostname[256] = "";
    extract_str(line, "ip",       ip,       sizeof(ip));
    extract_str(line, "hostname", hostname, sizeof(hostname));
    long port = extract_num(line, "port");
    const char *primary = ip[0] ? ip : hostname;
    if (primary[0] && port > 0)
        snprintf(out->target, sizeof(out->target), "%s:%ld", primary, port);
    else if (primary[0])
        snprintf(out->target, sizeof(out->target), "%s", primary);
    return 0;
}
