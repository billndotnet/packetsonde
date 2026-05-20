#include "finding.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

static void copy_str(char *dst, size_t dst_sz, const char *src) {
    if (!src) { dst[0] = '\0'; return; }
    size_t n = strlen(src);
    if (n >= dst_sz) n = dst_sz - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void stamp_now(char *buf, size_t sz) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    gmtime_r(&tv.tv_sec, &tm);
    snprintf(buf, sz, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             (int)(tv.tv_usec / 1000));
}

void ps_finding_init(struct ps_finding *f,
                     const char *run_id,
                     const char *source,
                     const char *host,
                     const char *kind,
                     enum ps_severity severity,
                     enum ps_confidence confidence,
                     const char *title) {
    memset(f, 0, sizeof(*f));
    ps_ulid_new(f->id, sizeof(f->id));
    copy_str(f->run_id, sizeof(f->run_id), run_id);
    copy_str(f->source, sizeof(f->source), source);
    copy_str(f->host,   sizeof(f->host),   host);
    copy_str(f->kind,   sizeof(f->kind),   kind);
    copy_str(f->title,  sizeof(f->title),  title);
    f->severity   = severity;
    f->confidence = confidence;
    stamp_now(f->ts, sizeof(f->ts));
}

void ps_finding_set_target_ip(struct ps_finding *f, const char *ip, uint16_t port) {
    copy_str(f->target_ip, sizeof(f->target_ip), ip);
    f->target_port = port;
}

void ps_finding_set_target_hostname(struct ps_finding *f, const char *hostname, uint16_t port) {
    copy_str(f->target_hostname, sizeof(f->target_hostname), hostname);
    if (port) f->target_port = port;
}

void ps_finding_set_via_agent(struct ps_finding *f, const char *agent_name) {
    copy_str(f->via_agent, sizeof(f->via_agent), agent_name);
}

void ps_finding_set_evidence_json(struct ps_finding *f, const char *evidence) {
    copy_str(f->evidence_json, sizeof(f->evidence_json), evidence);
}

static const char *SEV[]  = { "info", "low", "medium", "high", "critical" };
static const char *CONF[] = { "tentative", "firm", "confirmed" };

const char *ps_severity_str(enum ps_severity s) {
    if ((int)s < 0 || (size_t)s >= sizeof(SEV)/sizeof(SEV[0])) return "info";
    return SEV[s];
}
const char *ps_confidence_str(enum ps_confidence c) {
    if ((int)c < 0 || (size_t)c >= sizeof(CONF)/sizeof(CONF[0])) return "firm";
    return CONF[c];
}

static int json_escape(const char *in, char *out, size_t outsz) {
    size_t o = 0;
    for (size_t i = 0; in[i]; i++) {
        unsigned char c = (unsigned char)in[i];
        const char *esc = NULL;
        char ubuf[8];
        switch (c) {
            case '"':  esc = "\\\""; break;
            case '\\': esc = "\\\\"; break;
            case '\n': esc = "\\n";  break;
            case '\r': esc = "\\r";  break;
            case '\t': esc = "\\t";  break;
            case '\b': esc = "\\b";  break;
            case '\f': esc = "\\f";  break;
            default:
                if (c < 0x20) {
                    snprintf(ubuf, sizeof(ubuf), "\\u%04x", c);
                    esc = ubuf;
                }
                break;
        }
        if (esc) {
            size_t n = strlen(esc);
            if (o + n >= outsz) return -1;
            memcpy(out + o, esc, n);
            o += n;
        } else {
            if (o + 1 >= outsz) return -1;
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
    return (int)o;
}

int ps_finding_to_json(const struct ps_finding *f, char *buf, size_t bufsz) {
    char title_e[PS_FIND_TITLE_MAX * 6 + 1];
    if (json_escape(f->title, title_e, sizeof(title_e)) < 0) return -1;

    char target_obj[PS_FIND_TARGET_MAX * 6 + 96] = "";
    int has_target = (f->target_ip[0] || f->target_hostname[0] || f->target_port);
    if (has_target) {
        size_t o = 0;
        o += snprintf(target_obj + o, sizeof(target_obj) - o, "{");
        int first = 1;
        if (f->target_ip[0]) {
            o += snprintf(target_obj + o, sizeof(target_obj) - o, "\"ip\":\"%s\"", f->target_ip);
            first = 0;
        }
        if (f->target_hostname[0]) {
            char hn_e[PS_FIND_TARGET_MAX * 6 + 1];
            if (json_escape(f->target_hostname, hn_e, sizeof(hn_e)) < 0) return -1;
            o += snprintf(target_obj + o, sizeof(target_obj) - o, "%s\"hostname\":\"%s\"",
                          first ? "" : ",", hn_e);
            first = 0;
        }
        if (f->target_port) {
            o += snprintf(target_obj + o, sizeof(target_obj) - o, "%s\"port\":%u",
                          first ? "" : ",", (unsigned)f->target_port);
        }
        snprintf(target_obj + o, sizeof(target_obj) - o, "}");
    }

    int n = snprintf(buf, bufsz,
        "{\"v\":1,\"id\":\"%s\",\"run_id\":\"%s\",\"ts\":\"%s\","
        "\"source\":\"%s\",\"host\":\"%s\""
        "%s%s%s"
        ",\"kind\":\"%s\",\"severity\":\"%s\",\"confidence\":\"%s\""
        ",\"title\":\"%s\""
        "%s%s"
        "%s%s"
        "}\n",
        f->id, f->run_id, f->ts,
        f->source, f->host,
        f->via_agent[0] ? ",\"via_agent\":\"" : "",
        f->via_agent[0] ? f->via_agent       : "",
        f->via_agent[0] ? "\""                : "",
        f->kind, ps_severity_str(f->severity), ps_confidence_str(f->confidence),
        title_e,
        has_target ? ",\"target\":" : "",
        has_target ? target_obj     : "",
        f->evidence_json[0] ? ",\"evidence\":" : "",
        f->evidence_json[0] ? f->evidence_json : ""
    );
    if (n < 0 || (size_t)n >= bufsz) return -1;
    return n;
}

int ps_finding_to_text(const struct ps_finding *f, char *buf, size_t bufsz, int color) {
    const char *sev_color =
        f->severity == PS_SEV_CRITICAL ? "\x1b[1;31m" :
        f->severity == PS_SEV_HIGH     ? "\x1b[31m"   :
        f->severity == PS_SEV_MEDIUM   ? "\x1b[33m"   :
        f->severity == PS_SEV_LOW      ? "\x1b[36m"   : "\x1b[2m";
    const char *reset = "\x1b[0m";

    char target_s[PS_FIND_TARGET_MAX + 32] = "-";
    if (f->target_ip[0] && f->target_port) {
        snprintf(target_s, sizeof(target_s), "%s:%u", f->target_ip, f->target_port);
    } else if (f->target_hostname[0] && f->target_port) {
        snprintf(target_s, sizeof(target_s), "%s:%u", f->target_hostname, f->target_port);
    } else if (f->target_ip[0]) {
        snprintf(target_s, sizeof(target_s), "%s", f->target_ip);
    } else if (f->target_hostname[0]) {
        snprintf(target_s, sizeof(target_s), "%s", f->target_hostname);
    }

    int n;
    if (color) {
        n = snprintf(buf, bufsz, "%s%-8s%s  %-24s  %-32s  %s\n",
                     sev_color, ps_severity_str(f->severity), reset,
                     f->kind, target_s, f->title);
    } else {
        n = snprintf(buf, bufsz, "%-8s  %-24s  %-32s  %s\n",
                     ps_severity_str(f->severity), f->kind, target_s, f->title);
    }
    if (n < 0 || (size_t)n >= bufsz) return -1;
    return n;
}
