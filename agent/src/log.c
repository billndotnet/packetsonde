#include "log.h"
#include <stdio.h>
#include <time.h>
#include <string.h>

static enum ps_log_level s_min_level = PS_LOG_INFO;
static char s_prefix[64] = "agent";

static const char *level_str(enum ps_log_level level)
{
    switch (level) {
    case PS_LOG_DEBUG: return "DBG";
    case PS_LOG_INFO:  return "INF";
    case PS_LOG_WARN:  return "WRN";
    case PS_LOG_ERROR: return "ERR";
    case PS_LOG_FATAL: return "FTL";
    default:           return "???";
    }
}

void ps_log_set_level(enum ps_log_level level) { s_min_level = level; }

void ps_log_set_prefix(const char *prefix)
{
    if (prefix) snprintf(s_prefix, sizeof(s_prefix), "%s", prefix);
}

void ps_log(enum ps_log_level level, const char *fmt, ...)
{
    if (level < s_min_level) return;

    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);

    char timebuf[20];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm);

    fprintf(stderr, "%s [%s] %s: ", timebuf, level_str(level), s_prefix);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fputc('\n', stderr);
}
