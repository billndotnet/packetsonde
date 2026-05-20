#ifndef PS_LOG_H
#define PS_LOG_H

#include <stdarg.h>

enum ps_log_level {
    PS_LOG_DEBUG = 0,
    PS_LOG_INFO,
    PS_LOG_WARN,
    PS_LOG_ERROR,
    PS_LOG_FATAL
};

void ps_log_set_level(enum ps_log_level level);
void ps_log_set_prefix(const char *prefix);
void ps_log(enum ps_log_level level, const char *fmt, ...);

#define ps_debug(...) ps_log(PS_LOG_DEBUG, __VA_ARGS__)
#define ps_info(...)  ps_log(PS_LOG_INFO,  __VA_ARGS__)
#define ps_warn(...)  ps_log(PS_LOG_WARN,  __VA_ARGS__)
#define ps_error(...) ps_log(PS_LOG_ERROR, __VA_ARGS__)
#define ps_fatal(...) ps_log(PS_LOG_FATAL, __VA_ARGS__)

#endif
