#ifndef PS_PROC_PARSE_H
#define PS_PROC_PARSE_H
#include <stddef.h>

/* All take a NUL-terminated buffer (the file contents). Return 0 on success. */
int ps_proc_parse_ppid(const char *stat_buf);                 /* returns ppid, or -1 */
/* Parse starttime (field 22 of /proc/<pid>/stat, clock ticks since boot) into
 * *out. Returns 0 on success, -1 if the field is absent/unparseable. */
int ps_proc_parse_starttime(const char *stat_buf, unsigned long long *out);
int ps_proc_parse_comm(const char *stat_buf, char *out, size_t cap);
int ps_proc_parse_unit(const char *cgroup_buf, char *out, size_t cap);
int ps_proc_parse_mac(const char *attr_buf, char *label, size_t lcap,
                      char *mode, size_t mcap);
#endif /* PS_PROC_PARSE_H */
