#ifndef PS_CGROUP_UNIT_H
#define PS_CGROUP_UNIT_H
#include <stddef.h>
/* Extract the systemd unit from a cgroup path: the last '/'-segment if it ends
 * in .service/.socket/.mount/.scope. Returns 0 + unit name, or -1 if the cgroup
 * yields no evaluable unit (a .slice tail, empty, or non-unit). */
int ps_cgroup_to_unit(const char *cgroup, char *out, size_t cap);
#endif
