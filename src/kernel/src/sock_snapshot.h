#ifndef PS_SOCK_SNAPSHOT_H
#define PS_SOCK_SNAPSHOT_H
#include "activity_record.h"

/* For each pid in pids[], find its socket-inode fds and resolve them against
 * <proc_root>/net/{tcp,tcp6,udp,udp6}. Each resolved socket is appended to out[]
 * tagged with owner pid/comm/depth. Deduped by inode (nearest-to-root owner wins).
 * proc_root: "" or NULL -> "/proc". Returns count written (<= max). */
int ps_sock_snapshot(const char *proc_root, const int *pids, int npids,
                     const char *comms[], const int *depths,
                     struct ps_act_socket *out, int max);
#endif /* PS_SOCK_SNAPSHOT_H */
