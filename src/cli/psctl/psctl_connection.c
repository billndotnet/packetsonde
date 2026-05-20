/* Compatibility shim — forwards psctl_* names to libpacketsonde ps_ipc_*.
 * Retired in the task that retires the psctl binary. */
#include "psctl_connection.h"
#include "ipc.h"
#include <string.h>

_Static_assert(sizeof(struct psctl_conn) == sizeof(struct ps_ipc_conn),
               "psctl_conn must layout-match ps_ipc_conn");

int psctl_connect(struct psctl_conn *c, const char *p) {
    return ps_ipc_connect((struct ps_ipc_conn *)c, p);
}
void psctl_disconnect(struct psctl_conn *c) {
    ps_ipc_disconnect((struct ps_ipc_conn *)c);
}
int psctl_send(struct psctl_conn *c, const char *ch, const char *pl) {
    return ps_ipc_send((struct ps_ipc_conn *)c, ch, pl);
}
int psctl_recv(struct psctl_conn *c, char *cb, size_t cs, char *pb, size_t ps, int t) {
    return ps_ipc_recv((struct ps_ipc_conn *)c, cb, cs, pb, ps, t);
}
int psctl_recv_loop(struct psctl_conn *c, int t, psctl_frame_fn fn, void *u) {
    /* psctl_frame_fn and ps_ipc_frame_fn have identical signatures. */
    return ps_ipc_recv_loop((struct ps_ipc_conn *)c, t, (ps_ipc_frame_fn)fn, u);
}
