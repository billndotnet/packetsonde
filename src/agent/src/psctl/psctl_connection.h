#ifndef PSCTL_CONNECTION_H
#define PSCTL_CONNECTION_H

#include <stdint.h>
#include <stddef.h>

struct psctl_conn {
    int fd;
};

int  psctl_connect(struct psctl_conn *conn, const char *socket_path);
void psctl_disconnect(struct psctl_conn *conn);
int  psctl_send(struct psctl_conn *conn, const char *channel, const char *payload);

/* Receive one frame. Returns 0 on success, -1 on error/timeout.
 * channel_buf/payload_buf must be pre-allocated. */
int psctl_recv(struct psctl_conn *conn,
               char *channel_buf, size_t ch_bufsz,
               char *payload_buf, size_t pl_bufsz,
               int timeout_ms);

/* Callback for recv_loop */
typedef void (*psctl_frame_fn)(const char *channel, const char *payload, void *userdata);

/* Receive frames until timeout, calling fn for each. Returns frame count. */
int psctl_recv_loop(struct psctl_conn *conn, int timeout_ms,
                    psctl_frame_fn fn, void *userdata);

#endif
