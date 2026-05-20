#ifndef PS_IPC_H
#define PS_IPC_H

#include <stddef.h>

struct ps_ipc_conn {
    int fd;
};

int  ps_ipc_connect(struct ps_ipc_conn *conn, const char *socket_path);
void ps_ipc_disconnect(struct ps_ipc_conn *conn);

int  ps_ipc_send(struct ps_ipc_conn *conn, const char *channel, const char *payload);

/* Receive one frame. Returns 0 on success, -1 on error/timeout. */
int  ps_ipc_recv(struct ps_ipc_conn *conn,
                 char *channel_buf, size_t ch_bufsz,
                 char *payload_buf, size_t pl_bufsz,
                 int timeout_ms);

typedef void (*ps_ipc_frame_fn)(const char *channel, const char *payload, void *userdata);

int  ps_ipc_recv_loop(struct ps_ipc_conn *conn, int timeout_ms,
                      ps_ipc_frame_fn fn, void *userdata);

#endif
