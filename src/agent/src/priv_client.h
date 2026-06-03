#ifndef PS_PRIV_CLIENT_H
#define PS_PRIV_CLIENT_H

#include <stdint.h>
#include <sys/socket.h>
#include "priv_protocol.h"

#define PS_PRIV_CLIENT_ASYNC_QUEUE_SIZE 64
#define PS_PRIV_CLIENT_ASYNC_MSG_MAX   8192  /* Max async payload: activity records (8KB) */

struct ps_async_msg {
    struct ps_priv_msg hdr;
    uint8_t payload[PS_PRIV_CLIENT_ASYNC_MSG_MAX];
};

struct ps_priv_client {
    int fd;
    /* Async messages (PACKET_DATA, RAW_RESPONSE) received during synchronous
     * command waits are buffered here for later processing by the event loop. */
    struct ps_async_msg async_queue[PS_PRIV_CLIENT_ASYNC_QUEUE_SIZE];
    int async_count;
};

void ps_priv_client_init(struct ps_priv_client *pc, int fd);

/* Open a pcap handle. Returns handle_id >= 0 on success, -1 on error. */
int ps_priv_client_open_pcap(struct ps_priv_client *pc,
                              const char *iface,
                              const char *filter,
                              uint32_t snaplen);

/* Close a pcap handle. Returns 0 on success, -1 on error. */
int ps_priv_client_close_pcap(struct ps_priv_client *pc, uint16_t handle_id);

/* Create a raw socket. Returns handle_id >= 0 on success, -1 on error. */
int ps_priv_client_create_raw_socket(struct ps_priv_client *pc,
                                      uint8_t af, uint8_t proto);

/* Close a raw socket. Returns 0 on success, -1 on error. */
int ps_priv_client_close_raw_socket(struct ps_priv_client *pc, uint16_t handle_id);

/* Send a raw packet. Returns 0 on success, -1 on error. */
int ps_priv_client_send_raw(struct ps_priv_client *pc,
                             uint16_t handle_id, uint8_t ttl,
                             const struct sockaddr *dest, socklen_t dest_len,
                             const uint8_t *pkt, uint32_t pkt_len);

/*
 * Non-blocking receive: poll with 0ms timeout, read one message.
 * Returns bytes read (>0), 0 if nothing available, -1 on error.
 */
int ps_priv_client_recv(struct ps_priv_client *pc,
                         struct ps_priv_msg *hdr,
                         uint8_t *payload_buf, size_t bufsz);

/* Return the underlying fd for external poll integration. */
int ps_priv_client_fd(struct ps_priv_client *pc);

#endif /* PS_PRIV_CLIENT_H */
