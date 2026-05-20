#ifndef PS_REDIS_BRIDGE_H
#define PS_REDIS_BRIDGE_H

#ifdef HAVE_HIREDIS

struct ps_redis_bridge;

/* Create a Redis bridge connected to the given host:port.
 * prefix is prepended to all channel names (e.g., "packetsonde:").
 * Returns NULL on failure. */
struct ps_redis_bridge *ps_redis_bridge_create(const char *host, int port,
                                               const char *prefix);

void ps_redis_bridge_destroy(struct ps_redis_bridge *br);

/* Publish an outgoing message to Redis. Channel name is prefixed. */
int ps_redis_bridge_publish(struct ps_redis_bridge *br,
                             const char *channel, const char *payload,
                             int payload_len);

/* Subscribe to a Redis channel for incoming messages (UI->agent direction). */
int ps_redis_bridge_subscribe(struct ps_redis_bridge *br, const char *channel);

/* Non-blocking poll for incoming Redis messages.
 * Calls callback for each received message.
 * Returns number of messages processed, 0 if none, -1 on error. */
typedef void (*ps_redis_msg_fn)(const char *channel, const char *payload,
                                int payload_len, void *userdata);
int ps_redis_bridge_poll(struct ps_redis_bridge *br,
                          ps_redis_msg_fn callback, void *userdata);

#endif /* HAVE_HIREDIS */
#endif /* PS_REDIS_BRIDGE_H */
