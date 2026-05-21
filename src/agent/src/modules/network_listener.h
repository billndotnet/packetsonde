#ifndef PS_NETWORK_LISTENER_H
#define PS_NETWORK_LISTENER_H

/*
 * Cross-module hook used by discovery_listener.c to ask network_listener
 * for a one-shot session window. When a signed knock probe carrying
 * PS_DISCOVERY_FLAG_REQUEST_SESSION arrives, the discovery handler calls
 * this to:
 *   - bind a fresh TCP socket on 0.0.0.0:0 (kernel-picked port)
 *   - hand off to a thread that accepts ONE connection within
 *     `timeout_secs` and then closes the listener
 * The returned port is what the discovery reply advertises in
 * `listen_port`. Beyond the accept window, the port is gone -- there is
 * no idle listening socket between knocks.
 *
 * Returns 0 on success with *out_port set, -1 on any failure (typically
 * because the network_listener module isn't enabled in this agent
 * deployment).
 */
#include <stdint.h>

int ps_nl_open_session_window(int timeout_secs, uint16_t *out_port);

#endif
