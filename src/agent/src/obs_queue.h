#ifndef PS_OBS_QUEUE_H
#define PS_OBS_QUEUE_H

#include <stddef.h>

#define PS_OBS_QUEUE_CAP      256   /* max pending findings before drop-oldest */
#define PS_OBS_ITEM_MAX      4096   /* max bytes per wrapped event JSON */

/* Initialize the global queue (call once at startup before any enqueue). */
void ps_obs_queue_init(void);

/* Build the event-JSON wrapper {"kind":<channel>,"ts":<iso>,"observation":<json>}
 * into `out` (cap bytes) from a published finding. `ts_iso` is a NUL-terminated
 * ISO-8601 string. Returns the length written, or 0 on overflow/bad args.
 * Pure (no global state) — unit-tested directly. */
size_t ps_obs_build_event(char *out, size_t cap,
                          const char *channel, const char *ts_iso,
                          const char *observation_json, size_t obs_len);

/* Enqueue one already-built event JSON. Thread-safe. Drops the oldest item if
 * full. Silently ignores items longer than PS_OBS_ITEM_MAX. */
void ps_obs_queue_push(const char *event_json, size_t len);

/* Drain up to `max` items into caller-owned storage. Copies each item into
 * out_items[i] (each a buffer of PS_OBS_ITEM_MAX bytes) and NUL-terminates.
 * Returns the number drained. Thread-safe. */
int ps_obs_queue_drain(char out_items[][PS_OBS_ITEM_MAX], int max);

/* Current pending count (thread-safe snapshot). */
int ps_obs_queue_count(void);

#endif /* PS_OBS_QUEUE_H */
