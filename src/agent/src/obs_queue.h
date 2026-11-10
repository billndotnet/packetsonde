#ifndef PS_OBS_QUEUE_H
#define PS_OBS_QUEUE_H

#include <stddef.h>
#include <stdint.h>

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
 * full (counted, see ps_obs_queue_dropped). Silently ignores items longer than
 * PS_OBS_ITEM_MAX. */
void ps_obs_queue_push(const char *event_json, size_t len);

/* Drain up to `max` items into caller-owned storage. Copies each item into
 * out_items[i] (each a buffer of PS_OBS_ITEM_MAX bytes) and NUL-terminates.
 * Returns the number drained. Thread-safe. */
int ps_obs_queue_drain(char out_items[][PS_OBS_ITEM_MAX], int max);

/* Copy up to `max` items from the head into caller-owned storage WITHOUT
 * removing them; *first_id receives the id of out_items[0] (items are
 * numbered in push order). Returns the number copied. Thread-safe. Pair with
 * ps_obs_queue_pop once the items are delivered. */
int ps_obs_queue_peek(char out_items[][PS_OBS_ITEM_MAX], int max, uint64_t *first_id);

/* Remove the `n` items peeked at `first_id` (ids first_id .. first_id+n-1)
 * that are still in the queue. Items the drop-oldest policy already pushed
 * out in between are not counted twice, and items pushed later are never
 * touched. Returns the number removed. Thread-safe. */
int ps_obs_queue_pop(uint64_t first_id, int n);

/* Items dropped (oldest first) because the queue was full, since start or
 * the last ps_obs_queue_init. Thread-safe. */
uint64_t ps_obs_queue_dropped(void);

/* Current pending count (thread-safe snapshot). */
int ps_obs_queue_count(void);

#endif /* PS_OBS_QUEUE_H */
