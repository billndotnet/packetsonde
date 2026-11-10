#ifndef PS_OBS_DEDUPE_H
#define PS_OBS_DEDUPE_H

/*
 * Observation dedupe: collapse repeat sightings without losing their timing.
 *
 * The first sighting of a content key is sent at once (PS_DEDUPE_SEND, no
 * "dedupe" object). Further sightings of the same key inside the key's window
 * are suppressed (PS_DEDUPE_SUPPRESS) and accounted; when the window ends (or
 * the entry is closed early, see below) ONE summary event is produced:
 *
 *   {"kind":K,"ts":<last repeat ISO>,"observation":<observation as first seen>,
 *    "dedupe":{"since":ISO,"first":ISO,"last":ISO,"n":N,
 *              "gap_min":S,"gap_max":S,"gap_mean":S,
 *              "seen":[[offset_s,n],...]}}
 *
 *   since     time of the sent (first) sighting this summary continues
 *   first     time of the first suppressed repeat
 *   last      time of the last suppressed repeat (also the event "ts")
 *   n         number of suppressed repeats (central count = 1 + sum of n)
 *   gap_*     seconds between consecutive sightings, over the n gaps from
 *             `since` to the first repeat, the first to the second, ... the
 *             last-but-one to `last`; gap_mean = (last - since) / n.
 *             Printed with millisecond precision, trailing zeros dropped.
 *   seen      run-length timeline, at most PS_DEDUPE_SEEN_MAX pairs. A run is
 *             a maximal sequence of repeats whose gap from their predecessor,
 *             rounded to whole seconds, is the same. Pair k is
 *             [offset_s, n_k]: offset_s is the time of the sighting that
 *             PRECEDES the run, in whole seconds after `since` (so the first
 *             pair's offset is always 0); the run's n_k repeats are evenly
 *             spaced from there up to the next pair's offset (the last run
 *             ends at `last`). Sum of n_k == n. So repeat i of run k sits at
 *             offset_k + i * (offset_{k+1} - offset_k) / n_k, i = 1..n_k.
 *   seen_coarse  (present, true) when runs had to be merged to stay within
 *             PS_DEDUPE_SEEN_MAX pairs or PS_OBS_ITEM_MAX bytes: the counts
 *             still sum to n and the span is exact, the spacing inside a
 *             merged run is averaged.
 *   truncated (present, true) when even a one-pair summary of this
 *             observation does not fit PS_OBS_ITEM_MAX: "observation" is then
 *             {"key_sha256":"<hex SHA-256 of the canonical key text>"}.
 *
 * Early close: a full table evicts the least recently seen entry, and a new
 * neighbor sighting closes an open entry with the same subject (ip,
 * interface, proto, ndp_type) but different content (e.g. a MAC change).
 * Either way the closed entry's summary is emitted at once, before the new
 * sighting is sent, so nothing is lost and order is kept.
 *
 * Canonical key text (shared with the central side; vectors in
 * src/agent/tests/fixtures/dedupe_vectors.json):
 *
 *   key = kind "|" canon(observation)
 *
 *   canon(object) = "{" members "}" with members "<canon(key)>:<canon(value)>"
 *                   joined by ",", sorted by the key's UTF-8 bytes; members
 *                   whose key is volatile are dropped at EVERY depth; on a
 *                   duplicate key the last one wins. Volatile keys:
 *                   ts seen_at first_seen last_seen count seq id timestamp
 *                   observed_at ttl
 *   canon(array)  = "[" elements joined by "," "]", in input order, except
 *                   an array that is the value of a member named "answers"
 *                   (any depth, any kind) and whose elements are all
 *                   objects: those are stably sorted by the tuple
 *                   (name, type, data) of each element after volatile
 *                   removal, compared bytewise; a missing field counts as
 *                   "", a string as its decoded text, a number as its
 *                   canonical text, true/false/null as "True"/"False"/
 *                   "None" (Python str()). Equal tuples keep input order.
 *   canon(string) = '"' + string with '"' -> \" , '\' -> \\ , \b \f \n \r \t,
 *                   other code points below 0x20 -> \u00xx (lowercase hex),
 *                   everything else as raw UTF-8 (input \uXXXX escapes are
 *                   decoded, surrogate pairs joined) + '"'.
 *                   (= Python json.dumps(s, ensure_ascii=False))
 *   canon(number) = an integer token (no fraction, no exponent) as the
 *                   integer it denotes ("-0" -> "0"); any other number as
 *                   Python repr(float(token)): shortest round-trip digits,
 *                   fixed notation with at least one fractional digit when
 *                   the decimal exponent is in (-4, 16], otherwise
 *                   d[.ddd]e+XX / e-XX (two-digit minimum exponent).
 *   true / false / null verbatim. No whitespace anywhere.
 *   (Reference: Python json.loads, drop volatile keys recursively, sort the
 *   answers arrays as above, json.dumps(sort_keys=True,
 *   separators=(",", ":"), ensure_ascii=False).)
 *
 * An observation that is not valid JSON, nests deeper than 32 levels or whose
 * key exceeds PS_DEDUPE_KEY_MAX is never suppressed (always SEND).
 *
 * Clock: every call takes now_ms (wall clock, ms since the Unix epoch) so
 * tests are deterministic. A clock step backwards counts as a zero gap.
 * All functions are thread-safe (one global table behind a mutex). Before
 * ps_obs_dedupe_init every offer returns SEND and flush returns 0.
 */

#include <stddef.h>
#include <stdint.h>
#include "obs_queue.h"   /* PS_OBS_ITEM_MAX */

#define PS_DEDUPE_KEY_MAX        8192
#define PS_DEDUPE_SEEN_MAX         32
#define PS_DEDUPE_TABLE_DEFAULT  2048
#define PS_DEDUPE_KIND_WINDOWS     16

enum ps_dedupe_action { PS_DEDUPE_SEND = 0, PS_DEDUPE_SUPPRESS = 1 };

struct ps_obs_dedupe;   /* opaque; one global instance */

struct ps_obs_dedupe_kind_window {
    char kind[64];   /* full kind ("discovery.dns"), its '_' spelling
                        ("discovery_dns") or its last segment ("dns") */
    int  window_s;   /* 0 disables suppression for this kind */
};

/* Called for summaries closed during an offer (eviction, subject change).
 * NULL means ps_obs_queue_push. Runs with the dedupe lock held. */
typedef void (*ps_obs_dedupe_emit_fn)(const char *event_json, size_t len, void *user);

struct ps_obs_dedupe_cfg {
    /* -1: unset (built-in defaults: discovery.dns 300 s, every other kind
     *     900 s); 0: suppression disabled for every kind; >0: the window for
     *     every kind that has no per-kind entry. */
    int window_s;
    int table_max;   /* <= 0 -> PS_DEDUPE_TABLE_DEFAULT */
    int n_kinds;
    struct ps_obs_dedupe_kind_window kinds[PS_DEDUPE_KIND_WINDOWS];
    ps_obs_dedupe_emit_fn emit;
    void *emit_user;
};

/* Timing of the repeats collapsed into one summary (all times in ms). */
struct ps_obs_dedupe_stats {
    int64_t  since_ms, first_ms, last_ms;
    uint32_t n;
    int64_t  gap_min_ms, gap_max_ms;
    int      npairs;
    int64_t  seen[PS_DEDUPE_SEEN_MAX][2];   /* [offset_s, n] */
    int      coarse;
};

struct ps_obs_dedupe_counters {
    uint64_t offered, sent, suppressed, summaries, summary_repeats,
             evicted, closed, truncated, unkeyed;
};

/* Fill cfg with defaults (window -1, table 2048, no per-kind entries). */
void ps_obs_dedupe_cfg_defaults(struct ps_obs_dedupe_cfg *cfg);

/* Fill cfg from PS_CENTRAL_DEDUPE_WINDOW_S, PS_CENTRAL_DEDUPE_TABLE_MAX and
 * every PS_CENTRAL_DEDUPE_WINDOW_<KIND> (set by config_to_env from the
 * [central] dedupe_window_s / dedupe_table_max / dedupe_window_<kind> keys). */
void ps_obs_dedupe_cfg_from_env(struct ps_obs_dedupe_cfg *cfg);

/* (Re)initialise the global table. Pending repeats of a previous table are
 * discarded, so call ps_obs_dedupe_flush(now, 1, ...) first when that
 * matters. Returns 0, or -1 on allocation failure (dedupe then disabled). */
int ps_obs_dedupe_init(const struct ps_obs_dedupe_cfg *cfg);

/* Free the table; afterwards every offer returns SEND. */
void ps_obs_dedupe_shutdown(void);

/* Window in seconds that applies to `kind` under the current config
 * (0 = never suppressed). */
int ps_obs_dedupe_window_for(const char *kind);

/* Canonical key text (see above). Returns its length, or -1. */
int ps_obs_dedupe_key(const char *kind, const char *observation_json,
                      char out_key[PS_DEDUPE_KEY_MAX]);
int ps_obs_dedupe_key_n(const char *kind, const char *observation_json,
                        size_t obs_len, char out_key[PS_DEDUPE_KEY_MAX]);

/* Offer one sighting. SEND: the caller ships it now (as before). SUPPRESS:
 * it is accounted for in a later summary. */
enum ps_dedupe_action ps_obs_dedupe_offer(const char *kind,
                                          const char *observation_json,
                                          int64_t now_ms);
enum ps_dedupe_action ps_obs_dedupe_offer_n(const char *kind,
                                            const char *observation_json,
                                            size_t obs_len, int64_t now_ms);

/* Write up to `max` summary events for entries whose window has ended (all
 * entries with `force`) into out_items and drop those entries; entries with
 * no repeats are dropped without a summary. Entries that do not fit in `max`
 * stay for the next call: call again while it returns `max`. */
int ps_obs_dedupe_flush(int64_t now_ms, int force,
                        char out_items[][PS_OBS_ITEM_MAX], int max);

/* Build a summary event (format above) into out. key_sha256_hex may be NULL
 * (then no truncated fallback is possible). Never writes more than
 * min(cap, PS_OBS_ITEM_MAX) - 1 bytes. Returns the length or 0. */
size_t ps_obs_dedupe_build_summary(char *out, size_t cap, const char *kind,
                                   const char *observation_json, size_t obs_len,
                                   const struct ps_obs_dedupe_stats *st,
                                   const char *key_sha256_hex);

/* Snapshot of the running counters. */
void ps_obs_dedupe_get_counters(struct ps_obs_dedupe_counters *out);

/* Number of open entries (tests / diagnostics). */
int ps_obs_dedupe_count(void);

#endif /* PS_OBS_DEDUPE_H */
