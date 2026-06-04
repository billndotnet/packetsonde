#ifndef PS_BASELINE_STORE_H
#define PS_BASELINE_STORE_H
#include "baseline_set.h"
/* Load <state_dir>/<slug>/{baseline,denials}.json into the sets (empty if absent). 0. */
int ps_baseline_load(const char *state_dir, const char *exe,
                     struct ps_baseline_set *baseline, struct ps_baseline_set *denials);
/* Append `path` to <state_dir>/<slug>/candidates.json (dedup), atomically. 0/-1. */
int ps_baseline_append_candidate(const char *state_dir, const char *exe, const char *path);
/* Network destinations (Phase B): parallel dest*.json files, key "dests". */
int ps_baseline_load_dests(const char *state_dir, const char *exe,
                           struct ps_baseline_set *baseline, struct ps_baseline_set *denials);
int ps_baseline_append_dest_candidate(const char *state_dir, const char *exe, const char *dest);
#endif
