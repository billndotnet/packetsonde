#ifndef PS_BASELINE_SET_H
#define PS_BASELINE_SET_H
#include <stddef.h>

#define PS_BL_MAX 512
#define PS_BL_PATHLEN 256
struct ps_baseline_set { char exe[256]; int n; char path[PS_BL_MAX][PS_BL_PATHLEN]; };

void ps_blset_init(struct ps_baseline_set *s, const char *exe);
int  ps_blset_add(struct ps_baseline_set *s, const char *path);     /* 1 added, 0 dup, -1 full */
int  ps_blset_covered(const struct ps_baseline_set *s, const char *path); /* dir-prefix match */
int  ps_blset_to_json(const struct ps_baseline_set *s, char *out, size_t cap);
int  ps_blset_from_json(const char *json, struct ps_baseline_set *s);
int  ps_blset_to_json_key(const struct ps_baseline_set *s, const char *key, char *out, size_t cap);
int  ps_blset_from_json_key(const char *json, const char *key, struct ps_baseline_set *s);
int  ps_blset_rollup(struct ps_baseline_set *s, int threshold);     /* collapse >=N files/dir -> dir */
#endif
