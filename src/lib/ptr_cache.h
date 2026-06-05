#ifndef PS_PTR_CACHE_H
#define PS_PTR_CACHE_H

#include <stddef.h>

/* Resolver function: fill name (cap bytes) for ip. Return 0 on success,
 * non-zero if no name (cached as negative). */
typedef int (*ps_ptr_resolver_fn)(const char *ip, char *name, size_t cap);

struct ps_ptr_cache;

/* Real cache: getnameinfo-backed resolver on a background thread. */
struct ps_ptr_cache *ps_ptr_cache_new(void);
/* Test/inject variant: supply your own resolver. */
struct ps_ptr_cache *ps_ptr_cache_new_ex(ps_ptr_resolver_fn resolver);
void ps_ptr_cache_free(struct ps_ptr_cache *c);

/* Non-blocking. Returns 1 if ip is resolved (name filled; empty string means
 * cached-negative), else 0 and schedules an async resolve. */
int ps_ptr_cache_lookup(struct ps_ptr_cache *c, const char *ip,
                        char *name, size_t cap);

/* Block up to timeout_ms for ip to resolve. Returns 1 if resolved (name
 * filled; empty = negative), 0 on timeout. timeout_ms <= 0 == lookup(). */
int ps_ptr_cache_wait(struct ps_ptr_cache *c, const char *ip,
                      int timeout_ms, char *name, size_t cap);

#endif
