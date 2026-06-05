#include "ptr_cache.h"
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>

#define CHECK(c) do{ if(!(c)){ fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c); return 1; } }while(0)

static atomic_int g_calls;
static int stub_resolver(const char *ip, char *name, size_t cap) {
    atomic_fetch_add(&g_calls, 1);
    if (strcmp(ip, "10.0.0.1") == 0) { snprintf(name, cap, "gw.local"); return 0; }
    return -1;   /* everything else: no name (negative) */
}

int main(void) {
    atomic_store(&g_calls, 0);
    struct ps_ptr_cache *c = ps_ptr_cache_new_ex(stub_resolver);
    CHECK(c);

    char name[256];
    /* First lookup is a miss (async). wait() resolves it. */
    CHECK(ps_ptr_cache_wait(c, "10.0.0.1", 2000, name, sizeof(name)) == 1);
    CHECK(strcmp(name, "gw.local") == 0);

    /* Second lookup is a cache hit; resolver not called again. */
    CHECK(ps_ptr_cache_lookup(c, "10.0.0.1", name, sizeof(name)) == 1);
    CHECK(strcmp(name, "gw.local") == 0);

    /* Negative result is cached (empty name), resolver not re-run. */
    CHECK(ps_ptr_cache_wait(c, "203.0.113.9", 2000, name, sizeof(name)) == 1);
    CHECK(name[0] == '\0');
    CHECK(ps_ptr_cache_lookup(c, "203.0.113.9", name, sizeof(name)) == 1);

    /* Dedupe: 10.0.0.1 + 203.0.113.9 each resolved exactly once. */
    CHECK(atomic_load(&g_calls) == 2);

    ps_ptr_cache_free(c);
    printf("ok\n");
    return 0;
}
