#include "iso8601.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char buf[32];

    /* 2026-05-23T08:00:00Z = 1779523200 s = 1779523200000000 usec */
    size_t n = ps_iso8601_utc(1779523200000000ULL, buf, sizeof(buf));
    assert(n == 20);
    assert(strcmp(buf, "2026-05-23T08:00:00Z") == 0);

    /* Unix epoch */
    n = ps_iso8601_utc(0ULL, buf, sizeof(buf));
    assert(strcmp(buf, "1970-01-01T00:00:00Z") == 0);

    /* sub-second microseconds are truncated to whole seconds */
    n = ps_iso8601_utc(1779523200999999ULL, buf, sizeof(buf));
    assert(strcmp(buf, "2026-05-23T08:00:00Z") == 0);

    /* too-small buffer returns 0 */
    assert(ps_iso8601_utc(0ULL, buf, 10) == 0);

    printf("test_iso8601: OK\n");
    return 0;
}
