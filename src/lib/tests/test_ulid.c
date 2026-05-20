#include "../ulid.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static void test_length_and_charset(void) {
    char buf[PS_ULID_STRLEN + 1];
    int rc = ps_ulid_new(buf, sizeof(buf));
    assert(rc == 0);
    assert(strlen(buf) == PS_ULID_STRLEN);
    /* Crockford base32: 0-9, A-Z minus I, L, O, U */
    for (size_t i = 0; i < PS_ULID_STRLEN; i++) {
        char c = buf[i];
        int ok = (c >= '0' && c <= '9') ||
                 (c >= 'A' && c <= 'Z' && c != 'I' && c != 'L' && c != 'O' && c != 'U');
        if (!ok) {
            fprintf(stderr, "bad char '%c' at pos %zu\n", c, i);
            assert(0);
        }
    }
}

static void test_monotonic_within_ms(void) {
    /* Two ULIDs generated back-to-back must be strictly increasing
     * as strings (sortable property). */
    char a[PS_ULID_STRLEN + 1], b[PS_ULID_STRLEN + 1];
    ps_ulid_new(a, sizeof(a));
    ps_ulid_new(b, sizeof(b));
    assert(strcmp(a, b) < 0);
}

static void test_short_buffer_errors(void) {
    char small[5];
    int rc = ps_ulid_new(small, sizeof(small));
    assert(rc != 0);
}

int main(void) {
    test_length_and_charset();
    test_monotonic_within_ms();
    test_short_buffer_errors();
    printf("test_ulid: OK\n");
    return 0;
}
