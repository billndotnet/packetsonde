/* Guard: assert() in test code must stay live in every build type.
 * Release defines NDEBUG, which deletes assert() and everything inside it;
 * many tests put real work in their asserts (mkdtemp, init calls), so a
 * Release run silently skipped setup and crashed. Tests include
 * "ps_test_assert.h" instead of <assert.h> to keep assert live. */
#include "ps_test_assert.h"

int main(void) {
    int ran = 0;
    assert((ran = 1) == 1);
    return ran == 1 ? 0 : 1;
}
