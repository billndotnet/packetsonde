/* assert() that survives -DNDEBUG (CMAKE_BUILD_TYPE=Release/RelWithDebInfo).
 *
 * Test code routinely does real work inside assert(): setup calls, mkdtemp,
 * init functions. Under NDEBUG the standard assert() expands to nothing, the
 * work never runs, and the test crashes or fails on state it never built
 * (see FRI-93). Tests must include this header, never <assert.h> directly.
 * Each include re-evaluates NDEBUG, so undefining it first is sufficient. */
#ifndef PS_TEST_ASSERT_H
#define PS_TEST_ASSERT_H
#undef NDEBUG
#include <assert.h>
#ifdef NDEBUG
#error "ps_test_assert.h: assert() is compiled out"
#endif
#endif
