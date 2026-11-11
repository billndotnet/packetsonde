/* ps_appendf / ps_list_has_token: bounded appends and whole-token matching. */
#include "strbuf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

static void test_append_fits_and_refuses(void)
{
    /* Heap buffer of the exact size, so ASAN sees any write past it. */
    char *b = malloc(8);
    size_t off = 0;
    b[0] = '\0';
    CHECK(ps_appendf(b, 8, &off, "%s", "abc") == 0 && off == 3);
    CHECK(ps_appendf(b, 8, &off, "%d", 1234) == 0 && off == 7);  /* exactly full */
    CHECK(strcmp(b, "abc1234") == 0);
    CHECK(ps_appendf(b, 8, &off, "x") == -1 && off == 7);         /* no room for 1 */
    CHECK(strcmp(b, "abc1234") == 0);
    CHECK(ps_appendf(b, 8, &off, "%s", "") == 0 && off == 7);    /* empty still fits */
    free(b);

    b = malloc(8);
    off = 0; b[0] = '\0';
    CHECK(ps_appendf(b, 8, &off, "ab") == 0);
    CHECK(ps_appendf(b, 8, &off, "%s", "123456") == -1);         /* would not fit */
    CHECK(off == 2 && strcmp(b, "ab") == 0);                      /* nothing partial */
    CHECK(ps_appendf(b, 8, &off, "%s", "12345") == 0 && off == 7);
    free(b);

    /* A limit below the buffer size keeps room for closing bytes. */
    char c[16]; off = 0; c[0] = '\0';
    CHECK(ps_appendf(c, sizeof c - 2, &off, "%s", "0123456789abc") == 0);
    CHECK(ps_appendf(c, sizeof c - 2, &off, "d") == -1);
    CHECK(ps_appendf(c, sizeof c, &off, "]}") == 0 && off == 15);
    CHECK(strcmp(c, "0123456789abc]}") == 0);

    /* Offset already past the limit (or a zero limit) is refused, not wrapped. */
    off = 20;
    CHECK(ps_appendf(c, sizeof c, &off, "z") == -1 && off == 20);
    off = 0;
    CHECK(ps_appendf(c, 0, &off, "z") == -1 && off == 0);
}

static void test_list_has_token(void)
{
    const char *seps = ", \t";
    CHECK(ps_list_has_token("aa11,bb22", seps, "aa11"));
    CHECK(ps_list_has_token("aa11,bb22", seps, "bb22"));
    CHECK(ps_list_has_token(" aa11 , bb22 ", seps, "bb22"));
    CHECK(ps_list_has_token("aa11,,\tbb22", seps, "bb22"));
    CHECK(!ps_list_has_token("aa11,bb22", seps, "a"));            /* substring */
    CHECK(!ps_list_has_token("aa11,bb22", seps, "aa1"));          /* prefix */
    CHECK(!ps_list_has_token("aa11,bb22", seps, "a11"));          /* suffix */
    CHECK(!ps_list_has_token("aa11,bb22", seps, "11,bb"));        /* spans a separator */
    CHECK(!ps_list_has_token("aa11,bb22", seps, "aa11,bb22"));    /* whole list */
    CHECK(!ps_list_has_token("aa11", seps, "aa111"));             /* longer */
    CHECK(!ps_list_has_token("aa11,bb22", seps, ""));
    CHECK(!ps_list_has_token("", seps, "aa11"));
    CHECK(!ps_list_has_token(",, ,", seps, "aa11"));
    CHECK(!ps_list_has_token(NULL, seps, "aa11"));
    CHECK(!ps_list_has_token("aa11", seps, NULL));
}

int main(void)
{
    test_append_fits_and_refuses();
    test_list_has_token();
    if (g_fail) { printf("FAILED: %d check(s)\n", g_fail); return 1; }
    printf("ok\n");
    return 0;
}
