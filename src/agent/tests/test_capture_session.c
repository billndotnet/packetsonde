#include "capture_session.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* Read an entire file into buf (NUL-terminated); returns bytes read, or -1. */
static long slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    fclose(f);
    return (long)n;
}

int main(void)
{
    char root[] = "/tmp/ps_capture_XXXXXX";
    assert(mkdtemp(root));
    setenv("PS_DETECT_CAPTURE_DIR", root, 1);

    char jsonl[512];
    snprintf(jsonl, sizeof jsonl, "%s/abc.jsonl", root);

    /* No active session: append is a noop, returns 0, writes nothing. */
    assert(ps_capture_session_append("{\"x\":1}") == 0);
    assert(access(jsonl, F_OK) != 0);   /* file must not exist */

    /* Activate session "abc": append returns 1 and writes one line. */
    ps_capture_session_set("abc");
    assert(ps_capture_session_append("{\"x\":1}") == 1);

    char buf[1024];
    long n = slurp(jsonl, buf, sizeof buf);
    assert(n > 0);
    assert(strcmp(buf, "{\"x\":1}\n") == 0);

    /* A second append appends (the helper supplies the newline itself). */
    assert(ps_capture_session_append("{\"x\":2}") == 1);
    n = slurp(jsonl, buf, sizeof buf);
    assert(n > 0);
    assert(strcmp(buf, "{\"x\":1}\n{\"x\":2}\n") == 0);

    /* A json_line that already ends in a newline must not get a second one. */
    assert(ps_capture_session_append("{\"x\":3}\n") == 1);
    n = slurp(jsonl, buf, sizeof buf);
    assert(n > 0);
    assert(strcmp(buf, "{\"x\":1}\n{\"x\":2}\n{\"x\":3}\n") == 0);

    /* Clear the session: append is a noop again, returns 0. */
    ps_capture_session_clear();
    assert(ps_capture_session_append("{\"y\":2}") == 0);

    /* The cleared session must not have written {"y":2} anywhere. */
    n = slurp(jsonl, buf, sizeof buf);
    assert(n > 0);
    assert(strstr(buf, "\"y\"") == NULL);

    printf("test_capture_session: OK\n");
    return 0;
}
