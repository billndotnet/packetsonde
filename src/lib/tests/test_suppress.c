#include "suppress.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    /* default-style list: prefixes, optional "comm:" qualifier */
    const char *list = "/usr/lib,/usr/share,smbd:/var/log";
    /* reads under a listed prefix are suppressed */
    assert(ps_suppress_match(list, "anything", "/usr/lib/x.so", 1) == 1);
    assert(ps_suppress_match(list, "anything", "/usr/share/zoneinfo", 1) == 1);
    /* comm-qualified rule only matches that comm */
    assert(ps_suppress_match(list, "smbd", "/var/log/a", 1) == 1);
    assert(ps_suppress_match(list, "nginx", "/var/log/a", 1) == 0);
    /* writes are NEVER suppressed even under a listed prefix */
    assert(ps_suppress_match(list, "anything", "/usr/lib/x.so", 0) == 0);
    /* non-listed path kept */
    assert(ps_suppress_match(list, "x", "/etc/shadow", 1) == 0);
    /* empty list suppresses nothing */
    assert(ps_suppress_match("", "x", "/usr/lib/y", 1) == 0);
    printf("test_suppress: OK\n");
    return 0;
}
