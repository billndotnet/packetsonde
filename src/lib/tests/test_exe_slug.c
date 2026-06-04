#include "exe_slug.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char s[256];
    assert(ps_exe_slug("/usr/sbin/nginx", s, sizeof s) == 0);
    assert(strcmp(s, "usr-sbin-nginx") == 0);
    assert(ps_exe_slug("/usr/bin/python3.11", s, sizeof s) == 0);
    assert(strcmp(s, "usr-bin-python3.11") == 0);          /* . and digits kept */
    assert(ps_exe_slug("", s, sizeof s) == -1);            /* empty -> error */
    /* odd chars collapse to '-' */
    assert(ps_exe_slug("/x y/z", s, sizeof s) == 0);
    assert(strcmp(s, "x-y-z") == 0);
    printf("test_exe_slug: OK\n");
    return 0;
}
