#include "../args.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* args.c calls into the verb registry to print the Verbs section of
 * usage; dispatch.c provides the real implementation. Stub it out here
 * so test_args can link without pulling in every audit/probe/scan TU. */
void ps_verbs_print_list(FILE *fp) { (void)fp; }

static void test_defaults(void) {
    char *argv[] = { "packetsonde", "version" };
    struct ps_args a = {0};
    int rc = ps_args_parse(2, argv, &a);
    assert(rc == 0);
    assert(a.fmt == PS_FMT_AUTO);
    assert(a.verb_argc == 1);
    assert(strcmp(a.verb_argv[0], "version") == 0);
    assert(a.via == NULL);
}

static void test_json_flag(void) {
    char *argv[] = { "packetsonde", "--json", "version" };
    struct ps_args a = {0};
    int rc = ps_args_parse(3, argv, &a);
    assert(rc == 0);
    assert(a.fmt == PS_FMT_JSON);
    assert(strcmp(a.verb_argv[0], "version") == 0);
}

static void test_via(void) {
    char *argv[] = { "packetsonde", "--via", "trunkbox", "version" };
    struct ps_args a = {0};
    int rc = ps_args_parse(4, argv, &a);
    assert(rc == 0);
    assert(a.via && strcmp(a.via, "trunkbox") == 0);
}

static void test_no_verb_is_error(void) {
    char *argv[] = { "packetsonde" };
    struct ps_args a = {0};
    int rc = ps_args_parse(1, argv, &a);
    assert(rc != 0);
}

static void test_unknown_flag_is_error(void) {
    char *argv[] = { "packetsonde", "--nope", "version" };
    struct ps_args a = {0};
    int rc = ps_args_parse(3, argv, &a);
    assert(rc != 0);
}

int main(void) {
    test_defaults();
    test_json_flag();
    test_via();
    test_no_verb_is_error();
    test_unknown_flag_is_error();
    printf("test_args: OK\n");
    return 0;
}
