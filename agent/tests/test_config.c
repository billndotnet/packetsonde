#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "config.h"

static void test_parse_basic(void)
{
    const char *ini =
        "[agent]\n"
        "ipc_socket = /var/run/packetsonde/agent.sock\n"
        "log_level = debug\n"
        "\n"
        "[capture]\n"
        "interfaces = en0\n"
        "promiscuous = true\n"
        "\n"
        "[export]\n"
        "collector = 127.0.0.1:2055\n"
        "source_id = 0x5053\n";

    struct ps_config cfg;
    int rc = ps_config_parse_string(&cfg, ini);
    assert(rc == 0);

    const char *sock = ps_config_get(&cfg, "agent", "ipc_socket");
    assert(sock && strcmp(sock, "/var/run/packetsonde/agent.sock") == 0);

    int promisc = ps_config_get_bool(&cfg, "capture", "promiscuous", 0);
    assert(promisc == 1);

    int src_id = ps_config_get_int(&cfg, "export", "source_id", 0);
    assert(src_id == 0x5053);

    assert(ps_config_get(&cfg, "agent", "nonexistent") == NULL);
    assert(ps_config_get_int(&cfg, "agent", "nonexistent", 42) == 42);

    ps_config_free(&cfg);
    printf("  PASS: parse basic INI\n");
}

static void test_parse_comments_and_blanks(void)
{
    const char *ini =
        "# This is a comment\n"
        "  \n"
        "[section]\n"
        "  key = value  \n"
        "# another comment\n"
        "key2=value2\n";

    struct ps_config cfg;
    int rc = ps_config_parse_string(&cfg, ini);
    assert(rc == 0);
    assert(strcmp(ps_config_get(&cfg, "section", "key"), "value") == 0);
    assert(strcmp(ps_config_get(&cfg, "section", "key2"), "value2") == 0);
    ps_config_free(&cfg);
    printf("  PASS: comments and blank lines\n");
}

int main(void)
{
    printf("test_config:\n");
    test_parse_basic();
    test_parse_comments_and_blanks();
    printf("All tests passed.\n");
    return 0;
}
