#include "ps_test_assert.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "module.h"

static int mock_init_called = 0;
static int mock_shutdown_called = 0;
static int mock_tick_called = 0;

static int mock_init(struct ps_module_ctx *ctx) { (void)ctx; mock_init_called++; return 0; }
static void mock_shutdown(struct ps_module_ctx *ctx) { (void)ctx; mock_shutdown_called++; }
static void mock_tick(struct ps_module_ctx *ctx, uint64_t now) { (void)ctx; (void)now; mock_tick_called++; }

static ps_module_t mock_module = {
    .name = "mock_module",
    .description = "Test module",
    .version = "0.1",
    .flags = PS_MOD_ACTIVE | PS_MOD_NEEDS_RAW,
    .init = mock_init,
    .shutdown = mock_shutdown,
    .on_packet = NULL,
    .on_job = NULL,
    .on_response = NULL,
    .tick = mock_tick,
};

static void test_register_and_find(void)
{
    struct ps_module_registry reg;
    ps_module_registry_init(&reg);
    assert(ps_module_registry_add(&reg, &mock_module) == 0);
    assert(reg.count == 1);
    assert(ps_module_registry_find(&reg, "mock_module") == &mock_module);
    assert(ps_module_registry_find(&reg, "nonexistent") == NULL);
    printf("  PASS: register and find\n");
}

static void test_lifecycle(void)
{
    struct ps_module_registry reg;
    ps_module_registry_init(&reg);
    ps_module_registry_add(&reg, &mock_module);
    mock_init_called = 0; mock_shutdown_called = 0;
    ps_module_registry_init_all(&reg);
    assert(mock_init_called == 1);
    ps_module_registry_shutdown_all(&reg);
    assert(mock_shutdown_called == 1);
    printf("  PASS: lifecycle init/shutdown\n");
}

static void test_tick_all(void)
{
    struct ps_module_registry reg;
    ps_module_registry_init(&reg);
    ps_module_registry_add(&reg, &mock_module);
    ps_module_registry_init_all(&reg);
    mock_tick_called = 0;
    ps_module_registry_tick_all(&reg, 1000000);
    assert(mock_tick_called == 1);
    ps_module_registry_shutdown_all(&reg);
    printf("  PASS: tick all\n");
}

/* discovery.control "list": the reply is bounded by the buffer it is given
 * and is complete JSON at every size (entries are left out whole). */
static int ends_with(const char *s, const char *suf)
{
    size_t a = strlen(s), b = strlen(suf);
    return a >= b && strcmp(s + a - b, suf) == 0;
}

static void test_passive_list_json(void)
{
    static ps_module_t passive[PS_MAX_MODULES];
    static char names[PS_MAX_MODULES][128];
    static ps_module_t active = { .name = "active_one", .flags = 0 };
    struct ps_module_registry reg;
    ps_module_registry_init(&reg);

    /* Small registry: exact reply, active modules left out. */
    snprintf(names[0], sizeof names[0], "lldp");
    passive[0] = (ps_module_t){ .name = names[0], .flags = PS_MOD_PASSIVE };
    snprintf(names[1], sizeof names[1], "cdp");
    passive[1] = (ps_module_t){ .name = names[1], .flags = PS_MOD_PASSIVE };
    ps_module_registry_add(&reg, &passive[0]);
    ps_module_registry_add(&reg, &active);
    ps_module_registry_add(&reg, &passive[1]);
    reg.instances[2].enabled = 0;
    char out[256];
    int n = ps_module_registry_passive_list_json(&reg, out, sizeof out);
    assert(n == (int)strlen(out));
    assert(strcmp(out, "{\"modules\":[{\"name\":\"lldp\",\"enabled\":true},"
                       "{\"name\":\"cdp\",\"enabled\":false}]}") == 0);

    /* A full registry of long names does not fit the agent's 2048-byte reply:
     * it used to run the offset past the buffer. */
    ps_module_registry_init(&reg);
    for (int i = 0; i < PS_MAX_MODULES; i++) {
        memset(names[i], 'a' + (i % 26), 100);
        snprintf(names[i] + 100, sizeof names[i] - 100, "%02d", i);
        passive[i] = (ps_module_t){ .name = names[i], .flags = PS_MOD_PASSIVE };
        assert(ps_module_registry_add(&reg, &passive[i]) == 0);
    }
    char *big = malloc(2048);
    n = ps_module_registry_passive_list_json(&reg, big, 2048);
    assert(n > 0 && n < 2048 && n == (int)strlen(big));
    assert(ends_with(big, "}],\"truncated\":true}"));
    free(big);

    /* Every buffer size: never writes past cap (heap-exact for ASAN), and is
     * either refused (-1) or a closed reply of its returned length. */
    for (size_t cap = 0; cap <= 4500; cap++) {
        char *b = malloc(cap ? cap : 1);
        n = ps_module_registry_passive_list_json(&reg, b, cap);
        if (n >= 0) {
            assert((size_t)n < cap && n == (int)strlen(b));
            assert(strncmp(b, "{\"modules\":[", 12) == 0);
            assert(ends_with(b, "]}") || ends_with(b, "],\"truncated\":true}"));
        } else {
            assert(cap < 64);
        }
        free(b);
    }
    /* Large enough for all 32: no truncation flag. */
    big = malloc(8192);
    n = ps_module_registry_passive_list_json(&reg, big, 8192);
    assert(n > 0 && ends_with(big, "}]}"));
    free(big);
    printf("  PASS: passive list json bounded\n");
}

int main(void)
{
    printf("test_module_registry:\n");
    test_register_and_find();
    test_lifecycle();
    test_tick_all();
    test_passive_list_json();
    printf("All tests passed.\n");
    return 0;
}
