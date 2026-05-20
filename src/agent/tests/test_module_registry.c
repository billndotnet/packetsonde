#include <assert.h>
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

int main(void)
{
    printf("test_module_registry:\n");
    test_register_and_find();
    test_lifecycle();
    test_tick_all();
    printf("All tests passed.\n");
    return 0;
}
