#include "module.h"
#include "log.h"

#include <string.h>
#include <stdint.h>

void ps_module_registry_init(struct ps_module_registry *reg)
{
    memset(reg, 0, sizeof(*reg));
}

int ps_module_registry_add(struct ps_module_registry *reg, const ps_module_t *mod)
{
    if (!reg || !mod) {
        ps_error("module_registry_add: null argument");
        return -1;
    }
    if (reg->count >= PS_MAX_MODULES) {
        ps_error("module_registry_add: registry full (max %d)", PS_MAX_MODULES);
        return -1;
    }

    struct ps_module_instance *inst = &reg->instances[reg->count];
    inst->module          = mod;
    inst->enabled         = 1;
    memset(&inst->ctx, 0, sizeof(inst->ctx));
    inst->ctx.module      = mod;
    inst->ctx.userdata    = NULL;

    reg->count++;
    ps_debug("module_registry: registered '%s' v%s", mod->name, mod->version ? mod->version : "?");
    return 0;
}

const ps_module_t *ps_module_registry_find(const struct ps_module_registry *reg, const char *name)
{
    if (!reg || !name) return NULL;
    for (int i = 0; i < reg->count; i++) {
        if (strcmp(reg->instances[i].module->name, name) == 0) {
            return reg->instances[i].module;
        }
    }
    return NULL;
}

void ps_module_registry_init_all(struct ps_module_registry *reg)
{
    for (int i = 0; i < reg->count; i++) {
        struct ps_module_instance *inst = &reg->instances[i];
        if (!inst->enabled) continue;
        if (!inst->module->init) continue;

        int rc = inst->module->init(&inst->ctx);
        if (rc != 0) {
            ps_warn("module_registry: init failed for '%s' (rc=%d) — disabling",
                    inst->module->name, rc);
            inst->enabled = 0;
        } else {
            ps_info("module_registry: initialized '%s'", inst->module->name);
        }
    }
}

void ps_module_registry_shutdown_all(struct ps_module_registry *reg)
{
    /* Shutdown in reverse registration order */
    for (int i = reg->count - 1; i >= 0; i--) {
        struct ps_module_instance *inst = &reg->instances[i];
        if (!inst->enabled) continue;
        if (!inst->module->shutdown) continue;

        ps_info("module_registry: shutting down '%s'", inst->module->name);
        inst->module->shutdown(&inst->ctx);
    }
}

void ps_module_registry_tick_all(struct ps_module_registry *reg, uint64_t now_usec)
{
    for (int i = 0; i < reg->count; i++) {
        struct ps_module_instance *inst = &reg->instances[i];
        if (!inst->enabled) continue;
        if (!inst->module->tick) continue;

        inst->module->tick(&inst->ctx, now_usec);
    }
}

void ps_module_registry_dispatch_packet(struct ps_module_registry *reg,
                                         const uint8_t *pkt, uint32_t len,
                                         uint64_t ts_usec, int handle_id)
{
    for (int i = 0; i < reg->count; i++) {
        struct ps_module_instance *inst = &reg->instances[i];
        if (!inst->enabled) continue;
        if (!(inst->module->flags & PS_MOD_PASSIVE)) continue;
        if (!inst->module->on_packet) continue;

        inst->module->on_packet(&inst->ctx, pkt, len, ts_usec, handle_id);
    }
}

void ps_module_registry_dispatch_response(struct ps_module_registry *reg,
                                           const uint8_t *pkt, uint32_t len,
                                           uint64_t ts_usec, int socket_id)
{
    for (int i = 0; i < reg->count; i++) {
        struct ps_module_instance *inst = &reg->instances[i];
        if (!inst->enabled) continue;
        if (!(inst->module->flags & PS_MOD_ACTIVE)) continue;
        if (!inst->module->on_response) continue;

        inst->module->on_response(&inst->ctx, pkt, len, ts_usec, socket_id);
    }
}

/* Global registry used by ps_module_register() for self-registering modules */
static struct ps_module_registry *g_registry = NULL;

void ps_module_set_global_registry(struct ps_module_registry *reg)
{
    g_registry = reg;
}

int ps_module_register(const ps_module_t *mod)
{
    if (!g_registry) {
        ps_error("ps_module_register: no global registry set");
        return -1;
    }
    return ps_module_registry_add(g_registry, mod);
}
