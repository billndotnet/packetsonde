#ifndef PS_MODULE_H
#define PS_MODULE_H

#include <packetsonde/module_api.h>

#define PS_MAX_MODULES 32

struct ps_module_instance {
    const ps_module_t  *module;
    ps_module_ctx_t     ctx;
    int                 enabled;
    uint64_t            event_count;
};

struct ps_module_registry {
    struct ps_module_instance instances[PS_MAX_MODULES];
    int count;
};

void ps_module_registry_init(struct ps_module_registry *reg);
int  ps_module_registry_add(struct ps_module_registry *reg, const ps_module_t *mod);
const ps_module_t *ps_module_registry_find(const struct ps_module_registry *reg, const char *name);

void ps_module_registry_init_all(struct ps_module_registry *reg);
void ps_module_registry_shutdown_all(struct ps_module_registry *reg);
void ps_module_registry_tick_all(struct ps_module_registry *reg, uint64_t now_usec);

void ps_module_registry_dispatch_packet(struct ps_module_registry *reg,
                                         const uint8_t *pkt, uint32_t len,
                                         uint64_t ts_usec, int handle_id);
void ps_module_registry_dispatch_response(struct ps_module_registry *reg,
                                           const uint8_t *pkt, uint32_t len,
                                           uint64_t ts_usec, int socket_id);

#endif
