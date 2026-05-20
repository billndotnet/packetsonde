#ifndef PS_AUDIT_LOADER_H
#define PS_AUDIT_LOADER_H

#include "audit_module.h"
#include <stddef.h>

struct ps_audit_loaded {
    const struct ps_audit_module *module;
    void                         *dl_handle;
    char                          source_path[512];
};

struct ps_audit_loader {
    struct ps_audit_loaded *items;
    size_t                  count;
    size_t                  cap;
};

/* Scans the configured plugin directories (env PS_AUDITS_DIR overrides;
 * otherwise: XDG_CONFIG_HOME/packetsonde/audits, ~/.config/packetsonde/audits,
 * a build-tree default, and /usr/lib/packetsonde/audits). dlopens every
 * .so/.dylib named audit-*, registers each module exporting a valid
 * ps_audit_module(). */
int  ps_audit_loader_scan(struct ps_audit_loader *L);

const struct ps_audit_loaded *ps_audit_loader_find(const struct ps_audit_loader *L,
                                                    const char *name);

void ps_audit_loader_destroy(struct ps_audit_loader *L);

#endif
