#ifndef PS_IFACE_SNAPSHOT_H
#define PS_IFACE_SNAPSHOT_H

#include <stdint.h>

/* Upper bound on interfaces tracked per snapshot. Larger than the 8-iface
 * capture cap because the monitor observes ALL interfaces (incl. down/virtual),
 * not just the ones being captured. */
#define PS_IFACE_SNAP_MAX 32

struct ps_iface_snap {
    char     name[64];
    int      up;        /* IFF_UP   */
    int      running;   /* IFF_RUNNING (carrier) */
    uint32_t addr_hash; /* order-independent hash of the iface's addresses */
};

enum ps_iface_change_kind {
    PS_IFC_ADDED,   /* in cur, not in prev */
    PS_IFC_REMOVED, /* in prev, not in cur */
    PS_IFC_STATE,   /* up/running differ */
    PS_IFC_ADDR     /* addr_hash differs (up/running unchanged) */
};

struct ps_iface_change {
    enum ps_iface_change_kind kind;
    char name[64];
    int  old_up, old_running, new_up, new_running; /* meaningful for STATE/ADDED */
};

/* Snapshot the host's interfaces via getifaddrs into out[], one entry per unique
 * name, up to `max`. Returns the count, or -1 on getifaddrs failure. */
int ps_iface_snapshot(struct ps_iface_snap out[], int max);

/* Pure: diff prev vs cur (matched by name). Fills changes[] up to `max`,
 * returns the number of changes written. */
int ps_iface_diff(const struct ps_iface_snap *prev, int nprev,
                  const struct ps_iface_snap *cur, int ncur,
                  struct ps_iface_change *changes, int max);

#endif /* PS_IFACE_SNAPSHOT_H */
