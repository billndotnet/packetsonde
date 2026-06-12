#include "iface_enum.h"
#include <ifaddrs.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>

int ps_iface_excluded(const char *name, const char *exclude_csv) {
    if (!name || !name[0]) return 1;
    if (strcmp(name, "lo") == 0) return 1;
    if (!exclude_csv || !exclude_csv[0]) return 0;
    const char *p = exclude_csv;
    while (*p) {
        while (*p == ',' || *p == ' ') p++;
        const char *start = p;
        while (*p && *p != ',') p++;
        const char *end = p;
        while (end > start && *(end - 1) == ' ') end--;
        size_t len = (size_t)(end - start);
        if (len > 0 && strncmp(name, start, len) == 0) return 1;
    }
    return 0;
}

int ps_iface_enumerate(const char *exclude_csv, char out[][64], int max) {
    struct ifaddrs *ifa, *cur;
    if (getifaddrs(&ifa) != 0) return 0;
    int n = 0;
    for (cur = ifa; cur && n < max; cur = cur->ifa_next) {
        const char *nm = cur->ifa_name;
        if (!nm || ps_iface_excluded(nm, exclude_csv)) continue;
        /* The passive modules (ARP/LLDP/CDP/STP/neighbor/broadcast) are L2
         * broadcast-segment features, and the combined BPF filter is Ethernet-
         * specific — it won't compile on the DLT_NULL/DLT_RAW links that
         * loopback, point-to-point tunnels (utun/gif/ppp), and encapsulation
         * pseudo-devices (stf 6to4) present. Keep only real Ethernet broadcast
         * segments, by flag, so this is correct regardless of platform naming
         * (lo vs lo0, etc). */
        if (cur->ifa_flags & (IFF_LOOPBACK | IFF_POINTOPOINT)) continue;
        if (!(cur->ifa_flags & IFF_BROADCAST)) continue;
        int dup = 0;
        for (int i = 0; i < n; i++) if (strcmp(out[i], nm) == 0) { dup = 1; break; }
        if (dup) continue;
        snprintf(out[n], 64, "%s", nm);
        n++;
    }
    freeifaddrs(ifa);
    return n;
}
