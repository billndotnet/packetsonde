#include "iface_snapshot.h"

#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>

/* FNV-1a over a byte range. */
static uint32_t fnv1a(const unsigned char *p, unsigned long n, uint32_t h) {
    while (n--) { h ^= *p++; h *= 16777619u; }
    return h;
}

/* Find an interface by name in arr[0..n); return index or -1. */
static int find_by_name(const struct ps_iface_snap *arr, int n, const char *name) {
    for (int i = 0; i < n; i++)
        if (strcmp(arr[i].name, name) == 0) return i;
    return -1;
}

int ps_iface_snapshot(struct ps_iface_snap out[], int max) {
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0) return -1;

    int count = 0;
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name) continue;

        int idx = find_by_name(out, count, ifa->ifa_name);
        if (idx < 0) {
            if (count >= max) continue; /* table full; skip extras */
            idx = count++;
            memset(&out[idx], 0, sizeof(out[idx]));
            strncpy(out[idx].name, ifa->ifa_name, sizeof(out[idx].name) - 1);
            out[idx].up      = (ifa->ifa_flags & IFF_UP)      ? 1 : 0;
            out[idx].running = (ifa->ifa_flags & IFF_RUNNING) ? 1 : 0;
        }

        /* Fold each address into an order-independent hash: hash this address
         * on its own, then XOR it in (XOR is commutative so getifaddrs ordering
         * never produces a false ADDR change). */
        if (ifa->ifa_addr) {
            const unsigned char *sa = (const unsigned char *)ifa->ifa_addr;
            /* sa_family is the first field across platforms we target; hash the
             * family plus a fixed window of the sockaddr payload. */
            uint32_t one = fnv1a(sa, sizeof(struct sockaddr), 2166136261u);
            out[idx].addr_hash ^= one;
        }
    }

    freeifaddrs(ifaddr);
    return count;
}

int ps_iface_diff(const struct ps_iface_snap *prev, int nprev,
                  const struct ps_iface_snap *cur, int ncur,
                  struct ps_iface_change *changes, int max) {
    int n = 0;

    /* Walk cur: ADDED / STATE / ADDR. */
    for (int i = 0; i < ncur && n < max; i++) {
        int p = find_by_name(prev, nprev, cur[i].name);
        if (p < 0) {
            struct ps_iface_change *c = &changes[n++];
            memset(c, 0, sizeof(*c));
            c->kind = PS_IFC_ADDED;
            strncpy(c->name, cur[i].name, sizeof(c->name) - 1);
            c->new_up = cur[i].up; c->new_running = cur[i].running;
            continue;
        }
        if (prev[p].up != cur[i].up || prev[p].running != cur[i].running) {
            struct ps_iface_change *c = &changes[n++];
            memset(c, 0, sizeof(*c));
            c->kind = PS_IFC_STATE;
            strncpy(c->name, cur[i].name, sizeof(c->name) - 1);
            c->old_up = prev[p].up; c->old_running = prev[p].running;
            c->new_up = cur[i].up;  c->new_running = cur[i].running;
            continue;
        }
        if (prev[p].addr_hash != cur[i].addr_hash) {
            struct ps_iface_change *c = &changes[n++];
            memset(c, 0, sizeof(*c));
            c->kind = PS_IFC_ADDR;
            strncpy(c->name, cur[i].name, sizeof(c->name) - 1);
        }
    }

    /* Walk prev: REMOVED. */
    for (int i = 0; i < nprev && n < max; i++) {
        if (find_by_name(cur, ncur, prev[i].name) < 0) {
            struct ps_iface_change *c = &changes[n++];
            memset(c, 0, sizeof(*c));
            c->kind = PS_IFC_REMOVED;
            strncpy(c->name, prev[i].name, sizeof(c->name) - 1);
            c->old_up = prev[i].up; c->old_running = prev[i].running;
        }
    }

    return n;
}
