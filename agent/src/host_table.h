#ifndef PS_HOST_TABLE_H
#define PS_HOST_TABLE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define PS_MAX_HOSTS       4096
#define PS_MAX_HOST_IPS    8
#define PS_MAX_HOST_NAMES  4
#define PS_MAX_HOST_SRCS   16

struct ps_host_entry {
    bool     valid;
    uint8_t  mac[6];
    bool     has_mac;
    char     ips[PS_MAX_HOST_IPS][46];
    int      ip_count;
    char     hostname[256];
    char     device_type[32];
    char     sources[PS_MAX_HOST_SRCS][32];
    int      source_count;
    uint64_t first_seen_usec;
    uint64_t last_seen_usec;
    int      event_count;
};

struct ps_host_table {
    struct ps_host_entry entries[PS_MAX_HOSTS];
    int count;  /* number of valid entries */
};

void ps_host_table_init(struct ps_host_table *ht);

struct ps_host_entry *ps_host_table_update(struct ps_host_table *ht,
    const char *ip, const uint8_t *mac,
    const char *hostname, const char *device_type,
    const char *source, uint64_t now_usec);

struct ps_host_entry *ps_host_table_find_by_ip(struct ps_host_table *ht, const char *ip);
struct ps_host_entry *ps_host_table_find_by_mac(struct ps_host_table *ht, const uint8_t *mac);

int ps_host_table_to_json(const struct ps_host_table *ht, char *buf, size_t bufsz);
int ps_host_entry_to_json(const struct ps_host_entry *entry, char *buf, size_t bufsz);

#endif
