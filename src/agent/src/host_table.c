#include "host_table.h"
#include "json.h"
#include "log.h"

#include <string.h>
#include <stdio.h>

void ps_host_table_init(struct ps_host_table *ht)
{
    memset(ht, 0, sizeof(*ht));
}

struct ps_host_entry *ps_host_table_find_by_mac(struct ps_host_table *ht,
                                                  const uint8_t *mac)
{
    if (!mac) return NULL;
    for (int i = 0; i < PS_MAX_HOSTS; i++) {
        if (!ht->entries[i].valid) continue;
        if (!ht->entries[i].has_mac) continue;
        if (memcmp(ht->entries[i].mac, mac, 6) == 0)
            return &ht->entries[i];
    }
    return NULL;
}

struct ps_host_entry *ps_host_table_find_by_ip(struct ps_host_table *ht,
                                                 const char *ip)
{
    if (!ip || ip[0] == '\0') return NULL;
    for (int i = 0; i < PS_MAX_HOSTS; i++) {
        if (!ht->entries[i].valid) continue;
        for (int j = 0; j < ht->entries[i].ip_count; j++) {
            if (strcmp(ht->entries[i].ips[j], ip) == 0)
                return &ht->entries[i];
        }
    }
    return NULL;
}

struct ps_host_entry *ps_host_table_update(struct ps_host_table *ht,
    const char *ip, const uint8_t *mac,
    const char *hostname, const char *device_type,
    const char *source, uint64_t now_usec)
{
    struct ps_host_entry *entry = NULL;

    /* Find by MAC first if provided */
    if (mac) {
        entry = ps_host_table_find_by_mac(ht, mac);
    }

    /* Fall back to IP lookup */
    if (!entry && ip && ip[0] != '\0') {
        entry = ps_host_table_find_by_ip(ht, ip);
    }

    /* Allocate a new entry if not found */
    if (!entry) {
        if (ht->count >= PS_MAX_HOSTS) {
            ps_warn("host_table: table full (%d entries), dropping update", PS_MAX_HOSTS);
            return NULL;
        }
        /* Find first invalid slot */
        for (int i = 0; i < PS_MAX_HOSTS; i++) {
            if (!ht->entries[i].valid) {
                entry = &ht->entries[i];
                memset(entry, 0, sizeof(*entry));
                entry->valid = true;
                entry->first_seen_usec = now_usec;
                ht->count++;
                break;
            }
        }
        if (!entry) {
            ps_warn("host_table: no free slot found despite count check");
            return NULL;
        }
    }

    /* Update MAC if provided and entry doesn't have one */
    if (mac && !entry->has_mac) {
        memcpy(entry->mac, mac, 6);
        entry->has_mac = true;
    }

    /* Add IP if provided and not already present */
    if (ip && ip[0] != '\0') {
        int found = 0;
        for (int i = 0; i < entry->ip_count; i++) {
            if (strcmp(entry->ips[i], ip) == 0) {
                found = 1;
                break;
            }
        }
        if (!found && entry->ip_count < PS_MAX_HOST_IPS) {
            strncpy(entry->ips[entry->ip_count], ip, 45);
            entry->ips[entry->ip_count][45] = '\0';
            entry->ip_count++;
        }
    }

    /* Set hostname if provided and entry's is empty */
    if (hostname && hostname[0] != '\0' && entry->hostname[0] == '\0') {
        strncpy(entry->hostname, hostname, sizeof(entry->hostname) - 1);
    }

    /* Set device_type if provided and entry's is empty */
    if (device_type && device_type[0] != '\0' && entry->device_type[0] == '\0') {
        strncpy(entry->device_type, device_type, sizeof(entry->device_type) - 1);
    }

    /* Add source if provided and not already present */
    if (source && source[0] != '\0') {
        int found = 0;
        for (int i = 0; i < entry->source_count; i++) {
            if (strcmp(entry->sources[i], source) == 0) {
                found = 1;
                break;
            }
        }
        if (!found && entry->source_count < PS_MAX_HOST_SRCS) {
            strncpy(entry->sources[entry->source_count], source, 31);
            entry->sources[entry->source_count][31] = '\0';
            entry->source_count++;
        }
    }

    entry->last_seen_usec = now_usec;
    entry->event_count++;

    return entry;
}

int ps_host_entry_to_json(const struct ps_host_entry *entry, char *buf, size_t bufsz)
{
    struct ps_json j;
    ps_json_init(&j, buf, bufsz);
    ps_json_object_begin(&j);

    /* MAC address as hex string */
    if (entry->has_mac) {
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 entry->mac[0], entry->mac[1], entry->mac[2],
                 entry->mac[3], entry->mac[4], entry->mac[5]);
        ps_json_key_string(&j, "mac", mac_str);
    } else {
        ps_json_key_null(&j, "mac");
    }

    /* IPs array */
    ps_json_array_begin(&j, "ips");
    for (int i = 0; i < entry->ip_count; i++) {
        ps_json_array_string(&j, entry->ips[i]);
    }
    ps_json_array_end(&j);

    ps_json_key_string(&j, "hostname",    entry->hostname[0]    ? entry->hostname    : "");
    ps_json_key_string(&j, "device_type", entry->device_type[0] ? entry->device_type : "");

    /* Sources array */
    ps_json_array_begin(&j, "sources");
    for (int i = 0; i < entry->source_count; i++) {
        ps_json_array_string(&j, entry->sources[i]);
    }
    ps_json_array_end(&j);

    ps_json_key_int(&j, "first_seen_usec", (int64_t)entry->first_seen_usec);
    ps_json_key_int(&j, "last_seen_usec",  (int64_t)entry->last_seen_usec);
    ps_json_key_int(&j, "event_count",     entry->event_count);

    ps_json_object_end(&j);
    return ps_json_finish(&j);
}

int ps_host_table_to_json(const struct ps_host_table *ht, char *buf, size_t bufsz)
{
    struct ps_json j;
    ps_json_init(&j, buf, bufsz);
    ps_json_object_begin(&j);
    ps_json_key_int(&j, "host_count", ht->count);

    ps_json_array_begin(&j, "hosts");
    for (int i = 0; i < PS_MAX_HOSTS; i++) {
        if (!ht->entries[i].valid) continue;

        /* Inline the entry object into the array */
        const struct ps_host_entry *e = &ht->entries[i];

        /* We need to nest an object inside the array — use raw approach:
         * open a nested object by emitting the comma + '{' via array_string
         * trick won't work. Use a temp buffer and splice. */
        char tmp[2048];
        int tlen = ps_host_entry_to_json(e, tmp, sizeof(tmp));
        if (tlen <= 0) continue;

        /* Emit array element separator and raw object */
        if (j.needs_comma && j.len < j.cap - 1) {
            j.buf[j.len++] = ',';
        }
        size_t remaining = j.cap - j.len;
        size_t copy = (size_t)tlen < remaining ? (size_t)tlen : remaining - 1;
        if (copy > 0) {
            memcpy(j.buf + j.len, tmp, copy);
            j.len += copy;
            if (j.len < j.cap) j.buf[j.len] = '\0';
        }
        j.needs_comma = 1;
    }
    ps_json_array_end(&j);

    ps_json_object_end(&j);
    return ps_json_finish(&j);
}
