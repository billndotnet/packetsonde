#ifndef PS_TARGETS_H
#define PS_TARGETS_H

#include <stddef.h>
#include <stdint.h>

#define PS_PORTS_MAX 65535

struct ps_cidr {
    uint32_t base;
    uint32_t count;
    int      prefix;
};

struct ps_portset {
    uint16_t *ports;
    size_t    count;
    size_t    cap;
};

int  ps_cidr_parse(const char *spec, struct ps_cidr *out);
int  ps_cidr_addr (const struct ps_cidr *c, uint32_t idx, char *out, size_t outsz);

int  ps_ports_parse  (const char *spec, struct ps_portset *out);
void ps_ports_destroy(struct ps_portset *p);

#endif
