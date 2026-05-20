#ifndef PS_TRACEROUTE_H
#define PS_TRACEROUTE_H

#include <stddef.h>
#include <stdint.h>

enum ps_tr_proto { PS_TR_PROTO_UDP = 0, PS_TR_PROTO_TCP, PS_TR_PROTO_ICMP };
enum ps_tr_mode  { PS_TR_MODE_CLASSIC = 0, PS_TR_MODE_PARIS, PS_TR_MODE_DUBLIN };

struct ps_traceroute_opts {
    enum ps_tr_proto proto;
    enum ps_tr_mode  mode;
    int              max_hops;
    int              timeout_ms;
    uint16_t         dst_port;
    int              flow_count;
};

#define PS_TRACEROUTE_DEFAULTS  \
    { PS_TR_PROTO_UDP, PS_TR_MODE_CLASSIC, 30, 1000, 33434, 8 }

struct ps_tr_hop {
    int      ttl;
    char     addr[64];
    long     rtt_us;
    int      reached_dst;
};

#define PS_TRACEROUTE_MAX_HOPS 64

struct ps_traceroute_result {
    struct ps_tr_hop hops[PS_TRACEROUTE_MAX_HOPS];
    int              hop_count;
    int              reached;
};

const char *ps_tr_proto_str(enum ps_tr_proto p);
const char *ps_tr_mode_str (enum ps_tr_mode  m);

int ps_traceroute_run(const char *target,
                      const struct ps_traceroute_opts *opts,
                      struct ps_traceroute_result *out);

#endif
