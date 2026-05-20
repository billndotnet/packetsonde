#include "../traceroute.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_default_opts(void) {
    struct ps_traceroute_opts o = PS_TRACEROUTE_DEFAULTS;
    assert(o.proto == PS_TR_PROTO_UDP);
    assert(o.mode  == PS_TR_MODE_CLASSIC);
    assert(o.max_hops == 30);
    assert(o.timeout_ms == 1000);
    assert(o.dst_port == 33434);
}

static void test_proto_mode_strings(void) {
    assert(strcmp(ps_tr_proto_str(PS_TR_PROTO_UDP),  "udp")  == 0);
    assert(strcmp(ps_tr_proto_str(PS_TR_PROTO_TCP),  "tcp")  == 0);
    assert(strcmp(ps_tr_proto_str(PS_TR_PROTO_ICMP), "icmp") == 0);
    assert(strcmp(ps_tr_mode_str(PS_TR_MODE_CLASSIC), "classic") == 0);
    assert(strcmp(ps_tr_mode_str(PS_TR_MODE_PARIS),   "paris")   == 0);
    assert(strcmp(ps_tr_mode_str(PS_TR_MODE_DUBLIN),  "dublin")  == 0);
}

int main(void) {
    test_default_opts();
    test_proto_mode_strings();
    printf("test_traceroute: OK\n");
    return 0;
}
