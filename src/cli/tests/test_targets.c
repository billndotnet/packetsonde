#include "../util/targets.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_cidr_24(void) {
    struct ps_cidr c;
    assert(ps_cidr_parse("10.0.0.0/24", &c) == 0);
    assert(c.count == 256);
    char buf[32];
    assert(ps_cidr_addr(&c, 0,   buf, sizeof(buf)) == 0);
    assert(strcmp(buf, "10.0.0.0") == 0);
    assert(ps_cidr_addr(&c, 255, buf, sizeof(buf)) == 0);
    assert(strcmp(buf, "10.0.0.255") == 0);
    assert(ps_cidr_addr(&c, 256, buf, sizeof(buf)) != 0);
}

static void test_single_host(void) {
    struct ps_cidr c;
    assert(ps_cidr_parse("192.168.1.42", &c) == 0);
    assert(c.count == 1);
    char buf[32];
    assert(ps_cidr_addr(&c, 0, buf, sizeof(buf)) == 0);
    assert(strcmp(buf, "192.168.1.42") == 0);
}

static void test_bad_cidr(void) {
    struct ps_cidr c;
    assert(ps_cidr_parse("not-a-cidr",     &c) != 0);
    assert(ps_cidr_parse("10.0.0.0/33",    &c) != 0);
    assert(ps_cidr_parse("999.0.0.0/24",   &c) != 0);
}

static void test_ports_simple(void) {
    struct ps_portset p;
    assert(ps_ports_parse("22,80,443", &p) == 0);
    assert(p.count == 3);
    assert(p.ports[0] == 22);
    assert(p.ports[1] == 80);
    assert(p.ports[2] == 443);
    ps_ports_destroy(&p);
}

static void test_ports_range(void) {
    struct ps_portset p;
    assert(ps_ports_parse("1-3,80", &p) == 0);
    assert(p.count == 4);
    assert(p.ports[0] == 1);
    assert(p.ports[1] == 2);
    assert(p.ports[2] == 3);
    assert(p.ports[3] == 80);
    ps_ports_destroy(&p);
}

static void test_ports_bad(void) {
    struct ps_portset p;
    assert(ps_ports_parse("0-65535", &p) != 0);
    assert(ps_ports_parse("not-a-port", &p) != 0);
    assert(ps_ports_parse("70000", &p) != 0);
}

int main(void) {
    test_cidr_24();
    test_single_host();
    test_bad_cidr();
    test_ports_simple();
    test_ports_range();
    test_ports_bad();
    printf("test_targets: OK\n");
    return 0;
}
