/* src/lib/tests/test_registration.c */
#include "registration.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void test_payload(void) {
    uint8_t pub[32]; for (int i=0;i<32;i++) pub[i]=(uint8_t)i;
    struct ps_reg_input in = { "edge-07", pub, "sha256:abc", "host", "direct", "10.0.1.42" };
    char buf[1024];
    int n = ps_reg_build_payload(buf, sizeof buf, &in);
    assert(n > 0);
    assert(strstr(buf, "\"agent_id\":\"edge-07\""));
    assert(strstr(buf, "\"deployment_mode\":\"host\""));
    assert(strstr(buf, "\"provenance\":\"direct\""));
    assert(strstr(buf, "\"ip_address\":\"10.0.1.42\""));
    assert(strstr(buf, "\"pubkey\":\"AAECAwQF"));  /* base64 of 0,1,2,... */
}

static void test_sha256_file(void) {
    char tmp[] = "/tmp/ps_sha_XXXXXX";
    int fd = mkstemp(tmp); assert(fd >= 0);
    assert(write(fd, "abc", 3) == 3); close(fd);
    char hex[65];
    assert(ps_sha256_file(tmp, hex) == 0);
    /* sha256("abc") */
    assert(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
    unlink(tmp);
}

static void test_marker(void) {
    char tmp[] = "/tmp/ps_marker_XXXXXX";
    int fd = mkstemp(tmp); assert(fd >= 0); close(fd); unlink(tmp);  /* want absent */
    char id[128];
    assert(ps_reg_marker_read(tmp, id, sizeof id) != 0);   /* absent */
    assert(ps_reg_marker_write(tmp, "edge-07", "pending") == 0);
    assert(ps_reg_marker_read(tmp, id, sizeof id) == 0 && strcmp(id, "edge-07") == 0);
    unlink(tmp);
}

int main(void) { test_payload(); test_sha256_file(); test_marker();
    printf("test_registration: OK\n"); return 0; }
