#include "../registry/agents.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *SAMPLE =
    "# packetsonde agents\n"
    "[agents.local]\n"
    "address = \"/tmp/packetsonde-agent.sock\"\n"
    "\n"
    "[agents.trunkbox]\n"
    "address = \"trunkbox.lan:8855\"\n"
    "key_fingerprint = \"SHA256:abc\"\n"
    "tags = \"vlan-trunk\"\n";

static const char *write_tmp(const char *body) {
    static char path[64];
    snprintf(path, sizeof(path), "/tmp/ps_reg_XXXXXX");
    int fd = mkstemp(path);
    assert(fd >= 0);
    ssize_t w = write(fd, body, strlen(body));
    (void)w;
    close(fd);
    return path;
}

static void test_local_only(void) {
    const char *p = write_tmp("[agents.local]\naddress = \"/tmp/x.sock\"\n");
    struct ps_agents A;
    assert(ps_agents_load(&A, p) == 0);
    const struct ps_agent *a = ps_agents_find(&A, "local");
    assert(a);
    assert(strcmp(a->address, "/tmp/x.sock") == 0);
    ps_agents_destroy(&A);
    unlink(p);
}

static void test_two_agents(void) {
    const char *p = write_tmp(SAMPLE);
    struct ps_agents A;
    assert(ps_agents_load(&A, p) == 0);
    assert(A.count == 2);
    const struct ps_agent *t = ps_agents_find(&A, "trunkbox");
    assert(t);
    assert(strcmp(t->address, "trunkbox.lan:8855") == 0);
    assert(strcmp(t->key_fingerprint, "SHA256:abc") == 0);
    assert(strcmp(t->tags, "vlan-trunk") == 0);
    ps_agents_destroy(&A);
    unlink(p);
}

static void test_missing_file_is_empty_not_error(void) {
    struct ps_agents A;
    assert(ps_agents_load(&A, "/nonexistent/path") == 0);
    assert(A.count == 0);
    ps_agents_destroy(&A);
}

int main(void) {
    test_local_only();
    test_two_agents();
    test_missing_file_is_empty_not_error();
    printf("test_agents_registry: OK\n");
    return 0;
}
