#include "relay_attest.h"
#include "keystore.h"
#include <openssl/evp.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

static void test_attest_string(void) {
    char s[256];
    int n = ps_relay_attest_string("SIGB64", "edge-07", "2026-05-22T10:00:00Z", s, sizeof s);
    assert(n > 0);
    assert(strcmp(s, "SIGB64|edge-07|2026-05-22T10:00:00Z") == 0);
}

static void test_attest_entry_signs_and_verifies(void) {
    struct ps_keypair kp; assert(ps_keystore_generate(&kp) == 0);
    char entry[1024];
    int n = ps_relay_attest_entry(&kp, "relay-1", "SIGB64", "edge-07", entry, sizeof entry);
    assert(n > 0);
    assert(strstr(entry, "\"relay_agent_id\":\"relay-1\""));
    assert(strstr(entry, "\"received_from\":\"edge-07\""));
    assert(strstr(entry, "\"ts\":\""));
    assert(strstr(entry, "\"sig\":\""));
}

int main(void) { test_attest_string(); test_attest_entry_signs_and_verifies();
    printf("test_relay_attest: OK\n"); return 0; }
