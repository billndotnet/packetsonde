/*
 * test_udp_probe.c — Unit tests for the UDP probe module.
 *
 * Tests payload building and response parsing WITHOUT needing network access.
 * We include the .c file directly with PS_UDP_PROBE_TESTING defined
 * to suppress the module symbol and access static helpers.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/in.h>

/* Suppress the module definition to avoid duplicate symbol errors */
#define PS_UDP_PROBE_TESTING 1

/* Pull in the implementation */
#include "../src/modules/udp_probe.c"

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static int tests_run    = 0;
static int tests_passed = 0;

#define CHECK(cond, msg) do { \
    tests_run++; \
    if (cond) { \
        tests_passed++; \
        printf("  PASS: %s\n", msg); \
    } else { \
        printf("  FAIL: %s  (line %d)\n", msg, __LINE__); \
    } \
} while(0)

/* ------------------------------------------------------------------ */
/* Test 1: DNS query payload                                            */
/* ------------------------------------------------------------------ */

static void test_dns_query_build(void)
{
    printf("test_dns_query_build:\n");

    uint8_t buf[64];
    uint32_t len = build_dns_query(buf, sizeof(buf));

    CHECK(len > 12, "dns_query: length > 12 bytes (header + question)");

    /* Check ID = 0x5053 */
    uint16_t id;
    memcpy(&id, buf, 2);
    id = ntohs(id);
    CHECK(id == 0x5053, "dns_query: ID == 0x5053 ('PS')");

    /* Check QR=0 (query, not response), RD=1 */
    uint8_t flags_hi = buf[2];
    CHECK((flags_hi & 0x80) == 0, "dns_query: QR bit == 0 (query)");
    CHECK((flags_hi & 0x01) == 1, "dns_query: RD bit == 1 (recursion desired)");

    /* QDCOUNT == 1 */
    uint16_t qdcount;
    memcpy(&qdcount, buf + 4, 2);
    qdcount = ntohs(qdcount);
    CHECK(qdcount == 1, "dns_query: QDCOUNT == 1");

    /* Buffer too small returns 0 */
    uint8_t tiny[4];
    uint32_t r = build_dns_query(tiny, sizeof(tiny));
    CHECK(r == 0, "dns_query: returns 0 when buffer too small");
}

/* ------------------------------------------------------------------ */
/* Test 2: SNMP query payload                                           */
/* ------------------------------------------------------------------ */

static void test_snmp_query_build(void)
{
    printf("test_snmp_query_build:\n");

    uint8_t buf[64];
    uint32_t len = build_snmp_query(buf, sizeof(buf));

    CHECK(len > 10, "snmp_query: length > 10 bytes");

    /* Top-level tag must be SEQUENCE (0x30) */
    CHECK(buf[0] == 0x30, "snmp_query: top-level tag is SEQUENCE (0x30)");

    /* Second byte is the length of the SEQUENCE body */
    uint32_t seq_len = (uint32_t)buf[1];
    CHECK((uint32_t)(seq_len + 2) == len,
          "snmp_query: SEQUENCE length + 2 == total packet length");

    /* Version field: INTEGER tag (0x02), length 1, value 1 (SNMPv2c) */
    CHECK(buf[2] == 0x02, "snmp_query: version tag is INTEGER (0x02)");
    CHECK(buf[3] == 0x01, "snmp_query: version length == 1");
    CHECK(buf[4] == 0x01, "snmp_query: version == 1 (SNMPv2c)");

    /* Community OCTET STRING */
    CHECK(buf[5] == 0x04, "snmp_query: community tag is OCTET STRING (0x04)");
    CHECK(buf[6] == 6,    "snmp_query: community length == 6");
    CHECK(memcmp(buf + 7, "public", 6) == 0, "snmp_query: community == 'public'");

    /* GetRequest-PDU tag */
    CHECK(buf[13] == 0xa0, "snmp_query: GetRequest-PDU tag == 0xa0");

    /* Request-ID contains 0x5053 */
    CHECK(buf[15] == 0x02, "snmp_query: request-id tag is INTEGER");
    CHECK(buf[16] == 0x04, "snmp_query: request-id length == 4");
    CHECK(buf[19] == 0x50 && buf[20] == 0x53,
          "snmp_query: request-id low bytes == 0x5053");

    /* Buffer too small returns 0 */
    uint8_t tiny[4];
    uint32_t r = build_snmp_query(tiny, sizeof(tiny));
    CHECK(r == 0, "snmp_query: returns 0 when buffer too small");
}

/* ------------------------------------------------------------------ */
/* Test 3: Generic probe payload                                        */
/* ------------------------------------------------------------------ */

static void test_generic_probe_payload(void)
{
    printf("test_generic_probe_payload:\n");

    CHECK(UDP_PROBE_GENERIC[0] == 0x00, "generic_probe: byte 0 == 0x00");
    CHECK(UDP_PROBE_GENERIC[1] == 0x50, "generic_probe: byte 1 == 0x50 ('P')");
    CHECK(UDP_PROBE_GENERIC[2] == 0x53, "generic_probe: byte 2 == 0x53 ('S')");
    CHECK(UDP_PROBE_GENERIC[3] == 0x00, "generic_probe: byte 3 == 0x00");
}

/* ------------------------------------------------------------------ */
/* Test 4: DNS response banner parsing                                  */
/* ------------------------------------------------------------------ */

static void test_dns_banner_parsing(void)
{
    printf("test_dns_banner_parsing:\n");

    /* Synthetic DNS response: ID=0x5053, QR=1 */
    uint8_t resp[12];
    memset(resp, 0, sizeof(resp));
    resp[0] = 0x50;
    resp[1] = 0x53;
    resp[2] = 0x80;  /* QR=1 */

    const char *banner = parse_dns_banner(resp, sizeof(resp));
    CHECK(strcmp(banner, "DNS responding") == 0,
          "dns_banner: valid response → 'DNS responding'");

    /* Too-short packet: still returns a banner (any response = alive) */
    uint8_t tiny[4] = {0x50, 0x53, 0x80, 0x00};
    banner = parse_dns_banner(tiny, sizeof(tiny));
    CHECK(banner != NULL && banner[0] != '\0',
          "dns_banner: short packet returns non-empty banner");

    /* Response with wrong ID still returns a generic banner */
    uint8_t foreign[12];
    memset(foreign, 0, sizeof(foreign));
    foreign[0] = 0x12;
    foreign[1] = 0x34;
    foreign[2] = 0x80;  /* QR=1 */
    banner = parse_dns_banner(foreign, sizeof(foreign));
    CHECK(banner != NULL, "dns_banner: foreign ID still returns a banner");
}

/* ------------------------------------------------------------------ */
/* Test 5: SNMP response banner parsing                                 */
/* ------------------------------------------------------------------ */

static void test_snmp_banner_parsing(void)
{
    printf("test_snmp_banner_parsing:\n");

    /* Synthetic SNMP GetResponse-PDU */
    uint8_t resp[20];
    memset(resp, 0, sizeof(resp));
    resp[0] = 0x30;   /* SEQUENCE */
    resp[1] = 0x12;   /* length */
    resp[2] = 0x02;   resp[3] = 0x01; resp[4] = 0x01;  /* version */
    resp[5] = 0xa2;   /* GetResponse-PDU tag */

    const char *banner = parse_snmp_banner(resp, sizeof(resp));
    CHECK(strcmp(banner, "SNMP responding") == 0,
          "snmp_banner: GetResponse-PDU → 'SNMP responding'");

    /* Non-SNMP response (wrong outer tag) */
    uint8_t not_snmp[8] = {0xff, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    banner = parse_snmp_banner(not_snmp, sizeof(not_snmp));
    CHECK(strcmp(banner, "UDP port open") == 0,
          "snmp_banner: non-SEQUENCE outer tag → 'UDP port open'");

    /* Short packet */
    uint8_t tiny[4] = {0x30, 0x02, 0x00, 0x00};
    banner = parse_snmp_banner(tiny, sizeof(tiny));
    CHECK(banner != NULL, "snmp_banner: short packet returns non-null banner");
}

/* ------------------------------------------------------------------ */
/* Test 6: Port constants are correct                                   */
/* ------------------------------------------------------------------ */

static void test_port_constants(void)
{
    printf("test_port_constants:\n");

    CHECK(PORT_DNS  == 53,  "PORT_DNS == 53");
    CHECK(PORT_SNMP == 161, "PORT_SNMP == 161");
    CHECK(UDP_PROBE_TIMEOUT_SEC == 3, "UDP_PROBE_TIMEOUT_SEC == 3");
    CHECK(UDP_PROBE_MAX_JOBS == 16,   "UDP_PROBE_MAX_JOBS == 16");
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== test_udp_probe ===\n");

    test_dns_query_build();
    test_snmp_query_build();
    test_generic_probe_payload();
    test_dns_banner_parsing();
    test_snmp_banner_parsing();
    test_port_constants();

    printf("\n%d/%d tests passed.\n", tests_passed, tests_run);

    if (tests_passed != tests_run) {
        printf("SOME TESTS FAILED\n");
        return 1;
    }

    printf("All tests passed.\n");
    return 0;
}
