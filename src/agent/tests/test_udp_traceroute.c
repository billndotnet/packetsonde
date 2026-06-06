/*
 * test_udp_traceroute.c — Unit tests for the UDP traceroute module.
 *
 * Tests response parsing WITHOUT needing root or network access.
 * We include the .c file directly with PS_UDP_TRACEROUTE_TESTING defined
 * to suppress the module symbol and access static helpers.
 */

#include <assert.h>
#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/in.h>

/* Suppress the module definition to avoid duplicate symbol errors */
#define PS_UDP_TRACEROUTE_TESTING 1

/* Pull in the implementation */
#include "../src/modules/udp_traceroute.c"

/* ------------------------------------------------------------------ */
/* Test framework                                                       */
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
/* Test 1: Parse ICMP Time Exceeded containing embedded UDP            */
/* ------------------------------------------------------------------ */

/*
 * Structure (as delivered by priv worker — full raw IPv4 packet):
 *
 *   [0..19]   Outer IP header (src = router, dst = us)
 *   [20..27]  ICMP Time Exceeded header (type=11, code=0)
 *   [28..47]  Inner IP header (src = us, dst = target, proto = UDP)
 *   [48..55]  Inner UDP header (src_port=0x5053, dst_port=33434+hop)
 */
static void test_parse_time_exceeded_with_udp(void)
{
    printf("test_parse_time_exceeded_with_udp:\n");

    const int    HOP_NUM   = 4;
    const char  *ROUTER_IP = "10.0.0.1";
    const char  *OUR_IP    = "192.168.1.100";
    const char  *TARGET_IP = "8.8.8.8";
    const uint16_t EXPECTED_DST_PORT = (uint16_t)(UDP_TR_BASE_DST_PORT + HOP_NUM);

    uint8_t pkt[56];
    memset(pkt, 0, sizeof(pkt));

    /* ---- Outer IP header ---- */
    pkt[0] = 0x45;          /* version=4, IHL=5 */
    pkt[8] = 64;            /* TTL */
    pkt[9] = IPPROTO_ICMP;

    struct in_addr router_addr, our_addr, target_addr;
    inet_pton(AF_INET, ROUTER_IP, &router_addr);
    inet_pton(AF_INET, OUR_IP,    &our_addr);
    inet_pton(AF_INET, TARGET_IP, &target_addr);
    memcpy(pkt + 12, &router_addr, 4);   /* src = router */
    memcpy(pkt + 16, &our_addr,    4);   /* dst = us */

    /* ---- ICMP Time Exceeded header (bytes 20..27) ---- */
    pkt[20] = ICMP_TYPE_TIME_EXCEEDED;   /* type = 11 */
    pkt[21] = 0;                          /* code = 0 */
    /* checksum and unused left zero for test */

    /* ---- Inner IP header (bytes 28..47) ---- */
    pkt[28] = 0x45;          /* version=4, IHL=5 */
    pkt[37] = IPPROTO_UDP;   /* protocol */
    memcpy(pkt + 40, &our_addr,    4);   /* src = us */
    memcpy(pkt + 44, &target_addr, 4);   /* dst = target */

    /* ---- Inner UDP header (bytes 48..55) ---- */
    uint16_t sp = htons(UDP_TR_SRC_PORT);          /* 0x5053 */
    uint16_t dp = htons(EXPECTED_DST_PORT);        /* 33434 + hop */
    uint16_t ul = htons(12);                       /* 8 hdr + 4 payload */
    memcpy(pkt + 48, &sp, 2);
    memcpy(pkt + 50, &dp, 2);
    memcpy(pkt + 52, &ul, 2);
    /* checksum left zero */

    /* ---- Parse ---- */
    struct udp_parse_result res = parse_udpv4_icmp_response(pkt, sizeof(pkt));

    CHECK(res.valid == 1,
          "parse_time_exceeded_udp: valid == 1");
    CHECK(res.is_time_exceeded == 1,
          "parse_time_exceeded_udp: is_time_exceeded == 1");
    CHECK(res.src_port == UDP_TR_SRC_PORT,
          "parse_time_exceeded_udp: src_port == 0x5053");
    CHECK(res.dst_port == EXPECTED_DST_PORT,
          "parse_time_exceeded_udp: dst_port == 33434 + hop");

    /* Verify hop number extracted from dst_port */
    int extracted_hop = (int)(res.dst_port - UDP_TR_BASE_DST_PORT);
    CHECK(extracted_hop == HOP_NUM,
          "parse_time_exceeded_udp: extracted hop matches expected hop number");

    /* Verify source address is the router */
    CHECK(strcmp(res.src_addr, ROUTER_IP) == 0,
          "parse_time_exceeded_udp: src_addr matches router IP");
}

/* ------------------------------------------------------------------ */
/* Test 2: Parse ICMP Port Unreachable (destination reached)           */
/* ------------------------------------------------------------------ */

/*
 * ICMP Destination Unreachable / Port Unreachable (type=3, code=3) means
 * the destination host received the UDP probe and rejected it — the trace
 * has reached its target.
 *
 * Structure:
 *   [0..19]   Outer IP header (src = target, dst = us)
 *   [20..27]  ICMP Dest Unreachable header (type=3, code=3)
 *   [28..47]  Inner IP header (proto = UDP)
 *   [48..55]  Inner UDP header (src_port=0x5053, dst_port=33434+hop)
 */
static void test_parse_port_unreachable(void)
{
    printf("test_parse_port_unreachable:\n");

    const int    HOP_NUM   = 10;
    const char  *TARGET_IP = "8.8.8.8";
    const char  *OUR_IP    = "192.168.1.100";
    const uint16_t EXPECTED_DST_PORT = (uint16_t)(UDP_TR_BASE_DST_PORT + HOP_NUM);

    uint8_t pkt[56];
    memset(pkt, 0, sizeof(pkt));

    /* ---- Outer IP header ---- */
    pkt[0] = 0x45;
    pkt[8] = 64;
    pkt[9] = IPPROTO_ICMP;

    struct in_addr target_addr, our_addr;
    inet_pton(AF_INET, TARGET_IP, &target_addr);
    inet_pton(AF_INET, OUR_IP,    &our_addr);
    memcpy(pkt + 12, &target_addr, 4);   /* src = target (sending the error) */
    memcpy(pkt + 16, &our_addr,    4);   /* dst = us */

    /* ---- ICMP Dest Unreachable (type=3, code=3 Port Unreachable) ---- */
    pkt[20] = ICMP_TYPE_DEST_UNREACHABLE;   /* type = 3 */
    pkt[21] = ICMP_CODE_PORT_UNREACHABLE;   /* code = 3 */

    /* ---- Inner IP header (bytes 28..47) ---- */
    pkt[28] = 0x45;
    pkt[37] = IPPROTO_UDP;
    memcpy(pkt + 40, &our_addr,    4);
    memcpy(pkt + 44, &target_addr, 4);

    /* ---- Inner UDP header (bytes 48..55) ---- */
    uint16_t sp = htons(UDP_TR_SRC_PORT);
    uint16_t dp = htons(EXPECTED_DST_PORT);
    uint16_t ul = htons(12);
    memcpy(pkt + 48, &sp, 2);
    memcpy(pkt + 50, &dp, 2);
    memcpy(pkt + 52, &ul, 2);

    /* ---- Parse ---- */
    struct udp_parse_result res = parse_udpv4_icmp_response(pkt, sizeof(pkt));

    CHECK(res.valid == 1,
          "parse_port_unreachable: valid == 1");
    CHECK(res.is_time_exceeded == 0,
          "parse_port_unreachable: is_time_exceeded == 0 (destination reached)");
    CHECK(res.src_port == UDP_TR_SRC_PORT,
          "parse_port_unreachable: src_port == 0x5053");
    CHECK(res.dst_port == EXPECTED_DST_PORT,
          "parse_port_unreachable: dst_port == 33434 + hop");

    /* is_time_exceeded == 0 is the signal that destination was reached */
    CHECK(!res.is_time_exceeded,
          "parse_port_unreachable: !is_time_exceeded means dest reached flag should be set");

    /* Verify the responder address is the target */
    CHECK(strcmp(res.src_addr, TARGET_IP) == 0,
          "parse_port_unreachable: src_addr matches target IP");
}

/* ------------------------------------------------------------------ */
/* Test 3: Non-UDP embedded packet is rejected                         */
/* ------------------------------------------------------------------ */

static void test_non_udp_embedded_rejected(void)
{
    printf("test_non_udp_embedded_rejected:\n");

    /* Build a Time Exceeded with inner proto = ICMP (not UDP) */
    uint8_t pkt[56];
    memset(pkt, 0, sizeof(pkt));

    pkt[0] = 0x45;
    pkt[9] = IPPROTO_ICMP;

    pkt[20] = ICMP_TYPE_TIME_EXCEEDED;
    pkt[21] = 0;

    /* Inner IP header — set proto to ICMP (not UDP) */
    pkt[28] = 0x45;
    pkt[37] = IPPROTO_ICMP;  /* <-- ICMP, not UDP */

    struct udp_parse_result res = parse_udpv4_icmp_response(pkt, sizeof(pkt));
    CHECK(res.valid == 0,
          "non_udp_embedded: ICMP-in-ICMP packet rejected (proto not UDP)");
}

/* ------------------------------------------------------------------ */
/* Test 4: Truncated packets are rejected                              */
/* ------------------------------------------------------------------ */

static void test_truncated_packets(void)
{
    printf("test_truncated_packets:\n");

    /* Packet too short for outer IP header */
    uint8_t tiny[10];
    memset(tiny, 0, sizeof(tiny));
    tiny[0] = 0x45;
    struct udp_parse_result res = parse_udpv4_icmp_response(tiny, sizeof(tiny));
    CHECK(res.valid == 0, "truncated: too short for IP header rejected");

    /* Time Exceeded but truncated — no room for inner IP+UDP */
    uint8_t pkt[35];
    memset(pkt, 0, sizeof(pkt));
    pkt[0]  = 0x45;
    pkt[9]  = IPPROTO_ICMP;
    pkt[20] = ICMP_TYPE_TIME_EXCEEDED;
    pkt[21] = 0;
    /* Only 15 bytes of embedded packet — not enough */
    res = parse_udpv4_icmp_response(pkt, sizeof(pkt));
    CHECK(res.valid == 0, "truncated: Time Exceeded with short embedded packet rejected");
}

/* ------------------------------------------------------------------ */
/* Test 5: Wrong ICMP type (e.g. echo reply) is rejected              */
/* ------------------------------------------------------------------ */

static void test_wrong_icmp_type_rejected(void)
{
    printf("test_wrong_icmp_type_rejected:\n");

    uint8_t pkt[56];
    memset(pkt, 0, sizeof(pkt));

    pkt[0] = 0x45;
    pkt[9] = IPPROTO_ICMP;
    pkt[20] = 0;  /* type=0 ICMP Echo Reply — not Time Exceeded or Dest Unreach */
    pkt[21] = 0;

    struct udp_parse_result res = parse_udpv4_icmp_response(pkt, sizeof(pkt));
    CHECK(res.valid == 0,
          "wrong_icmp_type: Echo Reply is not a valid UDP trace response");
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== test_udp_traceroute ===\n");

    test_parse_time_exceeded_with_udp();
    test_parse_port_unreachable();
    test_non_udp_embedded_rejected();
    test_truncated_packets();
    test_wrong_icmp_type_rejected();

    printf("\n%d/%d tests passed.\n", tests_passed, tests_run);

    if (tests_passed != tests_run) {
        printf("SOME TESTS FAILED\n");
        return 1;
    }

    printf("All tests passed.\n");
    return 0;
}
