/*
 * test_icmp_traceroute.c — Unit tests for the ICMP traceroute module.
 *
 * Tests packet crafting and response parsing WITHOUT needing root or network.
 * We include the .c file directly with PS_ICMP_TRACEROUTE_TESTING defined
 * to suppress the module symbol and access static helpers.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/in.h>

/* Suppress the module definition to avoid duplicate symbol errors */
#define PS_ICMP_TRACEROUTE_TESTING 1

/* Pull in the implementation */
#include "../src/modules/icmp_traceroute.c"

/* ------------------------------------------------------------------ */
/* Helper                                                               */
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
/* Test 1: ICMPv4 checksum validity                                     */
/* ------------------------------------------------------------------ */

/*
 * RFC 792: The checksum is computed over the ICMP header and data.
 * After including the checksum field itself, the one's-complement sum
 * of all 16-bit words must equal 0xFFFF.
 */
static void test_icmpv4_checksum(void)
{
    printf("test_icmpv4_checksum:\n");

    uint8_t icmp[8];
    icmp[0] = ICMP_TYPE_ECHO_REQUEST;  /* type */
    icmp[1] = 0;                        /* code */
    icmp[2] = 0;                        /* checksum placeholder */
    icmp[3] = 0;

    uint16_t id = htons(ICMP_TR_PROBE_ID);
    memcpy(icmp + 4, &id, 2);

    uint16_t seq = htons(1);
    memcpy(icmp + 6, &seq, 2);

    uint16_t cksum = icmp_checksum(icmp, 8);
    memcpy(icmp + 2, &cksum, 2);

    /* Verify: sum of all 16-bit words including checksum should be 0xFFFF */
    uint32_t sum = 0;
    for (int i = 0; i < 8; i += 2) {
        uint16_t w;
        memcpy(&w, icmp + i, 2);
        sum += w;
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    CHECK(sum == 0xffff, "ICMP checksum: one's-complement sum of all words == 0xFFFF");
    CHECK(cksum != 0,    "ICMP checksum: non-zero for non-trivial packet");
}

/* ------------------------------------------------------------------ */
/* Test 2: Parse ICMPv4 Time Exceeded response                         */
/* ------------------------------------------------------------------ */

/*
 * Build a synthetic ICMP Time Exceeded packet and verify that
 * parse_icmpv4_response extracts the correct hop_number and flags.
 *
 * Structure (as delivered by priv worker — full raw IP packet):
 *
 *   [0..19]   Outer IP header (src = router, dst = us)
 *   [20..27]  ICMP Time Exceeded header (type=11, code=0, cksum, unused)
 *   [28..47]  Inner IP header (src = us, dst = target)
 *   [48..55]  Inner ICMP echo request (type=8, id=0x5053, seq=hop_num)
 */
static void test_parse_time_exceeded_v4(void)
{
    printf("test_parse_time_exceeded_v4:\n");

    const int HOP_NUM = 5;
    const char *ROUTER_IP  = "10.0.0.1";
    const char *OUR_IP     = "192.168.1.100";
    const char *TARGET_IP  = "8.8.8.8";

    uint8_t pkt[56];
    memset(pkt, 0, sizeof(pkt));

    /* ---- Outer IP header ---- */
    pkt[0]  = 0x45;          /* version=4, IHL=5 */
    pkt[8]  = 64;            /* TTL */
    pkt[9]  = IPPROTO_ICMP;  /* protocol */
    /* src = router */
    struct in_addr router_addr;
    inet_pton(AF_INET, ROUTER_IP, &router_addr);
    memcpy(pkt + 12, &router_addr, 4);
    /* dst = us */
    struct in_addr our_addr;
    inet_pton(AF_INET, OUR_IP, &our_addr);
    memcpy(pkt + 16, &our_addr, 4);

    /* ---- ICMP Time Exceeded header (bytes 20..27) ---- */
    pkt[20] = ICMP_TYPE_TIME_EXCEEDED;  /* type = 11 */
    pkt[21] = 0;                         /* code = 0 (TTL exceeded in transit) */
    /* checksum and unused left zero for test purposes */

    /* ---- Inner IP header (bytes 28..47) ---- */
    pkt[28] = 0x45;          /* version=4, IHL=5 */
    pkt[37] = IPPROTO_ICMP;  /* protocol */
    /* src = us */
    memcpy(pkt + 40, &our_addr, 4);
    /* dst = target */
    struct in_addr target_addr;
    inet_pton(AF_INET, TARGET_IP, &target_addr);
    memcpy(pkt + 44, &target_addr, 4);

    /* ---- Inner ICMP echo request (bytes 48..55) ---- */
    pkt[48] = ICMP_TYPE_ECHO_REQUEST;  /* type = 8 */
    pkt[49] = 0;                        /* code = 0 */
    uint16_t id  = htons(ICMP_TR_PROBE_ID);
    uint16_t seq = htons((uint16_t)HOP_NUM);
    memcpy(pkt + 52, &id,  2);
    memcpy(pkt + 54, &seq, 2);

    /* ---- Parse ---- */
    struct icmp_parse_result res = parse_icmpv4_response(pkt, sizeof(pkt));

    CHECK(res.valid == 1,             "parse_time_exceeded: valid == 1");
    CHECK(res.is_time_exceeded == 1,  "parse_time_exceeded: is_time_exceeded == 1");
    CHECK(res.id  == ICMP_TR_PROBE_ID, "parse_time_exceeded: id == 0x5053");
    CHECK(res.seq == (uint16_t)HOP_NUM, "parse_time_exceeded: seq == hop_number");

    /* Verify source address is the router */
    CHECK(strcmp(res.src_addr, ROUTER_IP) == 0,
          "parse_time_exceeded: src_addr matches router IP");
}

/* ------------------------------------------------------------------ */
/* Test 3: Parse ICMPv4 Echo Reply (destination reached)               */
/* ------------------------------------------------------------------ */

static void test_parse_echo_reply_v4(void)
{
    printf("test_parse_echo_reply_v4:\n");

    const int HOP_NUM  = 8;
    const char *DST_IP = "8.8.8.8";

    uint8_t pkt[28];
    memset(pkt, 0, sizeof(pkt));

    /* Outer IP header */
    pkt[0] = 0x45;
    pkt[9] = IPPROTO_ICMP;
    struct in_addr dst_addr;
    inet_pton(AF_INET, DST_IP, &dst_addr);
    memcpy(pkt + 12, &dst_addr, 4);  /* src = destination responding */

    /* ICMP Echo Reply */
    pkt[20] = ICMP_TYPE_ECHO_REPLY;
    pkt[21] = 0;
    uint16_t id  = htons(ICMP_TR_PROBE_ID);
    uint16_t seq = htons((uint16_t)HOP_NUM);
    memcpy(pkt + 24, &id,  2);
    memcpy(pkt + 26, &seq, 2);

    struct icmp_parse_result res = parse_icmpv4_response(pkt, sizeof(pkt));

    CHECK(res.valid == 1,              "parse_echo_reply: valid == 1");
    CHECK(res.is_time_exceeded == 0,   "parse_echo_reply: is_time_exceeded == 0");
    CHECK(res.id  == ICMP_TR_PROBE_ID, "parse_echo_reply: id == 0x5053");
    CHECK(res.seq == (uint16_t)HOP_NUM, "parse_echo_reply: seq == hop_number");
    CHECK(strcmp(res.src_addr, DST_IP) == 0, "parse_echo_reply: src_addr matches destination");
}

/* ------------------------------------------------------------------ */
/* Test 4: Foreign ICMP packets are ignored                            */
/* ------------------------------------------------------------------ */

static void test_foreign_icmp_ignored(void)
{
    printf("test_foreign_icmp_ignored:\n");

    /* Echo reply with a different probe ID — should not be valid for us */
    uint8_t pkt[28];
    memset(pkt, 0, sizeof(pkt));

    pkt[0] = 0x45;
    pkt[9] = IPPROTO_ICMP;

    pkt[20] = ICMP_TYPE_ECHO_REPLY;
    uint16_t id  = htons(0x1234);   /* different ID */
    uint16_t seq = htons(3);
    memcpy(pkt + 24, &id,  2);
    memcpy(pkt + 26, &seq, 2);

    struct icmp_parse_result res = parse_icmpv4_response(pkt, sizeof(pkt));

    /* parse_icmpv4_response itself doesn't filter by ID — it returns valid=1.
     * The caller (tr_on_response) checks id == ICMP_TR_PROBE_ID.
     * Test that the ID is correctly extracted so the caller can reject it. */
    CHECK(res.valid == 1,           "foreign_icmp: packet parses OK");
    CHECK(res.id == 0x1234,         "foreign_icmp: foreign ID extracted correctly");
    CHECK(res.id != ICMP_TR_PROBE_ID, "foreign_icmp: ID != PS probe ID (caller rejects)");
}

/* ------------------------------------------------------------------ */
/* Test 5: Truncated packets are rejected                              */
/* ------------------------------------------------------------------ */

static void test_truncated_packets(void)
{
    printf("test_truncated_packets:\n");

    /* Too-short packet */
    uint8_t tiny[10] = {0x45, 0, 0, 0, 0, 0, 0, 64, IPPROTO_ICMP, 0};
    struct icmp_parse_result res = parse_icmpv4_response(tiny, sizeof(tiny));
    CHECK(res.valid == 0, "truncated: packet shorter than ICMP header rejected");

    /* Time Exceeded but truncated inner IP */
    uint8_t pkt[35];
    memset(pkt, 0, sizeof(pkt));
    pkt[0]  = 0x45;
    pkt[9]  = IPPROTO_ICMP;
    pkt[20] = ICMP_TYPE_TIME_EXCEEDED;
    pkt[21] = 0;
    /* Only 15 bytes of embedded packet — not enough for inner IP+ICMP */
    res = parse_icmpv4_response(pkt, sizeof(pkt));
    CHECK(res.valid == 0, "truncated: Time Exceeded with short embedded packet rejected");
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== test_icmp_traceroute ===\n");

    test_icmpv4_checksum();
    test_parse_time_exceeded_v4();
    test_parse_echo_reply_v4();
    test_foreign_icmp_ignored();
    test_truncated_packets();

    printf("\n%d/%d tests passed.\n", tests_passed, tests_run);

    if (tests_passed != tests_run) {
        printf("SOME TESTS FAILED\n");
        return 1;
    }

    printf("All tests passed.\n");
    return 0;
}
