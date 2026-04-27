/*
 * test_tcp_probe.c — Unit tests for the TCP probe module.
 *
 * Tests SYN packet building, TCP checksum, and response parsing WITHOUT
 * needing root or a live network. We include the .c file directly with
 * PS_TCP_PROBE_TESTING defined to suppress the module symbol and access
 * static helpers.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/* Suppress the module definition to avoid duplicate symbol errors */
#define PS_TCP_PROBE_TESTING 1

/* Pull in the implementation */
#include "../src/modules/tcp_probe.c"

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
/* Test 1: SYN probe packet building                                   */
/* ------------------------------------------------------------------ */

/*
 * Build a SYN probe packet and verify:
 *  - Total length is 40 bytes (20 IP + 20 TCP)
 *  - IP version/IHL correct
 *  - IP TTL equals TCP_PROBE_TTL
 *  - IP protocol is IPPROTO_TCP
 *  - Destination IP encoded correctly
 *  - TCP src_port and dst_port correct
 *  - TCP sequence number equals TCP_PROBE_MAGIC_SEQ
 *  - TCP flags contain SYN only
 *  - TCP checksum is non-zero
 */
static void test_build_syn_probe(void)
{
    printf("test_build_syn_probe:\n");

    const char *DST_IP   = "93.184.216.34";   /* example.com */
    const uint16_t SRC_PORT = (uint16_t)(TCP_PROBE_BASE_SRC_PORT + 3);
    const uint16_t DST_PORT = 443;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, DST_IP, &dst.sin_addr);

    uint8_t buf[40];
    uint32_t len = build_syn_probe_v4(buf, sizeof(buf), &dst, SRC_PORT, DST_PORT);

    CHECK(len == 40, "build_syn_probe: returns 40");

    /* IP version/IHL */
    CHECK((buf[0] >> 4) == 4,  "build_syn_probe: IPv4 version");
    CHECK((buf[0] & 0x0f) == 5, "build_syn_probe: IHL=5 (20 bytes)");

    /* IP TTL */
    CHECK(buf[8] == TCP_PROBE_TTL, "build_syn_probe: TTL equals TCP_PROBE_TTL");

    /* IP protocol */
    CHECK(buf[9] == IPPROTO_TCP, "build_syn_probe: protocol = TCP");

    /* Destination IP */
    struct in_addr dst_in;
    memcpy(&dst_in, buf + 16, 4);
    char dst_str[64];
    inet_ntop(AF_INET, &dst_in, dst_str, sizeof(dst_str));
    CHECK(strcmp(dst_str, DST_IP) == 0, "build_syn_probe: destination IP encoded correctly");

    /* TCP source port */
    uint16_t sp;
    memcpy(&sp, buf + 20, 2);
    CHECK(ntohs(sp) == SRC_PORT, "build_syn_probe: TCP src_port matches");

    /* TCP destination port */
    uint16_t dp;
    memcpy(&dp, buf + 22, 2);
    CHECK(ntohs(dp) == DST_PORT, "build_syn_probe: TCP dst_port matches");

    /* TCP sequence number */
    uint32_t seq;
    memcpy(&seq, buf + 24, 4);
    CHECK(ntohl(seq) == (uint32_t)TCP_PROBE_MAGIC_SEQ,
          "build_syn_probe: TCP seq equals TCP_PROBE_MAGIC_SEQ");

    /* TCP data offset = 5 */
    CHECK((buf[32] >> 4) == 5, "build_syn_probe: TCP data offset = 5");

    /* TCP flags: SYN only */
    CHECK(buf[33] == TCP_FLAG_SYN, "build_syn_probe: TCP flags = SYN only");

    /* TCP checksum non-zero */
    uint16_t cksum;
    memcpy(&cksum, buf + 36, 2);
    CHECK(cksum != 0, "build_syn_probe: TCP checksum is non-zero");
}

/* ------------------------------------------------------------------ */
/* Test 2: Buffer too small returns 0                                  */
/* ------------------------------------------------------------------ */

static void test_build_syn_probe_short_buf(void)
{
    printf("test_build_syn_probe_short_buf:\n");

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, "1.2.3.4", &dst.sin_addr);

    uint8_t buf[20];   /* too short */
    uint32_t len = build_syn_probe_v4(buf, sizeof(buf), &dst, 0x5070, 80);

    CHECK(len == 0, "build_syn_probe: returns 0 for buffer < 40 bytes");
}

/* ------------------------------------------------------------------ */
/* Test 3: Parse SYN-ACK response (open port)                         */
/* ------------------------------------------------------------------ */

/*
 * Build a synthetic SYN-ACK packet (IP + TCP) and verify that
 * parse_tcp_response_v4() correctly identifies the response src port
 * and returns is_rst=0.
 *
 * Structure (raw IPv4 packet):
 *   [0..19]   IP header (src=target, dst=us, proto=TCP)
 *   [20..39]  TCP header (src_port=443, dst_port=our_src, SYN|ACK)
 */
static void test_parse_synack(void)
{
    printf("test_parse_synack:\n");

    const int      SLOT      = 2;
    const uint16_t OUR_PORT  = (uint16_t)(TCP_PROBE_BASE_SRC_PORT + SLOT);
    const uint16_t THEIR_PORT = 443;
    const char *TARGET_IP    = "93.184.216.34";

    uint8_t pkt[40];
    memset(pkt, 0, sizeof(pkt));

    /* IP header */
    pkt[0] = 0x45;
    pkt[8] = 64;
    pkt[9] = IPPROTO_TCP;
    struct in_addr target_addr;
    inet_pton(AF_INET, TARGET_IP, &target_addr);
    memcpy(pkt + 12, &target_addr, 4);  /* src = target */

    /* TCP header */
    uint16_t sp = htons(THEIR_PORT);  /* src port = target's port */
    uint16_t dp = htons(OUR_PORT);    /* dst port = our probe src */
    memcpy(pkt + 20, &sp, 2);
    memcpy(pkt + 22, &dp, 2);
    pkt[32] = 0x50;                    /* data offset = 5 */
    pkt[33] = TCP_FLAG_SYN | TCP_FLAG_ACK;

    int is_rst = 0;
    char src_addr[64];
    uint16_t matched = parse_tcp_response_v4(pkt, sizeof(pkt), &is_rst,
                                              src_addr, sizeof(src_addr));

    CHECK(matched == OUR_PORT, "parse_synack: matched src port == our probe src port");
    CHECK(is_rst == 0,         "parse_synack: is_rst == 0 for SYN-ACK");
    CHECK(strcmp(src_addr, TARGET_IP) == 0,
          "parse_synack: src_addr extracted correctly");
}

/* ------------------------------------------------------------------ */
/* Test 4: Parse RST response (closed port)                           */
/* ------------------------------------------------------------------ */

static void test_parse_rst(void)
{
    printf("test_parse_rst:\n");

    const int      SLOT     = 0;
    const uint16_t OUR_PORT = (uint16_t)(TCP_PROBE_BASE_SRC_PORT + SLOT);
    const char *TARGET_IP   = "10.0.0.5";

    uint8_t pkt[40];
    memset(pkt, 0, sizeof(pkt));

    pkt[0] = 0x45;
    pkt[9] = IPPROTO_TCP;
    struct in_addr target_addr;
    inet_pton(AF_INET, TARGET_IP, &target_addr);
    memcpy(pkt + 12, &target_addr, 4);

    uint16_t sp = htons(23);         /* target src port */
    uint16_t dp = htons(OUR_PORT);   /* our probe src port */
    memcpy(pkt + 20, &sp, 2);
    memcpy(pkt + 22, &dp, 2);
    pkt[32] = 0x50;
    pkt[33] = TCP_FLAG_RST;          /* RST only */

    int is_rst = 0;
    char src_addr[64];
    uint16_t matched = parse_tcp_response_v4(pkt, sizeof(pkt), &is_rst,
                                              src_addr, sizeof(src_addr));

    CHECK(matched == OUR_PORT, "parse_rst: matched src port");
    CHECK(is_rst == 1,         "parse_rst: is_rst == 1 for RST");
}

/* ------------------------------------------------------------------ */
/* Test 5: Non-TCP packet not matched                                  */
/* ------------------------------------------------------------------ */

static void test_parse_non_tcp_ignored(void)
{
    printf("test_parse_non_tcp_ignored:\n");

    uint8_t pkt[40];
    memset(pkt, 0, sizeof(pkt));

    pkt[0] = 0x45;
    pkt[9] = IPPROTO_UDP;   /* not TCP */
    pkt[33] = TCP_FLAG_SYN | TCP_FLAG_ACK;

    int is_rst = 0;
    char src_addr[64];
    uint16_t matched = parse_tcp_response_v4(pkt, sizeof(pkt), &is_rst,
                                              src_addr, sizeof(src_addr));

    CHECK(matched == 0, "parse_non_tcp: non-TCP packet returns 0");
}

/* ------------------------------------------------------------------ */
/* Test 6: ICMP Destination Unreachable parsing                        */
/* ------------------------------------------------------------------ */

/*
 * Build a synthetic ICMP Destination Unreachable packet with an embedded
 * IP+TCP segment (probe's inner TCP). Verify parse_icmp_unreach_v4
 * extracts our probe source port.
 *
 * Structure:
 *   [0..19]   Outer IP header (src=router, dst=us, proto=ICMP)
 *   [20..27]  ICMP Destination Unreachable header (type=3, code=1)
 *   [28..47]  Inner IP header (proto=TCP)
 *   [48..55]  First 8 bytes of inner TCP (src_port=probe_src, dst_port=target)
 */
static void test_parse_icmp_unreach(void)
{
    printf("test_parse_icmp_unreach:\n");

    const int      SLOT     = 5;
    const uint16_t OUR_PORT = (uint16_t)(TCP_PROBE_BASE_SRC_PORT + SLOT);
    const uint16_t DST_PORT = 80;
    const char *ROUTER_IP   = "10.0.0.1";

    uint8_t pkt[56];
    memset(pkt, 0, sizeof(pkt));

    /* Outer IP header */
    pkt[0] = 0x45;
    pkt[8] = 64;
    pkt[9] = IPPROTO_ICMP;
    struct in_addr router_addr;
    inet_pton(AF_INET, ROUTER_IP, &router_addr);
    memcpy(pkt + 12, &router_addr, 4);

    /* ICMP Destination Unreachable header */
    pkt[20] = ICMP_TYPE_DEST_UNREACH;   /* type = 3 */
    pkt[21] = 1;                          /* code = 1 (host unreach) */

    /* Inner IP header */
    pkt[28] = 0x45;
    pkt[37] = IPPROTO_TCP;

    /* Inner TCP first 8 bytes */
    uint16_t sp = htons(OUR_PORT);  /* our probe src port */
    uint16_t dp = htons(DST_PORT);
    memcpy(pkt + 48, &sp, 2);
    memcpy(pkt + 50, &dp, 2);

    uint16_t probe_src = parse_icmp_unreach_v4(pkt, sizeof(pkt));

    CHECK(probe_src == OUR_PORT,
          "parse_icmp_unreach: extracted probe src port matches");
}

/* ------------------------------------------------------------------ */
/* Test 7: ICMP too short / wrong type rejected                        */
/* ------------------------------------------------------------------ */

static void test_parse_icmp_unreach_rejects(void)
{
    printf("test_parse_icmp_unreach_rejects:\n");

    /* Too short */
    uint8_t tiny[10] = {0};
    tiny[0] = 0x45;
    CHECK(parse_icmp_unreach_v4(tiny, sizeof(tiny)) == 0,
          "parse_icmp_unreach: packet too short returns 0");

    /* Wrong ICMP type (Time Exceeded, not Dest Unreach) */
    uint8_t pkt[56];
    memset(pkt, 0, sizeof(pkt));
    pkt[0]  = 0x45;
    pkt[9]  = IPPROTO_ICMP;
    pkt[20] = ICMP_TYPE_TIME_EXCEEDED;   /* type 11 — not 3 */
    pkt[21] = 0;
    pkt[28] = 0x45;
    pkt[37] = IPPROTO_TCP;
    CHECK(parse_icmp_unreach_v4(pkt, sizeof(pkt)) == 0,
          "parse_icmp_unreach: Time Exceeded (not Dest Unreach) returns 0");
}

/* ------------------------------------------------------------------ */
/* Test 8: Banner port detection                                       */
/* ------------------------------------------------------------------ */

static void test_banner_port_detection(void)
{
    printf("test_banner_port_detection:\n");

    CHECK(is_banner_port(80)   == 1, "is_banner_port: port 80 is banner port");
    CHECK(is_banner_port(443)  == 1, "is_banner_port: port 443 is banner port");
    CHECK(is_banner_port(22)   == 1, "is_banner_port: port 22 is banner port");
    CHECK(is_banner_port(8080) == 1, "is_banner_port: port 8080 is banner port");
    CHECK(is_banner_port(1234) == 0, "is_banner_port: port 1234 is not banner port");
    CHECK(is_banner_port(9999) == 0, "is_banner_port: port 9999 is not banner port");
}

/* ------------------------------------------------------------------ */
/* Test 9: TCP checksum correctness                                    */
/* ------------------------------------------------------------------ */

/*
 * Build a minimal TCP SYN via build_syn_probe_v4 with known src/dst,
 * then manually verify the one's-complement sum of pseudo-header + TCP
 * segment (including checksum) equals 0xFFFF.
 *
 * Note: Since build_syn_probe_v4 uses src_addr=0 (kernel fills it),
 * we verify only that the checksum of (0, dst, tcp) is internally
 * consistent — not against a real-world expected value.
 */
static void test_tcp_checksum_consistency(void)
{
    printf("test_tcp_checksum_consistency:\n");

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, "203.0.113.5", &dst.sin_addr);

    uint8_t buf[40];
    uint32_t len = build_syn_probe_v4(buf, sizeof(buf), &dst,
                                       TCP_PROBE_BASE_SRC_PORT, 443);
    CHECK(len == 40, "checksum_consistency: packet built successfully");

    /* Extract TCP segment (bytes 20..39) and checksum */
    const uint8_t *tcp = buf + 20;
    uint16_t stored_cksum;
    memcpy(&stored_cksum, tcp + 16, 2);
    CHECK(stored_cksum != 0, "checksum_consistency: checksum field is non-zero");

    /*
     * Verify: pseudo-header(src=0, dst=target) + TCP-with-checksum must
     * fold to 0xFFFF.
     */
    uint8_t pseudo[12 + 20];
    memset(pseudo, 0, 12);
    /* src = 0 (bytes 0..3) */
    memcpy(pseudo + 4, &dst.sin_addr.s_addr, 4);
    pseudo[8] = 0;
    pseudo[9] = IPPROTO_TCP;
    uint16_t tlen = htons(20);
    memcpy(pseudo + 10, &tlen, 2);
    memcpy(pseudo + 12, tcp, 20);

    uint32_t sum = 0;
    for (int i = 0; i + 1 < (int)(12 + 20); i += 2) {
        uint16_t w;
        memcpy(&w, pseudo + i, 2);
        sum += w;
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    CHECK(sum == 0xffff,
          "checksum_consistency: one's-complement sum == 0xFFFF");
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== test_tcp_probe ===\n");

    test_build_syn_probe();
    test_build_syn_probe_short_buf();
    test_parse_synack();
    test_parse_rst();
    test_parse_non_tcp_ignored();
    test_parse_icmp_unreach();
    test_parse_icmp_unreach_rejects();
    test_banner_port_detection();
    test_tcp_checksum_consistency();

    printf("\n%d/%d tests passed.\n", tests_passed, tests_run);

    if (tests_passed != tests_run) {
        printf("SOME TESTS FAILED\n");
        return 1;
    }

    printf("All tests passed.\n");
    return 0;
}
