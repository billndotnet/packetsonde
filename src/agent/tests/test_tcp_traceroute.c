/*
 * test_tcp_traceroute.c — Unit tests for the TCP SYN traceroute module.
 *
 * Tests TCP checksum computation and response parsing WITHOUT needing root
 * or a live network. We include the .c file directly with
 * PS_TCP_TRACEROUTE_TESTING defined to suppress the module symbol and
 * access static helpers.
 */

#include <assert.h>
#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/* Suppress the module definition to avoid duplicate symbol errors */
#define PS_TCP_TRACEROUTE_TESTING 1

/* Pull in the implementation */
#include "../src/modules/tcp_traceroute.c"

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
/* Test 1: TCP checksum over pseudo-header                             */
/* ------------------------------------------------------------------ */

/*
 * Construct a TCP SYN header with known fields, compute the checksum via
 * tcp_checksum_v4(), then verify by recomputing manually.
 *
 * The one's-complement sum of the pseudo-header + TCP segment (including
 * the checksum field) must equal 0xFFFF.
 */
static void test_tcp_checksum(void)
{
    printf("test_tcp_checksum:\n");

    const char *SRC_IP = "192.168.1.100";
    const char *DST_IP = "93.184.216.34";  /* example.com */
    const uint16_t SRC_PORT = TCP_TR_BASE_SRC_PORT;
    const uint16_t DST_PORT = 443;
    const uint32_t SEQ_NUM  = 1;

    struct in_addr src, dst;
    inet_pton(AF_INET, SRC_IP, &src);
    inet_pton(AF_INET, DST_IP, &dst);

    /* Build a 20-byte TCP SYN header */
    uint8_t tcp[20];
    memset(tcp, 0, sizeof(tcp));

    uint16_t sp = htons(SRC_PORT);
    uint16_t dp = htons(DST_PORT);
    uint32_t sq = htonl(SEQ_NUM);

    memcpy(tcp + 0, &sp, 2);   /* src port */
    memcpy(tcp + 2, &dp, 2);   /* dst port */
    memcpy(tcp + 4, &sq, 4);   /* seq */
    tcp[12] = 0x50;              /* data offset = 5 */
    tcp[13] = TCP_FLAG_SYN;      /* SYN */
    uint16_t win = htons(1024);
    memcpy(tcp + 14, &win, 2);

    /* Compute checksum */
    uint16_t cksum = tcp_checksum_v4(&src, &dst, tcp, 20);
    memcpy(tcp + 16, &cksum, 2);

    CHECK(cksum != 0, "tcp_checksum: non-zero for non-trivial packet");

    /*
     * Verify: manually compute the one's-complement sum of the pseudo-header
     * + TCP segment (now including the checksum). It must equal 0xFFFF.
     */
    uint8_t pseudo[12 + 20];
    memcpy(pseudo,     &src.s_addr, 4);
    memcpy(pseudo + 4, &dst.s_addr, 4);
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
          "tcp_checksum: one's-complement sum of pseudo-header + TCP == 0xFFFF");
}

/* ------------------------------------------------------------------ */
/* Test 2: Parse ICMP Time Exceeded containing embedded TCP header     */
/* ------------------------------------------------------------------ */

/*
 * Build a synthetic ICMP Time Exceeded packet with an embedded IP+TCP
 * segment. Verify that parse_icmp_time_exceeded_v4 extracts the correct
 * hop number (from TCP seq) and job index (from TCP src_port).
 *
 * Structure (raw IPv4 packet):
 *   [0..19]   Outer IP header (src=router, dst=us)
 *   [20..27]  ICMP Time Exceeded header (type=11, code=0, cksum, unused)
 *   [28..47]  Inner IP header (src=us, dst=target)
 *   [48..55]  Inner TCP header (first 8 bytes: src_port, dst_port, seq[4])
 */
static void test_parse_icmp_time_exceeded_with_tcp(void)
{
    printf("test_parse_icmp_time_exceeded_with_tcp:\n");

    const int     HOP_NUM   = 7;
    const int     JOB_IDX   = 2;
    const uint16_t SRC_PORT = (uint16_t)(TCP_TR_BASE_SRC_PORT + JOB_IDX);
    const uint16_t DST_PORT = 443;
    const char *ROUTER_IP   = "10.0.0.1";
    const char *OUR_IP      = "192.168.1.5";
    const char *TARGET_IP   = "8.8.8.8";

    uint8_t pkt[56];
    memset(pkt, 0, sizeof(pkt));

    /* ---- Outer IP header ---- */
    pkt[0] = 0x45;           /* version=4, IHL=5 */
    pkt[8] = 64;             /* TTL */
    pkt[9] = IPPROTO_ICMP;
    struct in_addr router_addr, our_addr, target_addr;
    inet_pton(AF_INET, ROUTER_IP, &router_addr);
    inet_pton(AF_INET, OUR_IP,    &our_addr);
    inet_pton(AF_INET, TARGET_IP, &target_addr);
    memcpy(pkt + 12, &router_addr, 4);  /* src = router */
    memcpy(pkt + 16, &our_addr,    4);  /* dst = us */

    /* ---- ICMP Time Exceeded header (bytes 20..27) ---- */
    pkt[20] = ICMP_TYPE_TIME_EXCEEDED;  /* type = 11 */
    pkt[21] = 0;                         /* code = 0 */

    /* ---- Inner IP header (bytes 28..47) ---- */
    pkt[28] = 0x45;
    pkt[37] = IPPROTO_TCP;
    memcpy(pkt + 40, &our_addr,    4);  /* src = us */
    memcpy(pkt + 44, &target_addr, 4);  /* dst = target */

    /* ---- Inner TCP header (first 8 bytes, bytes 48..55) ---- */
    uint16_t sp = htons(SRC_PORT);
    uint16_t dp = htons(DST_PORT);
    uint32_t sq = htonl((uint32_t)HOP_NUM);
    memcpy(pkt + 48, &sp, 2);   /* src_port */
    memcpy(pkt + 50, &dp, 2);   /* dst_port */
    memcpy(pkt + 52, &sq, 4);   /* seq = hop number */

    /* ---- Parse ---- */
    struct tcp_parse_result res = parse_icmp_time_exceeded_v4(pkt, sizeof(pkt));

    CHECK(res.valid == 1,
          "parse_icmp_time_exceeded: valid == 1");
    CHECK(res.is_time_exceeded == 1,
          "parse_icmp_time_exceeded: is_time_exceeded == 1");
    CHECK(res.job_src_port == SRC_PORT,
          "parse_icmp_time_exceeded: job_src_port matches expected (job index encoded)");
    CHECK(res.hop_seq == (uint32_t)HOP_NUM,
          "parse_icmp_time_exceeded: hop_seq matches hop number");
    CHECK(strcmp(res.src_addr, ROUTER_IP) == 0,
          "parse_icmp_time_exceeded: src_addr matches router IP");
}

/* ------------------------------------------------------------------ */
/* Test 3: Parse TCP SYN-ACK response (destination reached)           */
/* ------------------------------------------------------------------ */

/*
 * Build a synthetic TCP SYN-ACK packet (with IP header) as would be
 * received on the raw TCP socket when the destination responds.
 * Verify destination-reached detection and port matching.
 *
 * Structure:
 *   [0..19]   IP header (src=target, dst=us)
 *   [20..39]  TCP header (src_port=443, dst_port=0x5053+idx, flags=SYN|ACK)
 */
static void test_parse_synack_response(void)
{
    printf("test_parse_synack_response:\n");

    const int     JOB_IDX   = 1;
    const uint16_t OUR_PORT = (uint16_t)(TCP_TR_BASE_SRC_PORT + JOB_IDX);
    const uint16_t DST_PORT = 443;
    const char *TARGET_IP   = "93.184.216.34";

    uint8_t pkt[40];
    memset(pkt, 0, sizeof(pkt));

    /* ---- IP header ---- */
    pkt[0] = 0x45;
    pkt[8] = 64;
    pkt[9] = IPPROTO_TCP;
    struct in_addr target_addr;
    inet_pton(AF_INET, TARGET_IP, &target_addr);
    memcpy(pkt + 12, &target_addr, 4);  /* src = target */
    /* dst (us) left as 0 — not checked */

    /* ---- TCP header ---- */
    uint16_t sp = htons(DST_PORT);  /* target's src port = 443 */
    uint16_t dp = htons(OUR_PORT);  /* our src port that we sent */
    uint32_t sq = htonl(0);         /* target's seq */
    uint32_t ak = htonl(2);         /* ack = our_seq + 1 */
    memcpy(pkt + 20, &sp, 2);       /* src_port */
    memcpy(pkt + 22, &dp, 2);       /* dst_port */
    memcpy(pkt + 24, &sq, 4);       /* seq */
    memcpy(pkt + 28, &ak, 4);       /* ack */
    pkt[32] = 0x50;                  /* data offset = 5 */
    pkt[33] = TCP_FLAG_SYN | TCP_FLAG_ACK;  /* SYN|ACK */

    /* ---- Parse ---- */
    struct tcp_parse_result res = parse_tcp_reply_v4(pkt, sizeof(pkt));

    CHECK(res.valid == 1,
          "parse_synack: valid == 1");
    CHECK(res.is_time_exceeded == 0,
          "parse_synack: is_time_exceeded == 0 (direct TCP reply)");
    CHECK(res.is_rst == 0,
          "parse_synack: is_rst == 0 (SYN-ACK, not RST)");
    CHECK(res.job_src_port == OUR_PORT,
          "parse_synack: job_src_port matches our source port");
    CHECK(strcmp(res.src_addr, TARGET_IP) == 0,
          "parse_synack: src_addr matches target IP");
}

/* ------------------------------------------------------------------ */
/* Test 4: Parse TCP RST response                                      */
/* ------------------------------------------------------------------ */

static void test_parse_rst_response(void)
{
    printf("test_parse_rst_response:\n");

    const int     JOB_IDX   = 0;
    const uint16_t OUR_PORT = (uint16_t)(TCP_TR_BASE_SRC_PORT + JOB_IDX);
    const uint16_t DST_PORT = 80;
    const char *TARGET_IP   = "192.0.2.1";

    uint8_t pkt[40];
    memset(pkt, 0, sizeof(pkt));

    pkt[0] = 0x45;
    pkt[9] = IPPROTO_TCP;
    struct in_addr target_addr;
    inet_pton(AF_INET, TARGET_IP, &target_addr);
    memcpy(pkt + 12, &target_addr, 4);

    uint16_t sp = htons(DST_PORT);
    uint16_t dp = htons(OUR_PORT);
    memcpy(pkt + 20, &sp, 2);
    memcpy(pkt + 22, &dp, 2);
    pkt[32] = 0x50;
    pkt[33] = TCP_FLAG_RST;  /* RST only */

    struct tcp_parse_result res = parse_tcp_reply_v4(pkt, sizeof(pkt));

    CHECK(res.valid == 1,
          "parse_rst: valid == 1");
    CHECK(res.is_rst == 1,
          "parse_rst: is_rst == 1");
    CHECK(res.job_src_port == OUR_PORT,
          "parse_rst: job_src_port matches our source port");
}

/* ------------------------------------------------------------------ */
/* Test 5: Truncated ICMP packet rejected                             */
/* ------------------------------------------------------------------ */

static void test_truncated_icmp_rejected(void)
{
    printf("test_truncated_icmp_rejected:\n");

    /* Too short to hold outer IP header */
    uint8_t tiny[10];
    memset(tiny, 0, sizeof(tiny));
    tiny[0] = 0x45;
    struct tcp_parse_result res = parse_icmp_time_exceeded_v4(tiny, sizeof(tiny));
    CHECK(res.valid == 0,
          "truncated_icmp: packet shorter than ICMP body rejected");

    /*
     * Has ICMP TE type but inner data truncated to 10 bytes — not enough
     * for a full inner IP header (20 bytes) + 8 bytes TCP.
     * Buffer is 38 bytes: outer IP(20) + ICMP TE header(8) + inner IP stub(10).
     * pkt[37] = inner_ip[9] = protocol field (offset 28+9=37, which is in range).
     */
    uint8_t pkt[38];
    memset(pkt, 0, sizeof(pkt));
    pkt[0]  = 0x45;
    pkt[9]  = IPPROTO_ICMP;
    pkt[20] = ICMP_TYPE_TIME_EXCEEDED;
    pkt[21] = 0;
    /* inner IP starts at offset 28; proto at offset 28+9=37 */
    pkt[28] = 0x45;  /* inner IP version+IHL */
    pkt[37] = IPPROTO_TCP;
    res = parse_icmp_time_exceeded_v4(pkt, sizeof(pkt));
    CHECK(res.valid == 0,
          "truncated_icmp: Time Exceeded with truncated inner TCP rejected");
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== test_tcp_traceroute ===\n");

    test_tcp_checksum();
    test_parse_icmp_time_exceeded_with_tcp();
    test_parse_synack_response();
    test_parse_rst_response();
    test_truncated_icmp_rejected();

    printf("\n%d/%d tests passed.\n", tests_passed, tests_run);

    if (tests_passed != tests_run) {
        printf("SOME TESTS FAILED\n");
        return 1;
    }

    printf("All tests passed.\n");
    return 0;
}
