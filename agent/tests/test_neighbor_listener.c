/*
 * test_neighbor_listener.c — Unit tests for the neighbor listener module.
 *
 * Tests ARP and NDP parsing WITHOUT needing root, pcap, or network access.
 * We include the .c file directly with PS_NEIGHBOR_LISTENER_TESTING defined
 * to suppress the module symbol and access static helpers.
 *
 * Packet byte arrays are hand-crafted Ethernet frames (DLT_EN10MB) as the
 * real priv worker would deliver them.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/in.h>

/* Suppress the module export symbol */
#define PS_NEIGHBOR_LISTENER_TESTING 1

/* Pull in the implementation */
#include "../src/modules/neighbor_listener.c"

/* ------------------------------------------------------------------ */
/* Minimal publish stub                                                 */
/* ------------------------------------------------------------------ */

/*
 * We intercept publish() calls to capture what the module emits.
 * The test sets g_capture_channel / g_capture_json before calling
 * into the parser, then inspects them afterwards.
 */
static char g_capture_channel[128];
static char g_capture_json[1024];
static int  g_publish_count;

static int stub_publish(ps_module_ctx_t *ctx,
                         const char *channel,
                         const char *json,
                         uint32_t json_len)
{
    (void)ctx;
    (void)json_len;
    strncpy(g_capture_channel, channel, sizeof(g_capture_channel) - 1);
    strncpy(g_capture_json,    json,    sizeof(g_capture_json) - 1);
    g_publish_count++;
    return 0;
}

static void stub_log(ps_module_ctx_t *ctx, int level, const char *fmt, ...)
{
    (void)ctx; (void)level; (void)fmt;
}

static ps_module_ctx_t make_test_ctx(void)
{
    ps_module_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.publish = stub_publish;
    ctx.log     = stub_log;
    return ctx;
}

static struct neighbor_state g_test_state;

static ps_module_ctx_t make_ctx_with_state(void)
{
    ps_module_ctx_t ctx = make_test_ctx();
    memset(&g_test_state, 0, sizeof(g_test_state));
    strncpy(g_test_state.iface, "en0", sizeof(g_test_state.iface) - 1);
    ctx.userdata = &g_test_state;
    return ctx;
}

/* ------------------------------------------------------------------ */
/* Test framework                                                       */
/* ------------------------------------------------------------------ */

static int tests_run    = 0;
static int tests_passed = 0;

#define CHECK(cond, msg) do { \
    tests_run++; \
    if (cond) { \
        tests_passed++; \
        printf("  PASS: %s\n", (msg)); \
    } else { \
        printf("  FAIL: %s  (line %d)\n", (msg), __LINE__); \
    } \
} while(0)

/* ------------------------------------------------------------------ */
/* Packet construction helpers                                          */
/* ------------------------------------------------------------------ */

/*
 * Write a big-endian 16-bit value into a byte buffer.
 */
static void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

/*
 * Write a big-endian 32-bit value into a byte buffer.
 */
static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v & 0xff);
}

/*
 * Build an Ethernet header.
 * dst_mac, src_mac: 6-byte arrays
 * ethertype: e.g. 0x0806 for ARP, 0x86DD for IPv6
 */
static void build_eth_hdr(uint8_t *buf,
                            const uint8_t *dst_mac,
                            const uint8_t *src_mac,
                            uint16_t ethertype)
{
    memcpy(buf,     dst_mac, 6);
    memcpy(buf + 6, src_mac, 6);
    put_be16(buf + 12, ethertype);
}

/*
 * Build an IPv6 header (40 bytes).
 * next_header: 58 for ICMPv6
 * payload_len: length of data after the IPv6 header
 */
static void build_ipv6_hdr(uint8_t *buf,
                             uint8_t next_header,
                             uint16_t payload_len,
                             const struct in6_addr *src,
                             const struct in6_addr *dst)
{
    memset(buf, 0, 40);
    buf[0] = 0x60;  /* version=6, traffic class high nibble=0 */
    put_be16(buf + 4, payload_len);
    buf[6] = next_header;
    buf[7] = 255;   /* hop limit */
    memcpy(buf + 8,  src, 16);
    memcpy(buf + 24, dst, 16);
}

/* ------------------------------------------------------------------ */
/* Test 1: ARP Reply                                                    */
/* ------------------------------------------------------------------ */

/*
 * Standard ARP reply: sender MAC=aa:bb:cc:dd:ee:ff, sender IP=192.168.1.1
 * Expected: publish to discovery.neighbor with proto="arp", correct MAC+IP.
 */
static void test_parse_arp_reply(void)
{
    printf("test_parse_arp_reply:\n");

    /* --- Build Ethernet + ARP frame --- */
    /*
     * Layout:
     *   [0..13]  Ethernet header (14 bytes)
     *   [14..41] ARP payload (28 bytes)
     *   Total: 42 bytes
     */
    uint8_t pkt[42];
    memset(pkt, 0, sizeof(pkt));

    const uint8_t bcast_mac[6]  = {0xff,0xff,0xff,0xff,0xff,0xff};
    const uint8_t sender_mac[6] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const char   *sender_ip_str = "192.168.1.1";

    /* Ethernet */
    build_eth_hdr(pkt, bcast_mac, sender_mac, ETHERTYPE_ARP);

    /* ARP */
    uint8_t *arp = pkt + 14;
    put_be16(arp + 0, ARP_HW_ETHERNET);  /* hw type = 1 */
    put_be16(arp + 2, ARP_PROTO_IPV4);   /* proto = 0x0800 */
    arp[4] = ARP_HLEN_ETH;               /* HLEN = 6 */
    arp[5] = ARP_PLEN_IPV4;              /* PLEN = 4 */
    put_be16(arp + 6, ARP_OP_REPLY);     /* opcode = 2 (reply) */
    memcpy(arp + 8, sender_mac, 6);      /* sender MAC */
    struct in_addr sip;
    inet_pton(AF_INET, sender_ip_str, &sip);
    memcpy(arp + 14, &sip, 4);           /* sender IP */
    memcpy(arp + 18, bcast_mac, 6);      /* target MAC (broadcast/unknown) */
    /* target IP left zero (don't care for learning purposes) */

    /* --- Run parser --- */
    ps_module_ctx_t ctx = make_ctx_with_state();
    g_publish_count = 0;
    memset(g_capture_json, 0, sizeof(g_capture_json));

    neighbor_on_packet(&ctx, pkt, sizeof(pkt), 0, 0);

    /* --- Verify --- */
    CHECK(g_publish_count == 1,
          "arp_reply: exactly one publish call");
    CHECK(strcmp(g_capture_channel, "discovery.neighbor") == 0,
          "arp_reply: channel is discovery.neighbor");
    CHECK(strstr(g_capture_json, "\"ip\":\"192.168.1.1\"") != NULL,
          "arp_reply: IP 192.168.1.1 in JSON");
    CHECK(strstr(g_capture_json, "\"mac\":\"aa:bb:cc:dd:ee:ff\"") != NULL,
          "arp_reply: MAC aa:bb:cc:dd:ee:ff in JSON");
    CHECK(strstr(g_capture_json, "\"proto\":\"arp\"") != NULL,
          "arp_reply: proto=arp in JSON");
    CHECK(strstr(g_capture_json, "\"ndp_type\":null") != NULL,
          "arp_reply: ndp_type=null in JSON");
    CHECK(strstr(g_capture_json, "\"router\":false") != NULL,
          "arp_reply: router=false in JSON");
    CHECK(strstr(g_capture_json, "\"interface\":\"en0\"") != NULL,
          "arp_reply: interface=en0 in JSON");
}

/* ------------------------------------------------------------------ */
/* Test 2: ARP Request                                                  */
/* ------------------------------------------------------------------ */

/*
 * ARP request: sender MAC=11:22:33:44:55:66, sender IP=10.0.0.50
 * We learn from the sender fields even in requests.
 */
static void test_parse_arp_request(void)
{
    printf("test_parse_arp_request:\n");

    uint8_t pkt[42];
    memset(pkt, 0, sizeof(pkt));

    const uint8_t bcast_mac[6]  = {0xff,0xff,0xff,0xff,0xff,0xff};
    const uint8_t sender_mac[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    const char   *sender_ip_str = "10.0.0.50";

    build_eth_hdr(pkt, bcast_mac, sender_mac, ETHERTYPE_ARP);

    uint8_t *arp = pkt + 14;
    put_be16(arp + 0, ARP_HW_ETHERNET);
    put_be16(arp + 2, ARP_PROTO_IPV4);
    arp[4] = ARP_HLEN_ETH;
    arp[5] = ARP_PLEN_IPV4;
    put_be16(arp + 6, ARP_OP_REQUEST);   /* opcode = 1 (request) */
    memcpy(arp + 8, sender_mac, 6);
    struct in_addr sip;
    inet_pton(AF_INET, sender_ip_str, &sip);
    memcpy(arp + 14, &sip, 4);
    /* target MAC = zero (unknown in request), target IP = whatever */

    ps_module_ctx_t ctx = make_ctx_with_state();
    g_publish_count = 0;
    memset(g_capture_json, 0, sizeof(g_capture_json));

    neighbor_on_packet(&ctx, pkt, sizeof(pkt), 0, 0);

    CHECK(g_publish_count == 1,
          "arp_request: exactly one publish call");
    CHECK(strstr(g_capture_json, "\"ip\":\"10.0.0.50\"") != NULL,
          "arp_request: IP 10.0.0.50 in JSON");
    CHECK(strstr(g_capture_json, "\"mac\":\"11:22:33:44:55:66\"") != NULL,
          "arp_request: MAC 11:22:33:44:55:66 in JSON");
    CHECK(strstr(g_capture_json, "\"proto\":\"arp\"") != NULL,
          "arp_request: proto=arp in JSON");
}

/* ------------------------------------------------------------------ */
/* Test 3: NDP Neighbor Advertisement (NA) with TLLA option            */
/* ------------------------------------------------------------------ */

/*
 * Neighbor Advertisement from fe80::1 (router) advertising target fe80::1
 * with Target Link-Layer Address option = de:ad:be:ef:00:01
 * Flags: Router=1, Solicited=1, Override=1 → raw bits 0xE0000000 → flags_byte=0xe0
 */
static void test_parse_ndp_na(void)
{
    printf("test_parse_ndp_na:\n");

    /*
     * Frame layout:
     *   [0..13]  Ethernet header (14)
     *   [14..53] IPv6 header (40)
     *   [54..57] ICMPv6 header: type=136, code=0, cksum=0,0
     *   [58..61] NA flags (big-endian 32-bit)
     *   [62..77] Target address (16 bytes)
     *   [78..85] TLLA option: type=2, length=1(×8=8 bytes), MAC(6), pad
     *   Total: 86 bytes
     */
    uint8_t pkt[86];
    memset(pkt, 0, sizeof(pkt));

    const uint8_t src_mac[6]  = {0xde,0xad,0xbe,0xef,0x00,0x01};
    const uint8_t dst_mac[6]  = {0x33,0x33,0x00,0x00,0x00,0x01};
    const uint8_t tlla_mac[6] = {0xde,0xad,0xbe,0xef,0x00,0x01};

    struct in6_addr src6, dst6, target6;
    inet_pton(AF_INET6, "fe80::1", &src6);
    inet_pton(AF_INET6, "ff02::1", &dst6);
    inet_pton(AF_INET6, "fe80::1", &target6);

    /* Ethernet */
    build_eth_hdr(pkt, dst_mac, src_mac, ETHERTYPE_IPV6);

    /*
     * IPv6: payload = ICMPv6 header (4) + NA flags (4) + target (16) +
     *                 TLLA option (8) = 32 bytes
     */
    build_ipv6_hdr(pkt + 14, 58, 32, &src6, &dst6);

    /* ICMPv6 NA */
    uint8_t *icmp = pkt + 54;
    icmp[0] = ICMPV6_NA;  /* type = 136 */
    icmp[1] = 0;           /* code */
    /* checksum left zero — parser doesn't verify it */

    /* NA flags: Router(bit31) | Solicited(bit30) | Override(bit29) = 0xE0000000 */
    put_be32(icmp + 4, 0xE0000000UL);

    /* Target address */
    memcpy(icmp + 8, &target6, 16);

    /* TLLA option: type=2, length=1 (8 bytes), MAC, 1 byte pad */
    icmp[24] = NDP_OPT_TLLA;  /* type */
    icmp[25] = 1;               /* length in 8-byte units */
    memcpy(icmp + 26, tlla_mac, 6);
    /* byte 32 = pad, already zero */

    /* Run */
    ps_module_ctx_t ctx = make_ctx_with_state();
    g_publish_count = 0;
    memset(g_capture_json, 0, sizeof(g_capture_json));

    neighbor_on_packet(&ctx, pkt, sizeof(pkt), 0, 0);

    CHECK(g_publish_count == 1,
          "ndp_na: exactly one publish call");
    CHECK(strcmp(g_capture_channel, "discovery.neighbor") == 0,
          "ndp_na: channel is discovery.neighbor");
    CHECK(strstr(g_capture_json, "\"proto\":\"ndp\"") != NULL,
          "ndp_na: proto=ndp in JSON");
    CHECK(strstr(g_capture_json, "\"ndp_type\":\"na\"") != NULL,
          "ndp_na: ndp_type=na in JSON");
    CHECK(strstr(g_capture_json, "\"router\":true") != NULL,
          "ndp_na: router=true in JSON");
    /* Target IP should be published (fe80::1) */
    CHECK(strstr(g_capture_json, "fe80::1") != NULL,
          "ndp_na: target IP fe80::1 in JSON");
    /* TLLA MAC should be in JSON */
    CHECK(strstr(g_capture_json, "\"mac\":\"de:ad:be:ef:00:01\"") != NULL,
          "ndp_na: TLLA MAC de:ad:be:ef:00:01 in JSON");
    CHECK(strstr(g_capture_json, "\"interface\":\"en0\"") != NULL,
          "ndp_na: interface=en0 in JSON");
    /* flags_byte = 0xE0 = 224 */
    CHECK(strstr(g_capture_json, "\"flags\":224") != NULL,
          "ndp_na: flags=224 (0xE0) in JSON");
}

/* ------------------------------------------------------------------ */
/* Test 4: NDP Router Advertisement (RA) with Prefix Information option */
/* ------------------------------------------------------------------ */

/*
 * Router Advertisement from fe80::1 with:
 *   - Managed flag set (0x80)
 *   - Source Link-Layer Address option = aa:bb:cc:00:00:01
 *   - Prefix Information option (type=3, 32 bytes) — prefix 2001:db8::/64
 *
 * We verify: proto=ndp, ndp_type=ra, router=true, SLLA MAC extracted,
 * source IP = fe80::1, flags contains M flag.
 */
static void test_parse_ndp_ra(void)
{
    printf("test_parse_ndp_ra:\n");

    /*
     * Frame layout:
     *   [0..13]  Ethernet header (14)
     *   [14..53] IPv6 header (40)
     *   [54..57] ICMPv6 header: type=134, code=0, cksum=0,0
     *   [58]     Cur Hop Limit
     *   [59]     RA flags (M=0x80)
     *   [60..61] Router Lifetime
     *   [62..65] Reachable Time
     *   [66..69] Retrans Timer
     *   [70..77] SLLA option: type=1, len=1, MAC(6)
     *   [78..109] Prefix Info option: type=3, len=4 (32 bytes)
     *   Total: 110 bytes
     */
    uint8_t pkt[110];
    memset(pkt, 0, sizeof(pkt));

    const uint8_t src_mac[6]  = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    const uint8_t dst_mac[6]  = {0x33,0x33,0x00,0x00,0x00,0x01};
    const uint8_t slla_mac[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};

    struct in6_addr src6, dst6;
    inet_pton(AF_INET6, "fe80::1", &src6);
    inet_pton(AF_INET6, "ff02::1", &dst6);

    /* Ethernet */
    build_eth_hdr(pkt, dst_mac, src_mac, ETHERTYPE_IPV6);

    /*
     * IPv6: payload = ICMPv6 header(4) + RA fixed(12) + SLLA(8) + PI(32) = 56
     */
    build_ipv6_hdr(pkt + 14, 58, 56, &src6, &dst6);

    /* ICMPv6 RA */
    uint8_t *icmp = pkt + 54;
    icmp[0] = ICMPV6_RA;   /* type = 134 */
    icmp[1] = 0;            /* code */
    /* checksum left zero */
    icmp[4] = 64;           /* cur hop limit */
    icmp[5] = RA_FLAG_MANAGED;  /* flags: M=1 */
    put_be16(icmp + 6, 1800);   /* router lifetime = 1800s */
    /* reachable time and retrans timer left zero */

    /* SLLA option: type=1, length=1 (8 bytes), MAC(6), 1 byte pad */
    uint8_t *slla = icmp + 16;
    slla[0] = NDP_OPT_SLLA;
    slla[1] = 1;
    memcpy(slla + 2, slla_mac, 6);

    /* Prefix Information option: type=3, length=4 (32 bytes) */
    uint8_t *pi = icmp + 24;
    pi[0] = NDP_OPT_PI;
    pi[1] = 4;   /* 4 × 8 = 32 bytes */
    pi[2] = 64;  /* prefix length = /64 */
    pi[3] = 0xC0; /* flags: L=1, A=1 */
    put_be32(pi + 4,  86400);   /* valid lifetime */
    put_be32(pi + 8,  14400);   /* preferred lifetime */
    /* reserved[4] at pi+12 left zero */
    /* prefix: 2001:db8:: */
    struct in6_addr pfx;
    inet_pton(AF_INET6, "2001:db8::", &pfx);
    memcpy(pi + 16, &pfx, 16);

    /* Run */
    ps_module_ctx_t ctx = make_ctx_with_state();
    g_publish_count = 0;
    memset(g_capture_json, 0, sizeof(g_capture_json));

    neighbor_on_packet(&ctx, pkt, sizeof(pkt), 0, 0);

    CHECK(g_publish_count == 1,
          "ndp_ra: exactly one publish call");
    CHECK(strcmp(g_capture_channel, "discovery.neighbor") == 0,
          "ndp_ra: channel is discovery.neighbor");
    CHECK(strstr(g_capture_json, "\"proto\":\"ndp\"") != NULL,
          "ndp_ra: proto=ndp in JSON");
    CHECK(strstr(g_capture_json, "\"ndp_type\":\"ra\"") != NULL,
          "ndp_ra: ndp_type=ra in JSON");
    CHECK(strstr(g_capture_json, "\"router\":true") != NULL,
          "ndp_ra: router=true in JSON");
    CHECK(strstr(g_capture_json, "fe80::1") != NULL,
          "ndp_ra: source IP fe80::1 in JSON");
    CHECK(strstr(g_capture_json, "\"mac\":\"aa:bb:cc:00:00:01\"") != NULL,
          "ndp_ra: SLLA MAC aa:bb:cc:00:00:01 in JSON");
    /* flags = RA_FLAG_MANAGED = 0x80 = 128 */
    CHECK(strstr(g_capture_json, "\"flags\":128") != NULL,
          "ndp_ra: flags=128 (M flag) in JSON");
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== test_neighbor_listener ===\n");

    test_parse_arp_reply();
    test_parse_arp_request();
    test_parse_ndp_na();
    test_parse_ndp_ra();

    printf("\n%d/%d tests passed.\n", tests_passed, tests_run);

    if (tests_passed != tests_run) {
        printf("SOME TESTS FAILED\n");
        return 1;
    }

    printf("All tests passed.\n");
    return 0;
}
