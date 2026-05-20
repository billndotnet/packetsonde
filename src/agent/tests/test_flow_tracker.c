/*
 * test_flow_tracker.c — Unit tests for flow tracker core
 *
 * Builds synthetic Ethernet frames and feeds them to the flow table.
 * No pcap, no network access needed.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "flow_tracker.h"

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
/* Packet building helpers                                              */
/* ------------------------------------------------------------------ */

/* Build a minimal Ethernet + IPv4 + TCP frame.
 * Returns total frame length, or 0 on error.
 * buf must be at least 54 + payload_len bytes.
 */
static int
build_eth_ipv4_tcp(uint8_t *buf, size_t bufsz,
                    uint32_t src_ip, uint32_t dst_ip,
                    uint16_t src_port, uint16_t dst_port,
                    uint8_t tcp_flags, int payload_len)
{
    /* Ethernet(14) + IPv4(20) + TCP(20) + payload */
    int total = 14 + 20 + 20 + payload_len;
    if ((size_t)total > bufsz) return 0;

    memset(buf, 0, (size_t)total);

    /* Ethernet header */
    /* dst MAC: 00:00:00:00:00:01, src MAC: 00:00:00:00:00:02 */
    buf[5]  = 0x01;
    buf[11] = 0x02;
    buf[12] = 0x08;  /* ethertype = 0x0800 (IPv4) */
    buf[13] = 0x00;

    /* IPv4 header at offset 14 */
    uint8_t *ip = buf + 14;
    ip[0] = 0x45;                       /* version=4, IHL=5 */
    ip[1] = 0x00;                       /* ToS */
    uint16_t ip_len = htons((uint16_t)(20 + 20 + payload_len));
    memcpy(ip + 2, &ip_len, 2);
    ip[8] = 64;                         /* TTL */
    ip[9] = 6;                          /* protocol = TCP */
    uint32_t sip = htonl(src_ip);
    uint32_t dip = htonl(dst_ip);
    memcpy(ip + 12, &sip, 4);
    memcpy(ip + 16, &dip, 4);

    /* TCP header at offset 34 */
    uint8_t *tcp = buf + 34;
    uint16_t sp = htons(src_port);
    uint16_t dp = htons(dst_port);
    memcpy(tcp, &sp, 2);
    memcpy(tcp + 2, &dp, 2);
    tcp[12] = 0x50;                     /* data offset = 5 (20 bytes) */
    tcp[13] = tcp_flags;

    return total;
}

/* Build a minimal Ethernet + IPv4 + UDP frame. */
static int
build_eth_ipv4_udp(uint8_t *buf, size_t bufsz,
                    uint32_t src_ip, uint32_t dst_ip,
                    uint16_t src_port, uint16_t dst_port,
                    int payload_len)
{
    /* Ethernet(14) + IPv4(20) + UDP(8) + payload */
    int total = 14 + 20 + 8 + payload_len;
    if ((size_t)total > bufsz) return 0;

    memset(buf, 0, (size_t)total);

    /* Ethernet header */
    buf[5]  = 0x01;
    buf[11] = 0x02;
    buf[12] = 0x08;
    buf[13] = 0x00;

    /* IPv4 header */
    uint8_t *ip = buf + 14;
    ip[0] = 0x45;
    uint16_t ip_len = htons((uint16_t)(20 + 8 + payload_len));
    memcpy(ip + 2, &ip_len, 2);
    ip[8] = 64;
    ip[9] = 17;  /* UDP */
    uint32_t sip = htonl(src_ip);
    uint32_t dip = htonl(dst_ip);
    memcpy(ip + 12, &sip, 4);
    memcpy(ip + 16, &dip, 4);

    /* UDP header */
    uint8_t *udp = buf + 34;
    uint16_t sp = htons(src_port);
    uint16_t dp = htons(dst_port);
    memcpy(udp, &sp, 2);
    memcpy(udp + 2, &dp, 2);
    uint16_t udp_len = htons((uint16_t)(8 + payload_len));
    memcpy(udp + 4, &udp_len, 2);

    return total;
}

/* Build 802.1Q tagged frame (Ethernet + VLAN tag + IPv4 + TCP) */
static int
build_eth_vlan_ipv4_tcp(uint8_t *buf, size_t bufsz,
                         uint16_t vlan_id,
                         uint32_t src_ip, uint32_t dst_ip,
                         uint16_t src_port, uint16_t dst_port,
                         uint8_t tcp_flags, int payload_len)
{
    /* Ethernet(14) + VLAN(4) + IPv4(20) + TCP(20) + payload */
    int total = 14 + 4 + 20 + 20 + payload_len;
    if ((size_t)total > bufsz) return 0;

    memset(buf, 0, (size_t)total);

    /* Ethernet header with 802.1Q ethertype */
    buf[5]  = 0x01;
    buf[11] = 0x02;
    buf[12] = 0x81;  /* 802.1Q */
    buf[13] = 0x00;

    /* VLAN tag at offset 14 */
    buf[14] = (uint8_t)(vlan_id >> 8);
    buf[15] = (uint8_t)(vlan_id & 0xFF);
    buf[16] = 0x08;  /* inner ethertype = IPv4 */
    buf[17] = 0x00;

    /* IPv4 header at offset 18 */
    uint8_t *ip = buf + 18;
    ip[0] = 0x45;
    uint16_t ip_len = htons((uint16_t)(20 + 20 + payload_len));
    memcpy(ip + 2, &ip_len, 2);
    ip[8] = 64;
    ip[9] = 6;  /* TCP */
    uint32_t sip = htonl(src_ip);
    uint32_t dip = htonl(dst_ip);
    memcpy(ip + 12, &sip, 4);
    memcpy(ip + 16, &dip, 4);

    /* TCP header at offset 38 */
    uint8_t *tcp = buf + 38;
    uint16_t sp = htons(src_port);
    uint16_t dp = htons(dst_port);
    memcpy(tcp, &sp, 2);
    memcpy(tcp + 2, &dp, 2);
    tcp[12] = 0x50;
    tcp[13] = tcp_flags;

    return total;
}

/* ------------------------------------------------------------------ */
/* Test 1: IPv4 TCP flow creation and bidirectional update              */
/* ------------------------------------------------------------------ */

static void test_ipv4_tcp_flow(void)
{
    printf("test_ipv4_tcp_flow:\n");

    struct ps_flow_table *ft = ps_flow_table_create(1024, PS_TRACK_IP_PROTO_PORT);
    CHECK(ft != NULL, "flow table created");

    uint8_t buf[256];
    uint64_t ts = 1000000ULL;  /* 1 second in usec */

    /* SYN packet: 10.0.0.1:12345 -> 10.0.0.2:80 */
    int len = build_eth_ipv4_tcp(buf, sizeof(buf),
                                  0x0A000001, 0x0A000002,
                                  12345, 80, 0x02 /* SYN */, 0);
    CHECK(len > 0, "SYN packet built");

    int rc = ps_flow_table_process_packet(ft, buf, (uint32_t)len, ts);
    CHECK(rc == 0, "SYN packet processed");
    CHECK(ps_flow_table_count(ft) == 1, "flow count = 1 after SYN");

    /* SYN-ACK from server: 10.0.0.2:80 -> 10.0.0.1:12345 */
    ts += 1000;
    len = build_eth_ipv4_tcp(buf, sizeof(buf),
                              0x0A000002, 0x0A000001,
                              80, 12345, 0x12 /* SYN-ACK */, 0);
    CHECK(len > 0, "SYN-ACK packet built");

    rc = ps_flow_table_process_packet(ft, buf, (uint32_t)len, ts);
    CHECK(rc == 0, "SYN-ACK packet processed");
    CHECK(ps_flow_table_count(ft) == 1, "still 1 flow after SYN-ACK (bidirectional)");

    /* Expire to read the flow and verify counters */
    struct ps_flow expired[4];
    /* Advance past TCP short timeout (SYN seen, no established) */
    ts += 3601ULL * 1000000;
    int n = ps_flow_table_expire(ft, ts, expired, 4);
    CHECK(n == 1, "1 flow expired");

    if (n == 1) {
        /* Canonical ordering: 10.0.0.1 < 10.0.0.2, so src=10.0.0.1 */
        CHECK(expired[0].packets[0] == 1, "forward packets = 1 (SYN)");
        CHECK(expired[0].packets[1] == 1, "reverse packets = 1 (SYN-ACK)");
        CHECK(expired[0].key.proto == 6, "proto = TCP");
        CHECK(expired[0].key.src_port == 12345, "src_port = 12345");
        CHECK(expired[0].key.dst_port == 80, "dst_port = 80");
    }

    CHECK(ps_flow_table_count(ft) == 0, "flow count = 0 after expiry");

    ps_flow_table_destroy(ft);
}

/* ------------------------------------------------------------------ */
/* Test 2: IPv4 UDP flow                                                */
/* ------------------------------------------------------------------ */

static void test_ipv4_udp_flow(void)
{
    printf("test_ipv4_udp_flow:\n");

    struct ps_flow_table *ft = ps_flow_table_create(1024, PS_TRACK_IP_PROTO_PORT);
    CHECK(ft != NULL, "flow table created");

    uint8_t buf[256];
    uint64_t ts = 1000000ULL;

    int len = build_eth_ipv4_udp(buf, sizeof(buf),
                                  0xC0A80001, 0x08080808,
                                  54321, 53, 32);
    CHECK(len > 0, "UDP packet built");

    int rc = ps_flow_table_process_packet(ft, buf, (uint32_t)len, ts);
    CHECK(rc == 0, "UDP packet processed");
    CHECK(ps_flow_table_count(ft) == 1, "flow count = 1");

    /* Verify it's a UDP flow by expiring */
    struct ps_flow expired[4];
    ts += 301ULL * 1000000;  /* Past UDP timeout */
    int n = ps_flow_table_expire(ft, ts, expired, 4);
    CHECK(n == 1, "1 UDP flow expired");
    if (n == 1) {
        CHECK(expired[0].key.proto == 17, "proto = UDP");
    }

    ps_flow_table_destroy(ft);
}

/* ------------------------------------------------------------------ */
/* Test 3: Canonical ordering                                           */
/* ------------------------------------------------------------------ */

static void test_canonical_ordering(void)
{
    printf("test_canonical_ordering:\n");

    struct ps_flow_table *ft = ps_flow_table_create(1024, PS_TRACK_IP_PROTO_PORT);
    CHECK(ft != NULL, "flow table created");

    uint8_t buf[256];
    uint64_t ts = 1000000ULL;

    /* Packet A -> B (A=10.0.0.1, B=10.0.0.2) */
    int len = build_eth_ipv4_tcp(buf, sizeof(buf),
                                  0x0A000001, 0x0A000002,
                                  1111, 2222, 0x02, 100);
    int rc = ps_flow_table_process_packet(ft, buf, (uint32_t)len, ts);
    CHECK(rc == 0, "A->B packet processed");
    CHECK(ps_flow_table_count(ft) == 1, "count = 1 after A->B");

    /* Packet B -> A (reverse) */
    ts += 1000;
    len = build_eth_ipv4_tcp(buf, sizeof(buf),
                              0x0A000002, 0x0A000001,
                              2222, 1111, 0x10, 200);
    rc = ps_flow_table_process_packet(ft, buf, (uint32_t)len, ts);
    CHECK(rc == 0, "B->A packet processed");
    CHECK(ps_flow_table_count(ft) == 1, "still count = 1 after B->A (same flow)");

    /* Packet B -> A again with different packet — still same flow */
    ts += 1000;
    len = build_eth_ipv4_tcp(buf, sizeof(buf),
                              0x0A000002, 0x0A000001,
                              2222, 1111, 0x10, 50);
    rc = ps_flow_table_process_packet(ft, buf, (uint32_t)len, ts);
    CHECK(rc == 0, "second B->A packet processed");
    CHECK(ps_flow_table_count(ft) == 1, "still 1 flow");

    ps_flow_table_destroy(ft);
}

/* ------------------------------------------------------------------ */
/* Test 4: Flow expiry by timeout                                       */
/* ------------------------------------------------------------------ */

static void test_flow_expiry(void)
{
    printf("test_flow_expiry:\n");

    struct ps_flow_table *ft = ps_flow_table_create(1024, PS_TRACK_IP_PROTO_PORT);
    CHECK(ft != NULL, "flow table created");

    uint8_t buf[256];
    uint64_t ts = 1000000ULL;

    /* Create a UDP flow */
    int len = build_eth_ipv4_udp(buf, sizeof(buf),
                                  0x0A000001, 0x0A000002,
                                  5000, 5001, 10);
    ps_flow_table_process_packet(ft, buf, (uint32_t)len, ts);
    CHECK(ps_flow_table_count(ft) == 1, "1 flow created");

    /* Try expiry before timeout — should expire 0 */
    struct ps_flow expired[4];
    ts += 200ULL * 1000000;  /* 200s < 300s UDP timeout */
    int n = ps_flow_table_expire(ft, ts, expired, 4);
    CHECK(n == 0, "no flows expired before timeout");
    CHECK(ps_flow_table_count(ft) == 1, "count still 1");

    /* Advance past UDP timeout */
    ts += 101ULL * 1000000;  /* total 301s > 300s */
    n = ps_flow_table_expire(ft, ts, expired, 4);
    CHECK(n == 1, "1 flow expired after timeout");
    CHECK(ps_flow_table_count(ft) == 0, "count = 0 after expiry");

    ps_flow_table_destroy(ft);
}

/* ------------------------------------------------------------------ */
/* Test 5: Max flows limit                                              */
/* ------------------------------------------------------------------ */

static void test_max_flows(void)
{
    printf("test_max_flows:\n");

    int max = 4;
    struct ps_flow_table *ft = ps_flow_table_create(max, PS_TRACK_IP_PROTO_PORT);
    CHECK(ft != NULL, "flow table created with max=4");

    uint8_t buf[256];
    uint64_t ts = 1000000ULL;

    /* Fill table to max */
    for (int i = 0; i < max; i++) {
        int len = build_eth_ipv4_udp(buf, sizeof(buf),
                                      0x0A000001, 0x0A000002 + (uint32_t)i,
                                      5000, (uint16_t)(6000 + i), 10);
        int rc = ps_flow_table_process_packet(ft, buf, (uint32_t)len, ts);
        CHECK(rc == 0, "flow inserted");
    }
    CHECK(ps_flow_table_count(ft) == max, "table is full");

    /* Try to add one more — should fail gracefully */
    int len = build_eth_ipv4_udp(buf, sizeof(buf),
                                  0x0A000001, 0x0A000099,
                                  9999, 9998, 10);
    int rc = ps_flow_table_process_packet(ft, buf, (uint32_t)len, ts);
    CHECK(rc == -1, "overflow packet rejected");
    CHECK(ps_flow_table_count(ft) == max, "count unchanged after overflow");

    ps_flow_table_destroy(ft);
}

/* ------------------------------------------------------------------ */
/* Test 6: 802.1Q VLAN tagged frame                                     */
/* ------------------------------------------------------------------ */

static void test_vlan_tagged(void)
{
    printf("test_vlan_tagged:\n");

    struct ps_flow_table *ft = ps_flow_table_create(1024, PS_TRACK_FULL_VLAN);
    CHECK(ft != NULL, "flow table created (FULL_VLAN)");

    uint8_t buf[256];
    uint64_t ts = 1000000ULL;

    int len = build_eth_vlan_ipv4_tcp(buf, sizeof(buf),
                                       100,  /* VLAN 100 */
                                       0x0A000001, 0x0A000002,
                                       8080, 443, 0x02, 0);
    CHECK(len > 0, "VLAN-tagged packet built");

    int rc = ps_flow_table_process_packet(ft, buf, (uint32_t)len, ts);
    CHECK(rc == 0, "VLAN packet processed");
    CHECK(ps_flow_table_count(ft) == 1, "1 flow created");

    /* Same flow on different VLAN should be a separate flow */
    len = build_eth_vlan_ipv4_tcp(buf, sizeof(buf),
                                   200,  /* VLAN 200 */
                                   0x0A000001, 0x0A000002,
                                   8080, 443, 0x02, 0);
    rc = ps_flow_table_process_packet(ft, buf, (uint32_t)len, ts);
    CHECK(rc == 0, "VLAN 200 packet processed");
    CHECK(ps_flow_table_count(ft) == 2, "2 flows (different VLANs)");

    /* Expire to verify VLAN ID in flow key */
    struct ps_flow expired[4];
    ts += 3601ULL * 1000000;
    int n = ps_flow_table_expire(ft, ts, expired, 4);
    CHECK(n == 2, "2 flows expired");

    /* Verify at least one has VLAN 100 and the other 200 */
    int found_100 = 0, found_200 = 0;
    for (int i = 0; i < n; i++) {
        if (expired[i].key.vlan_id == 100) found_100 = 1;
        if (expired[i].key.vlan_id == 200) found_200 = 1;
    }
    CHECK(found_100, "found flow with VLAN 100");
    CHECK(found_200, "found flow with VLAN 200");

    ps_flow_table_destroy(ft);
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== flow_tracker tests ===\n\n");

    test_ipv4_tcp_flow();
    printf("\n");
    test_ipv4_udp_flow();
    printf("\n");
    test_canonical_ordering();
    printf("\n");
    test_flow_expiry();
    printf("\n");
    test_max_flows();
    printf("\n");
    test_vlan_tagged();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
