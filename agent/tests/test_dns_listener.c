/*
 * test_dns_listener.c — Unit tests for the DNS listener module.
 *
 * Builds synthetic Ethernet+IP+UDP+DNS frames as byte arrays and verifies
 * that the parser produces the expected output.
 *
 * No pcap, network, or root access needed. We include the .c file directly
 * with PS_DNS_LISTENER_TESTING defined to suppress the module symbol and
 * access static helpers.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#define PS_DNS_LISTENER_TESTING 1

/* Pull in the implementation */
#include "../src/modules/dns_listener.c"

/* ------------------------------------------------------------------ */
/* Test harness                                                         */
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
/* Mock publish context                                                 */
/* ------------------------------------------------------------------ */

#define MAX_PUBLISHED 8

struct mock_ctx {
    int         count;
    char        channel[MAX_PUBLISHED][64];
    char        json[MAX_PUBLISHED][4096];
    uint32_t    json_len[MAX_PUBLISHED];
};

static int mock_publish(ps_module_ctx_t *ctx,
                         const char *channel,
                         const char *json, uint32_t json_len)
{
    struct mock_ctx *m = (struct mock_ctx *)ctx->userdata;
    if (m->count >= MAX_PUBLISHED) return -1;
    int i = m->count++;
    strncpy(m->channel[i], channel, sizeof(m->channel[i]) - 1);
    if (json_len >= sizeof(m->json[i])) json_len = sizeof(m->json[i]) - 1;
    memcpy(m->json[i], json, json_len);
    m->json[i][json_len] = '\0';
    m->json_len[i] = json_len;
    return 0;
}

static void mock_log(ps_module_ctx_t *ctx, int level, const char *fmt, ...)
{
    (void)ctx; (void)level; (void)fmt;
}

static ps_module_ctx_t make_ctx(struct mock_ctx *m)
{
    ps_module_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.userdata = m;
    ctx.publish  = mock_publish;
    ctx.log      = mock_log;
    return ctx;
}

/* ------------------------------------------------------------------ */
/* Frame builder helpers                                                */
/* ------------------------------------------------------------------ */

/*
 * Write a 14-byte Ethernet header (dst, src, ethertype=0x0800 IPv4)
 * followed by a 20-byte IPv4 header (proto=UDP) into buf.
 * Returns offset to UDP payload area.
 */
static int write_eth_ipv4_udp(uint8_t *buf, size_t bufsz,
                               uint32_t src_ip, uint32_t dst_ip,
                               uint16_t src_port, uint16_t dst_port,
                               uint16_t udp_payload_len)
{
    if (bufsz < 14 + 20 + 8) return -1;

    /* Ethernet */
    memset(buf, 0xAA, 6);           /* dst MAC */
    memset(buf + 6, 0xBB, 6);       /* src MAC */
    buf[12] = 0x08; buf[13] = 0x00; /* ethertype IPv4 */

    /* IPv4 */
    uint8_t *ip = buf + 14;
    ip[0] = 0x45;                   /* version=4, IHL=5 */
    ip[1] = 0;                      /* DSCP/ECN */
    uint16_t ip_total = htons(20 + 8 + udp_payload_len);
    memcpy(ip + 2, &ip_total, 2);
    ip[8] = 64;                     /* TTL */
    ip[9] = 17;                     /* UDP */
    uint32_t sip = htonl(src_ip);
    uint32_t dip = htonl(dst_ip);
    memcpy(ip + 12, &sip, 4);
    memcpy(ip + 16, &dip, 4);

    /* UDP */
    uint8_t *udp = ip + 20;
    uint16_t sp = htons(src_port);
    uint16_t dp = htons(dst_port);
    memcpy(udp + 0, &sp, 2);
    memcpy(udp + 2, &dp, 2);
    uint16_t udp_len = htons(8 + udp_payload_len);
    memcpy(udp + 4, &udp_len, 2);
    /* checksum left zero — not validated by parser */

    return 14 + 20 + 8;  /* offset to DNS payload */
}

/*
 * Write a DNS name in wire format (length-prefixed labels + NUL) into buf.
 * Returns bytes written.
 */
static int write_dns_name(uint8_t *buf, const char *name)
{
    int out = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int label_len = dot ? (int)(dot - p) : (int)strlen(p);
        buf[out++] = (uint8_t)label_len;
        memcpy(buf + out, p, (size_t)label_len);
        out += label_len;
        if (!dot) break;
        p = dot + 1;
    }
    buf[out++] = 0;  /* root label */
    return out;
}

/* Write a DNS header (12 bytes) */
static void write_dns_hdr(uint8_t *buf,
                           uint16_t id, uint16_t flags,
                           uint16_t qdcount, uint16_t ancount,
                           uint16_t nscount, uint16_t arcount)
{
    uint16_t f;
    f = htons(id);       memcpy(buf + 0,  &f, 2);
    f = htons(flags);    memcpy(buf + 2,  &f, 2);
    f = htons(qdcount);  memcpy(buf + 4,  &f, 2);
    f = htons(ancount);  memcpy(buf + 6,  &f, 2);
    f = htons(nscount);  memcpy(buf + 8,  &f, 2);
    f = htons(arcount);  memcpy(buf + 10, &f, 2);
}

/* ------------------------------------------------------------------ */
/* Test 1: A record for "example.com" → 93.184.216.34                  */
/* ------------------------------------------------------------------ */

static void test_parse_a_record(void)
{
    printf("test_parse_a_record:\n");

    struct mock_ctx m;
    memset(&m, 0, sizeof(m));
    ps_module_ctx_t ctx = make_ctx(&m);

    uint8_t pkt[512];
    memset(pkt, 0, sizeof(pkt));

    /* Ethernet + IPv4 + UDP headers */
    /* We'll fill in DNS payload, then compute udp_payload_len */
    uint8_t dns[256];
    int dns_pos = 0;

    /* DNS header: response, 1 question, 1 answer */
    write_dns_hdr(dns, 0x1234, 0x8180, 1, 1, 0, 0);
    dns_pos = 12;

    /* Question: example.com A IN */
    dns_pos += write_dns_name(dns + dns_pos, "example.com");
    uint16_t qtype = htons(1);   /* A */
    uint16_t qclass = htons(1);  /* IN */
    memcpy(dns + dns_pos, &qtype,  2); dns_pos += 2;
    memcpy(dns + dns_pos, &qclass, 2); dns_pos += 2;

    /* Answer: example.com A 300 93.184.216.34 */
    dns_pos += write_dns_name(dns + dns_pos, "example.com");
    uint16_t rtype  = htons(1);    /* A */
    uint16_t rclass = htons(1);    /* IN */
    uint32_t rttl   = htonl(300);
    uint16_t rdlen  = htons(4);
    uint8_t  rdata[4] = {93, 184, 216, 34};
    memcpy(dns + dns_pos, &rtype,  2); dns_pos += 2;
    memcpy(dns + dns_pos, &rclass, 2); dns_pos += 2;
    memcpy(dns + dns_pos, &rttl,   4); dns_pos += 4;
    memcpy(dns + dns_pos, &rdlen,  2); dns_pos += 2;
    memcpy(dns + dns_pos, rdata,   4); dns_pos += 4;

    /* Build full packet */
    int dns_off = write_eth_ipv4_udp(pkt, sizeof(pkt),
                                      0xC0A80101, 0xC0A80102,
                                      12345, 53,
                                      (uint16_t)dns_pos);
    memcpy(pkt + dns_off, dns, (size_t)dns_pos);
    int total = dns_off + dns_pos;

    /* Parse */
    dns_parse_and_publish(&ctx, pkt, total, dns_off);

    CHECK(m.count == 1, "a_record: one event published");
    if (m.count > 0) {
        CHECK(strcmp(m.channel[0], "discovery.dns") == 0,
              "a_record: channel == discovery.dns");
        CHECK(strstr(m.json[0], "\"query\":\"example.com\"") != NULL,
              "a_record: query == example.com");
        CHECK(strstr(m.json[0], "\"type\":\"A\"") != NULL,
              "a_record: top-level type == A");
        CHECK(strstr(m.json[0], "\"data\":\"93.184.216.34\"") != NULL,
              "a_record: data == 93.184.216.34");
        CHECK(strstr(m.json[0], "\"ttl\":300") != NULL,
              "a_record: ttl == 300");
    }
}

/* ------------------------------------------------------------------ */
/* Test 2: AAAA record                                                  */
/* ------------------------------------------------------------------ */

static void test_parse_aaaa_record(void)
{
    printf("test_parse_aaaa_record:\n");

    struct mock_ctx m;
    memset(&m, 0, sizeof(m));
    ps_module_ctx_t ctx = make_ctx(&m);

    uint8_t pkt[512];
    memset(pkt, 0, sizeof(pkt));

    uint8_t dns[256];
    int dns_pos = 0;

    /* DNS header: response, 1 question, 1 answer */
    write_dns_hdr(dns, 0xABCD, 0x8180, 1, 1, 0, 0);
    dns_pos = 12;

    /* Question: ipv6test.example AAAA IN */
    dns_pos += write_dns_name(dns + dns_pos, "ipv6test.example");
    uint16_t qtype = htons(28);  /* AAAA */
    uint16_t qclass = htons(1);
    memcpy(dns + dns_pos, &qtype,  2); dns_pos += 2;
    memcpy(dns + dns_pos, &qclass, 2); dns_pos += 2;

    /* Answer: AAAA 60 2606:2800:220:1:248:1893:25c8:1946 */
    dns_pos += write_dns_name(dns + dns_pos, "ipv6test.example");
    uint16_t rtype  = htons(28); /* AAAA */
    uint16_t rclass = htons(1);
    uint32_t rttl   = htonl(60);
    uint16_t rdlen  = htons(16);
    /* 2606:2800:0220:0001:0248:1893:25c8:1946 */
    uint8_t rdata[16] = {
        0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
        0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46
    };
    memcpy(dns + dns_pos, &rtype,  2); dns_pos += 2;
    memcpy(dns + dns_pos, &rclass, 2); dns_pos += 2;
    memcpy(dns + dns_pos, &rttl,   4); dns_pos += 4;
    memcpy(dns + dns_pos, &rdlen,  2); dns_pos += 2;
    memcpy(dns + dns_pos, rdata,  16); dns_pos += 16;

    int dns_off = write_eth_ipv4_udp(pkt, sizeof(pkt),
                                      0xC0A80101, 0xC0A80102,
                                      54321, 53,
                                      (uint16_t)dns_pos);
    memcpy(pkt + dns_off, dns, (size_t)dns_pos);
    int total = dns_off + dns_pos;

    dns_parse_and_publish(&ctx, pkt, total, dns_off);

    CHECK(m.count == 1, "aaaa_record: one event published");
    if (m.count > 0) {
        CHECK(strcmp(m.channel[0], "discovery.dns") == 0,
              "aaaa_record: channel == discovery.dns");
        CHECK(strstr(m.json[0], "\"type\":\"AAAA\"") != NULL,
              "aaaa_record: type == AAAA");
        /* 2606:2800:220:1:248:1893:25c8:1946 */
        CHECK(strstr(m.json[0], "2606:2800") != NULL,
              "aaaa_record: IPv6 address present in data");
    }
}

/* ------------------------------------------------------------------ */
/* Test 3: DNS name pointer (compression)                               */
/* ------------------------------------------------------------------ */

static void test_name_decompression(void)
{
    printf("test_name_decompression:\n");

    /*
     * Build a minimal DNS packet where the answer name is a pointer back
     * to the question name. This is the most common form of DNS compression.
     *
     * Layout:
     *   [0..11]  DNS header (1 question, 1 answer)
     *   [12..]   Question name "ptr.example.com" + QTYPE + QCLASS
     *   [...]    Answer name = pointer to offset 12 (0xC0 0x0C)
     *            + TYPE A + CLASS IN + TTL + RDLEN + RDATA
     */

    uint8_t dns[256];
    int dns_pos = 0;

    write_dns_hdr(dns, 0x0001, 0x8180, 1, 1, 0, 0);
    dns_pos = 12;

    int name_offset = dns_pos;  /* remember where the name starts */
    dns_pos += write_dns_name(dns + dns_pos, "ptr.example.com");
    uint16_t qtype  = htons(1);
    uint16_t qclass = htons(1);
    memcpy(dns + dns_pos, &qtype,  2); dns_pos += 2;
    memcpy(dns + dns_pos, &qclass, 2); dns_pos += 2;

    /* Answer with compressed name (pointer to name_offset = 12) */
    dns[dns_pos++] = 0xC0;
    dns[dns_pos++] = (uint8_t)name_offset;

    uint16_t rtype  = htons(1);
    uint16_t rclass = htons(1);
    uint32_t rttl   = htonl(120);
    uint16_t rdlen  = htons(4);
    uint8_t  rdata[4] = {1, 2, 3, 4};
    memcpy(dns + dns_pos, &rtype,  2); dns_pos += 2;
    memcpy(dns + dns_pos, &rclass, 2); dns_pos += 2;
    memcpy(dns + dns_pos, &rttl,   4); dns_pos += 4;
    memcpy(dns + dns_pos, &rdlen,  2); dns_pos += 2;
    memcpy(dns + dns_pos, rdata,   4); dns_pos += 4;

    /* Test dns_decompress_name on the question name */
    char out[DNS_MAX_NAME];
    int consumed = dns_decompress_name(dns, dns_pos, 12, out, sizeof(out));
    CHECK(consumed > 0, "name_decompression: literal name consumed > 0 bytes");
    CHECK(strcmp(out, "ptr.example.com") == 0,
          "name_decompression: literal name == ptr.example.com");

    /* Test pointer decompression — find where pointer starts */
    int ptr_off = 12 + consumed + 4;  /* skip question name + QTYPE + QCLASS */
    int consumed2 = dns_decompress_name(dns, dns_pos, ptr_off, out, sizeof(out));
    CHECK(consumed2 == 2, "name_decompression: pointer consumes exactly 2 bytes");
    CHECK(strcmp(out, "ptr.example.com") == 0,
          "name_decompression: pointer resolves to ptr.example.com");

    /* Now build a full packet and run through the full parser */
    uint8_t pkt[512];
    memset(pkt, 0, sizeof(pkt));
    struct mock_ctx m;
    memset(&m, 0, sizeof(m));
    ps_module_ctx_t ctx = make_ctx(&m);

    int dns_off = write_eth_ipv4_udp(pkt, sizeof(pkt),
                                      0x01010101, 0x02020202,
                                      11111, 53,
                                      (uint16_t)dns_pos);
    memcpy(pkt + dns_off, dns, (size_t)dns_pos);
    int total = dns_off + dns_pos;

    dns_parse_and_publish(&ctx, pkt, total, dns_off);

    CHECK(m.count == 1, "name_decompression: full parse published one event");
    if (m.count > 0) {
        CHECK(strstr(m.json[0], "\"query\":\"ptr.example.com\"") != NULL,
              "name_decompression: query name correct in full parse");
        CHECK(strstr(m.json[0], "\"name\":\"ptr.example.com\"") != NULL,
              "name_decompression: answer name correct (pointer resolved)");
        CHECK(strstr(m.json[0], "\"data\":\"1.2.3.4\"") != NULL,
              "name_decompression: rdata IP address correct");
    }
}

/* ------------------------------------------------------------------ */
/* Test 4: EDNS ECS option (client subnet)                             */
/* ------------------------------------------------------------------ */

static void test_parse_edns_ecs(void)
{
    printf("test_parse_edns_ecs:\n");

    /*
     * Build a DNS response with:
     *   - 1 question: "ecs.example.com"
     *   - 1 answer:   A record → 198.51.100.1
     *   - 1 additional: OPT record with ECS option
     *     family=1 (IPv4), src_prefix=24, scope_prefix=0, addr=198.51.100.0
     */

    struct mock_ctx m;
    memset(&m, 0, sizeof(m));
    ps_module_ctx_t ctx = make_ctx(&m);

    uint8_t dns[512];
    int dns_pos = 0;

    write_dns_hdr(dns, 0x5678, 0x8180, 1, 1, 0, 1);
    dns_pos = 12;

    /* Question */
    dns_pos += write_dns_name(dns + dns_pos, "ecs.example.com");
    uint16_t qtype  = htons(1);
    uint16_t qclass = htons(1);
    memcpy(dns + dns_pos, &qtype,  2); dns_pos += 2;
    memcpy(dns + dns_pos, &qclass, 2); dns_pos += 2;

    /* Answer: A 300 198.51.100.1 */
    dns_pos += write_dns_name(dns + dns_pos, "ecs.example.com");
    uint16_t rtype  = htons(1);
    uint16_t rclass = htons(1);
    uint32_t rttl   = htonl(300);
    uint16_t rdlen  = htons(4);
    uint8_t  rdata[4] = {198, 51, 100, 1};
    memcpy(dns + dns_pos, &rtype,  2); dns_pos += 2;
    memcpy(dns + dns_pos, &rclass, 2); dns_pos += 2;
    memcpy(dns + dns_pos, &rttl,   4); dns_pos += 4;
    memcpy(dns + dns_pos, &rdlen,  2); dns_pos += 2;
    memcpy(dns + dns_pos, rdata,   4); dns_pos += 4;

    /*
     * OPT record (EDNS0):
     *   NAME   = 0x00 (root/empty)
     *   TYPE   = 41 (OPT)
     *   CLASS  = 4096 (UDP payload size — encoded in CLASS field)
     *   TTL    = 0 (extended RCODE and flags)
     *   RDLEN  = length of RDATA
     *   RDATA  = EDNS options
     *
     * ECS option (code=8):
     *   opt-code  (2) = 8
     *   opt-len   (2) = 7   (family(2)+src(1)+scope(1)+addr(3))
     *   family    (2) = 1   (IPv4)
     *   src_prefix(1) = 24
     *   scope_prefix(1) = 0
     *   address   (3) = 198.51.100  (only 3 bytes for /24)
     */

    /* ECS option data */
    uint8_t ecs_opt[11];
    uint16_t opt_code = htons(8);
    uint16_t opt_len  = htons(7);  /* family(2)+src(1)+scope(1)+addr(3) */
    uint16_t ecs_family = htons(1);
    memcpy(ecs_opt + 0, &opt_code,   2);
    memcpy(ecs_opt + 2, &opt_len,    2);
    memcpy(ecs_opt + 4, &ecs_family, 2);
    ecs_opt[6] = 24;   /* src_prefix */
    ecs_opt[7] = 0;    /* scope_prefix */
    ecs_opt[8] = 198;  /* address bytes (only 3 for /24) */
    ecs_opt[9] = 51;
    ecs_opt[10]= 100;

    /* OPT record */
    dns[dns_pos++] = 0x00;  /* empty name */
    uint16_t opt_type  = htons(41);
    uint16_t opt_class = htons(4096);  /* UDP payload size */
    uint32_t opt_ttl   = htonl(0);
    uint16_t opt_rdlen = htons(11);    /* length of ecs_opt */
    memcpy(dns + dns_pos, &opt_type,  2); dns_pos += 2;
    memcpy(dns + dns_pos, &opt_class, 2); dns_pos += 2;
    memcpy(dns + dns_pos, &opt_ttl,   4); dns_pos += 4;
    memcpy(dns + dns_pos, &opt_rdlen, 2); dns_pos += 2;
    memcpy(dns + dns_pos, ecs_opt,   11); dns_pos += 11;

    /* Build full packet */
    uint8_t pkt[512];
    memset(pkt, 0, sizeof(pkt));
    int dns_off = write_eth_ipv4_udp(pkt, sizeof(pkt),
                                      0xC0A80101, 0xC0A80102,
                                      12345, 53,
                                      (uint16_t)dns_pos);
    memcpy(pkt + dns_off, dns, (size_t)dns_pos);
    int total = dns_off + dns_pos;

    dns_parse_and_publish(&ctx, pkt, total, dns_off);

    CHECK(m.count == 1, "edns_ecs: one event published");
    if (m.count > 0) {
        CHECK(strstr(m.json[0], "\"query\":\"ecs.example.com\"") != NULL,
              "edns_ecs: query name correct");
        CHECK(strstr(m.json[0], "\"data\":\"198.51.100.1\"") != NULL,
              "edns_ecs: A record data correct");
        CHECK(strstr(m.json[0], "\"edns\"") != NULL,
              "edns_ecs: edns key present");
        CHECK(strstr(m.json[0], "\"ecs_subnet\"") != NULL,
              "edns_ecs: ecs_subnet key present");
        CHECK(strstr(m.json[0], "198.51.100") != NULL,
              "edns_ecs: ECS subnet address in output");
        CHECK(strstr(m.json[0], "/24") != NULL,
              "edns_ecs: ECS prefix length /24 present");
        CHECK(strstr(m.json[0], "\"ecs_family\":1") != NULL,
              "edns_ecs: ecs_family == 1");
    }
}

/* ------------------------------------------------------------------ */
/* Test 5: Query packet (QR=0) is silently dropped                     */
/* ------------------------------------------------------------------ */

static void test_query_dropped(void)
{
    printf("test_query_dropped:\n");

    struct mock_ctx m;
    memset(&m, 0, sizeof(m));
    ps_module_ctx_t ctx = make_ctx(&m);

    uint8_t dns[64];
    int dns_pos = 0;

    /* flags = 0x0100: QR=0 (query), RD=1 */
    write_dns_hdr(dns, 0x0001, 0x0100, 1, 0, 0, 0);
    dns_pos = 12;
    dns_pos += write_dns_name(dns + dns_pos, "example.com");
    uint16_t qtype  = htons(1);
    uint16_t qclass = htons(1);
    memcpy(dns + dns_pos, &qtype,  2); dns_pos += 2;
    memcpy(dns + dns_pos, &qclass, 2); dns_pos += 2;

    uint8_t pkt[256];
    memset(pkt, 0, sizeof(pkt));
    int dns_off = write_eth_ipv4_udp(pkt, sizeof(pkt),
                                      0xC0A80101, 0xC0A80102,
                                      55555, 53,
                                      (uint16_t)dns_pos);
    memcpy(pkt + dns_off, dns, (size_t)dns_pos);
    int total = dns_off + dns_pos;

    dns_parse_and_publish(&ctx, pkt, total, dns_off);

    CHECK(m.count == 0, "query_dropped: DNS query (QR=0) produces no event");
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== test_dns_listener ===\n");

    test_parse_a_record();
    test_parse_aaaa_record();
    test_name_decompression();
    test_parse_edns_ecs();
    test_query_dropped();

    printf("\n%d/%d tests passed.\n", tests_passed, tests_run);

    if (tests_passed != tests_run) {
        printf("SOME TESTS FAILED\n");
        return 1;
    }

    printf("All tests passed.\n");
    return 0;
}
