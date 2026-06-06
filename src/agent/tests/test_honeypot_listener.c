/*
 * test_honeypot_listener.c — Unit tests for the honeypot listener module.
 *
 * Tests the config parser (hp_parse_config_string) without needing root,
 * pcap, network access, or Redis. We include the .c file directly with
 * PS_HONEYPOT_LISTENER_TESTING defined to suppress the module symbol and
 * access static helpers.
 */

#include <assert.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>

/* Suppress the module export symbol */
#define PS_HONEYPOT_LISTENER_TESTING 1

/* Pull in the implementation */
#include "../src/modules/honeypot_listener.c"

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
/* Mock context (matches dns_listener test pattern)                    */
/* ------------------------------------------------------------------ */

#define MAX_PUBLISHED 8

struct mock_ctx {
    int      count;
    char     channel[MAX_PUBLISHED][64];
    char     json[MAX_PUBLISHED][4096];
    uint32_t json_len[MAX_PUBLISHED];
};

static int mock_publish(ps_module_ctx_t *ctx,
                         const char *channel,
                         const char *json, uint32_t json_len)
{
    struct mock_ctx *m = (struct mock_ctx *)ctx->userdata;
    if (m->count >= MAX_PUBLISHED) return -1;
    int i = m->count++;
    strncpy(m->channel[i], channel, sizeof(m->channel[i]) - 1);
    if (json_len >= sizeof(m->json[i])) json_len = (uint32_t)sizeof(m->json[i]) - 1;
    memcpy(m->json[i], json, json_len);
    m->json[i][json_len] = '\0';
    m->json_len[i] = json_len;
    return 0;
}

static void mock_log(ps_module_ctx_t *ctx, int level, const char *fmt, ...)
{
    (void)ctx; (void)level; (void)fmt;
}

static ps_module_ctx_t make_test_ctx(struct mock_ctx *m)
{
    ps_module_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.userdata = m;
    ctx.publish  = mock_publish;
    ctx.log      = mock_log;
    return ctx;
}

/* ------------------------------------------------------------------ */
/* Test 1: parse_config_basic                                           */
/* ------------------------------------------------------------------ */

/*
 * Full config with all scalar keys and three trap ports.
 * Verifies:
 *   - enabled parsed as true
 *   - timeout, max_payload parsed correctly
 *   - redis_key and redis_channel stored
 *   - port 22 trap: SSH banner with \r\n unescaped to CRLF
 *   - port 80 trap: HTTP banner with embedded CRLF sequences
 *   - port 443 trap: present and correct port
 *   - trap_count == 3
 */
static void test_parse_config_basic(void)
{
    printf("test_parse_config_basic:\n");

    const char *cfg_text =
        "[honeypot]\n"
        "enabled = true\n"
        "timeout = 30\n"
        "max_payload = 512\n"
        "redis_key = packetsonde:test:probes\n"
        "redis_channel = test.probe\n"
        "22 = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\\r\\n\n"
        "80 = HTTP/1.1 200 OK\\r\\nServer: Apache\\r\\n\\r\\n\n"
        "443 = HTTP/1.1 200 OK\\r\\nServer: nginx\\r\\n\\r\\n\n";

    struct hp_config cfg;
    int rc = hp_parse_config_string(&cfg, cfg_text);

    CHECK(rc == 0,                   "basic: parse returns 0");
    CHECK(cfg.enabled == 1,          "basic: enabled=true");
    CHECK(cfg.timeout_sec == 30,     "basic: timeout=30");
    CHECK(cfg.max_payload == 512,    "basic: max_payload=512");
    CHECK(strcmp(cfg.redis_key,     "packetsonde:test:probes") == 0,
          "basic: redis_key correct");
    CHECK(strcmp(cfg.redis_channel, "test.probe") == 0,
          "basic: redis_channel correct");
    CHECK(cfg.trap_count == 3,       "basic: trap_count==3");

    /* Find the port-22 trap */
    int idx22 = -1;
    for (int i = 0; i < cfg.trap_count; i++) {
        if (cfg.traps[i].port == 22) { idx22 = i; break; }
    }
    CHECK(idx22 >= 0, "basic: port 22 trap present");
    if (idx22 >= 0) {
        /* Banner should have \r\n unescaped to actual CR LF */
        const char *b = cfg.traps[idx22].banner;
        int   blen    = cfg.traps[idx22].banner_len;
        /* Last two bytes must be CR + LF */
        CHECK(blen >= 2 && b[blen-2] == '\r' && b[blen-1] == '\n',
              "basic: port 22 banner ends with CRLF");
        CHECK(strncmp(b, "SSH-2.0-OpenSSH_8.9p1", 21) == 0,
              "basic: port 22 banner starts with SSH version string");
    }

    /* Find the port-80 trap */
    int idx80 = -1;
    for (int i = 0; i < cfg.trap_count; i++) {
        if (cfg.traps[i].port == 80) { idx80 = i; break; }
    }
    CHECK(idx80 >= 0, "basic: port 80 trap present");
    if (idx80 >= 0) {
        const char *b = cfg.traps[idx80].banner;
        /* Should contain at least one CRLF pair */
        CHECK(strstr(b, "\r\n") != NULL,
              "basic: port 80 banner contains CRLF");
        CHECK(strncmp(b, "HTTP/1.1 200 OK", 15) == 0,
              "basic: port 80 banner starts with HTTP status line");
    }

    /* Port 443 should be present */
    int idx443 = -1;
    for (int i = 0; i < cfg.trap_count; i++) {
        if (cfg.traps[i].port == 443) { idx443 = i; break; }
    }
    CHECK(idx443 >= 0, "basic: port 443 trap present");
}

/* ------------------------------------------------------------------ */
/* Test 2: parse_config_defaults                                        */
/* ------------------------------------------------------------------ */

/*
 * Minimal config with only [honeypot] and one port.
 * Verifies defaults are applied for all unspecified scalar keys.
 */
static void test_parse_config_defaults(void)
{
    printf("test_parse_config_defaults:\n");

    const char *cfg_text =
        "[honeypot]\n"
        "22 = SSH-2.0-OpenSSH_8.9p1\\r\\n\n";

    struct hp_config cfg;
    int rc = hp_parse_config_string(&cfg, cfg_text);

    CHECK(rc == 0,                          "defaults: parse returns 0");
    CHECK(cfg.enabled == 0,                 "defaults: enabled defaults to false");
    CHECK(cfg.timeout_sec == 10,            "defaults: timeout defaults to 10");
    CHECK(cfg.max_payload == HP_MAX_PAYLOAD,"defaults: max_payload defaults to HP_MAX_PAYLOAD");
    CHECK(strcmp(cfg.redis_key,
                 "packetsonde:honeypot:probes") == 0,
          "defaults: redis_key is default value");
    CHECK(strcmp(cfg.redis_channel, "honeypot.probe") == 0,
          "defaults: redis_channel is default value");
    CHECK(cfg.trap_count == 1,              "defaults: one trap defined");
}

/* ------------------------------------------------------------------ */
/* Test 3: parse_config_disabled                                        */
/* ------------------------------------------------------------------ */

/*
 * Config with enabled=false (explicit).
 * Verifies cfg.enabled is 0 and other fields still parse correctly.
 */
static void test_parse_config_disabled(void)
{
    printf("test_parse_config_disabled:\n");

    const char *cfg_text =
        "[honeypot]\n"
        "enabled = false\n"
        "timeout = 5\n"
        "redis_channel = disabled.probe\n"
        "# No traps defined — disabled module\n";

    struct hp_config cfg;
    int rc = hp_parse_config_string(&cfg, cfg_text);

    CHECK(rc == 0,                            "disabled: parse returns 0");
    CHECK(cfg.enabled == 0,                   "disabled: enabled=false parsed");
    CHECK(cfg.timeout_sec == 5,               "disabled: timeout=5 parsed");
    CHECK(strcmp(cfg.redis_channel,
                 "disabled.probe") == 0,
          "disabled: redis_channel parsed");
    CHECK(cfg.trap_count == 0,                "disabled: no traps defined");
}

/* ------------------------------------------------------------------ */
/* Test 4: test_build_probe_event_json                                  */
/* ------------------------------------------------------------------ */

/*
 * Build a mock session with one SYN packet and call hp_emit_probe_event.
 * Verifies:
 *   - Event published to correct channel
 *   - JSON contains "dst_port":22
 *   - JSON contains "src_ip":"192.0.2.87"
 *   - JSON contains "connection_type":"established"
 *   - JSON contains the "packets":[ array marker
 *   - JSON contains tcp_flags "S" for a pure SYN packet
 *   - JSON contains "banner_sent" field
 */
static void test_build_probe_event_json(void)
{
    printf("test_build_probe_event_json:\n");

    struct mock_ctx m;
    memset(&m, 0, sizeof(m));

    ps_module_ctx_t ctx = make_test_ctx(&m);

    /* Build a minimal hp_config */
    struct hp_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled     = 1;
    cfg.timeout_sec = 10;
    cfg.max_payload = HP_MAX_PAYLOAD;
    snprintf(cfg.redis_channel, sizeof(cfg.redis_channel), "honeypot.probe");

    /* One trap on port 22 with an SSH banner */
    cfg.trap_count = 1;
    cfg.traps[0].port = 22;
    const char *banner = "SSH-2.0-OpenSSH_8.9\r\n";
    strncpy(cfg.traps[0].banner, banner, sizeof(cfg.traps[0].banner) - 1);
    cfg.traps[0].banner_len = (int)strlen(banner);

    /* Build a mock session */
    struct hp_session session;
    memset(&session, 0, sizeof(session));
    session.fd          = -1;       /* not used by emit */
    session.trap_port   = 22;
    session.start_usec  = 1000000;  /* 1 second since epoch */
    session.banner_sent = 1;
    session.packet_count = 1;
    session.total_bytes  = 20;
    session.trap         = &cfg.traps[0];

    /* Peer address: 192.0.2.87:54321 */
    memset(&session.peer, 0, sizeof(session.peer));
    session.peer.sin_family = AF_INET;
    inet_pton(AF_INET, "192.0.2.87", &session.peer.sin_addr);
    session.peer.sin_port = htons(54321);

    /* One SYN packet */
    session.packets[0].seq            = 1;
    session.packets[0].time_offset_ms = 0.0;
    session.packets[0].tcp_flags      = 0x02;  /* SYN */
    session.packets[0].tcp_window     = 1024;
    session.packets[0].ttl            = 64;
    session.packets[0].ip_flags_df    = 1;
    session.packets[0].ecn            = 0;
    session.packets[0].payload_len    = 0;     /* SYN has no payload */

    uint64_t close_usec = 1500000; /* 0.5 s later */
    hp_emit_probe_event(&ctx, &cfg, &session, close_usec);

    /* Should have published exactly one event */
    CHECK(m.count == 1, "probe_event: one event published");

    if (m.count >= 1) {
        const char *ch  = m.channel[0];
        const char *js  = m.json[0];

        CHECK(strcmp(ch, "honeypot.probe") == 0,
              "probe_event: published to honeypot.probe channel");

        CHECK(strstr(js, "\"dst_port\":22") != NULL ||
              strstr(js, "\"dst_port\": 22") != NULL,
              "probe_event: dst_port is 22");

        CHECK(strstr(js, "\"src_ip\":\"192.0.2.87\"") != NULL ||
              strstr(js, "\"src_ip\": \"192.0.2.87\"") != NULL,
              "probe_event: src_ip is 192.0.2.87");

        CHECK(strstr(js, "\"connection_type\":\"established\"") != NULL ||
              strstr(js, "\"connection_type\": \"established\"") != NULL,
              "probe_event: connection_type is established");

        CHECK(strstr(js, "\"packets\":[") != NULL ||
              strstr(js, "\"packets\": [") != NULL,
              "probe_event: packets array present");

        CHECK(strstr(js, "\"tcp_flags\":\"S\"") != NULL ||
              strstr(js, "\"tcp_flags\": \"S\"") != NULL,
              "probe_event: SYN flag rendered as S");

        CHECK(strstr(js, "\"banner_sent\"") != NULL,
              "probe_event: banner_sent field present");

        /* Also verify src_port */
        CHECK(strstr(js, "\"src_port\":54321") != NULL ||
              strstr(js, "\"src_port\": 54321") != NULL,
              "probe_event: src_port is 54321");
    }
}

/* ------------------------------------------------------------------ */
/* Test 5: test_halfopen_syn_packet                                     */
/* ------------------------------------------------------------------ */

/*
 * honeypot_tick reads ctx->userdata as honeypot_state*, but hp_emit_probe_event_ex
 * calls ctx->publish with that same ctx.  Our mock_publish expects userdata to be
 * mock_ctx*.  We bridge the gap with a module-level static pointer that a publish
 * shim reads directly, keeping honeypot_state in ctx->userdata where the tick needs it.
 */
static struct mock_ctx *g_halfopen_sink = NULL;

static int halfopen_publish(ps_module_ctx_t *ctx,
                             const char *channel,
                             const char *json, uint32_t json_len)
{
    (void)ctx;
    if (!g_halfopen_sink) return -1;
    /* mock_publish reads ctx->userdata as mock_ctx* — build a minimal ctx */
    ps_module_ctx_t sink_ctx;
    memset(&sink_ctx, 0, sizeof(sink_ctx));
    sink_ctx.userdata = g_halfopen_sink;
    sink_ctx.publish  = mock_publish;
    sink_ctx.log      = mock_log;
    return mock_publish(&sink_ctx, channel, json, json_len);
}

/*
 * Craft a raw Ethernet + IPv4 + TCP SYN frame (54 bytes) and feed it to
 * honeypot_on_packet.  Verify burst accumulation, then simulate a tick past
 * the dedup window and verify the half-open probe event is emitted.
 *
 * Frame layout:
 *   [0..13]  Ethernet header (ethertype 0x0800 at [12..13])
 *   [14]     IP: version=4, IHL=5 → 0x45
 *   [20]     IP flags = 0x40 (DF set, bit 6 of byte [20])
 *   [22]     TTL = 64
 *   [23]     Protocol = 6 (TCP)
 *   [26..29] Src IP = 192.0.2.87
 *   [30..33] Dst IP = 192.168.1.100
 *   [34..35] TCP src port = 54321
 *   [36..37] TCP dst port = 22
 *   [46]     TCP data offset = 0x50 (5 * 4 = 20 bytes)
 *   [47]     TCP flags = 0x02 (SYN)
 *   [48..49] TCP window = 1024
 */
static void test_halfopen_syn_packet(void)
{
    printf("test_halfopen_syn_packet:\n");

    /* ---- Build a minimal honeypot_state with one trap on port 22 ---- */
    /* Use heap — honeypot_state contains large burst/session arrays (~20 MB). */
    struct honeypot_state *st = calloc(1, sizeof(*st));
    assert(st != NULL);
    st->cfg.enabled       = 1;
    st->cfg.timeout_sec   = 10;
    st->cfg.max_payload   = HP_MAX_PAYLOAD;
    snprintf(st->cfg.redis_channel, sizeof(st->cfg.redis_channel), "honeypot.probe");
    st->cfg.trap_count    = 1;
    st->cfg.traps[0].port = 22;
    for (int i = 0; i < HP_MAX_TRAPS; i++)
        st->trap_fds[i] = st->listen_fds[i] = -1;
    st->pcap_handle = -1;

    /* Context: userdata = st (honeypot_state); publish = halfopen_publish shim */
    ps_module_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.userdata = st;
    ctx.publish  = halfopen_publish;
    ctx.log      = mock_log;

    /* ---- Craft the 54-byte raw frame ---- */
    uint8_t pkt[54];
    memset(pkt, 0, sizeof(pkt));

    /* Ethernet */
    pkt[12] = 0x08; pkt[13] = 0x00;

    /* IPv4 */
    pkt[14] = 0x45;                              /* version 4, IHL 5 */
    pkt[16] = 0x00; pkt[17] = 0x28;             /* total length = 40 */
    pkt[20] = 0x40;                              /* DF flag */
    pkt[22] = 64;                                /* TTL */
    pkt[23] = 6;                                 /* protocol TCP */
    pkt[26] = 10; pkt[27] = 0; pkt[28] = 1; pkt[29] = 87;    /* src 192.0.2.87 */
    pkt[30] = 192; pkt[31] = 168; pkt[32] = 1; pkt[33] = 100; /* dst */

    /* TCP */
    pkt[34] = (54321 >> 8) & 0xFF; pkt[35] = 54321 & 0xFF;  /* src port */
    pkt[36] = 0x00; pkt[37] = 22;                            /* dst port = 22 */
    pkt[46] = 0x50;                                           /* data offset */
    pkt[47] = 0x02;                                           /* SYN */
    pkt[48] = 0x04; pkt[49] = 0x00;                          /* window = 1024 */

    /* ---- Deliver packet ---- */
    uint64_t ts = 1000000ULL;
    honeypot_on_packet(&ctx, pkt, sizeof(pkt), ts, 0);

    CHECK(st->burst_count == 1, "halfopen: burst created after SYN packet");

    if (st->burst_count >= 1) {
        struct hp_halfopen_burst *b = &st->bursts[0];
        CHECK(b->active == 1,       "halfopen: burst is active");
        CHECK(b->packet_count == 1, "halfopen: one packet in burst");
        CHECK(b->dst_port == 22,    "halfopen: burst dst_port == 22");

        if (b->packet_count >= 1) {
            const struct hp_packet *p = &b->packets[0];
            CHECK(p->tcp_flags  == 0x02, "halfopen: tcp_flags == SYN (0x02)");
            CHECK(p->tcp_window == 1024, "halfopen: tcp_window == 1024");
            CHECK(p->ttl        == 64,   "halfopen: ttl == 64");
        }
    }

    /* ---- Flush: tick past the dedup window ---- */
    struct mock_ctx sink;
    memset(&sink, 0, sizeof(sink));
    g_halfopen_sink = &sink;   /* wire halfopen_publish → sink */

    uint64_t flush_ts = ts + (uint64_t)HP_DEDUP_WINDOW_MS * 1000ULL + 1ULL;
    honeypot_tick(&ctx, flush_ts);

    g_halfopen_sink = NULL;

    CHECK(st->burst_count == 0, "halfopen: burst compacted after flush");
    CHECK(sink.count >= 1,      "halfopen: event published after burst flush");

    if (sink.count >= 1) {
        const char *js = sink.json[0];
        CHECK(strstr(js, "\"connection_type\":\"half_open\"") != NULL ||
              strstr(js, "\"connection_type\": \"half_open\"") != NULL,
              "halfopen: connection_type is half_open");
        CHECK(strstr(js, "\"dst_port\":22") != NULL ||
              strstr(js, "\"dst_port\": 22") != NULL,
              "halfopen: dst_port is 22");
        CHECK(strstr(js, "\"tcp_flags\":\"S\"") != NULL ||
              strstr(js, "\"tcp_flags\": \"S\"") != NULL,
              "halfopen: tcp_flags rendered as S");
    }

    free(st);
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== test_honeypot_listener ===\n");

    test_parse_config_basic();
    test_parse_config_defaults();
    test_parse_config_disabled();
    test_build_probe_event_json();
    test_halfopen_syn_packet();

    printf("\n%d/%d tests passed.\n", tests_passed, tests_run);

    if (tests_passed != tests_run) {
        printf("SOME TESTS FAILED\n");
        return 1;
    }

    printf("All tests passed.\n");
    return 0;
}
