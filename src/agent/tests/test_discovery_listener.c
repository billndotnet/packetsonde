/*
 * test_discovery_listener -- end-to-end test of the agent-side discovery
 * module. Synthesises a broadcast frame containing a signed PSDP probe,
 * invokes the module's on_packet directly, and verifies a signed reply
 * arrives at a local UDP socket.
 *
 * Includes the module source directly so we don't depend on the daemon
 * being initialised. Stubs out log and module_register.
 */
#include "discovery.h"
#include "keystore.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* Stub the agent symbols the module references at link time. */
void ps_info(const char *fmt, ...) { (void)fmt; }
void ps_warn(const char *fmt, ...) { (void)fmt; }

#include "packetsonde/module_api.h"
int ps_module_register(const ps_module_t *mod) { (void)mod; return 0; }
/* And the additional log helpers the module may indirectly use. */
void ps_error(const char *fmt, ...) { (void)fmt; }
void ps_debug(const char *fmt, ...) { (void)fmt; }

/* Stub for the cross-module hook the discovery_listener now calls when
 * a probe carries PS_DISCOVERY_FLAG_REQUEST_SESSION. The legacy tests
 * here don't exercise that path; return -1 so any accidental hit yields
 * a silent drop rather than touching the network. */
int ps_nl_open_session_window(int timeout_secs, uint16_t *out_port) {
    (void)timeout_secs; (void)out_port; return -1;
}

/* Pull the module source itself in. */
#include "modules/discovery_listener.c"

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); return 1; } \
} while (0)

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

static uint16_t ip_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)data[i] << 8 | data[i + 1];
    if (len & 1) sum += (uint32_t)data[len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* Build a fake ethernet+ip+udp frame whose payload is `probe_wire`. The
 * src ip is 127.0.0.1 and src port routes the agent's reply to our
 * test socket. */
static size_t build_frame(uint8_t *buf, const uint8_t *probe_wire,
                          size_t probe_len, uint16_t src_port) {
    /* Ethernet: dst broadcast, src dummy, type IPv4 */
    static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    static const uint8_t mac[6]   = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
    memcpy(buf + 0,  bcast, 6);
    memcpy(buf + 6,  mac,   6);
    put_be16(buf + 12, 0x0800);

    /* IPv4 header (20 bytes), proto=17 UDP */
    uint8_t *ip = buf + 14;
    size_t total_ip = 20 + 8 + probe_len;
    ip[0] = 0x45;             /* ver 4 + ihl 5 */
    ip[1] = 0;                /* tos */
    put_be16(ip + 2, (uint16_t)total_ip);
    put_be16(ip + 4, 0);      /* id */
    put_be16(ip + 6, 0);      /* flags+frag */
    ip[8] = 64;               /* ttl */
    ip[9] = 17;               /* udp */
    put_be16(ip + 10, 0);     /* checksum (zeroed for our test) */
    /* src 127.0.0.1, dst 127.255.255.255 */
    ip[12] = 127; ip[13] = 0; ip[14] = 0; ip[15] = 1;
    ip[16] = 127; ip[17] = 255; ip[18] = 255; ip[19] = 255;
    put_be16(ip + 10, ip_checksum(ip, 20));

    /* UDP header */
    uint8_t *udp = ip + 20;
    put_be16(udp + 0, src_port);
    put_be16(udp + 2, 9999);  /* dst port irrelevant in knock mode */
    put_be16(udp + 4, (uint16_t)(8 + probe_len));
    put_be16(udp + 6, 0);     /* checksum 0 = unused on v4 */

    memcpy(udp + 8, probe_wire, probe_len);
    return 14 + total_ip;
}

int main(void) {
    /* Create a CLI key + an agent key on disk in a temp dir. Configure
     * the module via env to use these. */
    char tmpl[] = "/tmp/ps_dlist_XXXXXX";
    char *dir = mkdtemp(tmpl);
    CHECK(dir != NULL);
    char authdir[1024]; snprintf(authdir, sizeof(authdir), "%s/authorized", dir);
    mkdir(authdir, 0755);

    struct ps_keypair cli_kp, agent_kp;
    CHECK(ps_keystore_generate(&cli_kp)   == 0);
    CHECK(ps_keystore_generate(&agent_kp) == 0);
    CHECK(ps_keystore_save(dir, "agent", &agent_kp) == 0);
    /* Drop the cli pubkey into authorized/. */
    char authpath[1100];
    snprintf(authpath, sizeof(authpath), "%s/cli.pub", authdir);
    FILE *f = fopen(authpath, "wb");
    CHECK(f != NULL);
    CHECK(fwrite(cli_kp.pubkey, 1, 32, f) == 32);
    fclose(f);

    setenv("PS_DISCOVERY_ENABLED", "1", 1);
    setenv("PS_KEY_DIR", dir, 1);
    setenv("PS_DISCOVERY_AGENT_KEY", "agent", 1);
    setenv("PS_DISCOVERY_AUTHORIZED_DIR", authdir, 1);
    setenv("PS_DISCOVERY_LISTEN_IP", "10.20.30.40", 1);
    setenv("PS_DISCOVERY_LISTEN_PORT", "7777", 1);

    /* Bring up the module. */
    ps_module_ctx_t ctx; memset(&ctx, 0, sizeof(ctx));
    CHECK(dlist_init(&ctx) == 0);

    /* Open a local UDP socket to receive the reply. */
    int rfd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(rfd >= 0);
    struct sockaddr_in la; memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
    la.sin_port = 0;
    CHECK(bind(rfd, (struct sockaddr *)&la, sizeof(la)) == 0);
    socklen_t la_l = sizeof(la);
    CHECK(getsockname(rfd, (struct sockaddr *)&la, &la_l) == 0);
    uint16_t local_port = ntohs(la.sin_port);

    /* Build + sign a probe. */
    struct ps_discovery_probe p = {0};
    p.version = PS_DISCOVERY_VERSION;
    p.max_skew_ms = 2000;
    p.timestamp_ms = ps_discovery_now_ms();
    ps_discovery_random(p.nonce, PS_DISCOVERY_NONCE_SIZE);
    memcpy(p.pubkey, cli_kp.pubkey, PS_DISCOVERY_PUBKEY_SIZE);
    CHECK(ps_discovery_probe_sign(&p, cli_kp.seckey) == 0);
    uint8_t probe_wire[PS_DISCOVERY_PROBE_SIZE];
    ps_discovery_probe_pack(&p, probe_wire);

    uint8_t frame[2048];
    size_t  frame_len = build_frame(frame, probe_wire, sizeof(probe_wire),
                                    local_port);

    /* Drive the module. */
    on_packet(&ctx, frame, (uint32_t)frame_len, 0, 0);

    /* Expect a 136-byte reply on rfd. */
    struct timeval tv = { 1, 0 };
    setsockopt(rfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    uint8_t reply[256];
    ssize_t n = recv(rfd, reply, sizeof(reply), 0);
    CHECK(n == PS_DISCOVERY_REPLY_SIZE);

    struct ps_discovery_reply r;
    CHECK(ps_discovery_reply_unpack(&r, reply) == 0);
    CHECK(memcmp(r.nonce, p.nonce, PS_DISCOVERY_NONCE_SIZE) == 0);
    CHECK(memcmp(r.agent_pub, agent_kp.pubkey, PS_DISCOVERY_PUBKEY_SIZE) == 0);
    CHECK(r.listen_port == 7777);
    /* v4-mapped 10.20.30.40 */
    CHECK(r.listen_ip[10] == 0xff && r.listen_ip[11] == 0xff);
    CHECK(r.listen_ip[12] == 10 && r.listen_ip[13] == 20 &&
          r.listen_ip[14] == 30 && r.listen_ip[15] == 40);
    CHECK(ps_discovery_reply_verify(&r) == 1);

    /* Replay: same probe must NOT produce a second reply. */
    on_packet(&ctx, frame, (uint32_t)frame_len, 0, 0);
    n = recv(rfd, reply, sizeof(reply), 0);
    CHECK(n < 0); /* timeout */

    dlist_shutdown(&ctx);
    close(rfd);
    fprintf(stderr, "test_discovery_listener: OK\n");
    return 0;
}
