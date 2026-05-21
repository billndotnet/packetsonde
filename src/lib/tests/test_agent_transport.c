/*
 * test_agent_transport -- loopback mTLS handshake using two Ed25519
 * keypairs, asserts:
 *   - both sides complete the handshake
 *   - peer_fingerprint() returns the expected hex
 *   - a fingerprint pin on the client refuses a server with a different key
 *   - frames flow correctly in both directions over the AEAD tunnel
 */
#include "agent_proto.h"
#include "agent_transport.h"
#include "keystore.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s (errno=%d %s)\n", \
    __FILE__, __LINE__, #c, errno, strerror(errno)); return 1; } } while (0)

struct server_args {
    struct ps_at_ctx *ctx;
    int               listen_fd;
    SSL              *accepted;
    int               handshake_ok;
};

static void *server_thread(void *arg) {
    struct server_args *sa = arg;
    sa->accepted = ps_at_accept(sa->ctx, sa->listen_fd);
    sa->handshake_ok = (sa->accepted != NULL);
    return NULL;
}

static int open_listener(uint16_t *port_out) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in la; memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(0x7f000001);
    la.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&la, sizeof(la)) != 0) { close(fd); return -1; }
    if (listen(fd, 1) != 0) { close(fd); return -1; }
    socklen_t l = sizeof(la);
    getsockname(fd, (struct sockaddr *)&la, &l);
    *port_out = ntohs(la.sin_port);
    return fd;
}

static int test_handshake_and_frame_exchange(void) {
    struct ps_keypair s_kp, c_kp;
    CHECK(ps_keystore_generate(&s_kp) == 0);
    CHECK(ps_keystore_generate(&c_kp) == 0);
    char s_fpr[PS_KEYSTORE_FPR_HEX_SIZE];
    char c_fpr[PS_KEYSTORE_FPR_HEX_SIZE];
    ps_keystore_fingerprint(s_kp.pubkey, s_fpr);
    ps_keystore_fingerprint(c_kp.pubkey, c_fpr);

    struct ps_at_ctx sctx, cctx;
    CHECK(ps_at_ctx_init(&sctx, PS_AT_SERVER, &s_kp, c_fpr) == 0);
    CHECK(ps_at_ctx_init(&cctx, PS_AT_CLIENT, &c_kp, s_fpr) == 0);

    uint16_t port;
    int lfd = open_listener(&port);
    CHECK(lfd >= 0);

    struct server_args sa = { &sctx, lfd, NULL, 0 };
    pthread_t tid;
    CHECK(pthread_create(&tid, NULL, server_thread, &sa) == 0);

    SSL *client = ps_at_connect(&cctx, "127.0.0.1", port);
    pthread_join(tid, NULL);
    close(lfd);

    CHECK(client != NULL);
    CHECK(sa.handshake_ok);

    /* Frame round-trip: client -> server -> client. */
    struct ps_ap_io cio, sio;
    ps_at_make_io(client, &cio);
    ps_at_make_io(sa.accepted, &sio);

    const char *req = "{\"type\":\"audit\",\"kind\":\"tls\"}";
    CHECK(ps_ap_write_frame(&cio, req, strlen(req)) == PS_AP_OK);
    uint8_t buf[1024]; size_t len;
    CHECK(ps_ap_read_frame(&sio, buf, sizeof(buf), &len) == PS_AP_OK);
    CHECK(len == strlen(req));
    CHECK(memcmp(buf, req, len) == 0);

    const char *reply = "{\"type\":\"finding\",\"payload\":{\"v\":1}}";
    CHECK(ps_ap_write_frame(&sio, reply, strlen(reply)) == PS_AP_OK);
    CHECK(ps_ap_read_frame(&cio, buf, sizeof(buf), &len) == PS_AP_OK);
    CHECK(len == strlen(reply));
    CHECK(memcmp(buf, reply, len) == 0);

    /* Peer fingerprint accessor. */
    char got[PS_KEYSTORE_FPR_HEX_SIZE];
    CHECK(ps_at_peer_fingerprint(client, got, sizeof(got)) == 0);
    CHECK(strcmp(got, s_fpr) == 0);
    CHECK(ps_at_peer_fingerprint(sa.accepted, got, sizeof(got)) == 0);
    CHECK(strcmp(got, c_fpr) == 0);

    ps_at_close(client);
    ps_at_close(sa.accepted);
    ps_at_ctx_destroy(&sctx);
    ps_at_ctx_destroy(&cctx);
    return 0;
}

static int test_wrong_pin_refused(void) {
    struct ps_keypair s_kp, c_kp, attacker_kp;
    CHECK(ps_keystore_generate(&s_kp) == 0);
    CHECK(ps_keystore_generate(&c_kp) == 0);
    CHECK(ps_keystore_generate(&attacker_kp) == 0);
    char attacker_fpr[PS_KEYSTORE_FPR_HEX_SIZE];
    char c_fpr[PS_KEYSTORE_FPR_HEX_SIZE];
    ps_keystore_fingerprint(attacker_kp.pubkey, attacker_fpr);
    ps_keystore_fingerprint(c_kp.pubkey, c_fpr);

    /* Server keeps its real keypair. Client expects to talk to attacker_fpr
     * (which does not match s_kp). Connection must be refused. */
    struct ps_at_ctx sctx, cctx;
    CHECK(ps_at_ctx_init(&sctx, PS_AT_SERVER, &s_kp, c_fpr) == 0);
    CHECK(ps_at_ctx_init(&cctx, PS_AT_CLIENT, &c_kp, attacker_fpr) == 0);

    uint16_t port;
    int lfd = open_listener(&port);
    CHECK(lfd >= 0);

    struct server_args sa = { &sctx, lfd, NULL, 0 };
    pthread_t tid;
    CHECK(pthread_create(&tid, NULL, server_thread, &sa) == 0);

    SSL *client = ps_at_connect(&cctx, "127.0.0.1", port);
    pthread_join(tid, NULL);
    close(lfd);

    CHECK(client == NULL); /* refused by pin check */
    if (sa.accepted) ps_at_close(sa.accepted);

    ps_at_ctx_destroy(&sctx);
    ps_at_ctx_destroy(&cctx);
    return 0;
}

#include <signal.h>
int main(void) {
    signal(SIGPIPE, SIG_IGN); /* peer-close mid-write must not kill us */
    if (test_handshake_and_frame_exchange()) return 1;
    if (test_wrong_pin_refused())            return 1;
    fprintf(stderr, "test_agent_transport: OK\n");
    return 0;
}
