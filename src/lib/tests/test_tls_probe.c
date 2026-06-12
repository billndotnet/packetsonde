/* Tests for the shared TLS primitive. The proto-table checks always run; the
 * live handshake checks need `openssl s_server` and run only under PS_TLS_LIVE=1. */
#include "tls_probe.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/ssl.h>

#define CHECK(c) do{ if(!(c)){ fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c); return 1; } }while(0)

static int test_proto_table(void) {
    CHECK(ps_tls_proto_id("TLS1.0") == TLS1_VERSION);
    CHECK(ps_tls_proto_id("TLS1.2") == TLS1_2_VERSION);
    CHECK(ps_tls_proto_id("TLS1.3") == TLS1_3_VERSION);
    CHECK(ps_tls_proto_id("SSLv3")  == SSL3_VERSION);
    CHECK(ps_tls_proto_id("bogus")  == -1);
    char lbl[16];
    ps_tls_proto_label(TLS1_2_VERSION, lbl, sizeof(lbl)); CHECK(strcmp(lbl, "TLS1.2") == 0);
    ps_tls_proto_label(TLS1_VERSION,   lbl, sizeof(lbl)); CHECK(strcmp(lbl, "TLS1.0") == 0);
    return 0;
}

/* ---- live fixture: generate a self-signed cert + fork openssl s_server ---- */

static pid_t g_srv = 0;

static int start_s_server(int port, const char *protoflag, const char *cipher) {
    if (system("openssl req -x509 -newkey rsa:2048 -keyout /tmp/ps_tlstest_k.pem "
               "-out /tmp/ps_tlstest_c.pem -days 1 -nodes -subj /CN=localhost "
               ">/dev/null 2>&1") != 0) return -1;
    char ports[16]; snprintf(ports, sizeof(ports), "%d", port);
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int dn = open("/dev/null", 1); if (dn >= 0) { dup2(dn, 1); dup2(dn, 2); }
        execlp("openssl", "openssl", "s_server", "-accept", ports,
               "-key", "/tmp/ps_tlstest_k.pem", "-cert", "/tmp/ps_tlstest_c.pem",
               protoflag, "-cipher", cipher, "-www", "-quiet", (char *)NULL);
        _exit(127);
    }
    g_srv = pid;
    /* wait for the listener */
    for (int i = 0; i < 50; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET; sa.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) { close(fd); return 0; }
        close(fd); usleep(100000);
    }
    return -1;
}

static void stop_s_server(void) {
    if (g_srv > 0) { kill(g_srv, SIGTERM); waitpid(g_srv, NULL, 0); g_srv = 0; }
}

static int raw_connect(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    return fd;
}

static int test_live(void) {
    const int P = 14433;
    if (start_s_server(P, "-tls1_2", "ECDHE-RSA-AES128-GCM-SHA256") != 0) {
        fprintf(stderr, "could not start s_server; skipping live\n"); stop_s_server(); return 0;
    }

    /* probe: TLS1.2 accepted, TLS1.0 rejected */
    struct ps_tls_probe_result r = {0};
    CHECK(ps_tls_probe("127.0.0.1", P, "TLS1.2", "TLS1.2", NULL, NULL, 3000, &r) == 0);
    CHECK(r.ok == 1);
    CHECK(strcmp(r.version, "TLS1.2") == 0);
    CHECK(strstr(r.cipher, "AES128-GCM") != NULL);

    struct ps_tls_probe_result r2 = {0};
    CHECK(ps_tls_probe("127.0.0.1", P, "TLS1.0", "TLS1.0", NULL, NULL, 3000, &r2) == 0);
    CHECK(r2.ok == 0);

    /* upgrade an existing fd: negotiated session + self-signed leaf facts */
    int fd = raw_connect(P);
    CHECK(fd >= 0);
    struct ps_tls_info info;
    SSL *ssl = ps_tls_upgrade_fd(fd, "localhost", NULL, 3000, &info);
    CHECK(ssl != NULL);
    CHECK(strcmp(info.version, "TLS1.2") == 0);
    CHECK(info.cert_self_signed == 1);
    CHECK(strcmp(info.cert_subject_cn, "localhost") == 0);
    CHECK(strcmp(info.cert_key_type, "RSA") == 0);
    CHECK(info.cert_key_bits == 2048);
    CHECK(info.ja4[0] == 't');           /* TCP JA4 */
    SSL_free(ssl); close(fd);

    stop_s_server();
    return 0;
}

int main(void) {
    if (test_proto_table() != 0) return 1;
    if (getenv("PS_TLS_LIVE")) { if (test_live() != 0) { stop_s_server(); return 1; } }
    printf("ok\n");
    return 0;
}
