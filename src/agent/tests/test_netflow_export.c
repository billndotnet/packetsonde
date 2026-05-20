/*
 * test_netflow_export -- captures real exporter output on loopback and
 * validates the on-wire bytes for NetFlow v5, NetFlow v9, and IPFIX.
 *
 * The receiver is a plain UDP socket; we drain packets and parse them
 * with the same field layouts a real collector would expect.
 */
#include "flow_tracker.h"
#include "netflow_export.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

void ps_info(const char *fmt, ...) { (void)fmt; }
void ps_warn(const char *fmt, ...) { (void)fmt; }
void ps_error(const char *fmt, ...) { (void)fmt; }
void ps_debug(const char *fmt, ...) { (void)fmt; }

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); return 1; } \
} while (0)

static int open_listener(uint16_t *port_out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in la; memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(0x7f000001);
    la.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&la, sizeof(la)) != 0) { close(fd); return -1; }
    socklen_t l = sizeof(la);
    getsockname(fd, (struct sockaddr *)&la, &l);
    *port_out = ntohs(la.sin_port);
    struct timeval tv = { 1, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return fd;
}

static void make_v4_flow(struct ps_flow *f, uint64_t now_us) {
    memset(f, 0, sizeof(*f));
    f->key.af = AF_INET; f->key.proto = 6; /* TCP */
    f->key.src_addr[0] = 10; f->key.src_addr[1] = 0;
    f->key.src_addr[2] = 0;  f->key.src_addr[3] = 5;
    f->key.dst_addr[0] = 192; f->key.dst_addr[1] = 0;
    f->key.dst_addr[2] = 2;   f->key.dst_addr[3] = 80;
    f->key.src_port = 51000; f->key.dst_port = 443;
    f->packets[0] = 10; f->packets[1] = 8;
    f->octets [0] = 1500; f->octets[1] = 1200;
    f->tcp_flags[0] = 0x18; f->tcp_flags[1] = 0x18;
    f->flow_start = now_us - 5000000;
    f->flow_last  = now_us;
}

static uint16_t rb16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rb32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}
static uint64_t rb64(const uint8_t *p) {
    uint64_t v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | p[i]; return v;
}

static int test_v9_has_timestamps(void) {
    uint16_t port;
    int rfd = open_listener(&port);
    CHECK(rfd >= 0);

    struct ps_nf_exporter *exp = ps_nf_exporter_create("127.0.0.1", port, 0xabcd, 9);
    CHECK(exp != NULL);

    struct ps_flow f;
    struct timeval tv; gettimeofday(&tv, NULL);
    uint64_t now_us = (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
    make_v4_flow(&f, now_us);

    CHECK(ps_nf_exporter_send(exp, &f, 1) > 0);

    /* Receive packet(s). First one will include the template. */
    uint8_t buf[2048];
    ssize_t n = recv(rfd, buf, sizeof(buf), 0);
    CHECK(n > 20);
    CHECK(rb16(buf) == 9); /* version */
    /* Walk flowsets looking for the v4 template (ID 256) and verify the
     * last two fields are FIRST_SWITCHED (22) + LAST_SWITCHED (21). */
    int found_first = 0, found_last = 0;
    size_t p = 20;
    while (p + 4 <= (size_t)n) {
        uint16_t set_id = rb16(buf + p);
        uint16_t set_len = rb16(buf + p + 2);
        if (set_len < 4 || p + set_len > (size_t)n) break;
        if (set_id == 0) {
            /* template flowset */
            size_t q = p + 4;
            while (q + 4 <= p + set_len) {
                uint16_t tid = rb16(buf + q);
                uint16_t nf  = rb16(buf + q + 2);
                q += 4;
                if (tid != 256) { q += nf * 4; continue; }
                /* check field list */
                for (int i = 0; i < nf && q + 4 <= p + set_len; i++) {
                    uint16_t ft = rb16(buf + q);
                    if (ft == 22) found_first = 1;
                    if (ft == 21) found_last  = 1;
                    q += 4;
                }
            }
        }
        p += set_len;
    }
    CHECK(found_first);
    CHECK(found_last);

    ps_nf_exporter_destroy(exp);
    close(rfd);
    return 0;
}

static int test_ipfix_wire_format(void) {
    uint16_t port;
    int rfd = open_listener(&port);
    CHECK(rfd >= 0);

    struct ps_nf_exporter *exp = ps_nf_exporter_create("127.0.0.1", port, 42, 10);
    CHECK(exp != NULL);

    struct ps_flow f;
    struct timeval tv; gettimeofday(&tv, NULL);
    uint64_t now_us = (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
    make_v4_flow(&f, now_us);

    CHECK(ps_nf_exporter_send(exp, &f, 1) > 0);

    uint8_t buf[2048];
    ssize_t n = recv(rfd, buf, sizeof(buf), 0);
    CHECK(n >= 16);
    CHECK(rb16(buf) == 10);              /* IPFIX version */
    CHECK(rb16(buf + 2) == (uint16_t)n); /* length */
    /* Observation Domain ID = source_id (42) at offset 12. */
    CHECK(rb32(buf + 12) == 42);

    /* Walk sets. Expect a template set (ID=2) then a v4 data set (ID=256). */
    size_t p = 16;
    int saw_template_v4 = 0;
    int saw_data_v4 = 0;
    int saw_flow_start_ms = 0;
    while (p + 4 <= (size_t)n) {
        uint16_t set_id  = rb16(buf + p);
        uint16_t set_len = rb16(buf + p + 2);
        if (set_len < 4 || p + set_len > (size_t)n) break;
        if (set_id == 2) {
            /* IPFIX template set; walk template records. */
            size_t q = p + 4;
            while (q + 4 <= p + set_len) {
                uint16_t tid = rb16(buf + q);
                uint16_t nf  = rb16(buf + q + 2);
                q += 4;
                if (tid == 256) {
                    saw_template_v4 = 1;
                    for (int i = 0; i < nf && q + 4 <= p + set_len; i++) {
                        if (rb16(buf + q) == 152) saw_flow_start_ms = 1;
                        q += 4;
                    }
                } else {
                    q += nf * 4;
                }
            }
        } else if (set_id == 256) {
            saw_data_v4 = 1;
            /* Layout: srcIP(4) dstIP(4) sp(2) dp(2) proto(1) tcp(1) tos(1)
             * octets(8) packets(8) start_ms(8) end_ms(8). Check counters. */
            const uint8_t *rec = buf + p + 4;
            uint64_t octets  = rb64(rec + 4 + 4 + 2 + 2 + 1 + 1 + 1);
            uint64_t packets = rb64(rec + 4 + 4 + 2 + 2 + 1 + 1 + 1 + 8);
            uint64_t start_ms = rb64(rec + 4 + 4 + 2 + 2 + 1 + 1 + 1 + 16);
            CHECK(octets == 2700);
            CHECK(packets == 18);
            CHECK(start_ms > 0);
        }
        p += set_len;
    }
    CHECK(saw_template_v4);
    CHECK(saw_data_v4);
    CHECK(saw_flow_start_ms);

    ps_nf_exporter_destroy(exp);
    close(rfd);
    return 0;
}

static int test_v5_still_works(void) {
    uint16_t port;
    int rfd = open_listener(&port);
    CHECK(rfd >= 0);
    struct ps_nf_exporter *exp = ps_nf_exporter_create("127.0.0.1", port, 1, 5);
    CHECK(exp != NULL);
    struct ps_flow f;
    struct timeval tv; gettimeofday(&tv, NULL);
    uint64_t now_us = (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
    make_v4_flow(&f, now_us);
    CHECK(ps_nf_exporter_send(exp, &f, 1) > 0);
    uint8_t buf[2048];
    ssize_t n = recv(rfd, buf, sizeof(buf), 0);
    CHECK(n >= 24);
    CHECK(rb16(buf) == 5);
    CHECK(rb16(buf + 2) == 1); /* one record */
    ps_nf_exporter_destroy(exp);
    close(rfd);
    return 0;
}

int main(void) {
    if (test_v5_still_works())          return 1;
    if (test_v9_has_timestamps())       return 1;
    if (test_ipfix_wire_format())       return 1;
    fprintf(stderr, "test_netflow_export: OK\n");
    return 0;
}
