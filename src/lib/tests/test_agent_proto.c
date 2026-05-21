#include "agent_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); return 1; } } while (0)

/* In-memory ring used as a paired read/write target for round-trip tests. */
struct mem_io {
    uint8_t  buf[16384];
    size_t   r, w;
};

static ssize_t mem_read(void *ctx, void *buf, size_t n) {
    struct mem_io *m = ctx;
    size_t avail = m->w - m->r;
    if (avail == 0) return -1; /* would block; emulate as I/O error for tests */
    if (n > avail) n = avail;
    memcpy(buf, m->buf + m->r, n);
    m->r += n;
    return (ssize_t)n;
}
static ssize_t mem_write(void *ctx, const void *buf, size_t n) {
    struct mem_io *m = ctx;
    if (m->w + n > sizeof(m->buf)) return -1;
    memcpy(m->buf + m->w, buf, n);
    m->w += n;
    return (ssize_t)n;
}

static int test_roundtrip(void) {
    struct mem_io m = {0};
    struct ps_ap_io io = { mem_read, mem_write, &m };
    const char *p1 = "{\"type\":\"hello\",\"v\":1}";
    CHECK(ps_ap_write_frame(&io, p1, strlen(p1)) == PS_AP_OK);
    const char *p2 = "{\"type\":\"finding\",\"payload\":{\"kind\":\"tls.metadata\"}}";
    CHECK(ps_ap_write_frame(&io, p2, strlen(p2)) == PS_AP_OK);

    uint8_t buf[1024]; size_t len;
    CHECK(ps_ap_read_frame(&io, buf, sizeof(buf), &len) == PS_AP_OK);
    CHECK(len == strlen(p1));
    CHECK(memcmp(buf, p1, len) == 0);
    CHECK(ps_ap_read_frame(&io, buf, sizeof(buf), &len) == PS_AP_OK);
    CHECK(len == strlen(p2));
    CHECK(memcmp(buf, p2, len) == 0);
    return 0;
}

static int test_oversize_refused(void) {
    struct mem_io m = {0};
    struct ps_ap_io io = { mem_read, mem_write, &m };
    /* Manually craft a length header claiming 2 MiB; should be refused
     * BEFORE we attempt to read 2 MiB of body. */
    uint8_t hdr[4] = { 0x00, 0x20, 0x00, 0x00 }; /* 2 MiB */
    mem_write(&m, hdr, 4);
    uint8_t buf[1024]; size_t len;
    int rc = ps_ap_read_frame(&io, buf, sizeof(buf), &len);
    CHECK(rc == PS_AP_ERR_OVERSIZE);
    return 0;
}

static int test_short_buffer(void) {
    struct mem_io m = {0};
    struct ps_ap_io io = { mem_read, mem_write, &m };
    /* Write a valid 50-byte frame. */
    char payload[50]; memset(payload, '.', sizeof(payload));
    payload[0] = '{'; payload[49] = '}';
    CHECK(ps_ap_write_frame(&io, payload, sizeof(payload)) == PS_AP_OK);
    uint8_t buf[16]; size_t len;
    CHECK(ps_ap_read_frame(&io, buf, sizeof(buf), &len) == PS_AP_ERR_SHORT);
    return 0;
}

static int test_bad_json_payload(void) {
    struct mem_io m = {0};
    struct ps_ap_io io = { mem_read, mem_write, &m };
    /* Length 10, payload "not-json!!" -- should be flagged as PS_AP_ERR_BAD_JSON. */
    uint8_t hdr[4] = { 0, 0, 0, 10 };
    mem_write(&m, hdr, 4);
    mem_write(&m, "not-json!!", 10);
    uint8_t buf[64]; size_t len;
    CHECK(ps_ap_read_frame(&io, buf, sizeof(buf), &len) == PS_AP_ERR_BAD_JSON);
    return 0;
}

static int test_frame_type(void) {
    char out[32];
    const char *a = "{\"type\":\"hello\",\"v\":1}";
    CHECK(ps_ap_frame_type((const uint8_t *)a, strlen(a), out, sizeof(out)) == 0);
    CHECK(strcmp(out, "hello") == 0);

    /* type may appear after other keys */
    const char *b = "{\"foo\":\"bar\",\"v\":1,\"type\":\"finding\"}";
    CHECK(ps_ap_frame_type((const uint8_t *)b, strlen(b), out, sizeof(out)) == 0);
    CHECK(strcmp(out, "finding") == 0);

    /* nested objects must not confuse the scanner */
    const char *c = "{\"payload\":{\"type\":\"junk\"},\"type\":\"log\"}";
    CHECK(ps_ap_frame_type((const uint8_t *)c, strlen(c), out, sizeof(out)) == 0);
    CHECK(strcmp(out, "log") == 0);

    /* missing type yields -1 */
    const char *d = "{\"v\":1}";
    CHECK(ps_ap_frame_type((const uint8_t *)d, strlen(d), out, sizeof(out)) == -1);
    return 0;
}

int main(void) {
    if (test_roundtrip())          return 1;
    if (test_oversize_refused())   return 1;
    if (test_short_buffer())       return 1;
    if (test_bad_json_payload())   return 1;
    if (test_frame_type())         return 1;
    fprintf(stderr, "test_agent_proto: OK\n");
    return 0;
}
