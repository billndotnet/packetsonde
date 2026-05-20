#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "ipc_server.h"

static void test_encode_frame(void)
{
    uint8_t buf[256];
    const char *channel = "traceroute.hop";
    const char *payload = "{\"hop_number\":3}";

    int len = ps_ipc_encode_frame(buf, sizeof(buf), channel, payload, (uint32_t)strlen(payload));
    assert(len > 0);

    uint32_t ch_len;
    memcpy(&ch_len, buf, 4);
    assert(ch_len == strlen(channel));

    char decoded_ch[64];
    memcpy(decoded_ch, buf + 4, ch_len);
    decoded_ch[ch_len] = '\0';
    assert(strcmp(decoded_ch, channel) == 0);

    uint32_t pl_len;
    memcpy(&pl_len, buf + 4 + ch_len, 4);
    assert(pl_len == strlen(payload));

    char decoded_pl[256];
    memcpy(decoded_pl, buf + 4 + ch_len + 4, pl_len);
    decoded_pl[pl_len] = '\0';
    assert(strcmp(decoded_pl, payload) == 0);

    printf("  PASS: encode/decode frame\n");
}

static void test_frame_reader(void)
{
    struct ps_frame_reader reader;
    ps_frame_reader_init(&reader);

    const char *channel = "test.ch";
    const char *payload = "{\"x\":1}";

    uint8_t wire[256];
    int wire_len = ps_ipc_encode_frame(wire, sizeof(wire), channel, payload, (uint32_t)strlen(payload));
    assert(wire_len > 0);

    int got_frame = 0;
    for (int i = 0; i < wire_len; i++) {
        int rc = ps_frame_reader_feed(&reader, wire[i]);
        if (rc == 1) {
            got_frame = 1;
            assert(strcmp(reader.channel, "test.ch") == 0);
            assert(reader.payload_len == strlen(payload));
            assert(memcmp(reader.payload, payload, reader.payload_len) == 0);
        }
    }
    assert(got_frame);

    ps_frame_reader_free(&reader);
    printf("  PASS: incremental frame reader\n");
}

int main(void)
{
    printf("test_ipc_framing:\n");
    test_encode_frame();
    test_frame_reader();
    printf("All tests passed.\n");
    return 0;
}
