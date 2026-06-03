#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "priv_protocol.h"

static void test_header_size(void)
{
    assert(sizeof(struct ps_priv_msg) == 8);
    printf("  PASS: header size is 8 bytes\n");
}

static void test_encode_decode_open_pcap(void)
{
    uint8_t buf[512];
    const char *iface = "en0";
    const char *filter = "arp";
    uint32_t snaplen = 96;

    size_t len = ps_priv_encode_open_pcap(buf, sizeof(buf), iface, filter, snaplen);
    assert(len > 0);

    struct ps_priv_msg hdr;
    memcpy(&hdr, buf, sizeof(hdr));
    assert(hdr.opcode == PS_OP_OPEN_PCAP);
    assert(hdr.payload_len == len - sizeof(hdr));

    const uint8_t *p = buf + sizeof(hdr);
    assert(strcmp((const char *)p, "en0") == 0);
    p += strlen("en0") + 1;
    assert(strcmp((const char *)p, "arp") == 0);
    p += strlen("arp") + 1;
    uint32_t decoded_snaplen;
    memcpy(&decoded_snaplen, p, 4);
    assert(decoded_snaplen == 96);

    printf("  PASS: encode/decode OPEN_PCAP\n");
}

static void test_encode_decode_send_raw(void)
{
    uint8_t buf[512];
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = 0x08080808;

    uint8_t pkt[] = { 0x08, 0x00, 0xab, 0xcd };
    size_t len = ps_priv_encode_send_raw(buf, sizeof(buf), 3, 5,
                                          (struct sockaddr *)&dest, sizeof(dest),
                                          pkt, sizeof(pkt));
    assert(len > 0);

    struct ps_priv_msg hdr;
    memcpy(&hdr, buf, sizeof(hdr));
    assert(hdr.opcode == PS_OP_SEND_RAW);
    assert(hdr.handle_id == 3);

    printf("  PASS: encode/decode SEND_RAW\n");
}

static void test_encode_create_raw_socket_v6(void)
{
    uint8_t buf[64];
    size_t len = ps_priv_encode_create_raw_socket(buf, sizeof(buf), AF_INET6, 58); /* IPPROTO_ICMPV6 = 58 */
    assert(len > 0);

    struct ps_priv_msg hdr;
    memcpy(&hdr, buf, sizeof(hdr));
    assert(hdr.opcode == PS_OP_CREATE_RAW_SOCKET);
    assert(hdr.payload_len == 2);

    const uint8_t *p = buf + sizeof(hdr);
    assert(p[0] == AF_INET6);
    assert(p[1] == 58);

    printf("  PASS: encode CREATE_RAW_SOCKET IPv6\n");
}

int main(void)
{
    printf("test_priv_protocol:\n");
    test_header_size();
    test_encode_decode_open_pcap();
    test_encode_decode_send_raw();
    test_encode_create_raw_socket_v6();

    /* activity async frame encode round-trip */
    {
        uint8_t ab[256];
        const char *j = "{\"v\":1}";
        size_t an = ps_priv_encode_activity(ab, sizeof ab, j, strlen(j));
        assert(an == sizeof(struct ps_priv_msg) + strlen(j));
        struct ps_priv_msg ahdr;
        memcpy(&ahdr, ab, sizeof ahdr);
        assert(ahdr.opcode == PS_OP_ACTIVITY_DATA);
        assert(ahdr.payload_len == strlen(j));
        assert(memcmp(ab + sizeof ahdr, j, strlen(j)) == 0);
    }

    printf("All tests passed.\n");
    return 0;
}
