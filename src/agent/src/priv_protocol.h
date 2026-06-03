#ifndef PS_PRIV_PROTOCOL_H
#define PS_PRIV_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Commands (brain → priv) */
#define PS_OP_OPEN_PCAP           0x01
#define PS_OP_CLOSE_PCAP          0x02
#define PS_OP_CREATE_RAW_SOCKET   0x03
#define PS_OP_CLOSE_RAW_SOCKET    0x04
#define PS_OP_SEND_RAW            0x05

/* Responses (priv → brain) */
#define PS_OP_PACKET_DATA         0x81
#define PS_OP_RAW_RESPONSE        0x82
#define PS_OP_ERROR               0x83
#define PS_OP_ACTIVITY_DATA       0x84   /* async priv -> brain: one activity record JSON */

/* Status codes */
#define PS_STATUS_OK              0x00
#define PS_STATUS_BAD_IFACE       0x01
#define PS_STATUS_BAD_FILTER      0x02
#define PS_STATUS_HANDLE_LIMIT    0x03
#define PS_STATUS_BAD_HANDLE      0x04
#define PS_STATUS_SEND_FAILED     0x05
#define PS_STATUS_INTERNAL        0xFF

/* Limits */
#define PS_MAX_PCAP_HANDLES       16
#define PS_MAX_RAW_HANDLES        32
#define PS_MAX_MSG_PAYLOAD        65536

#pragma pack(push, 1)
struct ps_priv_msg {
    uint8_t  opcode;
    uint8_t  status;
    uint16_t handle_id;
    uint32_t payload_len;
};
#pragma pack(pop)

/* All encode functions return total bytes written (header + payload), or 0 on overflow. */

static inline size_t ps_priv_encode_open_pcap(uint8_t *buf, size_t bufsz,
                                               const char *iface, const char *bpf_filter,
                                               uint32_t snaplen)
{
    size_t iface_len = strlen(iface) + 1;
    size_t filter_len = strlen(bpf_filter) + 1;
    size_t payload_len = iface_len + filter_len + 4;
    size_t total = sizeof(struct ps_priv_msg) + payload_len;
    if (total > bufsz) return 0;

    struct ps_priv_msg hdr = {0};
    hdr.opcode = PS_OP_OPEN_PCAP;
    hdr.payload_len = (uint32_t)payload_len;
    memcpy(buf, &hdr, sizeof(hdr));

    uint8_t *p = buf + sizeof(hdr);
    memcpy(p, iface, iface_len); p += iface_len;
    memcpy(p, bpf_filter, filter_len); p += filter_len;
    memcpy(p, &snaplen, 4);
    return total;
}

static inline size_t ps_priv_encode_close_handle(uint8_t *buf, size_t bufsz,
                                                  uint8_t opcode, uint16_t handle_id)
{
    size_t total = sizeof(struct ps_priv_msg);
    if (total > bufsz) return 0;

    struct ps_priv_msg hdr = {0};
    hdr.opcode = opcode;
    hdr.handle_id = handle_id;
    hdr.payload_len = 0;
    memcpy(buf, &hdr, sizeof(hdr));
    return total;
}

static inline size_t ps_priv_encode_create_raw_socket(uint8_t *buf, size_t bufsz,
                                                       uint8_t af, uint8_t proto)
{
    size_t total = sizeof(struct ps_priv_msg) + 2;
    if (total > bufsz) return 0;

    struct ps_priv_msg hdr = {0};
    hdr.opcode = PS_OP_CREATE_RAW_SOCKET;
    hdr.payload_len = 2;
    memcpy(buf, &hdr, sizeof(hdr));

    buf[sizeof(hdr)]     = af;
    buf[sizeof(hdr) + 1] = proto;
    return total;
}

static inline size_t ps_priv_encode_send_raw(uint8_t *buf, size_t bufsz,
                                              uint16_t handle_id, uint8_t ttl,
                                              const struct sockaddr *dest, socklen_t dest_len,
                                              const uint8_t *pkt, uint32_t pkt_len)
{
    size_t payload_len = 1 + 2 + dest_len + pkt_len;
    size_t total = sizeof(struct ps_priv_msg) + payload_len;
    if (total > bufsz) return 0;

    struct ps_priv_msg hdr = {0};
    hdr.opcode = PS_OP_SEND_RAW;
    hdr.handle_id = handle_id;
    hdr.payload_len = (uint32_t)payload_len;
    memcpy(buf, &hdr, sizeof(hdr));

    uint8_t *p = buf + sizeof(hdr);
    *p++ = ttl;
    uint16_t dl = (uint16_t)dest_len;
    memcpy(p, &dl, 2); p += 2;
    memcpy(p, dest, dest_len); p += dest_len;
    memcpy(p, pkt, pkt_len);
    return total;
}

static inline size_t ps_priv_encode_response(uint8_t *buf, size_t bufsz,
                                              uint8_t opcode, uint8_t status,
                                              uint16_t handle_id,
                                              const uint8_t *data, uint32_t data_len)
{
    size_t total = sizeof(struct ps_priv_msg) + data_len;
    if (total > bufsz) return 0;

    struct ps_priv_msg hdr = {0};
    hdr.opcode = opcode;
    hdr.status = status;
    hdr.handle_id = handle_id;
    hdr.payload_len = data_len;
    memcpy(buf, &hdr, sizeof(hdr));
    if (data_len > 0 && data) memcpy(buf + sizeof(hdr), data, data_len);
    return total;
}

static inline size_t ps_priv_encode_packet_data(uint8_t *buf, size_t bufsz,
                                                  uint16_t handle_id,
                                                  uint64_t ts_usec,
                                                  const uint8_t *pkt, uint32_t pkt_len)
{
    uint32_t data_len = 8 + pkt_len;
    size_t total = sizeof(struct ps_priv_msg) + data_len;
    if (total > bufsz) return 0;

    struct ps_priv_msg hdr = {0};
    hdr.opcode = PS_OP_PACKET_DATA;
    hdr.handle_id = handle_id;
    hdr.payload_len = data_len;
    memcpy(buf, &hdr, sizeof(hdr));

    uint8_t *p = buf + sizeof(hdr);
    memcpy(p, &ts_usec, 8); p += 8;
    memcpy(p, pkt, pkt_len);
    return total;
}

static inline size_t ps_priv_encode_activity(uint8_t *buf, size_t bufsz,
                                             const char *json, size_t json_len)
{
    size_t total = sizeof(struct ps_priv_msg) + json_len;
    if (total > bufsz) return 0;
    struct ps_priv_msg hdr = {0};
    hdr.opcode = PS_OP_ACTIVITY_DATA;
    hdr.payload_len = (uint32_t)json_len;
    memcpy(buf, &hdr, sizeof(hdr));
    memcpy(buf + sizeof(hdr), json, json_len);
    return total;
}

#endif /* PS_PRIV_PROTOCOL_H */
