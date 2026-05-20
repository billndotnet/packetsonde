/*
 * netflow_export.c — NetFlow v5/v9 exporter for PacketSonde Agent
 *
 * Serializes expired ps_flow records into NetFlow v5 or v9 UDP packets
 * and sends them to a collector.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "flow_tracker.h"
#include "netflow_export.h"
#include "log.h"

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

/* NetFlow v5 */
#define NFV5_HEADER_LEN    24
#define NFV5_RECORD_LEN    48
#define NFV5_MAX_RECORDS   30

/* NetFlow v9 */
#define NFV9_HEADER_LEN    20
#define NFV9_TEMPLATE_ID_V4  256
#define NFV9_TEMPLATE_ID_V6  257
#define NFV9_TEMPLATE_RESEND_PKTS   20
#define NFV9_TEMPLATE_RESEND_SEC   300

/* NetFlow v9 field type IDs */
#define NF9_IN_BYTES           1
#define NF9_IN_PKTS            2
#define NF9_PROTOCOL           4
#define NF9_TOS                5
#define NF9_TCP_FLAGS          6
#define NF9_L4_SRC_PORT        7
#define NF9_IPV4_SRC_ADDR      8
#define NF9_L4_DST_PORT       11
#define NF9_IPV4_DST_ADDR     12
#define NF9_IPV6_SRC_ADDR     27
#define NF9_IPV6_DST_ADDR     28
#define NF9_IPV6_FLOW_LABEL   31

/* Max UDP payload */
#define NF_MAX_PACKET        1400

/* ------------------------------------------------------------------ */
/* Exporter state                                                       */
/* ------------------------------------------------------------------ */

struct ps_nf_exporter {
    int       sock;
    int       version;           /* 5 or 9 */
    uint32_t  source_id;

    /* Counters */
    uint32_t  flow_sequence;     /* v5: flow count, v9: packet count */
    uint32_t  v9_pkt_sequence;

    /* Boot time (for sys_uptime calculation) */
    uint64_t  boot_time_sec;     /* seconds since epoch */

    /* v9 template tracking */
    uint32_t  v9_pkts_since_template;
    uint64_t  v9_last_template_sec;

    /* Resolved collector address */
    struct sockaddr_storage dest_ss;
    socklen_t               dest_sslen;
};

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static void put_u8(uint8_t *buf, int *off, uint8_t val)
{
    buf[*off] = val;
    *off += 1;
}

static void put_u16(uint8_t *buf, int *off, uint16_t val)
{
    buf[*off]     = (uint8_t)(val >> 8);
    buf[*off + 1] = (uint8_t)(val);
    *off += 2;
}

static void put_u32(uint8_t *buf, int *off, uint32_t val)
{
    buf[*off]     = (uint8_t)(val >> 24);
    buf[*off + 1] = (uint8_t)(val >> 16);
    buf[*off + 2] = (uint8_t)(val >> 8);
    buf[*off + 3] = (uint8_t)(val);
    *off += 4;
}

static void put_bytes(uint8_t *buf, int *off, const uint8_t *src, int n)
{
    memcpy(buf + *off, src, n);
    *off += n;
}

static uint32_t now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint32_t)ts.tv_sec;
}

static uint32_t sys_uptime_ms(const struct ps_nf_exporter *exp)
{
    uint32_t now = now_sec();
    return (now - (uint32_t)exp->boot_time_sec) * 1000;
}

/* Convert flow timestamp (usec since epoch) to sys_uptime (ms) */
static uint32_t flow_ts_to_uptime(const struct ps_nf_exporter *exp,
                                   uint64_t flow_ts_usec)
{
    uint64_t flow_sec = flow_ts_usec / 1000000;
    if (flow_sec < exp->boot_time_sec) return 0;
    return (uint32_t)(flow_sec - exp->boot_time_sec) * 1000 +
           (uint32_t)((flow_ts_usec % 1000000) / 1000);
}

static int send_udp(const struct ps_nf_exporter *exp,
                     const uint8_t *buf, int len)
{
    ssize_t n = sendto(exp->sock, buf, (size_t)len, 0,
                       (const struct sockaddr *)&exp->dest_ss,
                       exp->dest_sslen);
    if (n < 0) {
        ps_warn("netflow_export: sendto failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* NetFlow v5                                                           */
/* ------------------------------------------------------------------ */

static int
export_v5(struct ps_nf_exporter *exp, const struct ps_flow *flows, int count)
{
    int packets_sent = 0;
    int flow_idx = 0;

    while (flow_idx < count) {
        /* Count how many IPv4 flows fit in this packet */
        int batch = 0;
        int scan = flow_idx;
        while (scan < count && batch < NFV5_MAX_RECORDS) {
            if (flows[scan].key.af == AF_INET) {
                batch++;
            }
            scan++;
            if (batch >= NFV5_MAX_RECORDS) break;
        }

        if (batch == 0) {
            /* No IPv4 flows in remaining — skip all */
            flow_idx = scan;
            continue;
        }

        uint8_t buf[NFV5_HEADER_LEN + NFV5_MAX_RECORDS * NFV5_RECORD_LEN];
        int off = 0;

        /* Header */
        uint32_t uptime = sys_uptime_ms(exp);
        uint32_t unix_secs = now_sec();
        uint32_t unix_nsecs = 0;

        put_u16(buf, &off, 5);                   /* version */
        put_u16(buf, &off, (uint16_t)batch);      /* count */
        put_u32(buf, &off, uptime);                /* sys_uptime */
        put_u32(buf, &off, unix_secs);             /* unix_secs */
        put_u32(buf, &off, unix_nsecs);            /* unix_nsecs */
        put_u32(buf, &off, exp->flow_sequence);    /* flow_sequence */
        put_u8 (buf, &off, 0);                     /* engine_type */
        put_u8 (buf, &off, (uint8_t)(exp->source_id & 0xFF)); /* engine_id */
        put_u16(buf, &off, 0);                     /* sampling_interval */

        /* Records */
        int written = 0;
        while (flow_idx < count && written < batch) {
            const struct ps_flow *f = &flows[flow_idx];
            flow_idx++;

            if (f->key.af != AF_INET) continue;

            /* For bidirectional flows, we export the forward direction.
             * A more complete implementation would export two unidirectional
             * records, but for v1 this is sufficient. */
            put_bytes(buf, &off, f->key.src_addr, 4);   /* srcaddr */
            put_bytes(buf, &off, f->key.dst_addr, 4);   /* dstaddr */
            put_u32  (buf, &off, 0);                     /* nexthop */
            put_u16  (buf, &off, 0);                     /* input */
            put_u16  (buf, &off, 0);                     /* output */

            uint32_t pkts   = (uint32_t)(f->packets[0] + f->packets[1]);
            uint32_t octets = (uint32_t)(f->octets[0] + f->octets[1]);
            put_u32(buf, &off, pkts);                    /* dPkts */
            put_u32(buf, &off, octets);                  /* dOctets */

            put_u32(buf, &off, flow_ts_to_uptime(exp, f->flow_start)); /* First */
            put_u32(buf, &off, flow_ts_to_uptime(exp, f->flow_last));  /* Last */

            put_u16(buf, &off, f->key.src_port);         /* srcport */
            put_u16(buf, &off, f->key.dst_port);         /* dstport */
            put_u8 (buf, &off, 0);                       /* pad1 */
            put_u8 (buf, &off, f->tcp_flags[0] | f->tcp_flags[1]); /* tcp_flags */
            put_u8 (buf, &off, f->key.proto);            /* prot */
            put_u8 (buf, &off, f->key.tos);              /* tos */
            put_u16(buf, &off, 0);                       /* src_as */
            put_u16(buf, &off, 0);                       /* dst_as */
            put_u8 (buf, &off, 0);                       /* src_mask */
            put_u8 (buf, &off, 0);                       /* dst_mask */
            put_u16(buf, &off, 0);                       /* pad2 */

            written++;
        }

        if (send_udp(exp, buf, off) == 0) {
            packets_sent++;
            exp->flow_sequence += (uint32_t)written;
        }
    }

    return packets_sent;
}

/* ------------------------------------------------------------------ */
/* NetFlow v9                                                           */
/* ------------------------------------------------------------------ */

/*
 * IPv4 template (ID 256):
 *   IPV4_SRC_ADDR(8,4), IPV4_DST_ADDR(12,4), L4_SRC_PORT(7,2),
 *   L4_DST_PORT(11,2), PROTOCOL(4,1), IN_BYTES(1,4), IN_PKTS(2,4),
 *   TCP_FLAGS(6,1), TOS(5,1)
 */
struct nf9_template_field {
    uint16_t type;
    uint16_t length;
};

static const struct nf9_template_field tmpl_v4_fields[] = {
    { NF9_IPV4_SRC_ADDR, 4 },
    { NF9_IPV4_DST_ADDR, 4 },
    { NF9_L4_SRC_PORT,   2 },
    { NF9_L4_DST_PORT,   2 },
    { NF9_PROTOCOL,      1 },
    { NF9_IN_BYTES,      4 },
    { NF9_IN_PKTS,       4 },
    { NF9_TCP_FLAGS,     1 },
    { NF9_TOS,           1 },
};
#define TMPL_V4_NFIELDS  (sizeof(tmpl_v4_fields) / sizeof(tmpl_v4_fields[0]))
#define TMPL_V4_RECORD_LEN  (4+4+2+2+1+4+4+1+1)  /* 23 bytes */

/*
 * IPv6 template (ID 257):
 *   IPV6_SRC_ADDR(27,16), IPV6_DST_ADDR(28,16), L4_SRC_PORT(7,2),
 *   L4_DST_PORT(11,2), PROTOCOL(4,1), IN_BYTES(1,4), IN_PKTS(2,4),
 *   TCP_FLAGS(6,1), IPV6_FLOW_LABEL(31,4)
 */
static const struct nf9_template_field tmpl_v6_fields[] = {
    { NF9_IPV6_SRC_ADDR,    16 },
    { NF9_IPV6_DST_ADDR,    16 },
    { NF9_L4_SRC_PORT,       2 },
    { NF9_L4_DST_PORT,       2 },
    { NF9_PROTOCOL,          1 },
    { NF9_IN_BYTES,          4 },
    { NF9_IN_PKTS,           4 },
    { NF9_TCP_FLAGS,         1 },
    { NF9_IPV6_FLOW_LABEL,   4 },
};
#define TMPL_V6_NFIELDS  (sizeof(tmpl_v6_fields) / sizeof(tmpl_v6_fields[0]))
#define TMPL_V6_RECORD_LEN  (16+16+2+2+1+4+4+1+4)  /* 50 bytes */

static int
write_v9_header(uint8_t *buf, uint16_t nrecords, uint32_t uptime,
                uint32_t unix_secs, uint32_t sequence, uint32_t source_id)
{
    int off = 0;
    put_u16(buf, &off, 9);                    /* version */
    put_u16(buf, &off, nrecords);             /* count (flowsets, not flows) */
    put_u32(buf, &off, uptime);               /* sys_uptime */
    put_u32(buf, &off, unix_secs);            /* unix_secs */
    put_u32(buf, &off, sequence);             /* sequence */
    put_u32(buf, &off, source_id);            /* source_id */
    return off;
}

static int
write_template_flowset(uint8_t *buf, int max_len,
                       uint16_t template_id,
                       const struct nf9_template_field *fields,
                       int nfields)
{
    /* FlowSet header (4 bytes) + template header (4 bytes) + fields (4 each) */
    int flowset_len = 4 + 4 + nfields * 4;

    /* Pad to 4-byte boundary */
    int padded_len = (flowset_len + 3) & ~3;
    if (padded_len > max_len) return -1;

    int off = 0;
    put_u16(buf, &off, 0);                         /* FlowSet ID = 0 (template) */
    put_u16(buf, &off, (uint16_t)padded_len);       /* Length */
    put_u16(buf, &off, template_id);                 /* Template ID */
    put_u16(buf, &off, (uint16_t)nfields);           /* Field Count */

    for (int i = 0; i < nfields; i++) {
        put_u16(buf, &off, fields[i].type);
        put_u16(buf, &off, fields[i].length);
    }

    /* Pad with zeros */
    while (off < padded_len) {
        buf[off++] = 0;
    }

    return padded_len;
}

static int
write_v4_data_record(uint8_t *buf, int off, const struct ps_flow *f)
{
    put_bytes(buf, &off, f->key.src_addr, 4);
    put_bytes(buf, &off, f->key.dst_addr, 4);
    put_u16  (buf, &off, f->key.src_port);
    put_u16  (buf, &off, f->key.dst_port);
    put_u8   (buf, &off, f->key.proto);
    put_u32  (buf, &off, (uint32_t)(f->octets[0] + f->octets[1]));
    put_u32  (buf, &off, (uint32_t)(f->packets[0] + f->packets[1]));
    put_u8   (buf, &off, f->tcp_flags[0] | f->tcp_flags[1]);
    put_u8   (buf, &off, f->key.tos);
    return off;
}

static int
write_v6_data_record(uint8_t *buf, int off, const struct ps_flow *f)
{
    put_bytes(buf, &off, f->key.src_addr, 16);
    put_bytes(buf, &off, f->key.dst_addr, 16);
    put_u16  (buf, &off, f->key.src_port);
    put_u16  (buf, &off, f->key.dst_port);
    put_u8   (buf, &off, f->key.proto);
    put_u32  (buf, &off, (uint32_t)(f->octets[0] + f->octets[1]));
    put_u32  (buf, &off, (uint32_t)(f->packets[0] + f->packets[1]));
    put_u8   (buf, &off, f->tcp_flags[0] | f->tcp_flags[1]);
    put_u32  (buf, &off, f->flow_label);
    return off;
}

static int
need_template(struct ps_nf_exporter *exp)
{
    uint32_t now = now_sec();

    if (exp->v9_pkts_since_template >= NFV9_TEMPLATE_RESEND_PKTS)
        return 1;
    if ((now - (uint32_t)exp->v9_last_template_sec) >= NFV9_TEMPLATE_RESEND_SEC)
        return 1;
    if (exp->v9_last_template_sec == 0)
        return 1;

    return 0;
}

static int
export_v9(struct ps_nf_exporter *exp, const struct ps_flow *flows, int count)
{
    int packets_sent = 0;
    uint32_t uptime    = sys_uptime_ms(exp);
    uint32_t unix_secs = now_sec();

    /* Separate flows by AF */
    int v4_indices[count > 0 ? count : 1];
    int v6_indices[count > 0 ? count : 1];
    int v4_count = 0, v6_count = 0;

    for (int i = 0; i < count; i++) {
        if (flows[i].key.af == AF_INET)
            v4_indices[v4_count++] = i;
        else if (flows[i].key.af == AF_INET6)
            v6_indices[v6_count++] = i;
    }

    /* Send packets, including template when needed */
    int v4_sent = 0, v6_sent = 0;

    while (v4_sent < v4_count || v6_sent < v6_count) {
        uint8_t buf[NF_MAX_PACKET];
        int off = NFV9_HEADER_LEN;
        int flowset_count = 0;
        int send_tmpl = need_template(exp);

        /* Templates */
        if (send_tmpl) {
            int tmpl_len = write_template_flowset(
                buf + off, NF_MAX_PACKET - off,
                NFV9_TEMPLATE_ID_V4,
                tmpl_v4_fields, TMPL_V4_NFIELDS);
            if (tmpl_len > 0) {
                off += tmpl_len;
                flowset_count++;
            }

            if (v6_count > 0) {
                tmpl_len = write_template_flowset(
                    buf + off, NF_MAX_PACKET - off,
                    NFV9_TEMPLATE_ID_V6,
                    tmpl_v6_fields, TMPL_V6_NFIELDS);
                if (tmpl_len > 0) {
                    off += tmpl_len;
                    flowset_count++;
                }
            }

            exp->v9_pkts_since_template = 0;
            exp->v9_last_template_sec = unix_secs;
        }

        /* IPv4 data flowset */
        if (v4_sent < v4_count) {
            int fs_header_off = off;
            off += 4;  /* Reserve space for flowset header */

            int records = 0;
            while (v4_sent < v4_count &&
                   (off + TMPL_V4_RECORD_LEN) <= NF_MAX_PACKET) {
                off = write_v4_data_record(buf, off, &flows[v4_indices[v4_sent]]);
                v4_sent++;
                records++;
            }

            if (records > 0) {
                /* Pad to 4-byte boundary */
                int data_len = off - fs_header_off;
                int padded = (data_len + 3) & ~3;
                while (off < fs_header_off + padded)
                    buf[off++] = 0;

                /* Write flowset header */
                int hoff = fs_header_off;
                put_u16(buf, &hoff, NFV9_TEMPLATE_ID_V4);
                put_u16(buf, &hoff, (uint16_t)(off - fs_header_off));
                flowset_count++;
            } else {
                off = fs_header_off;  /* Revert */
            }
        }

        /* IPv6 data flowset */
        if (v6_sent < v6_count && off + 4 + TMPL_V6_RECORD_LEN <= NF_MAX_PACKET) {
            int fs_header_off = off;
            off += 4;

            int records = 0;
            while (v6_sent < v6_count &&
                   (off + TMPL_V6_RECORD_LEN) <= NF_MAX_PACKET) {
                off = write_v6_data_record(buf, off, &flows[v6_indices[v6_sent]]);
                v6_sent++;
                records++;
            }

            if (records > 0) {
                int data_len = off - fs_header_off;
                int padded = (data_len + 3) & ~3;
                while (off < fs_header_off + padded)
                    buf[off++] = 0;

                int hoff = fs_header_off;
                put_u16(buf, &hoff, NFV9_TEMPLATE_ID_V6);
                put_u16(buf, &hoff, (uint16_t)(off - fs_header_off));
                flowset_count++;
            } else {
                off = fs_header_off;
            }
        }

        if (flowset_count == 0) break;

        /* Write v9 header at start */
        write_v9_header(buf, (uint16_t)flowset_count, uptime,
                        unix_secs, exp->v9_pkt_sequence, exp->source_id);

        if (send_udp(exp, buf, off) == 0) {
            packets_sent++;
            exp->v9_pkt_sequence++;
            exp->v9_pkts_since_template++;
        }
    }

    exp->flow_sequence += (uint32_t)count;
    return packets_sent;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

struct ps_nf_exporter *
ps_nf_exporter_create(const char *collector_host, int collector_port,
                       uint32_t source_id, int version)
{
    if (!collector_host || (version != 5 && version != 9))
        return NULL;

    struct ps_nf_exporter *exp = calloc(1, sizeof(*exp));
    if (!exp) return NULL;

    exp->version   = version;
    exp->source_id = source_id;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    exp->boot_time_sec = (uint64_t)ts.tv_sec;

    /* Resolve collector address */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", collector_port);

    int rc = getaddrinfo(collector_host, port_str, &hints, &res);
    if (rc != 0) {
        ps_warn("netflow_export: getaddrinfo('%s:%d') failed: %s",
                collector_host, collector_port, gai_strerror(rc));
        free(exp);
        return NULL;
    }

    memcpy(&exp->dest_ss, res->ai_addr, res->ai_addrlen);
    exp->dest_sslen = res->ai_addrlen;

    /* Create UDP socket */
    exp->sock = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    freeaddrinfo(res);

    if (exp->sock < 0) {
        ps_warn("netflow_export: socket() failed: %s", strerror(errno));
        free(exp);
        return NULL;
    }

    ps_info("netflow_export: created v%d exporter -> %s:%d (source_id=%u)",
            version, collector_host, collector_port, source_id);

    return exp;
}

void
ps_nf_exporter_destroy(struct ps_nf_exporter *exp)
{
    if (!exp) return;
    if (exp->sock >= 0) close(exp->sock);
    free(exp);
}

int
ps_nf_exporter_send(struct ps_nf_exporter *exp,
                     const struct ps_flow *flows, int count)
{
    if (!exp || !flows || count <= 0) return 0;

    if (exp->version == 5)
        return export_v5(exp, flows, count);
    else
        return export_v9(exp, flows, count);
}
