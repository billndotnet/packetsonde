/*
 * dns_listener.c — Passive DNS/mDNS listener for PacketSonde Agent
 *
 * Captures DNS responses (QR=1) on port 53 and 5353 (mDNS).
 * Parses A, AAAA, PTR records in the answer section.
 * Parses EDNS OPT records (type 41) in the additional section for
 * ECS (option 8) and NSID (option 3) data.
 *
 * Publishes to "discovery.dns".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "packetsonde/module_api.h"
#include "json.h"
#include "log.h"

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

#define DNS_HDR_LEN       12
#define ETH_HDR_LEN       14
#define ETH_TYPE_IPV4     0x0800
#define ETH_TYPE_IPV6     0x86DD

#define DNS_FLAG_QR       0x8000   /* Query=0, Response=1 */

#define DNS_TYPE_A        1
#define DNS_TYPE_NS       2
#define DNS_TYPE_CNAME    5
#define DNS_TYPE_PTR      12
#define DNS_TYPE_AAAA     28
#define DNS_TYPE_OPT      41       /* EDNS pseudo-RR */

#define EDNS_OPT_NSID     3
#define EDNS_OPT_ECS      8

#define DNS_MAX_NAME      256
#define DNS_MAX_ANSWERS   32
#define DNS_DECOMP_LIMIT  10       /* max pointer hops (avoid infinite loops) */

/* IPv6 extension header next-header values we recognise as headers
 * (not upper-layer protocols) */
#define IPV6_EXT_HOP_BY_HOP  0
#define IPV6_EXT_DEST_OPTS   60
#define IPV6_EXT_ROUTING     43
#define IPV6_EXT_FRAGMENT    44
#define IPV6_EXT_AUTH        51
#define IPV6_EXT_ESP         50

/* ------------------------------------------------------------------ */
/* Module state                                                         */
/* ------------------------------------------------------------------ */

struct dns_state {
    int pcap_handle;
};

/* ------------------------------------------------------------------ */
/* DNS name decompression                                               */
/* ------------------------------------------------------------------ */

/*
 * Decompress a DNS name starting at byte offset `offset` within `pkt`.
 * Writes the dotted-label string into `out` (NUL-terminated, max out_size).
 * Returns the number of bytes consumed in the packet at `offset`
 * (for pointer labels, only the 2-byte pointer counts, not the target).
 * Returns -1 on error (truncated, invalid, or too deeply nested).
 */
static int dns_decompress_name(const uint8_t *pkt, int pkt_len, int offset,
                                char *out, int out_size)
{
    int out_pos   = 0;
    int consumed  = -1;   /* bytes consumed at the original offset */
    int hops      = 0;
    int cur       = offset;
    int first_seg = 1;

    while (cur < pkt_len) {
        uint8_t len_byte = pkt[cur];

        if (len_byte == 0) {
            /* End of name */
            if (consumed == -1) consumed = cur - offset + 1;
            break;
        }

        if ((len_byte & 0xC0) == 0xC0) {
            /* Pointer: 14-bit offset */
            if (cur + 1 >= pkt_len) return -1;
            if (consumed == -1) consumed = cur - offset + 2;
            if (++hops > DNS_DECOMP_LIMIT) return -1;

            int ptr = ((len_byte & 0x3F) << 8) | pkt[cur + 1];
            if (ptr >= pkt_len) return -1;
            cur = ptr;
            continue;
        }

        if ((len_byte & 0xC0) != 0) {
            /* Reserved / extended label type — not supported */
            return -1;
        }

        /* Literal label */
        int label_len = len_byte;
        cur++;  /* advance past length byte */

        if (cur + label_len > pkt_len) return -1;

        /* Append "." separator (except before the first label) */
        if (!first_seg) {
            if (out_pos + 1 >= out_size) return -1;
            out[out_pos++] = '.';
        }
        first_seg = 0;

        if (out_pos + label_len >= out_size) return -1;
        memcpy(out + out_pos, pkt + cur, (size_t)label_len);
        out_pos += label_len;
        cur     += label_len;
    }

    if (cur >= pkt_len && consumed == -1) return -1;

    out[out_pos] = '\0';
    return consumed;
}

/* ------------------------------------------------------------------ */
/* Skip a DNS name at offset, return bytes consumed (for iteration)    */
/* ------------------------------------------------------------------ */

static int dns_skip_name(const uint8_t *pkt, int pkt_len, int offset)
{
    int cur = offset;

    while (cur < pkt_len) {
        uint8_t b = pkt[cur];

        if (b == 0) {
            return cur - offset + 1;
        }
        if ((b & 0xC0) == 0xC0) {
            /* Pointer — consumes exactly 2 bytes */
            if (cur + 1 >= pkt_len) return -1;
            return cur - offset + 2;
        }
        if ((b & 0xC0) != 0) {
            return -1;
        }
        /* Literal label */
        int label_len = b;
        cur += 1 + label_len;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* Strip network headers, return offset to DNS payload                 */
/* ------------------------------------------------------------------ */

/*
 * Returns the byte offset into `pkt` where the DNS message begins.
 * Returns -1 if the packet cannot contain a valid DNS message.
 */
static int strip_headers(const uint8_t *pkt, int pkt_len)
{
    if (pkt_len < ETH_HDR_LEN + 1) return -1;

    /* Ethernet */
    uint16_t ethertype;
    memcpy(&ethertype, pkt + 12, 2);
    ethertype = ntohs(ethertype);

    int ip_off = ETH_HDR_LEN;

    if (ethertype == ETH_TYPE_IPV4) {
        /* IPv4 */
        if (ip_off + 20 > pkt_len) return -1;
        int ip_hl = (pkt[ip_off] & 0x0F) * 4;
        if (ip_hl < 20 || ip_off + ip_hl + 8 > pkt_len) return -1;
        uint8_t proto = pkt[ip_off + 9];
        if (proto != 17 /* UDP */) return -1;
        int udp_off = ip_off + ip_hl;
        if (udp_off + 8 > pkt_len) return -1;
        return udp_off + 8;

    } else if (ethertype == ETH_TYPE_IPV6) {
        /* IPv6 — walk extension headers */
        if (ip_off + 40 > pkt_len) return -1;
        uint8_t next_hdr = pkt[ip_off + 6];
        int cur = ip_off + 40;

        while (cur < pkt_len) {
            if (next_hdr == 17 /* UDP */) {
                if (cur + 8 > pkt_len) return -1;
                return cur + 8;
            }
            /* Extension headers we can skip */
            if (next_hdr == IPV6_EXT_HOP_BY_HOP ||
                next_hdr == IPV6_EXT_DEST_OPTS  ||
                next_hdr == IPV6_EXT_ROUTING) {
                if (cur + 2 > pkt_len) return -1;
                next_hdr = pkt[cur];
                int ext_len = (pkt[cur + 1] + 1) * 8;
                cur += ext_len;
            } else if (next_hdr == IPV6_EXT_FRAGMENT) {
                /* Fragment header is fixed 8 bytes */
                if (cur + 8 > pkt_len) return -1;
                next_hdr = pkt[cur];
                cur += 8;
            } else {
                /* Upper-layer or unknown — not UDP */
                return -1;
            }
        }
        return -1;
    }

    return -1;
}

/* ------------------------------------------------------------------ */
/* Answer record                                                        */
/* ------------------------------------------------------------------ */

struct dns_answer {
    char     name[DNS_MAX_NAME];
    uint16_t type;
    uint32_t ttl;
    char     data[DNS_MAX_NAME];   /* formatted rdata: IP string or domain */
};

/* ------------------------------------------------------------------ */
/* EDNS info                                                            */
/* ------------------------------------------------------------------ */

struct dns_edns {
    int  has_ecs;
    int  ecs_family;          /* 1=IPv4, 2=IPv6 */
    int  ecs_src_prefix;
    char ecs_subnet[64];      /* "198.51.100.0/24" */
    int  has_nsid;
    char nsid[128];           /* printable ASCII or hex */
};

/* ------------------------------------------------------------------ */
/* Parse DNS message and publish                                        */
/* ------------------------------------------------------------------ */

static void dns_parse_and_publish(ps_module_ctx_t *ctx,
                                   const uint8_t *pkt, int pkt_len,
                                   int dns_off)
{
    const uint8_t *dns = pkt + dns_off;
    int dns_len = pkt_len - dns_off;

    if (dns_len < DNS_HDR_LEN) return;

    /* DNS header fields */
    uint16_t flags;
    memcpy(&flags, dns + 2, 2);
    flags = ntohs(flags);

    /* Must be a response (QR=1) */
    if (!(flags & DNS_FLAG_QR)) return;

    uint16_t qdcount, ancount, nscount, arcount;
    memcpy(&qdcount, dns + 4,  2); qdcount = ntohs(qdcount);
    memcpy(&ancount, dns + 6,  2); ancount = ntohs(ancount);
    memcpy(&nscount, dns + 8,  2); nscount = ntohs(nscount);
    memcpy(&arcount, dns + 10, 2); arcount = ntohs(arcount);

    int pos = DNS_HDR_LEN;  /* position within dns[] */

    /* ---- Skip question section ---- */
    char first_query[DNS_MAX_NAME] = {0};

    for (int q = 0; q < (int)qdcount && pos < dns_len; q++) {
        char qname[DNS_MAX_NAME] = {0};
        int n = dns_decompress_name(dns, dns_len, pos, qname, sizeof(qname));
        if (n < 0) return;
        if (q == 0) memcpy(first_query, qname, sizeof(first_query));
        pos += n;
        pos += 4;  /* QTYPE(2) + QCLASS(2) */
        if (pos > dns_len) return;
    }

    /* ---- Parse answer section ---- */
    struct dns_answer answers[DNS_MAX_ANSWERS];
    int answer_count = 0;

    int section_count = (int)ancount + (int)nscount;  /* answers + authority */
    /* We only care about answer records, skip authority */
    for (int r = 0; r < section_count && pos < dns_len; r++) {
        char rname[DNS_MAX_NAME] = {0};
        int n = dns_decompress_name(dns, dns_len, pos, rname, sizeof(rname));
        if (n < 0) return;
        pos += n;

        if (pos + 10 > dns_len) return;

        uint16_t rtype, rclass;
        uint32_t rttl;
        uint16_t rdlen;
        memcpy(&rtype,  dns + pos,     2); rtype  = ntohs(rtype);
        memcpy(&rclass, dns + pos + 2, 2); rclass = ntohs(rclass);
        memcpy(&rttl,   dns + pos + 4, 4); rttl   = ntohl(rttl);
        memcpy(&rdlen,  dns + pos + 8, 2); rdlen  = ntohs(rdlen);
        pos += 10;

        if (pos + (int)rdlen > dns_len) return;

        /* Only store records from the answer section */
        if (r < (int)ancount && answer_count < DNS_MAX_ANSWERS) {
            struct dns_answer *ans = &answers[answer_count];
            memcpy(ans->name, rname, sizeof(ans->name));
            ans->type = rtype;
            ans->ttl  = rttl;
            ans->data[0] = '\0';

            if (rtype == DNS_TYPE_A && rdlen == 4) {
                struct in_addr a;
                memcpy(&a, dns + pos, 4);
                inet_ntop(AF_INET, &a, ans->data, sizeof(ans->data));
                answer_count++;
            } else if (rtype == DNS_TYPE_AAAA && rdlen == 16) {
                struct in6_addr a6;
                memcpy(&a6, dns + pos, 16);
                inet_ntop(AF_INET6, &a6, ans->data, sizeof(ans->data));
                answer_count++;
            } else if (rtype == DNS_TYPE_PTR) {
                int nm = dns_decompress_name(dns, dns_len, pos,
                                             ans->data, sizeof(ans->data));
                if (nm >= 0) answer_count++;
            } else {
                /* unsupported type — still count the record but no data */
                answer_count++;
            }
        }

        pos += (int)rdlen;
    }

    /* If no useful answers, bail early */
    if (answer_count == 0) return;

    /* ---- Parse additional section (for OPT/EDNS) ---- */
    struct dns_edns edns;
    memset(&edns, 0, sizeof(edns));

    for (int r = 0; r < (int)arcount && pos < dns_len; r++) {
        /* OPT record has an empty name (single zero byte) */
        int name_start = pos;
        int n = dns_skip_name(dns, dns_len, pos);
        if (n < 0) break;
        pos += n;

        if (pos + 10 > dns_len) break;

        uint16_t rtype, rdlen;
        memcpy(&rtype, dns + pos,     2); rtype = ntohs(rtype);
        memcpy(&rdlen, dns + pos + 8, 2); rdlen = ntohs(rdlen);
        pos += 10;

        if (pos + (int)rdlen > dns_len) break;

        if (rtype == DNS_TYPE_OPT) {
            /* Walk EDNS options */
            int opt_pos = pos;
            int opt_end = pos + (int)rdlen;

            while (opt_pos + 4 <= opt_end) {
                uint16_t opt_code, opt_len;
                memcpy(&opt_code, dns + opt_pos,     2); opt_code = ntohs(opt_code);
                memcpy(&opt_len,  dns + opt_pos + 2, 2); opt_len  = ntohs(opt_len);
                opt_pos += 4;

                if (opt_pos + (int)opt_len > opt_end) break;

                if (opt_code == EDNS_OPT_ECS && opt_len >= 4) {
                    /* family(2) + src_prefix(1) + scope_prefix(1) + addr(variable) */
                    uint16_t family;
                    memcpy(&family, dns + opt_pos, 2); family = ntohs(family);
                    uint8_t src_prefix   = dns[opt_pos + 2];
                    /* scope_prefix = dns[opt_pos + 3]; not stored */

                    edns.has_ecs       = 1;
                    edns.ecs_family    = (int)family;
                    edns.ecs_src_prefix = (int)src_prefix;

                    int addr_bytes = (int)opt_len - 4;
                    if (family == 1 && addr_bytes <= 4) {
                        /* IPv4 — pad to 4 bytes */
                        uint8_t addr4[4] = {0};
                        memcpy(addr4, dns + opt_pos + 4, (size_t)addr_bytes);
                        struct in_addr a;
                        memcpy(&a, addr4, 4);
                        char addr_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &a, addr_str, sizeof(addr_str));
                        snprintf(edns.ecs_subnet, sizeof(edns.ecs_subnet),
                                 "%s/%d", addr_str, (int)src_prefix);
                    } else if (family == 2 && addr_bytes <= 16) {
                        /* IPv6 — pad to 16 bytes */
                        uint8_t addr6[16] = {0};
                        memcpy(addr6, dns + opt_pos + 4, (size_t)addr_bytes);
                        struct in6_addr a6;
                        memcpy(&a6, addr6, 16);
                        char addr_str[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6, &a6, addr_str, sizeof(addr_str));
                        snprintf(edns.ecs_subnet, sizeof(edns.ecs_subnet),
                                 "%s/%d", addr_str, (int)src_prefix);
                    }

                } else if (opt_code == EDNS_OPT_NSID && opt_len > 0) {
                    edns.has_nsid = 1;
                    /* Copy as ASCII if printable, else hex */
                    int all_print = 1;
                    for (int i = 0; i < (int)opt_len; i++) {
                        uint8_t c = dns[opt_pos + i];
                        if (c < 0x20 || c > 0x7E) { all_print = 0; break; }
                    }
                    if (all_print) {
                        int copy_len = (int)opt_len < (int)sizeof(edns.nsid) - 1
                                     ? (int)opt_len : (int)sizeof(edns.nsid) - 1;
                        memcpy(edns.nsid, dns + opt_pos, (size_t)copy_len);
                        edns.nsid[copy_len] = '\0';
                    } else {
                        /* Hex encode */
                        int hex_out = 0;
                        for (int i = 0; i < (int)opt_len && hex_out + 3 < (int)sizeof(edns.nsid); i++) {
                            snprintf(edns.nsid + hex_out, sizeof(edns.nsid) - (size_t)hex_out,
                                     "%02x", dns[opt_pos + i]);
                            hex_out += 2;
                        }
                        edns.nsid[hex_out] = '\0';
                    }
                }

                opt_pos += (int)opt_len;
            }
        }

        pos += (int)rdlen;
        (void)name_start;
    }

    /* ---- Determine query name ---- */
    /* Use first_query if available, else first answer name */
    const char *query_name = first_query[0] ? first_query : answers[0].name;

    /* ---- Determine type string for the top-level "type" field ---- */
    const char *type_str = "UNKNOWN";
    if (answer_count > 0) {
        switch (answers[0].type) {
        case DNS_TYPE_A:    type_str = "A";    break;
        case DNS_TYPE_AAAA: type_str = "AAAA"; break;
        case DNS_TYPE_PTR:  type_str = "PTR";  break;
        case DNS_TYPE_CNAME: type_str = "CNAME"; break;
        case DNS_TYPE_NS:   type_str = "NS";   break;
        default:            type_str = "OTHER"; break;
        }
    }

    /* ---- Build EDNS sub-object (if present) ---- */
    /*
     * ps_json has no key+object emit helper. Strategy: build the edns
     * portion into a scratch buffer as a standalone JSON object, then
     * splice it into the main buffer via ps_json_key_string with the
     * pre-built value — but that would double-escape the braces.
     *
     * Correct approach: build the full JSON in one pass. For the "edns"
     * key we use ps_json_key_string with a placeholder value, then rewrite
     * the placeholder by hand (backing up j.len past the closing `"` of
     * the empty string value and writing a JSON object there instead).
     * This is safe because ps_json writes to a flat char buffer.
     */

    /* ---- Build JSON ---- */
    char buf[4096];
    struct ps_json j;
    ps_json_init(&j, buf, sizeof(buf));

    ps_json_object_begin(&j);
    ps_json_key_string(&j, "query", query_name);
    ps_json_key_string(&j, "type",  type_str);

    /* answers array */
    ps_json_array_begin(&j, "answers");
    for (int i = 0; i < answer_count; i++) {
        const struct dns_answer *ans = &answers[i];

        const char *atype = "OTHER";
        switch (ans->type) {
        case DNS_TYPE_A:    atype = "A";    break;
        case DNS_TYPE_AAAA: atype = "AAAA"; break;
        case DNS_TYPE_PTR:  atype = "PTR";  break;
        case DNS_TYPE_CNAME: atype = "CNAME"; break;
        case DNS_TYPE_NS:   atype = "NS";   break;
        }

        ps_json_object_begin(&j);
        ps_json_key_string(&j, "name", ans->name);
        ps_json_key_string(&j, "type", atype);
        ps_json_key_string(&j, "data", ans->data);
        ps_json_key_int   (&j, "ttl",  (int64_t)ans->ttl);
        ps_json_object_end(&j);
    }
    ps_json_array_end(&j);

    /* edns object */
    if (edns.has_ecs || edns.has_nsid) {
        /*
         * Emit `"edns":""` then rewind the closing `"` of the empty string
         * and write a real object `{...}` in its place. This keeps the
         * ps_json comma/depth state consistent for the outer object_end.
         */
        ps_json_key_string(&j, "edns", "");

        if (!j.error && j.len >= 1) {
            /* j.buf[j.len-1] is the closing `"` of the empty string value.
             * Back up one byte and overwrite with the edns object. */
            j.len--;  /* erase the trailing `"` */

            /* Write the edns object directly into the remainder of buf */
            char *edns_buf = buf + j.len;
            size_t edns_cap = sizeof(buf) - j.len;
            struct ps_json je;
            ps_json_init(&je, edns_buf, edns_cap);
            ps_json_object_begin(&je);
            if (edns.has_ecs) {
                ps_json_key_string(&je, "ecs_subnet", edns.ecs_subnet);
                ps_json_key_int   (&je, "ecs_family", (int64_t)edns.ecs_family);
            }
            if (edns.has_nsid) {
                ps_json_key_string(&je, "nsid", edns.nsid);
            }
            ps_json_object_end(&je);
            if (ps_json_finish(&je) > 0) {
                j.len += (size_t)je.len;
                /* needs_comma already set to 1 by ps_json_key_string above */
            } else {
                j.error = 1;
            }
        }
    }

    ps_json_object_end(&j);

    if (ps_json_finish(&j) > 0) {
        ctx->publish(ctx, "discovery.dns", buf, (uint32_t)j.len);
    } else {
        ps_warn("dns_listener: JSON buffer overflow on packet");
    }
}

/* ------------------------------------------------------------------ */
/* Module callbacks                                                     */
/* ------------------------------------------------------------------ */

static int dns_init(ps_module_ctx_t *ctx)
{
    struct dns_state *st = calloc(1, sizeof(*st));
    if (!st) {
        ps_error("dns_listener: out of memory");
        return -1;
    }

    st->pcap_handle = -1;

    ctx->userdata = st;
    ps_info("dns_listener: initialized");
    return 0;
}

static void dns_shutdown(ps_module_ctx_t *ctx)
{
    free(ctx->userdata);
    ctx->userdata = NULL;
    ps_info("dns_listener: shutdown");
}

static void dns_on_packet(ps_module_ctx_t *ctx, const uint8_t *pkt,
                           uint32_t len, uint64_t ts_usec, int handle_id)
{
    struct dns_state *st = (struct dns_state *)ctx->userdata;
    if (!st) return;

    (void)ts_usec;
    (void)handle_id;

    if ((int)len < ETH_HDR_LEN + 1) return;

    int dns_off = strip_headers(pkt, (int)len);
    if (dns_off < 0) return;

    dns_parse_and_publish(ctx, pkt, (int)len, dns_off);
}

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

#ifndef PS_DNS_LISTENER_TESTING

const ps_module_t ps_dns_listener_module = {
    .name        = "dns_listener",
    .description = "DNS/mDNS listener with EDNS ECS/NSID parsing",
    .version     = "1.0",
    .flags       = PS_MOD_PASSIVE | PS_MOD_NEEDS_PCAP,

    .init        = dns_init,
    .shutdown    = dns_shutdown,
    .on_packet   = dns_on_packet,
    .on_job      = NULL,
    .on_response = NULL,
    .tick        = NULL,
};

#endif /* PS_DNS_LISTENER_TESTING */
