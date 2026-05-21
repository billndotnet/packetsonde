#include "audit_module.h"
#include "audit_common.h"
#include "../args.h"
#include "finding.h"
#include "ulid.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/evp.h>

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    return ps_audit_parse_target(spec, host, host_sz, 22, port);
}

/* Connect + read the SSH version banner. Returns the still-open fd on
 * success so a caller can continue the SSH handshake (KEXINIT etc.).
 * The caller closes. Returns -1 on failure. */
static int connect_and_read_banner(const char *host, uint16_t port, int timeout_ms,
                                   char *ip_out, size_t ip_out_sz,
                                   char *banner_out, size_t banner_sz) {
    int fd = ps_audit_tcp_connect(host, port, timeout_ms, ip_out, ip_out_sz);
    if (fd < 0) return -1;

    /* SSH server sends the version banner first. Read until first \n. */
    size_t got = 0;
    while (got < banner_sz - 1) {
        char c;
        ssize_t r = recv(fd, &c, 1, 0);
        if (r <= 0) break;
        if (c == '\n') break;
        if (c == '\r') continue;
        if (c >= 0x20 && c < 0x7f) banner_out[got++] = c;
    }
    banner_out[got] = '\0';
    if (banner_out[0] == '\0') { close(fd); return -1; }
    return fd;
}

/* RFC 4253 §6 binary packet:
 *   uint32 packet_length    (excludes mac, excludes itself)
 *   byte   padding_length
 *   byte[] payload          (packet_length - padding_length - 1 bytes)
 *   byte[] random padding
 *   byte[] mac              (zero bytes before KEX completes)
 *
 * For KEXINIT we're pre-encryption and pre-MAC, so the wire layout is
 * exactly packet_length(4) + padding_length(1) + payload + padding.
 *
 * Reads one packet from fd into payload_out. Returns payload length on
 * success, -1 on error. */
static int read_ssh_packet(int fd, uint8_t *payload_out, size_t cap) {
    uint8_t hdr[5];
    size_t got = 0;
    while (got < 5) {
        ssize_t r = recv(fd, hdr + got, 5 - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    uint32_t pkt_len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16)
                     | ((uint32_t)hdr[2] << 8)  |  (uint32_t)hdr[3];
    uint8_t pad_len = hdr[4];
    if (pkt_len < 1u + pad_len) return -1;
    if (pkt_len > 65535) return -1;       /* sanity */
    size_t body_len = pkt_len - 1;        /* bytes still to read = payload+padding */
    if (body_len > cap + pad_len) return -1;
    uint8_t buf[70000];
    if (body_len > sizeof(buf)) return -1;
    got = 0;
    while (got < body_len) {
        ssize_t r = recv(fd, buf + got, body_len - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    size_t payload_len = body_len - pad_len;
    if (payload_len > cap) return -1;
    memcpy(payload_out, buf, payload_len);
    return (int)payload_len;
}

/* Send a minimal SSH version banner so the server will follow up with
 * its SSH_MSG_KEXINIT. Format per RFC 4253 §4.2: "SSH-2.0-<software>\r\n". */
static int send_banner(int fd) {
    static const char banner[] = "SSH-2.0-packetsonde\r\n";
    return (send(fd, banner, sizeof(banner) - 1, 0) == (ssize_t)(sizeof(banner) - 1))
           ? 0 : -1;
}

/* Read a uint32 length + string at *off in buf, advance *off, and
 * write the string into out (NUL-terminated, truncated to out_sz-1).
 * Returns 0 on success, -1 on overrun. */
static int parse_namelist(const uint8_t *buf, size_t buf_len, size_t *off,
                          char *out, size_t out_sz) {
    if (*off + 4 > buf_len) return -1;
    uint32_t L = ((uint32_t)buf[*off] << 24) | ((uint32_t)buf[*off + 1] << 16)
               | ((uint32_t)buf[*off + 2] << 8)  |  (uint32_t)buf[*off + 3];
    *off += 4;
    if (*off + L > buf_len) return -1;
    size_t k = L < out_sz - 1 ? L : out_sz - 1;
    memcpy(out, buf + *off, k);
    out[k] = '\0';
    *off += L;
    return 0;
}

static void md5_hex(const char *s, char *out_hex /* 33 bytes */) {
    unsigned char dig[16]; unsigned int dl = 0;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_DigestInit_ex(m, EVP_md5(), NULL);
    EVP_DigestUpdate(m, s, strlen(s));
    EVP_DigestFinal_ex(m, dig, &dl);
    EVP_MD_CTX_free(m);
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out_hex[i * 2]     = H[dig[i] >> 4];
        out_hex[i * 2 + 1] = H[dig[i] & 0x0f];
    }
    out_hex[32] = '\0';
}

/* Read the server's SSH_MSG_KEXINIT (msg type 20) and extract the four
 * algorithm name-lists needed for HASSH-Server:
 *   kex_algorithms ; encryption_algorithms_server_to_client ;
 *   mac_algorithms_server_to_client ; compression_algorithms_server_to_client
 *
 * KEXINIT payload layout (RFC 4253 §7.1):
 *   byte    SSH_MSG_KEXINIT = 20
 *   byte[16] cookie
 *   name-list kex_algorithms
 *   name-list server_host_key_algorithms
 *   name-list encryption_algorithms_client_to_server
 *   name-list encryption_algorithms_server_to_client
 *   name-list mac_algorithms_client_to_server
 *   name-list mac_algorithms_server_to_client
 *   name-list compression_algorithms_client_to_server
 *   name-list compression_algorithms_server_to_client
 *   (further fields not needed for HASSH)
 *
 * Returns 0 on success. */
static int read_kexinit_hassh(int fd,
                              char *kex,       size_t kex_sz,
                              char *enc_s2c,   size_t enc_sz,
                              char *mac_s2c,   size_t mac_sz,
                              char *cmp_s2c,   size_t cmp_sz,
                              char *hassh_md5_out) {
    uint8_t payload[65536];
    int plen = read_ssh_packet(fd, payload, sizeof(payload));
    if (plen < 17 || payload[0] != 20 /* SSH_MSG_KEXINIT */) return -1;
    size_t off = 1 + 16;  /* skip msg type + cookie */

    char skip[2048];
    if (parse_namelist(payload, (size_t)plen, &off, kex,     kex_sz) != 0) return -1;
    if (parse_namelist(payload, (size_t)plen, &off, skip,    sizeof(skip)) != 0) return -1; /* host key algos */
    if (parse_namelist(payload, (size_t)plen, &off, skip,    sizeof(skip)) != 0) return -1; /* enc c2s */
    if (parse_namelist(payload, (size_t)plen, &off, enc_s2c, enc_sz) != 0) return -1;
    if (parse_namelist(payload, (size_t)plen, &off, skip,    sizeof(skip)) != 0) return -1; /* mac c2s */
    if (parse_namelist(payload, (size_t)plen, &off, mac_s2c, mac_sz) != 0) return -1;
    if (parse_namelist(payload, (size_t)plen, &off, skip,    sizeof(skip)) != 0) return -1; /* compr c2s */
    if (parse_namelist(payload, (size_t)plen, &off, cmp_s2c, cmp_sz) != 0) return -1;

    /* HASSH-Server = MD5(kex ; enc_s2c ; mac_s2c ; cmp_s2c). */
    char joined[4 * 2048 + 8];
    snprintf(joined, sizeof(joined), "%s;%s;%s;%s", kex, enc_s2c, mac_s2c, cmp_s2c);
    md5_hex(joined, hassh_md5_out);
    return 0;
}

/* Returns 1 if the banner indicates a known-old / known-vulnerable OpenSSH.
 * Heuristic: OpenSSH < 7.4 is genuinely old (released 2016-12); flag those. */
static int openssh_is_old(const char *banner, char *ver_out, size_t ver_sz) {
    ver_out[0] = '\0';
    const char *p = strstr(banner, "OpenSSH_");
    if (!p) return 0;
    p += 8;
    /* Parse major.minor */
    int major = 0, minor = 0;
    if (sscanf(p, "%d.%d", &major, &minor) < 2) return 0;
    /* Copy version token */
    size_t k = 0;
    while (p[k] && (isdigit((unsigned char)p[k]) || p[k] == '.' || p[k] == 'p') && k < ver_sz - 1) {
        ver_out[k] = p[k]; k++;
    }
    ver_out[k] = '\0';
    if (major < 7) return 1;
    if (major == 7 && minor < 4) return 1;
    return 0;
}

static int ssh_run(int argc, char **argv,
                      const struct ps_args *opts,
                      const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit ssh <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 22;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit ssh: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    char ip[64] = "", banner[256] = "";
    int fd = connect_and_read_banner(host, port, 4000,
                                     ip, sizeof(ip), banner, sizeof(banner));
    if (fd < 0) {
        fprintf(stderr, "audit ssh: no banner from %s:%u\n", host, port); return 1;
    }
    if (strncmp(banner, "SSH-", 4) != 0) {
        fprintf(stderr, "audit ssh: %s:%u does not speak SSH (got %.80s)\n",
                host, port, banner);
        close(fd); return 1;
    }

    /* Continue the SSH handshake far enough to capture the server's
     * KEXINIT, then compute HASSH-Server. Failure here is non-fatal —
     * the banner-level findings still go out. */
    char kex[2048] = "", enc_s2c[2048] = "", mac_s2c[2048] = "", cmp_s2c[2048] = "";
    char hassh[33] = "";
    if (send_banner(fd) == 0) {
        read_kexinit_hassh(fd, kex, sizeof(kex), enc_s2c, sizeof(enc_s2c),
                           mac_s2c, sizeof(mac_s2c), cmp_s2c, sizeof(cmp_s2c),
                           hassh);
    }
    close(fd);

    /* Banner format: SSH-protoversion-softwareversion[ comments] */
    char esc[256]; size_t k = 0;
    for (size_t i = 0; banner[i] && k + 2 < sizeof(esc); i++) {
        unsigned char c = (unsigned char)banner[i];
        if (c == '"' || c == '\\') { esc[k++] = '\\'; esc[k++] = (char)c; }
        else esc[k++] = (char)c;
    }
    esc[k] = '\0';

    /* tls.metadata equivalent — record what we saw. */
    {
        char ev[8192];
        if (hassh[0]) {
            snprintf(ev, sizeof(ev),
                     "{\"banner\":\"%s\",\"hassh_server\":\"%s\","
                     "\"kex_algorithms\":\"%s\","
                     "\"encryption_algorithms_server_to_client\":\"%s\","
                     "\"mac_algorithms_server_to_client\":\"%s\","
                     "\"compression_algorithms_server_to_client\":\"%s\"}",
                     esc, hassh, kex, enc_s2c, mac_s2c, cmp_s2c);
        } else {
            snprintf(ev, sizeof(ev), "{\"banner\":\"%s\"}", esc);
        }
        char title[320];
        snprintf(title, sizeof(title), "SSH banner: %s", banner);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.ssh", self_host,
                        "ssh.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    /* Version disclosure — SSH banners always disclose software version per RFC,
     * so this is an info-severity acknowledgement, not a security finding. We
     * only flag if the version is identifiably old. */
    {
        char ver[64];
        if (openssh_is_old(banner, ver, sizeof(ver))) {
            char ev[256];
            snprintf(ev, sizeof(ev),
                     "{\"software\":\"OpenSSH\",\"version\":\"%s\","
                     "\"recommended_minimum\":\"7.4\"}", ver);
            char title[256];
            snprintf(title, sizeof(title),
                     "OpenSSH %s is older than 7.4 (released Dec 2016)", ver);
            struct ps_finding f;
            ps_finding_init(&f, run_id, "cli.audit.ssh", self_host,
                            "ssh.old_version", PS_SEV_MEDIUM, PS_CONF_FIRM, title);
            ps_finding_set_target_ip(&f, ip, port);
            ps_finding_set_target_hostname(&f, host, port);
            ps_finding_set_evidence_json(&f, ev);
            api->emit(&f);
        }
    }
    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "ssh",
    .summary     = "Audit SSH server: banner, known-old version",
    .run         = ssh_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_ssh_module(void) { return &MODULE; }
