/*
 * discovery_listener.c -- agent-side responder for packetsonde discovery.
 *
 * Inspects every passive-captured broadcast packet for a PSDP magic at the
 * UDP payload offset. On a valid + authorized + non-replayed probe, sends
 * a signed unicast UDP reply via an ordinary DGRAM socket to the probe's
 * source IP:port. No listening socket is ever bound -- the agent stays
 * invisible to port scans (see docs/specs/agent-discovery-brainstorm.md).
 *
 * Configuration (env-based for v1):
 *   PS_DISCOVERY_ENABLED            -- "1" to enable (default off)
 *   PS_KEY_DIR                      -- where the agent's keypair lives
 *   PS_DISCOVERY_AGENT_KEY          -- key name in PS_KEY_DIR (default "agent")
 *   PS_DISCOVERY_AUTHORIZED_DIR     -- dir of allowed .pub files; defaults
 *                                      to $PS_KEY_DIR/authorized
 *   PS_DISCOVERY_LISTEN_IP          -- IPv4 to advertise in replies
 *                                      (default: agent's primary v4)
 *   PS_DISCOVERY_LISTEN_PORT        -- u16 to advertise (default 0 -- means
 *                                      "main agent listener not exposed yet")
 *   PS_DISCOVERY_MAX_SKEW_MS_CAP    -- hard cap on probe.max_skew_ms; the
 *                                      effective window is min(probe, cap).
 *                                      default 30000 (30 s)
 */

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "packetsonde/module_api.h"
#include "log.h"
#include "discovery.h"
#include "keystore.h"

#define ETH_HDR_LEN     14
#define ETHERTYPE_IPV4  0x0800
#define MAX_AUTHORIZED  64

struct discovery_state {
    int                          enabled;
    struct ps_keypair            kp;             /* agent's identity */
    uint8_t                      authorized[MAX_AUTHORIZED][32];
    size_t                       authorized_n;
    uint16_t                     max_skew_cap_ms;
    uint16_t                     listen_port;
    uint8_t                      listen_ip_v4mapped[16];
    struct ps_discovery_replay   replay;
    int                          have_listen_ip;
};

static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void load_authorized(struct discovery_state *st, const char *dir) {
    DIR *d = opendir(dir);
    if (!d) {
        ps_info("discovery_listener: authorized dir '%s' not present (no pubkeys loaded)", dir);
        return;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL && st->authorized_n < MAX_AUTHORIZED) {
        size_t n = strlen(de->d_name);
        if (n < 5 || strcmp(de->d_name + n - 4, ".pub") != 0) continue;
        char p[1024];
        snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        FILE *f = fopen(p, "rb");
        if (!f) continue;
        if (fread(st->authorized[st->authorized_n], 1, 32, f) == 32) {
            st->authorized_n++;
        }
        fclose(f);
    }
    closedir(d);
    ps_info("discovery_listener: loaded %zu authorized pubkey(s) from %s",
            st->authorized_n, dir);
}

/* Best-effort primary v4 (first non-loopback, non-link-local IPv4). */
static int detect_primary_v4(uint8_t out_v4mapped[16]) {
    struct ifaddrs *ifap;
    if (getifaddrs(&ifap) != 0) return -1;
    int found = 0;
    for (struct ifaddrs *ia = ifap; ia; ia = ia->ifa_next) {
        if (!ia->ifa_addr || ia->ifa_addr->sa_family != AF_INET) continue;
        if (!(ia->ifa_flags & 0x1) /* IFF_UP */) continue;
        struct sockaddr_in *sin = (struct sockaddr_in *)ia->ifa_addr;
        uint32_t a = ntohl(sin->sin_addr.s_addr);
        if ((a & 0xff000000) == 0x7f000000) continue;        /* 127/8 */
        if ((a & 0xffff0000) == 0xa9fe0000) continue;        /* 169.254/16 */
        memset(out_v4mapped, 0, 16);
        out_v4mapped[10] = 0xff; out_v4mapped[11] = 0xff;
        out_v4mapped[12] = (a >> 24) & 0xff;
        out_v4mapped[13] = (a >> 16) & 0xff;
        out_v4mapped[14] = (a >>  8) & 0xff;
        out_v4mapped[15] = a & 0xff;
        found = 1; break;
    }
    freeifaddrs(ifap);
    return found ? 0 : -1;
}

static void send_reply(struct discovery_state *st,
                       const struct ps_discovery_probe *p,
                       uint32_t client_v4_be, uint16_t client_port) {
    struct ps_discovery_reply r = {0};
    r.version = PS_DISCOVERY_VERSION;
    memcpy(r.nonce, p->nonce, PS_DISCOVERY_NONCE_SIZE);
    memcpy(r.listen_ip, st->listen_ip_v4mapped, 16);
    r.listen_port = st->listen_port;
    memcpy(r.agent_pub, st->kp.pubkey, PS_DISCOVERY_PUBKEY_SIZE);
    if (ps_discovery_reply_sign(&r, st->kp.seckey) != 0) {
        ps_warn("discovery_listener: sign failed");
        return;
    }
    uint8_t wire[PS_DISCOVERY_REPLY_SIZE];
    ps_discovery_reply_pack(&r, wire);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { ps_warn("discovery_listener: socket: %s", strerror(errno)); return; }
    struct sockaddr_in to; memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(client_port);
    to.sin_addr.s_addr = client_v4_be;
    sendto(fd, wire, sizeof(wire), 0, (struct sockaddr *)&to, sizeof(to));
    close(fd);
}

static void on_packet(ps_module_ctx_t *ctx,
                       const uint8_t *pkt, uint32_t len,
                       uint64_t ts_usec, int handle_id) {
    (void)ts_usec; (void)handle_id;
    struct discovery_state *st = ctx->userdata;
    if (!st || !st->enabled) return;

    /* Ethernet broadcast IPv4 UDP only. */
    if (len < ETH_HDR_LEN + 20 + 8 + PS_DISCOVERY_PROBE_SIZE) return;
    const uint8_t *dst_mac = pkt;
    if (!(dst_mac[0] == 0xff && dst_mac[1] == 0xff && dst_mac[2] == 0xff &&
          dst_mac[3] == 0xff && dst_mac[4] == 0xff && dst_mac[5] == 0xff)) return;
    if (read_be16(pkt + 12) != ETHERTYPE_IPV4) return;

    const uint8_t *ip = pkt + ETH_HDR_LEN;
    int ihl = (ip[0] & 0x0f) * 4;
    if (ihl < 20) return;
    if (ip[9] != 17) return; /* not UDP */
    if (ETH_HDR_LEN + ihl + 8 + PS_DISCOVERY_PROBE_SIZE > len) return;

    const uint8_t *udp = ip + ihl;
    uint16_t src_port = read_be16(udp + 0);
    uint16_t udp_len = read_be16(udp + 4);
    if (udp_len < 8 + PS_DISCOVERY_PROBE_SIZE) return;

    const uint8_t *payload = udp + 8;
    if (memcmp(payload, PS_DISCOVERY_MAGIC_PROBE, 4) != 0) return;

    struct ps_discovery_probe p;
    if (ps_discovery_probe_unpack(&p, payload) != 0) return;
    if (p.version != PS_DISCOVERY_VERSION) return;

    /* Authorization: pubkey must be in the allowed set. */
    int allowed = 0;
    for (size_t i = 0; i < st->authorized_n; i++) {
        if (memcmp(st->authorized[i], p.pubkey, 32) == 0) { allowed = 1; break; }
    }
    if (!allowed) return;

    /* Signature verify (last gate before we do timestamp/replay -- order
     * matters because verify is the expensive step). */
    if (!ps_discovery_probe_verify(&p)) return;

    /* Timestamp window. */
    uint64_t now_ms = ps_discovery_now_ms();
    uint16_t skew_ms = p.max_skew_ms;
    if (skew_ms > st->max_skew_cap_ms) skew_ms = st->max_skew_cap_ms;
    if (skew_ms == 0) skew_ms = PS_DISCOVERY_DEFAULT_SKEW_MS;
    uint64_t delta = (now_ms > p.timestamp_ms) ? (now_ms - p.timestamp_ms)
                                                : (p.timestamp_ms - now_ms);
    if (delta > skew_ms) return;

    /* Replay LRU. */
    uint64_t expires_at = now_ms + 2ULL * skew_ms;
    if (ps_discovery_replay_check(&st->replay, p.pubkey, p.nonce,
                                  expires_at, now_ms) == 1) {
        return; /* replay */
    }

    /* Source IPv4 from IP header. */
    uint32_t src_v4_be;
    memcpy(&src_v4_be, ip + 12, 4);

    ps_info("discovery_listener: valid probe from src_port=%u, replying", src_port);
    send_reply(st, &p, src_v4_be, src_port);
}

static int dlist_init(ps_module_ctx_t *ctx) {
    const char *enabled_env = getenv("PS_DISCOVERY_ENABLED");
    int enabled = (enabled_env && strcmp(enabled_env, "1") == 0);
    if (!enabled) {
        ps_info("discovery_listener: disabled (set PS_DISCOVERY_ENABLED=1)");
        ctx->userdata = NULL;
        return 0;
    }

    struct discovery_state *st = calloc(1, sizeof(*st));
    if (!st) return -1;
    st->enabled = 1;
    ps_discovery_replay_init(&st->replay);

    const char *cap_env = getenv("PS_DISCOVERY_MAX_SKEW_MS_CAP");
    st->max_skew_cap_ms = cap_env ? (uint16_t)atoi(cap_env) : PS_DISCOVERY_HARDCAP_SKEW_MS;
    if (st->max_skew_cap_ms == 0) st->max_skew_cap_ms = PS_DISCOVERY_HARDCAP_SKEW_MS;

    char key_dir[1024];
    const char *kd = getenv("PS_KEY_DIR");
    if (kd && *kd) {
        snprintf(key_dir, sizeof(key_dir), "%s", kd);
    } else if (ps_keystore_default_dir(key_dir, sizeof(key_dir)) != 0) {
        ps_warn("discovery_listener: cannot resolve key dir");
        free(st); return -1;
    }
    const char *keyname = getenv("PS_DISCOVERY_AGENT_KEY");
    if (!keyname || !*keyname) keyname = "agent";
    if (ps_keystore_load(key_dir, keyname, &st->kp) != 0) {
        ps_warn("discovery_listener: cannot load agent key '%s' from %s",
                keyname, key_dir);
        free(st); return -1;
    }
    char fpr[PS_KEYSTORE_FPR_HEX_SIZE];
    ps_keystore_fingerprint(st->kp.pubkey, fpr);
    ps_info("discovery_listener: agent identity sha256:%s", fpr);

    const char *auth_dir = getenv("PS_DISCOVERY_AUTHORIZED_DIR");
    char auth_buf[1100];
    if (!auth_dir || !*auth_dir) {
        snprintf(auth_buf, sizeof(auth_buf), "%s/authorized", key_dir);
        auth_dir = auth_buf;
    }
    load_authorized(st, auth_dir);
    if (st->authorized_n == 0) {
        ps_warn("discovery_listener: no authorized pubkeys; all probes will be dropped");
    }

    const char *listen_ip_env = getenv("PS_DISCOVERY_LISTEN_IP");
    if (listen_ip_env && *listen_ip_env) {
        struct in_addr a;
        if (inet_aton(listen_ip_env, &a) == 1) {
            memset(st->listen_ip_v4mapped, 0, 16);
            st->listen_ip_v4mapped[10] = 0xff;
            st->listen_ip_v4mapped[11] = 0xff;
            memcpy(st->listen_ip_v4mapped + 12, &a, 4);
            st->have_listen_ip = 1;
        }
    }
    if (!st->have_listen_ip) {
        if (detect_primary_v4(st->listen_ip_v4mapped) == 0) {
            st->have_listen_ip = 1;
        } else {
            ps_warn("discovery_listener: cannot detect primary v4; advertising 0.0.0.0");
        }
    }
    const char *port_env = getenv("PS_DISCOVERY_LISTEN_PORT");
    st->listen_port = port_env ? (uint16_t)atoi(port_env) : 0;

    ctx->userdata = st;
    ps_info("discovery_listener: enabled, skew_cap=%u ms, listen_port=%u",
            st->max_skew_cap_ms, st->listen_port);
    return 0;
}

static void dlist_shutdown(ps_module_ctx_t *ctx) {
    if (ctx->userdata) {
        free(ctx->userdata);
        ctx->userdata = NULL;
    }
}

const ps_module_t discovery_listener_module = {
    .name        = "discovery_listener",
    .description = "Signed-broadcast agent discovery (knock-style)",
    .version     = "1.0",
    .flags       = PS_MOD_PASSIVE,
    .init        = dlist_init,
    .shutdown    = dlist_shutdown,
    .on_packet   = on_packet,
    .on_job      = NULL,
    .on_response = NULL,
    .tick        = NULL,
};

__attribute__((constructor))
static void register_discovery_listener(void) {
    ps_module_register(&discovery_listener_module);
}
