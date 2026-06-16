#include "audit_via.h"

#include "remote_session.h"
#include "via_connect.h"

#include "agent_proto.h"
#include "agent_transport.h"
#include "discovery.h"
#include "keystore.h"
#include "../registry/agents.h"
#include "recipe.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* Split "host:port" into host + port. Returns 0 on success. */
static int split_addr(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    const char *colon = strrchr(spec, ':');
    if (!colon) return -1;
    size_t hl = (size_t)(colon - spec);
    if (hl == 0 || hl >= host_sz) return -1;
    memcpy(host, spec, hl); host[hl] = '\0';
    long p = atol(colon + 1);
    if (p <= 0 || p > 65535) return -1;
    *port = (uint16_t)p;
    return 0;
}

/* Send a signed broadcast knock and wait for a reply from the agent whose
 * pubkey matches `pin`. On success fills *out_ip and *out_port with the
 * agent's session-window listener. Returns 0 on success. */
static int knock_for_session(const struct ps_keypair *kp, const char *pin,
                              const char *bcast, char *out_ip, size_t ip_cap,
                              uint16_t *out_port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    struct sockaddr_in la; memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET; la.sin_addr.s_addr = htonl(INADDR_ANY); la.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&la, sizeof(la)) != 0) { close(fd); return -1; }

    struct ps_discovery_probe p = {0};
    p.version = PS_DISCOVERY_VERSION;
    p.flags = PS_DISCOVERY_FLAG_REQUEST_SESSION;
    p.max_skew_ms = PS_DISCOVERY_DEFAULT_SKEW_MS;
    p.timestamp_ms = ps_discovery_now_ms();
    ps_discovery_random(p.nonce, PS_DISCOVERY_NONCE_SIZE);
    memcpy(p.pubkey, kp->pubkey, PS_DISCOVERY_PUBKEY_SIZE);
    if (ps_discovery_probe_sign(&p, kp->seckey) != 0) { close(fd); return -1; }

    uint8_t wire[PS_DISCOVERY_PROBE_SIZE];
    ps_discovery_probe_pack(&p, wire);
    /* The agent dst port doesn't matter -- its pcap listener catches by
     * broadcast MAC + magic. Pick a random high port so we blend with
     * ad-hoc UDP traffic. */
    uint8_t cp[2]; ps_discovery_random(cp, 2);
    uint16_t cover = (uint16_t)(32768 + ((cp[0] << 8 | cp[1]) & 0x7fff));
    struct sockaddr_in to; memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(cover);
    if (inet_aton(bcast, &to.sin_addr) == 0) { close(fd); return -1; }
    if (sendto(fd, wire, sizeof(wire), 0,
               (struct sockaddr *)&to, sizeof(to)) != (ssize_t)sizeof(wire)) {
        close(fd); return -1;
    }

    struct timeval tv = { 3, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    for (int tries = 0; tries < 8; tries++) {
        uint8_t rbuf[PS_DISCOVERY_REPLY_SIZE * 2];
        struct sockaddr_in from; socklen_t flen = sizeof(from);
        ssize_t n = recvfrom(fd, rbuf, sizeof(rbuf), 0,
                             (struct sockaddr *)&from, &flen);
        if (n <= 0) break;
        if (n != PS_DISCOVERY_REPLY_SIZE) continue;
        struct ps_discovery_reply r;
        if (ps_discovery_reply_unpack(&r, rbuf) != 0) continue;
        if (memcmp(r.nonce, p.nonce, PS_DISCOVERY_NONCE_SIZE) != 0) continue;
        if (!ps_discovery_reply_verify(&r)) continue;
        /* Compare the agent's pubkey to the pin. */
        char fpr[PS_KEYSTORE_FPR_HEX_SIZE];
        ps_keystore_fingerprint(r.agent_pub, fpr);
        if (strcmp(fpr, pin) != 0) continue;
        /* v4-mapped reply ip. */
        if (memcmp(r.listen_ip, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) != 0) continue;
        snprintf(out_ip, ip_cap, "%u.%u.%u.%u",
                 r.listen_ip[12], r.listen_ip[13],
                 r.listen_ip[14], r.listen_ip[15]);
        *out_port = r.listen_port;
        close(fd);
        return 0;
    }
    close(fd);
    return -1;
}

/* Connect to a registered via-agent over mTLS + exchange the client hello.
 * Returns 0 with *ctx_out/*ssl_out/*io_out owned by the caller, or -1 (cleans up). */
int ps_via_connect(const char *agent_name, struct ps_at_ctx *ctx_out,
                   SSL **ssl_out, struct ps_ap_io *io_out) {
    struct ps_agents A;
    if (ps_agents_load(&A, ps_agents_default_path()) != 0 || A.count == 0) {
        fprintf(stderr, "--via: no agents registered (see 'packetsonde config show')\n");
        return -1;
    }
    const struct ps_agent *ag = ps_agents_find(&A, agent_name);
    if (!ag) {
        fprintf(stderr, "--via: unknown agent '%s'\n", agent_name);
        ps_agents_destroy(&A); return -1;
    }
    char host[256] = ""; uint16_t port = 0;
    if (!ag->knock) {
        if (split_addr(ag->address, host, sizeof(host), &port) != 0) {
            fprintf(stderr, "--via: agent '%s' has bad address '%s'\n", ag->name, ag->address);
            ps_agents_destroy(&A); return -1;
        }
    }
    if (!ag->key_fingerprint[0]) {
        fprintf(stderr, "--via: agent '%s' has no key_fingerprint in registry\n", ag->name);
        ps_agents_destroy(&A); return -1;
    }
    const char *pin = ag->key_fingerprint;
    if (strncmp(pin, "sha256:", 7) == 0) pin += 7;

    char kdir[1024];
    if (ps_keystore_default_dir(kdir, sizeof(kdir)) != 0) { ps_agents_destroy(&A); return -1; }
    struct ps_keypair kp;
    if (ps_keystore_load(kdir, "default", &kp) != 0) {
        fprintf(stderr, "--via: no CLI key 'default' in %s\n"
                        "  (run: packetsonde key generate)\n", kdir);
        ps_agents_destroy(&A); return -1;
    }
    int has_sec = 0;
    for (size_t i = 0; i < PS_KEYSTORE_SECKEY_SIZE; i++)
        if (kp.seckey[i]) { has_sec = 1; break; }
    if (!has_sec) {
        fprintf(stderr, "--via: CLI key is pubkey-only\n");
        ps_agents_destroy(&A); return -1;
    }

    if (ag->knock) {
        const char *bcast = ag->broadcast[0] ? ag->broadcast : "255.255.255.255";
        if (knock_for_session(&kp, pin, bcast, host, sizeof(host), &port) != 0) {
            fprintf(stderr, "--via: knock failed (no reply from authorized agent on %s)\n", bcast);
            ps_agents_destroy(&A); return -1;
        }
    }

    ps_at_block_sigpipe();
    if (ps_at_ctx_init(ctx_out, PS_AT_CLIENT, &kp, pin) != 0) {
        fprintf(stderr, "--via: TLS context init failed\n");
        ps_agents_destroy(&A); return -1;
    }
    /* ctx_out copied the fingerprint; A (and pin) are no longer needed. */
    char namebuf[128]; snprintf(namebuf, sizeof namebuf, "%s", ag->name);
    ps_agents_destroy(&A);

    SSL *ssl = ps_at_connect(ctx_out, host, port);
    if (!ssl) {
        fprintf(stderr, "--via: cannot connect to agent '%s' at %s:%u "
                        "(network unreachable, refused, or fingerprint mismatch)\n",
                namebuf, host, port);
        ps_at_ctx_destroy(ctx_out); return -1;
    }
    ps_at_make_io(ssl, io_out);

    char self_fpr[PS_KEYSTORE_FPR_HEX_SIZE];
    ps_keystore_fingerprint(kp.pubkey, self_fpr);
    char hello[256];
    int hn = snprintf(hello, sizeof(hello),
                      "{\"type\":\"hello\",\"v\":%d,\"client_fingerprint\":\"sha256:%s\","
                      "\"max_recipe_schema\":%d}",
                      PS_AGENT_PROTO_VERSION, self_fpr, PS_RECIPE_SCHEMA_MAX);
    if (hn < 0 || ps_ap_write_frame(io_out, hello, (size_t)hn) != PS_AP_OK) {
        fprintf(stderr, "--via: hello write failed\n");
        ps_at_close(ssl); ps_at_ctx_destroy(ctx_out); return -1;
    }
    *ssl_out = ssl;
    return 0;
}

int ps_audit_via_run(int argc, char **argv,
                     const struct ps_args *opts,
                     struct ps_output *out) {
    /* argv[0] is the audit kind; argv[1..] are its arguments. The
     * verb-agnostic session machinery lives in remote_session.c. */
    return ps_remote_run("audit", argv[0], argc - 1, &argv[1], opts, out);
}
