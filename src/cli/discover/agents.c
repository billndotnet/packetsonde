#include "../args.h"
#include "../output/output.h"
#include "discovery.h"
#include "finding.h"
#include "keystore.h"
#include "ulid.h"

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int ps_discover_agents_run(int argc, char **argv, const struct ps_args *opts);

static void usage(void) {
    fprintf(stderr,
        "Usage: packetsonde discover agents <cidr|broadcast> [opts]\n"
        "\n"
        "  -t SEC, --wait SEC          Listen for replies (default 3)\n"
        "  -k NAME, --key NAME         Key name from PS_KEY_DIR (default 'default')\n"
        "  --max-skew MS               Replay-window hint sent to agent (default 2000)\n"
        "  --cover-port N              Probe destination port (default random)\n"
        "\n"
        "Sends a signed broadcast probe. Valid replies emit 'discovery.agent'\n"
        "info findings with the agent's listen address + identity pubkey in\n"
        "evidence. Invalid replies are silently discarded.\n");
}

static uint16_t random_port(void) {
    uint8_t b[2]; ps_discovery_random(b, 2);
    /* Bias to high ephemeral range. */
    return (uint16_t)(32768 + ((b[0] << 8 | b[1]) & 0x7fff));
}

static int prep_socket(uint16_t *out_src_port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)) != 0) {
        close(fd); return -1;
    }
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd); return -1;
    }
    socklen_t sl = sizeof(sa);
    if (getsockname(fd, (struct sockaddr *)&sa, &sl) == 0) {
        *out_src_port = ntohs(sa.sin_port);
    }
    return fd;
}

/* Compute the directed broadcast address for a CIDR (or accept the
 * literal 'broadcast' / 255.255.255.255). Writes a single broadcast IP
 * into `out`. Returns 0 on success. */
static int target_to_broadcast(const char *spec, char *out, size_t outsz) {
    if (strcmp(spec, "broadcast") == 0 || strcmp(spec, "255.255.255.255") == 0) {
        snprintf(out, outsz, "255.255.255.255");
        return 0;
    }
    /* Parse <addr>/<prefix> and compute the directed broadcast. */
    const char *slash = strchr(spec, '/');
    if (!slash) {
        /* No prefix -- treat as host address and broadcast directly to it.
         * Useful when the operator already knows the broadcast addr. */
        snprintf(out, outsz, "%s", spec);
        return 0;
    }
    char addr[64];
    size_t al = (size_t)(slash - spec);
    if (al >= sizeof(addr)) return -1;
    memcpy(addr, spec, al); addr[al] = '\0';
    int prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32) return -1;
    struct in_addr a;
    if (inet_aton(addr, &a) == 0) return -1;
    uint32_t mask = prefix == 0 ? 0 : (uint32_t)(0xffffffffu << (32 - prefix));
    uint32_t net = ntohl(a.s_addr) & mask;
    uint32_t bcast = net | (~mask);
    struct in_addr ba; ba.s_addr = htonl(bcast);
    if (!inet_ntop(AF_INET, &ba, out, outsz)) return -1;
    return 0;
}

static void emit_finding(struct ps_output *out, const char *run_id,
                         const char *self_host,
                         const struct ps_discovery_reply *r,
                         const char *src_ip, uint16_t src_port) {
    char fpr[PS_KEYSTORE_FPR_HEX_SIZE];
    ps_keystore_fingerprint(r->agent_pub, fpr);

    /* Render listen_ip as either v4 (if v4-mapped) or v6. */
    char listen_ip[64] = "";
    if (memcmp(r->listen_ip, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) == 0) {
        snprintf(listen_ip, sizeof(listen_ip), "%u.%u.%u.%u",
                 r->listen_ip[12], r->listen_ip[13],
                 r->listen_ip[14], r->listen_ip[15]);
    } else {
        inet_ntop(AF_INET6, r->listen_ip, listen_ip, sizeof(listen_ip));
    }

    char ev[640];
    snprintf(ev, sizeof(ev),
             "{\"agent_pub_fingerprint\":\"sha256:%s\","
             "\"listen_ip\":\"%s\",\"listen_port\":%u,"
             "\"replied_from\":\"%s:%u\"}",
             fpr, listen_ip, r->listen_port, src_ip, src_port);
    char title[200];
    snprintf(title, sizeof(title),
             "Discovered agent at %s:%u (sha256:%.16s...)",
             listen_ip, r->listen_port, fpr);

    struct ps_finding f;
    ps_finding_init(&f, run_id, "cli.discover.agents", self_host,
                    "discovery.agent", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
    ps_finding_set_target_ip(&f, listen_ip, r->listen_port);
    ps_finding_set_evidence_json(&f, ev);
    ps_output_emit(out, &f);
}

int ps_discover_agents_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) { usage(); return 2; }
    const char *target = argv[1];
    int wait_secs = 3;
    const char *keyname = "default";
    uint16_t max_skew_ms = PS_DISCOVERY_DEFAULT_SKEW_MS;
    uint16_t cover_port = 0;

    static const struct option longopts[] = {
        { "wait",       required_argument, NULL, 't' },
        { "key",        required_argument, NULL, 'k' },
        { "max-skew",   required_argument, NULL, 'M' },
        { "cover-port", required_argument, NULL, 'P' },
        { NULL, 0, NULL, 0 }
    };
    optind = 2;
    int c;
    while ((c = getopt_long(argc, argv, "t:k:", longopts, NULL)) != -1) {
        switch (c) {
            case 't': wait_secs    = atoi(optarg); break;
            case 'k': keyname      = optarg;       break;
            case 'M': max_skew_ms  = (uint16_t)atoi(optarg); break;
            case 'P': cover_port   = (uint16_t)atoi(optarg); break;
            default:  usage(); return 2;
        }
    }
    if (cover_port == 0) cover_port = random_port();
    if (max_skew_ms == 0) max_skew_ms = PS_DISCOVERY_DEFAULT_SKEW_MS;

    /* Load signing key. */
    char dir[1024];
    if (ps_keystore_default_dir(dir, sizeof(dir)) != 0) return 1;
    struct ps_keypair kp;
    if (ps_keystore_load(dir, keyname, &kp) != 0) {
        fprintf(stderr, "discover agents: cannot load key '%s' from %s\n"
                        "  (run: packetsonde key generate)\n", keyname, dir);
        return 1;
    }
    /* Need the secret half. */
    int has_sec = 0;
    for (size_t i = 0; i < PS_KEYSTORE_SECKEY_SIZE; i++) {
        if (kp.seckey[i]) { has_sec = 1; break; }
    }
    if (!has_sec) {
        fprintf(stderr, "discover agents: key '%s' is pubkey-only\n", keyname);
        return 1;
    }

    char bcast[64];
    if (target_to_broadcast(target, bcast, sizeof(bcast)) != 0) {
        fprintf(stderr, "discover agents: bad target '%s'\n", target); return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    struct ps_output_opts oopts; memset(&oopts, 0, sizeof(oopts));
    switch (opts->fmt) {
        case PS_FMT_TEXT:  oopts.fmt_force = PS_OFMT_TEXT;  break;
        case PS_FMT_JSON:  oopts.fmt_force = PS_OFMT_JSON;  break;
        case PS_FMT_JSONL: oopts.fmt_force = PS_OFMT_JSONL; break;
        case PS_FMT_QUIET: oopts.fmt_force = PS_OFMT_QUIET; break;
        default:           oopts.fmt_force = 0;             break;
    }
    oopts.color = opts->no_color ? 0 : 1;
    struct ps_output out; ps_output_init(&out, &oopts);

    uint16_t src_port = 0;
    int fd = prep_socket(&src_port);
    if (fd < 0) {
        fprintf(stderr, "discover agents: socket setup failed: %s\n", strerror(errno));
        ps_output_close(&out);
        return 1;
    }

    /* Build + sign probe. */
    struct ps_discovery_probe p = {0};
    p.version = PS_DISCOVERY_VERSION;
    p.max_skew_ms = max_skew_ms;
    p.timestamp_ms = ps_discovery_now_ms();
    ps_discovery_random(p.nonce, PS_DISCOVERY_NONCE_SIZE);
    memcpy(p.pubkey, kp.pubkey, PS_DISCOVERY_PUBKEY_SIZE);
    if (ps_discovery_probe_sign(&p, kp.seckey) != 0) {
        fprintf(stderr, "discover agents: sign failed\n");
        close(fd); ps_output_close(&out);
        return 1;
    }
    uint8_t wire[PS_DISCOVERY_PROBE_SIZE];
    ps_discovery_probe_pack(&p, wire);

    struct sockaddr_in to; memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(cover_port);
    if (inet_aton(bcast, &to.sin_addr) == 0) {
        fprintf(stderr, "discover agents: bad broadcast '%s'\n", bcast);
        close(fd); ps_output_close(&out); return 1;
    }
    if (sendto(fd, wire, sizeof(wire), 0,
               (struct sockaddr *)&to, sizeof(to)) != (ssize_t)sizeof(wire)) {
        fprintf(stderr, "discover agents: sendto: %s\n", strerror(errno));
        close(fd); ps_output_close(&out); return 1;
    }
    fprintf(stderr, "discover agents: probe sent to %s:%u from :%u (wait=%ds)\n",
            bcast, cover_port, src_port, wait_secs);

    /* Collect replies until wait expires. */
    struct timeval deadline; gettimeofday(&deadline, NULL);
    deadline.tv_sec += wait_secs;
    int found = 0;
    for (;;) {
        struct timeval now; gettimeofday(&now, NULL);
        long remain_us = (deadline.tv_sec - now.tv_sec) * 1000000L +
                         (deadline.tv_usec - now.tv_usec);
        if (remain_us <= 0) break;
        struct timeval tv = { remain_us / 1000000, remain_us % 1000000 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        uint8_t buf[PS_DISCOVERY_REPLY_SIZE * 2];
        struct sockaddr_in from; socklen_t flen = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &flen);
        if (n <= 0) break;
        if (n != PS_DISCOVERY_REPLY_SIZE) continue; /* not our shape */

        struct ps_discovery_reply r;
        if (ps_discovery_reply_unpack(&r, buf) != 0) continue;
        /* Nonce must match the probe we sent. */
        if (memcmp(r.nonce, p.nonce, PS_DISCOVERY_NONCE_SIZE) != 0) continue;
        if (!ps_discovery_reply_verify(&r)) continue;

        char from_ip[64];
        inet_ntop(AF_INET, &from.sin_addr, from_ip, sizeof(from_ip));
        emit_finding(&out, run_id, self_host, &r, from_ip, ntohs(from.sin_port));
        found++;
    }

    close(fd);
    if (!found) {
        fprintf(stderr, "discover agents: no replies within %ds\n", wait_secs);
    }
    ps_output_close(&out);
    return found ? 0 : 1;
}
