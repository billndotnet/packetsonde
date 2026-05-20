#include "redis.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../util/fail_on.h"
#include "finding.h"
#include "ulid.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int parse_target(const char *spec, char *host, size_t host_sz, uint16_t *port) {
    *port = 6379;
    const char *colon = strrchr(spec, ':');
    size_t hl = colon ? (size_t)(colon - spec) : strlen(spec);
    if (hl == 0 || hl >= host_sz) return -1;
    memcpy(host, spec, hl); host[hl] = '\0';
    if (colon) {
        long p = strtol(colon + 1, NULL, 10);
        if (p <= 0 || p > 65535) return -1;
        *port = (uint16_t)p;
    }
    return 0;
}

/* Find a key in Redis INFO output (lines like "redis_version:7.2.4\r\n"). */
static int info_field(const char *info, const char *key, char *out, size_t outsz) {
    out[0] = '\0';
    size_t klen = strlen(key);
    const char *p = info;
    while (p && *p) {
        const char *eol = strstr(p, "\r\n");
        size_t llen = eol ? (size_t)(eol - p) : strlen(p);
        if (llen > klen + 1 && !strncmp(p, key, klen) && p[klen] == ':') {
            size_t vlen = llen - klen - 1;
            if (vlen >= outsz) vlen = outsz - 1;
            memcpy(out, p + klen + 1, vlen);
            out[vlen] = '\0';
            return 1;
        }
        if (!eol) break;
        p = eol + 2;
    }
    return 0;
}

int ps_audit_redis_run(int argc, char **argv, const struct ps_args *opts) {
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit redis <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 6379;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit redis: bad target '%s'\n", argv[1]);
        return 2;
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

    char portstr[8]; snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        ps_output_close(&out); return 1;
    }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); ps_output_close(&out); return 1; }
    struct timeval tv = { 4, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    char ip[64] = "";
    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
    int rc = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (rc != 0) {
        fprintf(stderr, "audit redis: cannot connect to %s:%u\n", host, port);
        close(fd); ps_output_close(&out); return 1;
    }

    /* Send INFO using inline command syntax (works regardless of RESP version). */
    const char *cmd = "INFO\r\n";
    if (send(fd, cmd, strlen(cmd), 0) != (ssize_t)strlen(cmd)) {
        close(fd); ps_output_close(&out); return 1;
    }

    char buf[16384]; size_t total = 0;
    for (;;) {
        if (total >= sizeof(buf) - 1) break;
        ssize_t r = recv(fd, buf + total, sizeof(buf) - 1 - total, 0);
        if (r <= 0) break;
        total += (size_t)r;
        /* Redis bulk strings end with \r\n after the payload. INFO returns
         * a $<len>\r\n<payload>\r\n. We break when we've seen enough. */
        if (total > 64 && strstr(buf, "\r\n") != NULL) {
            /* Heuristic: stop if no more data within a short window. */
            struct timeval nb = { 0, 200000 };  /* 200ms */
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &nb, sizeof(nb));
        }
    }
    buf[total] = '\0';
    close(fd);

    if (total == 0) {
        fprintf(stderr, "audit redis: no response from %s:%u\n", host, port);
        ps_output_close(&out);
        return 1;
    }

    /* Three possible response shapes:
     *  (1) "-NOAUTH ..." or "-WRONGPASS ..."  -> server requires auth (good)
     *  (2) "$<len>\r\nredis_version:...\r\n..." -> INFO succeeded without auth (bad)
     *  (3) "-ERR unknown command 'INFO'" or other -> probably not Redis */
    int requires_auth = strncmp(buf, "-NOAUTH", 7) == 0 ||
                        strstr(buf, "NOAUTH Authentication required") != NULL;
    int info_succeeded = (buf[0] == '$') && (strstr(buf, "redis_version:") != NULL);
    int looks_like_redis = info_succeeded || requires_auth;

    if (!looks_like_redis) {
        /* Not Redis (or unrecognised). Emit a low-confidence metadata finding
         * and exit. */
        char ev[1024]; char banner_e[512]; size_t k = 0;
        for (size_t i = 0; i < total && i < 256 && k + 2 < sizeof(banner_e); i++) {
            unsigned char c = (unsigned char)buf[i];
            if (c == '"' || c == '\\') { banner_e[k++] = '\\'; banner_e[k++] = (char)c; }
            else if (c >= 0x20 && c < 0x7f) banner_e[k++] = (char)c;
        }
        banner_e[k] = '\0';
        snprintf(ev, sizeof(ev), "{\"first_bytes\":\"%s\"}", banner_e);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.redis", self_host,
                        "redis.unrecognized", PS_SEV_INFO, PS_CONF_TENTATIVE,
                        "Service does not look like Redis");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
        ps_output_snapshot(&out, &g_last_run_counts);
        ps_output_close(&out);
        return 0;
    }

    char version[64] = "", mode[64] = "", os[128] = "";
    if (info_succeeded) {
        info_field(buf, "redis_version", version, sizeof(version));
        info_field(buf, "redis_mode",    mode,    sizeof(mode));
        info_field(buf, "os",            os,      sizeof(os));
    }

    /* Metadata finding */
    {
        char ev[512];
        if (info_succeeded) {
            snprintf(ev, sizeof(ev),
                "{\"version\":\"%s\",\"mode\":\"%s\",\"os\":\"%s\",\"auth\":false}",
                version, mode, os);
        } else {
            snprintf(ev, sizeof(ev), "{\"auth\":true}");
        }
        char title[256];
        if (info_succeeded)
            snprintf(title, sizeof(title), "Redis %s (%s) reachable without auth",
                     version[0] ? version : "?", mode[0] ? mode : "?");
        else
            snprintf(title, sizeof(title), "Redis reachable, authentication required");
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.redis", self_host,
                        "redis.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
    }

    /* The actual security finding. */
    if (info_succeeded) {
        char ev[256];
        snprintf(ev, sizeof(ev), "{\"version\":\"%s\"}", version);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.redis", self_host,
                        "redis.noauth", PS_SEV_CRITICAL, PS_CONF_CONFIRMED,
                        "Redis is reachable without authentication");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        ps_output_emit(&out, &f);
    }

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
