#include "audit_module.h"
#include "audit_common.h"
#include "../args.h"
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
    return ps_audit_parse_target(spec, host, host_sz, 9200, port);
}

/* Extract a quoted string value for the FIRST `"key":"..."` in input. */
static int json_str(const char *in, const char *key, char *out, size_t outsz) {
    char pat[64]; snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(in, pat);
    if (!p) { out[0] = '\0'; return 0; }
    p += strlen(pat);
    size_t k = 0;
    while (*p && *p != '"' && k + 1 < outsz) out[k++] = *p++;
    out[k] = '\0'; return 1;
}

static int elasticsearch_run(int argc, char **argv,
                      const struct ps_args *opts,
                      const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit elasticsearch <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 9200;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit elasticsearch: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    char ip[64] = "";
    int fd = ps_audit_tcp_connect(host, port, 4000, ip, sizeof(ip));
    if (fd < 0) {
        fprintf(stderr, "audit elasticsearch: cannot connect to %s:%u\n", host, port);
        return 1;
    }

    char req[512];
    snprintf(req, sizeof(req),
        "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: packetsonde\r\n"
        "Connection: close\r\nAccept: application/json\r\n\r\n", host);
    if (send(fd, req, strlen(req), 0) != (ssize_t)strlen(req)) {
        close(fd); return 1;
    }

    char resp[8192]; size_t total = 0;
    for (;;) {
        if (total >= sizeof(resp) - 1) break;
        ssize_t r = recv(fd, resp + total, sizeof(resp) - 1 - total, 0);
        if (r <= 0) break;
        total += (size_t)r;
    }
    resp[total] = '\0';
    close(fd);

    if (total == 0) {
        fprintf(stderr, "audit elasticsearch: empty response\n"); return 1;
    }

    int status = 0;
    if (strncmp(resp, "HTTP/", 5) == 0) {
        const char *sp = strchr(resp, ' ');
        if (sp) status = atoi(sp + 1);
    }

    /* 401 with WWW-Authenticate "Basic realm=\"security\"" indicates ES with
     * auth required — record but don't escalate. */
    int requires_auth = (status == 401);

    /* Body starts after \r\n\r\n */
    const char *body = strstr(resp, "\r\n\r\n");
    body = body ? body + 4 : resp;

    char cluster[128] = "", version[64] = "", tagline[160] = "";
    json_str(body, "cluster_name",    cluster, sizeof(cluster));
    json_str(body, "tagline",         tagline, sizeof(tagline));
    /* version.number is nested; do a separate match for the "number":"..."
     * substring after the first occurrence of "version" */
    const char *vp = strstr(body, "\"version\"");
    if (vp) json_str(vp, "number", version, sizeof(version));

    int looks_like_es = (cluster[0] || version[0] ||
                          strstr(tagline, "elastic") != NULL);

    {
        char ev[640]; char cluster_e[160], version_e[80];
        snprintf(cluster_e, sizeof(cluster_e), "%s", cluster);
        snprintf(version_e, sizeof(version_e), "%s", version);
        snprintf(ev, sizeof(ev),
            "{\"status\":%d,\"cluster_name\":\"%s\",\"version\":\"%s\","
            "\"auth_required\":%s}",
            status, cluster_e, version_e, requires_auth ? "true" : "false");
        char title[256];
        if (requires_auth)
            snprintf(title, sizeof(title), "Elasticsearch %d (auth required)", status);
        else if (looks_like_es)
            snprintf(title, sizeof(title), "Elasticsearch %s reachable without auth", version);
        else
            snprintf(title, sizeof(title), "HTTP %d on port %u (not Elasticsearch)", status, port);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.elasticsearch", self_host,
                        "elasticsearch.metadata",
                        PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    if (looks_like_es && !requires_auth) {
        char ev[256];
        snprintf(ev, sizeof(ev), "{\"version\":\"%s\",\"cluster_name\":\"%s\"}",
                 version, cluster);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.elasticsearch", self_host,
                        "elasticsearch.unauthenticated",
                        PS_SEV_CRITICAL, PS_CONF_CONFIRMED,
                        "Elasticsearch cluster API reachable without authentication");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }
    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "elasticsearch",
    .summary     = "Audit Elasticsearch: unauthenticated cluster API",
    .run         = elasticsearch_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_elasticsearch_module(void) { return &MODULE; }
