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
    return ps_audit_parse_target(spec, host, host_sz, 3306, port);
}

static int mysql_run(int argc, char **argv,
                      const struct ps_args *opts,
                      const struct ps_audit_api *api) {
    (void)opts;
    if (argc < 2) {
        fprintf(stderr, "Usage: packetsonde audit mysql <host[:port]>\n");
        return 2;
    }
    char host[256]; uint16_t port = 3306;
    if (parse_target(argv[1], host, sizeof(host), &port) != 0) {
        fprintf(stderr, "audit mysql: bad target '%s'\n", argv[1]);
        return 2;
    }

    char self_host[256] = ""; gethostname(self_host, sizeof(self_host));
    char run_id[PS_ULID_STRLEN + 1]; ps_ulid_new(run_id, sizeof(run_id));

    char ip[64] = "";
    int fd = ps_audit_tcp_connect(host, port, 4000, ip, sizeof(ip));
    if (fd < 0) {
        fprintf(stderr, "audit mysql: cannot connect to %s:%u\n", host, port);
        return 1;
    }

    /* MySQL server sends the initial handshake packet immediately on connect.
     * Packet layout:
     *   3 bytes: payload length (LE)
     *   1 byte:  sequence id
     *   1 byte:  protocol version (10 for modern; 9 for the ancient one)
     *   N bytes: server version string (NUL-terminated)
     *   ... more fields, ignored here.
     */
    unsigned char buf[1024];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    close(fd);

    if (n < 6) {
        fprintf(stderr, "audit mysql: no handshake from %s:%u\n", host, port); return 1;
    }

    /* Packet header: 4 bytes (len + seq) */
    int proto_ver = buf[4];
    if (proto_ver != 10 && proto_ver != 9) {
        /* Doesn't look like MySQL. Could be MariaDB (same protocol) or
         * something else entirely. Emit a tentative metadata finding. */
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.mysql", self_host,
                        "mysql.unrecognized", PS_SEV_INFO, PS_CONF_TENTATIVE,
                        "Service does not look like MySQL");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        api->emit(&f);
        return 0;
    }

    /* Read NUL-terminated version string starting at offset 5. */
    char version[128] = "";
    size_t k = 0;
    for (size_t i = 5; i < (size_t)n && buf[i] && k + 1 < sizeof(version); i++) {
        version[k++] = (char)buf[i];
    }
    version[k] = '\0';

    {
        char ev[256];
        snprintf(ev, sizeof(ev),
            "{\"protocol_version\":%d,\"server_version\":\"%s\"}",
            proto_ver, version);
        char title[200];
        snprintf(title, sizeof(title), "MySQL/MariaDB %s reachable", version);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.mysql", self_host,
                        "mysql.metadata", PS_SEV_INFO, PS_CONF_CONFIRMED, title);
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    /* MySQL 5.x is EOL (5.7 went EOL 2023-10). Flag servers still on 5.x. */
    int major = 0, minor = 0;
    sscanf(version, "%d.%d", &major, &minor);
    if (major > 0 && major < 8) {
        char ev[128];
        snprintf(ev, sizeof(ev), "{\"server_version\":\"%s\"}", version);
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.mysql", self_host,
                        "mysql.old_version", PS_SEV_MEDIUM, PS_CONF_FIRM,
                        "MySQL server is older than 8.0 (5.x is end-of-life)");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        ps_finding_set_evidence_json(&f, ev);
        api->emit(&f);
    }

    /* MySQL/MariaDB on an externally-reachable port is itself a posture issue:
     * production DBs should never be reachable from the public internet. We
     * can't tell from inside packetsonde whether the target is "external" or
     * "internal" relative to the auditor — emit informational, let the
     * downstream reporter decide. */
    {
        struct ps_finding f;
        ps_finding_init(&f, run_id, "cli.audit.mysql", self_host,
                        "mysql.reachable", PS_SEV_LOW, PS_CONF_CONFIRMED,
                        "MySQL/MariaDB is reachable from the auditor's network position");
        ps_finding_set_target_ip(&f, ip, port);
        ps_finding_set_target_hostname(&f, host, port);
        api->emit(&f);
    }
    return 0;
}

static const struct ps_audit_module MODULE = {
    .abi_version = PS_AUDIT_ABI_VERSION,
    .name        = "mysql",
    .summary     = "Audit MySQL/MariaDB: version banner, EOL versions",
    .run         = mysql_run,
};

#ifdef PS_AUDIT_PLUGIN_BUILD
const struct ps_audit_module *ps_audit_module(void) { return &MODULE; }
#endif
const struct ps_audit_module *ps_audit_mysql_module(void) { return &MODULE; }
