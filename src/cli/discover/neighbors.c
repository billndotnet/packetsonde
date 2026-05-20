#include "neighbors.h"
#include "../output/output.h"
#include "../runstate.h"
#include "../util/fail_on.h"
#include "finding.h"
#include "ulid.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void emit_neighbor(struct ps_output *out, const char *run_id,
                          const char *self_host,
                          const char *ip, const char *mac, const char *iface) {
    char title[256];
    snprintf(title, sizeof(title), "%s at %s on %s", ip, mac, iface[0] ? iface : "-");
    char ev[256];
    snprintf(ev, sizeof(ev), "{\"mac\":\"%s\",\"iface\":\"%s\"}", mac, iface);
    struct ps_finding f;
    ps_finding_init(&f, run_id, "cli.discover.neighbors", self_host,
                    "discover.neighbor", PS_SEV_INFO, PS_CONF_FIRM, title);
    ps_finding_set_target_ip(&f, ip, 0);
    ps_finding_set_evidence_json(&f, ev);
    ps_output_emit(out, &f);
}

static int read_proc_net_arp(struct ps_output *out, const char *run_id, const char *self_host) {
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return -1;
    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }
    int n = 0;
    while (fgets(line, sizeof(line), f)) {
        char ip[64], mac[32], iface[32], hw[32], mask[32];
        int flags = 0, type = 0;
        if (sscanf(line, "%63s %x %x %31s %31s %31s",
                   ip, &type, &flags, mac, mask, iface) >= 4) {
            if (strcmp(mac, "00:00:00:00:00:00") == 0) continue;
            emit_neighbor(out, run_id, self_host, ip, mac, iface);
            n++;
        }
        (void)hw;
    }
    fclose(f);
    return n;
}

static int read_arp_command(struct ps_output *out, const char *run_id, const char *self_host) {
    FILE *p = popen("arp -an 2>/dev/null", "r");
    if (!p) return -1;
    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), p)) {
        char ip[64] = "", mac[32] = "", iface[32] = "";
        const char *lp = strchr(line, '(');
        const char *rp = lp ? strchr(lp, ')') : NULL;
        if (!lp || !rp) continue;
        size_t L = (size_t)(rp - lp - 1);
        if (L >= sizeof(ip)) continue;
        memcpy(ip, lp + 1, L); ip[L] = '\0';
        const char *at = strstr(rp, " at ");
        if (!at) continue;
        const char *m = at + 4;
        size_t mi = 0;
        while (*m && *m != ' ' && mi + 1 < sizeof(mac)) mac[mi++] = *m++;
        mac[mi] = '\0';
        const char *on = strstr(m, " on ");
        if (on) {
            const char *i = on + 4;
            size_t ii = 0;
            while (*i && *i != ' ' && ii + 1 < sizeof(iface)) iface[ii++] = *i++;
            iface[ii] = '\0';
        }
        if (mac[0] == '\0' || strcmp(mac, "(incomplete)") == 0) continue;
        emit_neighbor(out, run_id, self_host, ip, mac, iface);
        n++;
    }
    pclose(p);
    return n;
}

int ps_discover_neighbors_run(int argc, char **argv, const struct ps_args *opts) {
    (void)argc; (void)argv;

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

    if (read_proc_net_arp(&out, run_id, self_host) < 0) {
        read_arp_command(&out, run_id, self_host);
    }

    ps_output_snapshot(&out, &g_last_run_counts);
    ps_output_close(&out);
    return 0;
}
