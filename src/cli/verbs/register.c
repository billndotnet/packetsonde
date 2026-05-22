#include "verbs.h"
#include "config.h"          /* ps_config — from ../agent/src (CLI include path) */
#include "central_config.h"  /* ps_central_config — lib */
#include "registration.h"    /* ps_register — lib */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

/* ps_config preserves wrapping double-quotes on values (config_to_env strips
 * them for the agent's env path; direct ps_config_get callers must do it). */
static const char *unq(const char *v, char *buf, size_t cap) {
    if (!v) return NULL;
    size_t n = strlen(v);
    if (n >= 2 && v[0] == '"' && v[n-1] == '"') {
        size_t inner = n - 2; if (inner >= cap) inner = cap - 1;
        memcpy(buf, v + 1, inner); buf[inner] = 0;
    } else {
        snprintf(buf, cap, "%s", v);
    }
    return buf;
}

int ps_verb_register_run(int argc, char **argv, const struct ps_args *opts) {
    (void)opts;
    const char *cfg_path = "/etc/packetsonded/packetsonded.toml";
    const char *provenance = "salt";
    int force = 0;
    static struct option lo[] = {
        {"config", required_argument, 0, 'c'},
        {"provenance", required_argument, 0, 'p'},
        {"force", no_argument, 0, 'f'},
        {0, 0, 0, 0}
    };
    optind = 1;
    int c;
    while ((c = getopt_long(argc, argv, "c:p:f", lo, NULL)) != -1) {
        if (c == 'c') cfg_path = optarg;
        else if (c == 'p') provenance = optarg;
        else if (c == 'f') force = 1;
    }

    struct ps_config cfg;
    if (ps_config_parse_file(&cfg, cfg_path) != 0) {
        fprintf(stderr, "register: cannot read config %s\n", cfg_path);
        return 1;
    }
    char ub_url[512], ub_id[256], ub_mode[64], ub_ca[512], ub_keydir[512], ub_v[16], ub_ci[16];
    struct ps_central_config cc;
    cc.url             = unq(ps_config_get(&cfg, "central", "url"), ub_url, sizeof ub_url);
    cc.agent_id        = unq(ps_config_get(&cfg, "central", "agent_id"), ub_id, sizeof ub_id);
    cc.deployment_mode = unq(ps_config_get(&cfg, "central", "deployment_mode"), ub_mode, sizeof ub_mode);
    cc.ca_cert         = unq(ps_config_get(&cfg, "central", "ca_cert"), ub_ca, sizeof ub_ca);
    cc.key_dir         = unq(ps_config_get(&cfg, "keys", "dir"), ub_keydir, sizeof ub_keydir);
    const char *vs     = unq(ps_config_get(&cfg, "central", "verify"), ub_v, sizeof ub_v);
    cc.verify          = (vs && vs[0]) ? (vs[0] == '0' ? 0 : 1) : 1;
    const char *cis    = unq(ps_config_get(&cfg, "central", "checkin_seconds"), ub_ci, sizeof ub_ci);
    cc.checkin_seconds = (cis && cis[0]) ? atoi(cis) : 60;

    enum ps_reg_result r = ps_register(&cc, provenance, force);
    ps_config_free(&cfg);

    switch (r) {
        case PS_REG_OK:       printf("registered (pending validation)\n"); return 0;
        case PS_REG_ALREADY:  printf("already registered\n"); return 0;
        case PS_REG_HTTP_ERR: fprintf(stderr, "register: central unreachable / rejected\n"); return 2;
        default:              fprintf(stderr, "register: local error (central url unset?)\n"); return 1;
    }
}
