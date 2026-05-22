#include "verbs.h"
#include "config.h"          /* ps_config — from ../agent/src (CLI include path) */
#include "central_config.h"  /* ps_central_config — lib */
#include "registration.h"    /* ps_register — lib */
#include <stdio.h>
#include <string.h>
#include <getopt.h>

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
    struct ps_central_config cc;
    cc.url             = ps_config_get(&cfg, "central", "url");
    cc.agent_id        = ps_config_get(&cfg, "central", "agent_id");
    cc.deployment_mode = ps_config_get(&cfg, "central", "deployment_mode");
    cc.verify          = ps_config_get_bool(&cfg, "central", "verify", 1);
    cc.ca_cert         = ps_config_get(&cfg, "central", "ca_cert");
    cc.checkin_seconds = ps_config_get_int(&cfg, "central", "checkin_seconds", 60);
    cc.key_dir         = ps_config_get(&cfg, "keys", "dir");

    enum ps_reg_result r = ps_register(&cc, provenance, force);
    ps_config_free(&cfg);

    switch (r) {
        case PS_REG_OK:       printf("registered (pending validation)\n"); return 0;
        case PS_REG_ALREADY:  printf("already registered\n"); return 0;
        case PS_REG_HTTP_ERR: fprintf(stderr, "register: central unreachable / rejected\n"); return 2;
        default:              fprintf(stderr, "register: local error (central url unset?)\n"); return 1;
    }
}
