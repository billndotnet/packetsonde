#ifndef PS_CENTRAL_CONFIG_H
#define PS_CENTRAL_CONFIG_H

/* Resolved central-management settings. Plain fields so this stays in the
 * shared lib with no dependency on the agent's ps_config parser. Each caller
 * (agent daemon, CLI verb) fills it from its own config source. */
struct ps_central_config {
    const char *url;             /* "" / NULL -> central disabled */
    const char *agent_id;        /* "" -> caller substitutes hostname */
    const char *deployment_mode; /* e.g. "host" */
    int verify;                  /* TLS verify (1 default) */
    const char *ca_cert;         /* "" -> system CAs */
    int checkin_seconds;         /* default 60 */
    const char *key_dir;         /* keystore dir for the 'agent' identity */
    const char *report_mode;     /* "direct" (default) | "relay" */
    const char *relay_via;       /* edge: relay agent name when report_mode=relay */
};

#include <stdlib.h>

/* Build from PS_CENTRAL_* / PS_KEY_DIR env (set by config_to_env, already
 * quote-stripped). Pointers reference the process environment. */
static inline struct ps_central_config ps_central_config_from_env(void) {
    struct ps_central_config cc;
    cc.url             = getenv("PS_CENTRAL_URL");
    cc.agent_id        = getenv("PS_CENTRAL_AGENT_ID");
    cc.deployment_mode = getenv("PS_CENTRAL_DEPLOYMENT_MODE");
    const char *v      = getenv("PS_CENTRAL_VERIFY");
    cc.verify          = (v && v[0] == '0') ? 0 : 1;
    cc.ca_cert         = getenv("PS_CENTRAL_CA_CERT");
    const char *ci     = getenv("PS_CENTRAL_CHECKIN_SECONDS");
    cc.checkin_seconds = (ci && ci[0]) ? atoi(ci) : 60;
    cc.key_dir         = getenv("PS_KEY_DIR");
    cc.report_mode     = getenv("PS_CENTRAL_REPORT_MODE");
    if (!cc.report_mode || !cc.report_mode[0]) cc.report_mode = "direct";
    cc.relay_via       = getenv("PS_CENTRAL_RELAY_VIA");
    return cc;
}

#endif
