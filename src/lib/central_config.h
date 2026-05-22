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
};

#endif
