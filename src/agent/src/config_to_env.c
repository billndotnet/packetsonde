#include "config_to_env.h"

#include <stdlib.h>
#include <string.h>

struct mapping {
    const char *section;
    const char *key;
    const char *env_name;
};

static const struct mapping MAPPINGS[] = {
    /* discovery -- pcap-based knock listener */
    { "discovery", "enabled",              "PS_DISCOVERY_ENABLED" },
    { "discovery", "agent_key",            "PS_DISCOVERY_AGENT_KEY" },
    { "discovery", "authorized_dir",       "PS_DISCOVERY_AUTHORIZED_DIR" },
    { "discovery", "listen_ip",            "PS_DISCOVERY_LISTEN_IP" },
    { "discovery", "listen_port",          "PS_DISCOVERY_LISTEN_PORT" },
    { "discovery", "max_skew_ms_hard_cap", "PS_DISCOVERY_MAX_SKEW_MS_CAP" },

    /* agent_listen -- inbound mTLS sessions for --via */
    { "agent_listen", "mode",            "PS_AGENT_LISTEN_MODE" },
    { "agent_listen", "addr",            "PS_AGENT_LISTEN_ADDR" },
    { "agent_listen", "port",            "PS_AGENT_LISTEN_PORT" },
    { "agent_listen", "key",             "PS_AGENT_LISTEN_KEY" },
    { "agent_listen", "authorized_dir",  "PS_AGENT_AUTHORIZED_DIR" },
    { "agent_listen", "max_clients",     "PS_AGENT_MAX_CLIENTS" },
    { "agent_listen", "packetsonde_bin", "PS_PACKETSONDE_BIN" },

    /* capture -- passive pcap interface selection */
    { "capture", "exclude", "PS_CAPTURE_EXCLUDE" },

    /* iface_monitor -- interface change detection poll interval (seconds) */
    { "iface_monitor", "interval", "PS_IFACE_MONITOR_INTERVAL" },

    /* netflow / IPFIX exporter */
    { "netflow", "collector", "PS_NETFLOW_COLLECTOR" },
    { "netflow", "version",   "PS_NETFLOW_VERSION" },
    { "netflow", "source_id", "PS_NETFLOW_SOURCE_ID" },

    /* keystore */
    { "keys", "dir", "PS_KEY_DIR" },

    /* central management (rna-packetsonde) */
    { "central", "url",             "PS_CENTRAL_URL" },
    { "central", "agent_id",        "PS_CENTRAL_AGENT_ID" },
    { "central", "deployment_mode", "PS_CENTRAL_DEPLOYMENT_MODE" },
    { "central", "verify",          "PS_CENTRAL_VERIFY" },
    { "central", "ca_cert",         "PS_CENTRAL_CA_CERT" },
    { "central", "checkin_seconds", "PS_CENTRAL_CHECKIN_SECONDS" },
    { "central", "report_mode",     "PS_CENTRAL_REPORT_MODE" },
    { "central", "relay_via",       "PS_CENTRAL_RELAY_VIA" },

    /* relay role (this agent forwards others' envelopes to central) */
    { "relay", "role",          "PS_RELAY_ROLE" },
    { "relay", "allow_sources", "PS_RELAY_ALLOW_SOURCES" },

    /* detect -- process/file/socket collection (Linux) */
    { "detect", "enabled",        "PS_DETECT_ENABLED" },
    { "detect", "watch_paths",    "PS_DETECT_WATCH_PATHS" },
    { "detect", "suppress_paths", "PS_DETECT_SUPPRESS_PATHS" },
    { "detect", "max_depth",      "PS_DETECT_MAX_DEPTH" },
    { "detect", "max_events_ps",  "PS_DETECT_MAX_EVENTS_PS" },
    { "detect", "sink",           "PS_DETECT_SINK" },
    { "detect", "policy_mode",      "PS_DETECT_POLICY_MODE" },
    { "detect", "policy_cache_ttl", "PS_DETECT_POLICY_CACHE_TTL" },
    { "detect", "learn_state_dir",  "PS_DETECT_LEARN_STATE_DIR" },
    { "detect", "rollup_threshold", "PS_DETECT_ROLLUP_THRESHOLD" },
    { "detect", "baseline_mode",      "PS_DETECT_BASELINE_MODE" },
    { "detect", "baseline_state_dir", "PS_DETECT_BASELINE_STATE_DIR" },
    { "detect", "baseline_reload",    "PS_DETECT_BASELINE_RELOAD" },
    { "detect", "provenance_enabled",         "PS_DETECT_PROVENANCE_ENABLED" },
    { "detect", "provenance_transient_paths", "PS_DETECT_PROVENANCE_TRANSIENT_PATHS" },
    { "detect", "provenance_sensitive_paths", "PS_DETECT_PROVENANCE_SENSITIVE_PATHS" },

    { NULL, NULL, NULL }
};

int ps_config_to_env(const struct ps_config *cfg) {
    int set_count = 0;
    for (int i = 0; i < cfg->count; i++) {
        const struct ps_config_entry *e = &cfg->entries[i];
        for (const struct mapping *m = MAPPINGS; m->section; m++) {
            if (strcmp(e->section, m->section) != 0) continue;
            if (strcmp(e->key,     m->key)     != 0) continue;
            /* Env wins. Pre-existing PS_* override the file. */
            if (getenv(m->env_name) != NULL) break;
            /* The TOML parser preserves wrapping double-quotes; strip
             * them so modules see "1", "knock", etc. as raw values. */
            const char *val = e->value;
            char buf[sizeof(e->value)];
            size_t L = strlen(val);
            if (L >= 2 && val[0] == '"' && val[L - 1] == '"') {
                memcpy(buf, val + 1, L - 2);
                buf[L - 2] = '\0';
                val = buf;
            }
            if (setenv(m->env_name, val, 0) == 0) set_count++;
            break;
        }
    }
    return set_count;
}
