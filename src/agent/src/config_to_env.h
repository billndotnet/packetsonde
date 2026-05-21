#ifndef PS_CONFIG_TO_ENV_H
#define PS_CONFIG_TO_ENV_H

#include "config.h"

/*
 * Translate a loaded `ps_config` into environment variables that the
 * existing modules already read. Honors precedence: pre-existing env
 * variables win, so operator overrides at launch (-e in systemd unit,
 * env: in launchd plist) take precedence over the file.
 *
 * Section/key conventions, mapped to env vars:
 *
 *   [discovery]
 *     enabled              -> PS_DISCOVERY_ENABLED
 *     agent_key            -> PS_DISCOVERY_AGENT_KEY
 *     authorized_dir       -> PS_DISCOVERY_AUTHORIZED_DIR
 *     listen_ip            -> PS_DISCOVERY_LISTEN_IP
 *     listen_port          -> PS_DISCOVERY_LISTEN_PORT
 *     max_skew_ms_hard_cap -> PS_DISCOVERY_MAX_SKEW_MS_CAP
 *
 *   [agent_listen]
 *     mode                 -> PS_AGENT_LISTEN_MODE
 *     addr                 -> PS_AGENT_LISTEN_ADDR
 *     port                 -> PS_AGENT_LISTEN_PORT
 *     key                  -> PS_AGENT_LISTEN_KEY
 *     authorized_dir       -> PS_AGENT_AUTHORIZED_DIR
 *     max_clients          -> PS_AGENT_MAX_CLIENTS
 *     packetsonde_bin      -> PS_PACKETSONDE_BIN
 *
 *   [netflow]
 *     collector            -> PS_NETFLOW_COLLECTOR
 *     version              -> PS_NETFLOW_VERSION
 *     source_id            -> PS_NETFLOW_SOURCE_ID
 *
 *   [keys]
 *     dir                  -> PS_KEY_DIR
 *
 * Unknown sections / keys are silently ignored so future config keys
 * roll forward without breaking older binaries.
 *
 * Returns the number of env vars set (>= 0).
 */
int ps_config_to_env(const struct ps_config *cfg);

#endif
