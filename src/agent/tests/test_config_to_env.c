#include "config.h"
#include "config_to_env.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); return 1; } } while (0)

static const char TOML[] =
    "[discovery]\n"
    "enabled = \"1\"\n"
    "agent_key = \"prod\"\n"
    "[agent_listen]\n"
    "mode = \"knock\"\n"
    "max_clients = \"128\"\n"
    "[netflow]\n"
    "collector = \"collector.lab:2055\"\n"
    "version = \"10\"\n"
    "[iface_monitor]\n"
    "interval = \"5\"\n";

int main(void) {
    unsetenv("PS_DISCOVERY_ENABLED");
    unsetenv("PS_DISCOVERY_AGENT_KEY");
    unsetenv("PS_AGENT_LISTEN_MODE");
    unsetenv("PS_AGENT_MAX_CLIENTS");
    unsetenv("PS_NETFLOW_COLLECTOR");
    unsetenv("PS_NETFLOW_VERSION");
    unsetenv("PS_IFACE_MONITOR_INTERVAL");

    struct ps_config cfg; memset(&cfg, 0, sizeof(cfg));
    CHECK(ps_config_parse_string(&cfg, TOML) == 0);

    int n = ps_config_to_env(&cfg);
    CHECK(n == 7);
    CHECK(strcmp(getenv("PS_DISCOVERY_ENABLED"),        "1")                  == 0);
    CHECK(strcmp(getenv("PS_DISCOVERY_AGENT_KEY"),      "prod")               == 0);
    CHECK(strcmp(getenv("PS_AGENT_LISTEN_MODE"),        "knock")              == 0);
    CHECK(strcmp(getenv("PS_AGENT_MAX_CLIENTS"),        "128")                == 0);
    CHECK(strcmp(getenv("PS_NETFLOW_COLLECTOR"),        "collector.lab:2055") == 0);
    CHECK(strcmp(getenv("PS_NETFLOW_VERSION"),          "10")                 == 0);
    /* iface_monitor interval maps to PS_IFACE_MONITOR_INTERVAL */
    CHECK(getenv("PS_IFACE_MONITOR_INTERVAL") != NULL);
    CHECK(strcmp(getenv("PS_IFACE_MONITOR_INTERVAL"),  "5")                  == 0);

    /* Env wins: pre-existing PS_* should NOT be overwritten by a fresh
     * translation pass. Clear everything except DISCOVERY_ENABLED, then
     * set it to "0", then re-translate; the file's "1" must be ignored. */
    unsetenv("PS_DISCOVERY_AGENT_KEY");
    unsetenv("PS_AGENT_LISTEN_MODE");
    unsetenv("PS_AGENT_MAX_CLIENTS");
    unsetenv("PS_NETFLOW_COLLECTOR");
    unsetenv("PS_NETFLOW_VERSION");
    unsetenv("PS_IFACE_MONITOR_INTERVAL");
    setenv  ("PS_DISCOVERY_ENABLED", "0", 1);
    struct ps_config cfg2; memset(&cfg2, 0, sizeof(cfg2));
    CHECK(ps_config_parse_string(&cfg2, TOML) == 0);
    int n2 = ps_config_to_env(&cfg2);
    CHECK(n2 == 6); /* DISCOVERY_ENABLED already in env, other 6 get set */
    CHECK(strcmp(getenv("PS_DISCOVERY_ENABLED"), "0") == 0);

    fprintf(stderr, "test_config_to_env: OK\n");
    return 0;
}
