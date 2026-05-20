#ifndef PS_FINDING_H
#define PS_FINDING_H

#include "ulid.h"
#include <stddef.h>
#include <stdint.h>

enum ps_severity {
    PS_SEV_INFO = 0,
    PS_SEV_LOW,
    PS_SEV_MEDIUM,
    PS_SEV_HIGH,
    PS_SEV_CRITICAL
};

enum ps_confidence {
    PS_CONF_TENTATIVE = 0,
    PS_CONF_FIRM,
    PS_CONF_CONFIRMED
};

#define PS_FIND_TITLE_MAX     256
#define PS_FIND_EVIDENCE_MAX  4096
#define PS_FIND_TARGET_MAX    256
#define PS_FIND_HOST_MAX      128
#define PS_FIND_SOURCE_MAX    128
#define PS_FIND_KIND_MAX      128
#define PS_FIND_VIA_MAX       64

struct ps_finding {
    char id[PS_ULID_STRLEN + 1];
    char run_id[PS_ULID_STRLEN + 1];
    char ts[32];
    char source[PS_FIND_SOURCE_MAX];
    char host[PS_FIND_HOST_MAX];
    char via_agent[PS_FIND_VIA_MAX];
    char kind[PS_FIND_KIND_MAX];
    char title[PS_FIND_TITLE_MAX];
    enum ps_severity   severity;
    enum ps_confidence confidence;

    char target_ip[64];
    char target_hostname[PS_FIND_TARGET_MAX];
    uint16_t target_port;

    char evidence_json[PS_FIND_EVIDENCE_MAX];
};

void ps_finding_init(struct ps_finding *f,
                     const char *run_id,
                     const char *source,
                     const char *host,
                     const char *kind,
                     enum ps_severity severity,
                     enum ps_confidence confidence,
                     const char *title);

void ps_finding_set_target_ip      (struct ps_finding *f, const char *ip, uint16_t port);
void ps_finding_set_target_hostname(struct ps_finding *f, const char *hostname, uint16_t port);
void ps_finding_set_via_agent      (struct ps_finding *f, const char *agent_name);
void ps_finding_set_evidence_json  (struct ps_finding *f, const char *evidence);

const char *ps_severity_str  (enum ps_severity s);
const char *ps_confidence_str(enum ps_confidence c);

int ps_finding_to_json(const struct ps_finding *f, char *buf, size_t bufsz);
int ps_finding_to_text(const struct ps_finding *f, char *buf, size_t bufsz, int color);

#endif
