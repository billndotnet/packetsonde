#ifndef PS_UNIT_ENVELOPE_H
#define PS_UNIT_ENVELOPE_H
#include <stddef.h>

#define PS_ENV_MAX_PATHS 256
#define PS_ENV_PATHLEN   256
struct ps_unit_envelope {
    char unit[128];
    int n_read;  char rd[PS_ENV_MAX_PATHS][PS_ENV_PATHLEN];
    int n_write; char wr[PS_ENV_MAX_PATHS][PS_ENV_PATHLEN];
    int n_exec;  char ex[PS_ENV_MAX_PATHS][PS_ENV_PATHLEN];
    int touched_home, used_tmp, records, truncated;
};
void ps_envelope_init(struct ps_unit_envelope *e, const char *unit);
void ps_envelope_add(struct ps_unit_envelope *e, const char *event, const char *path);
int  ps_envelope_to_json(const struct ps_unit_envelope *e, char *out, size_t cap);
int  ps_envelope_from_json(const char *json, struct ps_unit_envelope *e);
#endif
