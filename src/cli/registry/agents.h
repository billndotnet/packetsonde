#ifndef PS_AGENTS_H
#define PS_AGENTS_H

#include <stddef.h>

#define PS_AGENT_NAME_MAX 64
#define PS_AGENT_FIELD_MAX 256

struct ps_agent {
    char name[PS_AGENT_NAME_MAX];
    char address[PS_AGENT_FIELD_MAX];          /* host:port for direct connect */
    char key_fingerprint[PS_AGENT_FIELD_MAX];  /* sha256:<hex>, pinned */
    char tags[PS_AGENT_FIELD_MAX];
    int  knock;                                 /* 1 = use knock-then-listen */
    char broadcast[PS_AGENT_FIELD_MAX];         /* broadcast addr for knock */
};

struct ps_agents {
    struct ps_agent *items;
    size_t           count;
    size_t           cap;
};

int  ps_agents_load   (struct ps_agents *A, const char *path);
const struct ps_agent *ps_agents_find(const struct ps_agents *A, const char *name);
void ps_agents_destroy(struct ps_agents *A);

const char *ps_agents_default_path(void);

#endif
