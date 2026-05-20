#ifndef PSCTL_FORMAT_H
#define PSCTL_FORMAT_H

enum psctl_fmt {
    PSCTL_FMT_TEXT = 0,
    PSCTL_FMT_JSON,
    PSCTL_FMT_QUIET
};

/* Format and print a modules response */
void psctl_print_modules(const char *json, enum psctl_fmt fmt);

/* Format and print a hosts list */
void psctl_print_hosts(const char *json, enum psctl_fmt fmt);

/* Format and print a single host detail */
void psctl_print_host(const char *json, enum psctl_fmt fmt);

/* Format and print agent stats */
void psctl_print_stats(const char *json, enum psctl_fmt fmt);

/* Format and print a live discovery event */
void psctl_print_event(const char *channel, const char *payload, enum psctl_fmt fmt);

/* Format and print a flows list */
void psctl_print_flows(const char *json, enum psctl_fmt fmt);

/* Print help text */
void psctl_print_help(void);

#endif
