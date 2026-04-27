#ifndef PSCTL_COMMANDS_H
#define PSCTL_COMMANDS_H

#include "psctl_connection.h"
#include "psctl_format.h"

/* Dispatch a command by name. Returns 0 on success. */
int psctl_dispatch(struct psctl_conn *conn, const char *cmd,
                   int argc, char **argv, enum psctl_fmt fmt);

/* Individual command handlers */
int psctl_cmd_modules(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt);
int psctl_cmd_hosts(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt);
int psctl_cmd_host(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt);
int psctl_cmd_stats(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt);
int psctl_cmd_listen(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt);
int psctl_cmd_enable(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt);
int psctl_cmd_disable(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt);
int psctl_cmd_trace(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt);
int psctl_cmd_ping(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt);
int psctl_cmd_probe(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt);
int psctl_cmd_version(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt);
int psctl_cmd_flows(struct psctl_conn *conn, int argc, char **argv, enum psctl_fmt fmt);

#endif
