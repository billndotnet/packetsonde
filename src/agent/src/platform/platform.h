#ifndef PS_PLATFORM_H
#define PS_PLATFORM_H

#include <stdint.h>
#include <sys/types.h>

/* Fork the priv worker. Returns socketpair fd in parent, never returns in child, -1 on error. */
int ps_platform_fork_priv_worker(const char *priv_binary_path);

/* Drop privileges to specified user. Returns 0 on success, -1 on error. Skips if not root. */
int ps_platform_drop_privs(const char *username);

/* Monotonic clock in microseconds. */
uint64_t ps_platform_now_usec(void);

/* Get directory containing the running executable. */
int ps_platform_exe_dir(char *buf, size_t bufsz);

#endif /* PS_PLATFORM_H */
