#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#ifdef __APPLE__
#  include <mach/mach_time.h>
#  include <mach-o/dyld.h>
#else
#  include <time.h>
#  include <linux/limits.h>
#endif

int ps_platform_fork_priv_worker(const char *priv_binary_path)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        perror("socketpair");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(sv[0]);
        close(sv[1]);
        return -1;
    }

    if (pid == 0) {
        /* Child: close parent's end */
        close(sv[0]);

        /* Build fd string for --fd argument */
        char fd_str[32];
        snprintf(fd_str, sizeof(fd_str), "%d", sv[1]);

        execl(priv_binary_path, priv_binary_path, "--fd", fd_str, (char *)NULL);
        /* If we reach here, exec failed */
        perror("execl");
        _exit(EXIT_FAILURE);
    }

    /* Parent: close child's end, return our fd */
    close(sv[1]);
    return sv[0];
}

int ps_platform_drop_privs(const char *username)
{
    if (getuid() != 0) {
        /* Not root, nothing to drop */
        return 0;
    }

    struct passwd *pw = getpwnam(username);
    if (!pw) {
        fprintf(stderr, "ps_platform_drop_privs: unknown user '%s'\n", username);
        return -1;
    }

    if (initgroups(pw->pw_name, pw->pw_gid) < 0) {
        perror("initgroups");
        return -1;
    }

    if (setgid(pw->pw_gid) < 0) {
        perror("setgid");
        return -1;
    }

    if (setuid(pw->pw_uid) < 0) {
        perror("setuid");
        return -1;
    }

    return 0;
}

uint64_t ps_platform_now_usec(void)
{
#ifdef __APPLE__
    static mach_timebase_info_data_t tb = {0, 0};
    if (tb.denom == 0) {
        mach_timebase_info(&tb);
    }
    uint64_t t = mach_absolute_time();
    /* Convert from nanoseconds to microseconds */
    return (t * tb.numer / tb.denom) / 1000ULL;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
#endif
}

int ps_platform_exe_dir(char *buf, size_t bufsz)
{
#ifdef __APPLE__
    uint32_t sz = (uint32_t)bufsz;
    if (_NSGetExecutablePath(buf, &sz) != 0) {
        return -1;
    }
    /* Truncate to directory */
    char *slash = strrchr(buf, '/');
    if (slash) {
        *slash = '\0';
    }
    return 0;
#else
    char tmp[4096];
    ssize_t n = readlink("/proc/self/exe", tmp, sizeof(tmp) - 1);
    if (n < 0) {
        perror("readlink");
        return -1;
    }
    tmp[n] = '\0';
    char *slash = strrchr(tmp, '/');
    if (slash) {
        *slash = '\0';
    }
    if (strlen(tmp) + 1 > bufsz) {
        return -1;
    }
    memcpy(buf, tmp, strlen(tmp) + 1);
    return 0;
#endif
}
