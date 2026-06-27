/* kernel_priv_worker.c — fanotify-only privilege-separated worker for
 * kernelsonded. Speaks the shared ps_priv_msg wire format but only ever
 * produces PS_OP_ACTIVITY_DATA frames. See priv_protocol.h.
 *
 * Structure (mirrors priv_worker.c's fanotify path):
 *   - parse --fd N  -> g_brain_fd
 *   - emit_activity(const char *json, size_t len, void *ctx):
 *       frame as PS_OP_ACTIVITY_DATA, write to g_brain_fd
 *   - fan_thread(void *cfg): call ps_fan_monitor_run(cfg, emit_activity, NULL)
 *   - main(): read PS_DETECT_* env into struct ps_fan_cfg, pthread_create(fan_thread),
 *       then poll(g_brain_fd) discarding any inbound frames until EOF, then exit.
 *
 * No pcap/raw slots, no command opcodes, no g_write_mu (single writer). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <pthread.h>

#include "priv_protocol.h"
#include "fan_monitor.h"
#include "log.h"

/* The socketpair fd connecting us to the brain */
static int g_brain_fd = -1;

/* Activity drop counter for lossy-tolerance logging */
static unsigned long g_activity_dropped = 0;

/* ------------------------------------------------------------------ */
/* I/O helpers                                                          */
/* ------------------------------------------------------------------ */

static int write_all(int fd, const uint8_t *buf, size_t n)
{
    while (n > 0) {
        ssize_t r = write(fd, buf, n);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = { .fd = fd, .events = POLLOUT };
                poll(&pfd, 1, 100);
                continue;
            }
            return -1;
        }
        buf += r;
        n   -= (size_t)r;
    }
    return 0;
}

static int read_all(int fd, uint8_t *buf, size_t n)
{
    while (n > 0) {
        ssize_t r = read(fd, buf, n);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = { .fd = fd, .events = POLLIN };
                poll(&pfd, 1, 100);
                continue;
            }
            return -1;
        }
        if (r == 0) return -1; /* EOF */
        buf += r;
        n   -= (size_t)r;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Fanotify emit callback + thread                                      */
/* ------------------------------------------------------------------ */

static void emit_activity(const char *json, size_t len, void *ctx)
{
    (void)ctx;
    if (len > PS_MAX_MSG_PAYLOAD) return;
    uint8_t frame[PS_MAX_MSG_PAYLOAD + 16];
    size_t n = ps_priv_encode_activity(frame, sizeof frame, json, len);
    if (!n) return;
    /* Single writer — no mutex needed. Activity records are lossy-tolerant:
     * drop this frame rather than block the fanotify thread on a backed-up pipe. */
    struct pollfd pw = { .fd = g_brain_fd, .events = POLLOUT, .revents = 0 };
    if (poll(&pw, 1, 0) == 1 && (pw.revents & POLLOUT)) {
        write_all(g_brain_fd, frame, n);
    } else {
        if ((++g_activity_dropped % 1000) == 1)
            ps_warn("kernel_priv_worker: brain pipe backed up, dropped %lu activity record(s)",
                    g_activity_dropped);
    }
}

static void *fan_thread(void *arg)
{
    struct ps_fan_cfg *cfg = arg;
    ps_fan_monitor_run(cfg, emit_activity, NULL);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Drain loop: discard all inbound frames until EOF                    */
/* ------------------------------------------------------------------ */

static void drain_loop(void)
{
    uint8_t discard[PS_MAX_MSG_PAYLOAD];

    for (;;) {
        struct pollfd pfd = { .fd = g_brain_fd, .events = POLLIN, .revents = 0 };
        int r = poll(&pfd, 1, 1000);
        if (r < 0) {
            if (errno == EINTR) continue;
            ps_error("kernel_priv_worker: poll failed: %s", strerror(errno));
            break;
        }

        if (pfd.revents & POLLHUP) {
            ps_info("kernel_priv_worker: brain disconnected, exiting");
            break;
        }

        if (pfd.revents & (POLLERR | POLLNVAL)) break;

        if (pfd.revents & POLLIN) {
            struct ps_priv_msg hdr;
            if (read_all(g_brain_fd, (uint8_t *)&hdr, sizeof(hdr)) < 0) {
                ps_info("kernel_priv_worker: brain closed connection");
                break;
            }
            uint32_t plen = hdr.payload_len;
            if (plen > PS_MAX_MSG_PAYLOAD) {
                ps_error("kernel_priv_worker: payload too large (%u), disconnecting", plen);
                break;
            }
            if (plen > 0) {
                if (read_all(g_brain_fd, discard, plen) < 0) {
                    ps_error("kernel_priv_worker: read payload failed");
                    break;
                }
            }
            /* kernelsonde-priv is emit-only: silently discard all inbound opcodes */
        }
    }
}

/* ------------------------------------------------------------------ */
/* Entry point                                                          */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    ps_log_set_prefix("kpriv");
    ps_log_set_level(PS_LOG_INFO);

    /* Parse --fd <N> */
    int fd = -1;
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--fd") == 0) {
            fd = atoi(argv[i + 1]);
            break;
        }
    }

    if (fd < 0) {
        fprintf(stderr, "kernelsonde-priv: usage: --fd <socketpair_fd>\n");
        return EXIT_FAILURE;
    }

    g_brain_fd = fd;

    /* Set non-blocking so the poll-before-write in emit_activity is meaningful */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    ps_info("kernel_priv_worker: started (fd=%d)", fd);

    /* Start fanotify collection thread if PS_DETECT_ENABLED is set.
     * Env block copied verbatim from priv_worker.c:623-638. */
    static struct ps_fan_cfg fan_cfg;
    const char *detect_enabled = getenv("PS_DETECT_ENABLED");
    if (detect_enabled && atoi(detect_enabled)) {
        const char *max_depth_str     = getenv("PS_DETECT_MAX_DEPTH");
        const char *max_events_ps_str = getenv("PS_DETECT_MAX_EVENTS_PS");
        fan_cfg.watch_paths   = getenv("PS_DETECT_WATCH_PATHS");
        fan_cfg.suppress      = getenv("PS_DETECT_SUPPRESS_PATHS");
        fan_cfg.max_depth     = max_depth_str     ? atoi(max_depth_str)     : 16;
        fan_cfg.max_events_ps = max_events_ps_str ? atoi(max_events_ps_str) : 2000;
        const char *prov_en = getenv("PS_DETECT_PROVENANCE_ENABLED");
        fan_cfg.prov.enabled         = prov_en ? atoi(prov_en) : 0;
        fan_cfg.prov.transient_paths = getenv("PS_DETECT_PROVENANCE_TRANSIENT_PATHS");
        fan_cfg.prov.sensitive_paths = getenv("PS_DETECT_PROVENANCE_SENSITIVE_PATHS");
        pthread_t t;
        if (pthread_create(&t, NULL, fan_thread, &fan_cfg) != 0) {
            ps_error("kernel_priv_worker: failed to create fan thread: %s", strerror(errno));
            return EXIT_FAILURE;
        }
        pthread_detach(t);
    }

    drain_loop();

    ps_info("kernel_priv_worker: exiting");
    close(fd);
    return EXIT_SUCCESS;
}
