/*
 * test_network_listener_driver -- hosts the network_listener module in a
 * tiny standalone process so the bash e2e test can drive a real
 * `packetsonde --via` against it.
 *
 * Uses the module's init/shutdown directly. SIGTERM triggers shutdown.
 */
#include "packetsonde/module_api.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void ps_info(const char *fmt, ...)  { (void)fmt; }
void ps_warn(const char *fmt, ...)  { (void)fmt; }
void ps_error(const char *fmt, ...) { (void)fmt; }
void ps_debug(const char *fmt, ...) { (void)fmt; }

int ps_module_register(const ps_module_t *mod) { (void)mod; return 0; }

/* Pull in the module source directly. */
#include "modules/network_listener.c"

static volatile sig_atomic_t g_stop = 0;
static void on_term(int sig) { (void)sig; g_stop = 1; }

int main(void) {
    signal(SIGTERM, on_term);
    signal(SIGINT,  on_term);
    ps_module_ctx_t ctx; memset(&ctx, 0, sizeof(ctx));
    if (nl_init(&ctx) != 0) {
        fprintf(stderr, "test_network_listener_driver: init failed\n");
        return 1;
    }
    while (!g_stop) sleep(1);
    nl_shutdown(&ctx);
    return 0;
}
