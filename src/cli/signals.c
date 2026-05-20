#include "signals.h"

#include <signal.h>
#include <stddef.h>

static struct ps_workers *g_pool = NULL;

static void handler(int signo) {
    (void)signo;
    if (g_pool) ps_workers_cancel(g_pool);
}

void ps_signals_install(struct ps_workers *W) {
    g_pool = W;
    struct sigaction sa;
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}
