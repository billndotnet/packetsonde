#ifndef PS_TRACEROUTE_INTERNAL_H
#define PS_TRACEROUTE_INTERNAL_H

#include "traceroute.h"

/* Hop sink: forwards each discovered hop to the user callback and owns the
 * early-stop decision. A hop with addr[0] == '\0' is a no-reply ("*") hop. */
struct ps_tr_sink {
    ps_tr_hop_cb cb;
    void        *user;
    int          max_gap;      /* copied from opts */
    int          seen_live;    /* at least one hop has answered */
    int          consec_dead;  /* current run of consecutive no-reply hops */
    int          stopped;      /* sticky: set once a stop condition fired */
};

void ps_tr_sink_init(struct ps_tr_sink *s, ps_tr_hop_cb cb, void *user,
                     int max_gap);

/* Emit one hop. Returns non-zero if the walk should stop. Once it returns
 * non-zero, the sink is "stopped" and further emits are no-ops returning 1. */
int ps_tr_sink_emit(struct ps_tr_sink *s, const struct ps_tr_hop *hop);

#endif
