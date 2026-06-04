#ifndef PS_DEST_MATCH_H
#define PS_DEST_MATCH_H
#include <stddef.h>
#include "baseline_set.h"
/* Does a baseline dest entry match a live raddr "ip:port"?  Entry forms:
 *   "1.2.3.4:443" exact | "1.2.3.4" host(any port) | ":443" port(any host)
 *   "1.2.3.0/24" v4-CIDR(any port) | "1.2.3.0/24:443" v4-CIDR+port. Returns 1/0. */
int ps_dest_match(const char *entry, const char *raddr);
int ps_destset_covered(const struct ps_baseline_set *s, const char *raddr);
/* Generalize a raddr per `form` ("exact"|"host"|"port"|"cidr/N") into out. 0/-1. */
int ps_dest_generalize(const char *raddr, const char *form, char *out, size_t cap);
#endif
