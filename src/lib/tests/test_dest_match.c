#include "dest_match.h"
#include "baseline_set.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    /* exact */
    assert(ps_dest_match("1.2.3.4:443", "1.2.3.4:443") == 1);
    assert(ps_dest_match("1.2.3.4:443", "1.2.3.4:80") == 0);
    /* host (any port) */
    assert(ps_dest_match("1.2.3.4", "1.2.3.4:443") == 1);
    assert(ps_dest_match("1.2.3.4", "1.2.3.5:443") == 0);
    /* port (any host) */
    assert(ps_dest_match(":443", "9.9.9.9:443") == 1);
    assert(ps_dest_match(":443", "9.9.9.9:80") == 0);
    /* v4 CIDR (any port) */
    assert(ps_dest_match("1.2.3.0/24", "1.2.3.200:443") == 1);
    assert(ps_dest_match("1.2.3.0/24", "1.2.4.1:443") == 0);
    /* CIDR + port */
    assert(ps_dest_match("10.0.0.0/8:22", "10.9.9.9:22") == 1);
    assert(ps_dest_match("10.0.0.0/8:22", "10.9.9.9:23") == 0);

    /* set coverage */
    struct ps_baseline_set s; ps_blset_init(&s, "/x");
    ps_blset_add(&s, "1.2.3.0/24"); ps_blset_add(&s, ":53");
    assert(ps_destset_covered(&s, "1.2.3.9:443") == 1);
    assert(ps_destset_covered(&s, "8.8.8.8:53") == 1);
    assert(ps_destset_covered(&s, "8.8.8.8:443") == 0);

    /* generalize */
    char o[64];
    assert(ps_dest_generalize("1.2.3.4:443", "host", o, sizeof o) == 0 && strcmp(o, "1.2.3.4") == 0);
    assert(ps_dest_generalize("1.2.3.4:443", "port", o, sizeof o) == 0 && strcmp(o, ":443") == 0);
    assert(ps_dest_generalize("1.2.3.4:443", "cidr/24", o, sizeof o) == 0 && strcmp(o, "1.2.3.0/24") == 0);
    assert(ps_dest_generalize("1.2.3.4:443", "exact", o, sizeof o) == 0 && strcmp(o, "1.2.3.4:443") == 0);
    printf("test_dest_match: OK\n");
    return 0;
}
