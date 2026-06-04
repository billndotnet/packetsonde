#include "systemd_policy.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static int g_calls = 0;
static int stub_loader(const char *unit, char *out, size_t cap) {
    g_calls++;
    if (!strcmp(unit, "app.service"))
        snprintf(out, cap, "FragmentPath=/x.service\nProtectHome=true\n");
    else
        snprintf(out, cap, "");   /* unknown unit */
    return 0;
}

int main(void) {
    struct ps_unit_policy p;
    /* cold miss -> loads */
    assert(ps_unit_policy_get("app.service", 1000, 300, stub_loader, &p) == 0);
    assert(p.known == 1 && p.protect_home == PS_PROTHOME_INACCESSIBLE);
    assert(g_calls == 1);
    /* within TTL -> cached, no reload */
    assert(ps_unit_policy_get("app.service", 1100, 300, stub_loader, &p) == 0);
    assert(g_calls == 1);
    /* past TTL -> reload */
    assert(ps_unit_policy_get("app.service", 1400, 300, stub_loader, &p) == 0);
    assert(g_calls == 2);
    /* unknown unit cached too (known=0) */
    assert(ps_unit_policy_get("nope.service", 1400, 300, stub_loader, &p) == 0);
    assert(p.known == 0);
    assert(g_calls == 3);
    assert(ps_unit_policy_get("nope.service", 1450, 300, stub_loader, &p) == 0);
    assert(g_calls == 3);   /* negative result cached */
    printf("test_systemd_policy_cache: OK\n");
    return 0;
}
