#include "iface_snapshot.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static struct ps_iface_snap mk(const char *name, int up, int running, uint32_t h) {
    struct ps_iface_snap s;
    memset(&s, 0, sizeof(s));
    strncpy(s.name, name, sizeof(s.name) - 1);
    s.up = up; s.running = running; s.addr_hash = h;
    return s;
}

static const struct ps_iface_change *find(const struct ps_iface_change *c, int n,
                                          const char *name,
                                          enum ps_iface_change_kind kind) {
    for (int i = 0; i < n; i++)
        if (c[i].kind == kind && strcmp(c[i].name, name) == 0) return &c[i];
    return NULL;
}

int main(void) {
    struct ps_iface_change ch[16];

    /* No change: identical sets -> 0 */
    {
        struct ps_iface_snap a[] = { mk("eth0",1,1,111), mk("eth1",1,1,222) };
        struct ps_iface_snap b[] = { mk("eth0",1,1,111), mk("eth1",1,1,222) };
        assert(ps_iface_diff(a,2,b,2,ch,16) == 0);
    }

    /* Ordering of inputs must not matter */
    {
        struct ps_iface_snap a[] = { mk("eth0",1,1,111), mk("eth1",1,1,222) };
        struct ps_iface_snap b[] = { mk("eth1",1,1,222), mk("eth0",1,1,111) };
        assert(ps_iface_diff(a,2,b,2,ch,16) == 0);
    }

    /* ADDED */
    {
        struct ps_iface_snap a[] = { mk("eth0",1,1,111) };
        struct ps_iface_snap b[] = { mk("eth0",1,1,111), mk("eth1",1,0,222) };
        int n = ps_iface_diff(a,1,b,2,ch,16);
        assert(n == 1);
        const struct ps_iface_change *c = find(ch,n,"eth1",PS_IFC_ADDED);
        assert(c && c->new_up == 1 && c->new_running == 0);
    }

    /* REMOVED */
    {
        struct ps_iface_snap a[] = { mk("eth0",1,1,111), mk("eth1",1,1,222) };
        struct ps_iface_snap b[] = { mk("eth0",1,1,111) };
        int n = ps_iface_diff(a,2,b,1,ch,16);
        assert(n == 1);
        assert(find(ch,n,"eth1",PS_IFC_REMOVED) != NULL);
    }

    /* STATE up->down */
    {
        struct ps_iface_snap a[] = { mk("eth1",1,1,222) };
        struct ps_iface_snap b[] = { mk("eth1",0,0,222) };
        int n = ps_iface_diff(a,1,b,1,ch,16);
        assert(n == 1);
        const struct ps_iface_change *c = find(ch,n,"eth1",PS_IFC_STATE);
        assert(c && c->old_up == 1 && c->new_up == 0);
    }

    /* STATE down->up */
    {
        struct ps_iface_snap a[] = { mk("eth1",0,0,222) };
        struct ps_iface_snap b[] = { mk("eth1",1,1,222) };
        int n = ps_iface_diff(a,1,b,1,ch,16);
        assert(n == 1);
        const struct ps_iface_change *c = find(ch,n,"eth1",PS_IFC_STATE);
        assert(c && c->old_up == 0 && c->new_up == 1);
    }

    /* ADDR change only (up/running same) */
    {
        struct ps_iface_snap a[] = { mk("eth0",1,1,111) };
        struct ps_iface_snap b[] = { mk("eth0",1,1,999) };
        int n = ps_iface_diff(a,1,b,1,ch,16);
        assert(n == 1);
        assert(find(ch,n,"eth0",PS_IFC_ADDR) != NULL);
    }

    /* STATE takes priority over ADDR when both differ (one change per iface) */
    {
        struct ps_iface_snap a[] = { mk("eth0",1,1,111) };
        struct ps_iface_snap b[] = { mk("eth0",0,0,999) };
        int n = ps_iface_diff(a,1,b,1,ch,16);
        assert(n == 1);
        assert(find(ch,n,"eth0",PS_IFC_STATE) != NULL);
    }

    printf("test_iface_snapshot: OK\n");
    return 0;
}
