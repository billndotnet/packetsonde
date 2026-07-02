/* Regression: dhcp_listener must actually process dispatched packets.
 *
 * The module never opens its own pcap handle (it relies on the shared capture),
 * so its historical `if (handle_id != st->pcap_handle) return;` guard — with
 * pcap_handle pinned to -1 in init — silently dropped 100% of packets, since
 * the registry always dispatches with the real capture handle (>= 0). This test
 * feeds a packet through on_packet with a realistic handle id and asserts it
 * reaches processing (packets_seen increments right after the guard). */
#include "../src/modules/dhcp_listener.c"
#include <stdio.h>
#include <string.h>
#define CHECK(c) do{ if(!(c)){ fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c); return 1; } }while(0)

static int stub_publish(ps_module_ctx_t *c, const char *ch, const char *j, uint32_t n)
{ (void)c;(void)ch;(void)j;(void)n; return 0; }
static void stub_log(ps_module_ctx_t *c, int lvl, const char *fmt, ...)
{ (void)c;(void)lvl;(void)fmt; }

int main(void) {
    ps_module_ctx_t ctx; memset(&ctx, 0, sizeof(ctx));
    ctx.publish = stub_publish; ctx.log = stub_log;
    CHECK(dhcp_init(&ctx) == 0);
    struct dhcp_state *st = ctx.userdata;
    CHECK(st && st->packets_seen == 0);

    uint8_t pkt[64]; memset(pkt, 0, sizeof(pkt));   /* content irrelevant to the guard */
    dhcp_on_packet(&ctx, pkt, sizeof(pkt), 0, /*handle_id*/0);

    CHECK(st->packets_seen == 1);   /* fails if the handle guard dropped it */
    dhcp_shutdown(&ctx);
    printf("ok\n");
    return 0;
}
