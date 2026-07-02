/* Regression: stp_listener must actually process dispatched packets.
 * See test_dhcp_listener.c — same dead-handle-guard defect (pcap_handle pinned
 * to -1, dispatcher always passes the real capture handle >= 0). */
#include "../src/modules/stp_listener.c"
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
    CHECK(stp_init(&ctx) == 0);
    struct stp_state *st = ctx.userdata;
    CHECK(st && st->packets_seen == 0);

    uint8_t pkt[64]; memset(pkt, 0, sizeof(pkt));
    stp_on_packet(&ctx, pkt, sizeof(pkt), 0, /*handle_id*/0);

    CHECK(st->packets_seen == 1);   /* fails if the handle guard dropped it */
    stp_shutdown(&ctx);
    printf("ok\n");
    return 0;
}
