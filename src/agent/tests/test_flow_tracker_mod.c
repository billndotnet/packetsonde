/* Regression: flow_tracker must release its pcap handles on stop, stop_all
 * and module shutdown.
 *
 * The priv worker's pcap table is a single 16-slot table shared by the whole
 * daemon. flow_tracker's stop/stop_all used to only mark its own slot inactive
 * (`pcap_handle = -1`) without calling ctx->close_pcap, so every start/stop
 * cycle leaked a priv-worker handle; 16 cycles exhausted the table and broke
 * open_pcap for every module until restart.
 *
 * The mock below models that table: open_pcap hands out the lowest free id and
 * fails when all 16 are taken, close_pcap frees an id and rejects one that is
 * not open (a double close would be a bug too). */
#include "../src/modules/flow_tracker_mod.c"
#include <stdio.h>
#include <string.h>
#define CHECK(c) do{ if(!(c)){ fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c); return 1; } }while(0)

#define MOCK_TABLE 16                   /* matches PS_MAX_PCAP_HANDLES */
static int g_open[MOCK_TABLE];
static int g_bad_close;                 /* close of an id that was not open */

static int open_count(void)
{
    int n = 0;
    for (int i = 0; i < MOCK_TABLE; i++) n += g_open[i];
    return n;
}

static int mock_open_pcap(ps_module_ctx_t *c, const char *iface,
                          const char *bpf, uint32_t snaplen)
{
    (void)c; (void)iface; (void)bpf; (void)snaplen;
    for (int i = 0; i < MOCK_TABLE; i++)
        if (!g_open[i]) { g_open[i] = 1; return i; }
    return -1;                          /* table full: what the leak caused */
}
static int mock_close_pcap(ps_module_ctx_t *c, int handle)
{
    (void)c;
    if (handle < 0 || handle >= MOCK_TABLE || !g_open[handle]) { g_bad_close++; return -1; }
    g_open[handle] = 0;
    return 0;
}
static int stub_publish(ps_module_ctx_t *c, const char *ch, const char *j, uint32_t n)
{ (void)c; (void)ch; (void)j; (void)n; return 0; }
static void stub_log(ps_module_ctx_t *c, int lvl, const char *fmt, ...)
{ (void)c; (void)lvl; (void)fmt; }

static void reset_table(void) { memset(g_open, 0, sizeof(g_open)); g_bad_close = 0; }

static ps_module_ctx_t make_ctx(void)
{
    ps_module_ctx_t ctx; memset(&ctx, 0, sizeof(ctx));
    ctx.open_pcap = mock_open_pcap; ctx.close_pcap = mock_close_pcap;
    ctx.publish = stub_publish; ctx.log = stub_log;
    return ctx;
}
static struct ps_job job(const char *action, const char *iface)
{
    struct ps_job j; memset(&j, 0, sizeof(j));
    snprintf(j.method, sizeof(j.method), "flow_control");
    snprintf(j.job_id, sizeof(j.job_id), "%s", action);
    snprintf(j.destination, sizeof(j.destination), "%s", iface);
    return j;
}
static int run(ps_module_ctx_t *ctx, const char *action, const char *iface)
{
    struct ps_job j = job(action, iface);
    return ft_mod_on_job(ctx, &j);
}

int main(void)
{
    ps_module_ctx_t ctx;
    ps_log_set_level(PS_LOG_ERROR);

    /* 1. start -> stop releases the handle; repeating it more times than the
     *    priv-worker table has slots keeps working. */
    reset_table();
    ctx = make_ctx();
    CHECK(ft_mod_init(&ctx) == 0);
    for (int i = 0; i < 3 * MOCK_TABLE; i++) {
        CHECK(run(&ctx, "start", "if0") == 0);   /* fails at i == 16 if leaked */
        CHECK(open_count() == 1);
        CHECK(run(&ctx, "stop", "if0") == 0);
        CHECK(open_count() == 0);
    }
    /* stopping an interface that is not captured closes nothing */
    CHECK(run(&ctx, "stop", "if0") == 0);
    CHECK(g_bad_close == 0);
    ft_mod_shutdown(&ctx);
    CHECK(open_count() == 0);
    CHECK(g_bad_close == 0);

    /* 2. stop_all releases every open handle, once each. */
    reset_table();
    ctx = make_ctx();
    CHECK(ft_mod_init(&ctx) == 0);
    CHECK(run(&ctx, "start", "if0") == 0);
    CHECK(run(&ctx, "start", "if1") == 0);
    CHECK(run(&ctx, "start", "if2") == 0);
    CHECK(open_count() == 3);
    CHECK(run(&ctx, "stop_all", "") == 0);
    CHECK(open_count() == 0);
    CHECK(run(&ctx, "stop_all", "") == 0);      /* nothing left: no double close */
    CHECK(g_bad_close == 0);
    ft_mod_shutdown(&ctx);
    CHECK(g_bad_close == 0);

    /* 3. module shutdown with captures still running releases them too
     *    (a module reload must not leak the table either). */
    reset_table();
    ctx = make_ctx();
    CHECK(ft_mod_init(&ctx) == 0);
    CHECK(run(&ctx, "start", "if0") == 0);
    CHECK(run(&ctx, "start", "if1") == 0);
    CHECK(run(&ctx, "stop", "if0") == 0);
    CHECK(open_count() == 1);
    ft_mod_shutdown(&ctx);
    CHECK(open_count() == 0);
    CHECK(g_bad_close == 0);

    /* 4. a context without close_pcap (older host) must not crash. */
    reset_table();
    ctx = make_ctx();
    ctx.close_pcap = NULL;
    CHECK(ft_mod_init(&ctx) == 0);
    CHECK(run(&ctx, "start", "if0") == 0);
    CHECK(run(&ctx, "stop", "if0") == 0);
    CHECK(run(&ctx, "start", "if0") == 0);
    CHECK(run(&ctx, "stop_all", "") == 0);
    ft_mod_shutdown(&ctx);

    printf("ok\n");
    return 0;
}
