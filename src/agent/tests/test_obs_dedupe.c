/* Observation dedupe: key canonicalisation, suppression windows and the
 * temporal summary. Deterministic clock (now_ms), no sleeping. */
#include "obs_dedupe.h"
#include "obs_queue.h"
#include "config.h"
#include "config_to_env.h"
#include "json_extract.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define T0 1767225600000LL   /* 2026-01-01T00:00:00Z */

static int g_fail;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

/* ---- emit capture ---- */
#define CAP_MAX 512
static char *g_emitted[CAP_MAX];
static int   g_nemit;
static long  g_emit_repeats;   /* sum of n over every emitted summary */
static long field_long(const char *ev, const char *key);
static void cap_emit(const char *ev, size_t len, void *user) {
    (void)user;
    CHECK(len < PS_OBS_ITEM_MAX);
    CHECK(strlen(ev) == len);
    g_emit_repeats += field_long(ev, "n");
    if (g_nemit < CAP_MAX) { g_emitted[g_nemit] = strndup(ev, len); g_nemit++; }
}
static void cap_reset(void) {
    for (int i = 0; i < g_nemit; i++) free(g_emitted[i]);
    g_nemit = 0;
    g_emit_repeats = 0;
}

static void init_cfg(int window_s, int table_max) {
    struct ps_obs_dedupe_cfg c;
    ps_obs_dedupe_cfg_defaults(&c);
    c.window_s = window_s;
    c.table_max = table_max;
    c.emit = cap_emit;
    assert(ps_obs_dedupe_init(&c) == 0);
    cap_reset();
}

static long field_long(const char *ev, const char *key) {
    long v = -1;
    const char *d = strstr(ev, "\"dedupe\":");
    if (!d || ps_json_extract_int(d, key, &v) != 0) return -1;
    return v;
}
static int field_str(const char *ev, const char *key, char *out, size_t cap) {
    const char *d = strstr(ev, "\"dedupe\":");
    return d ? ps_json_extract_string(d, key, out, cap) : -1;
}
static int has(const char *ev, const char *needle) { return strstr(ev, needle) != NULL; }

static char g_items[64][PS_OBS_ITEM_MAX];

static const char *NB_A = "{\"ip\":\"192.0.2.10\",\"mac\":\"02:00:00:00:00:01\",\"interface\":\"eth0\",\"proto\":\"arp\",\"ndp_type\":null,\"router\":false,\"flags\":0}";
static const char *NB_B = "{\"ip\":\"192.0.2.10\",\"mac\":\"02:00:00:00:00:02\",\"interface\":\"eth0\",\"proto\":\"arp\",\"ndp_type\":null,\"router\":false,\"flags\":0}";

/* ---------------------------------------------------------------- */
static void test_vectors(const char *path) {
    FILE *f = fopen(path, "r");
    CHECK(f != NULL);
    if (!f) return;
    static char line[16384];
    int n = 0;
    while (fgets(line, sizeof line, f)) {
        if (!strstr(line, "\"kind\"")) continue;
        char kind[128], want[PS_DEDUPE_KEY_MAX], got[PS_DEDUPE_KEY_MAX], name[256];
        CHECK(ps_json_extract_string(line, "name", name, sizeof name) >= 0);
        CHECK(ps_json_extract_string(line, "kind", kind, sizeof kind) >= 0);
        CHECK(ps_json_extract_string(line, "key", want, sizeof want) >= 0);
        const char *o = strstr(line, "\"observation\":");
        CHECK(o != NULL);
        if (!o) continue;
        o += strlen("\"observation\":");
        /* the observation is the last member: strip the vector's closing "}" */
        size_t L = strlen(o);
        while (L && (o[L-1] == '\n' || o[L-1] == ',' || o[L-1] == ' ')) L--;
        CHECK(L && o[L-1] == '}');
        L--;
        int r = ps_obs_dedupe_key_n(kind, o, L, got);
        if (r < 0 || strcmp(got, want) != 0) {
            fprintf(stderr, "vector '%s':\n  got  %s\n  want %s\n", name, r < 0 ? "(error)" : got, want);
            g_fail++;
        } else {
            CHECK((size_t)r == strlen(want));
        }
        n++;
    }
    fclose(f);
    CHECK(n >= 10);
}

static void test_key_properties(void) {
    char a[PS_DEDUPE_KEY_MAX], b[PS_DEDUPE_KEY_MAX];
    /* kind is part of the key */
    CHECK(ps_obs_dedupe_key("discovery.mld", "{\"group\":\"ff02::fb\"}", a) > 0);
    CHECK(ps_obs_dedupe_key("discovery.ssdp", "{\"group\":\"ff02::fb\"}", b) > 0);
    CHECK(strcmp(a, b) != 0);
    /* a non-volatile change changes the key */
    CHECK(ps_obs_dedupe_key("discovery.neighbor", NB_A, a) > 0);
    CHECK(ps_obs_dedupe_key("discovery.neighbor", NB_B, b) > 0);
    CHECK(strcmp(a, b) != 0);
    /* an extra DNS answer changes the key */
    CHECK(ps_obs_dedupe_key("discovery.dns", "{\"query\":\"q\",\"answers\":[{\"name\":\"q\",\"type\":\"A\",\"data\":\"198.51.100.1\",\"ttl\":5}]}", a) > 0);
    CHECK(ps_obs_dedupe_key("discovery.dns", "{\"query\":\"q\",\"answers\":[{\"name\":\"q\",\"type\":\"A\",\"data\":\"198.51.100.1\",\"ttl\":9},{\"name\":\"q\",\"type\":\"A\",\"data\":\"198.51.100.2\",\"ttl\":9}]}", b) > 0);
    CHECK(strcmp(a, b) != 0);
    /* invalid JSON, trailing garbage, too deep: no key */
    CHECK(ps_obs_dedupe_key("k", "{\"a\":", a) == -1);
    CHECK(ps_obs_dedupe_key("k", "{\"a\":1} x", a) == -1);
    CHECK(ps_obs_dedupe_key("k", "{\"a\":tru}", a) == -1);
    CHECK(ps_obs_dedupe_key("k", "{\"a\":\"\\ud800\"}", a) == -1);
    char deep[200]; int p = 0;
    for (int i = 0; i < 40; i++) deep[p++] = '[';
    for (int i = 0; i < 40; i++) deep[p++] = ']';
    deep[p] = 0;
    CHECK(ps_obs_dedupe_key("k", deep, a) == -1);
    /* surrogate pair decoded to raw UTF-8 */
    CHECK(ps_obs_dedupe_key("k", "{\"s\":\"\\ud83d\\ude00\"}", a) > 0);
    CHECK(strcmp(a, "k|{\"s\":\"\xf0\x9f\x98\x80\"}") == 0);
}

static void test_send_then_suppress(void) {
    init_cfg(-1, 0);
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", NB_A, T0) == PS_DEDUPE_SEND);
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", NB_A, T0 + 1000) == PS_DEDUPE_SUPPRESS);
    /* volatile field + member order do not matter */
    CHECK(ps_obs_dedupe_offer("discovery.neighbor",
        "{\"flags\":0,\"ts\":\"x\",\"router\":false,\"ndp_type\":null,\"proto\":\"arp\",\"interface\":\"eth0\",\"mac\":\"02:00:00:00:00:01\",\"ip\":\"192.0.2.10\"}",
        T0 + 2000) == PS_DEDUPE_SUPPRESS);
    /* same fields, other kind: its own first sighting */
    CHECK(ps_obs_dedupe_offer("discovery.other", NB_A, T0 + 2500) == PS_DEDUPE_SEND);
    /* unparseable observations are never suppressed */
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", "{bad", T0 + 3000) == PS_DEDUPE_SEND);
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", "{bad", T0 + 3001) == PS_DEDUPE_SEND);
    struct ps_obs_dedupe_counters c;
    ps_obs_dedupe_get_counters(&c);
    CHECK(c.offered == 6 && c.sent == 4 && c.suppressed == 2 && c.unkeyed == 2);
}

static void test_hundred_repeats(void) {
    init_cfg(-1, 0);
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", NB_A, T0) == PS_DEDUPE_SEND);
    for (int i = 1; i <= 100; i++)
        CHECK(ps_obs_dedupe_offer("discovery.neighbor", NB_A, T0 + i * 1000LL) == PS_DEDUPE_SUPPRESS);
    /* window (900 s) not over: nothing to flush */
    CHECK(ps_obs_dedupe_flush(T0 + 899999, 0, g_items, 64) == 0);
    int n = ps_obs_dedupe_flush(T0 + 900000, 0, g_items, 64);
    CHECK(n == 1);
    const char *ev = g_items[0];
    CHECK(has(ev, "\"kind\":\"discovery.neighbor\""));
    CHECK(has(ev, "\"ts\":\"2026-01-01T00:01:40Z\""));
    /* the observation as first seen */
    CHECK(has(ev, "\"observation\":{\"ip\":\"192.0.2.10\",\"mac\":\"02:00:00:00:00:01\""));
    CHECK(field_long(ev, "n") == 100);
    char s[64];
    CHECK(field_str(ev, "since", s, sizeof s) > 0 && strcmp(s, "2026-01-01T00:00:00Z") == 0);
    CHECK(field_str(ev, "first", s, sizeof s) > 0 && strcmp(s, "2026-01-01T00:00:01Z") == 0);
    CHECK(field_str(ev, "last", s, sizeof s) > 0 && strcmp(s, "2026-01-01T00:01:40Z") == 0);
    CHECK(has(ev, "\"gap_min\":1,") && has(ev, "\"gap_max\":1,") && has(ev, "\"gap_mean\":1,"));
    CHECK(has(ev, "\"seen\":[[0,100]]"));
    CHECK(!has(ev, "seen_coarse") && !has(ev, "truncated"));
    CHECK(strlen(ev) < PS_OBS_ITEM_MAX);
    /* exactly once */
    CHECK(ps_obs_dedupe_flush(T0 + 2000000, 0, g_items, 64) == 0);
    CHECK(ps_obs_dedupe_count() == 0);
    /* and the next sighting is a new first sighting */
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", NB_A, T0 + 2000000) == PS_DEDUPE_SEND);
}

static void test_irregular_gaps(void) {
    init_cfg(-1, 0);
    long gaps[] = { 1000, 1000, 5000, 5000, 2000 };
    int64_t t = T0;
    CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"group\":\"ff02::fb\"}", t) == PS_DEDUPE_SEND);
    for (int i = 0; i < 5; i++) {
        t += gaps[i];
        CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"group\":\"ff02::fb\"}", t) == PS_DEDUPE_SUPPRESS);
    }
    CHECK(ps_obs_dedupe_flush(t, 1, g_items, 64) == 1);
    const char *ev = g_items[0];
    CHECK(field_long(ev, "n") == 5);
    CHECK(has(ev, "\"gap_min\":1,") && has(ev, "\"gap_max\":5,") && has(ev, "\"gap_mean\":2.8,"));
    CHECK(has(ev, "\"seen\":[[0,2],[2,2],[12,1]]"));

    /* millisecond gaps: mean keeps ms precision */
    init_cfg(-1, 0);
    CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"g\":1}", T0) == PS_DEDUPE_SEND);
    CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"g\":1}", T0 + 250) == PS_DEDUPE_SUPPRESS);
    CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"g\":1}", T0 + 1500) == PS_DEDUPE_SUPPRESS);
    CHECK(ps_obs_dedupe_flush(T0, 1, g_items, 64) == 1);
    CHECK(has(g_items[0], "\"gap_min\":0.25,") && has(g_items[0], "\"gap_max\":1.25,") &&
          has(g_items[0], "\"gap_mean\":0.75,"));

    /* many different gaps: at most 32 pairs, counts and span preserved */
    init_cfg(-1, 0);
    t = T0;
    CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"g\":2}", t) == PS_DEDUPE_SEND);
    long mn = 1L << 30, mx = 0;
    for (int i = 0; i < 200; i++) {
        long g = 1000L * (1 + (i * 7) % 4);   /* 1,4,3,2,1,... s: always a new run */
        if (g < mn) mn = g;
        if (g > mx) mx = g;
        t += g;
        CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"g\":2}", t) == PS_DEDUPE_SUPPRESS);
    }
    CHECK(ps_obs_dedupe_flush(t, 1, g_items, 64) == 1);
    ev = g_items[0];
    CHECK(field_long(ev, "n") == 200);
    CHECK(has(ev, "\"gap_min\":1,") && has(ev, "\"gap_max\":4,"));
    CHECK(has(ev, "\"seen_coarse\":true"));
    const char *sp = strstr(ev, "\"seen\":[");
    CHECK(sp != NULL);
    int pairs = 0; long sum = 0, prev_off = -1, off, cnt;
    const char *q = sp + 8;
    while (q && sscanf(q, "[%ld,%ld]", &off, &cnt) == 2) {
        CHECK(off >= prev_off); prev_off = off;
        pairs++; sum += cnt;
        q = strchr(q, ']'); if (q) q++;
        if (q && *q == ',') q++; else break;
    }
    CHECK(pairs >= 2 && pairs <= PS_DEDUPE_SEEN_MAX);
    CHECK(sum == 200);
}

static void test_mac_change_closes(void) {
    init_cfg(-1, 0);
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", NB_A, T0) == PS_DEDUPE_SEND);
    for (int i = 1; i <= 3; i++)
        CHECK(ps_obs_dedupe_offer("discovery.neighbor", NB_A, T0 + i * 1000LL) == PS_DEDUPE_SUPPRESS);
    CHECK(g_nemit == 0);
    /* the IP now answers with another MAC: a new sighting, never suppressed */
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", NB_B, T0 + 10000) == PS_DEDUPE_SEND);
    CHECK(g_nemit == 1);
    CHECK(has(g_emitted[0], "02:00:00:00:00:01") && field_long(g_emitted[0], "n") == 3);
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", NB_B, T0 + 11000) == PS_DEDUPE_SUPPRESS);
    /* and back: A is a new first sighting again; B's window closes with n=1 */
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", NB_A, T0 + 12000) == PS_DEDUPE_SEND);
    CHECK(g_nemit == 2 && field_long(g_emitted[1], "n") == 1 && has(g_emitted[1], "02:00:00:00:00:02"));
    /* NS and NA of the same host do not close each other */
    init_cfg(-1, 0);
    const char *na = "{\"ip\":\"2001:db8::1\",\"mac\":\"02:00:00:00:00:03\",\"interface\":\"eth0\",\"proto\":\"ndp\",\"ndp_type\":\"na\",\"router\":false,\"flags\":64}";
    const char *ns = "{\"ip\":\"2001:db8::1\",\"mac\":\"02:00:00:00:00:03\",\"interface\":\"eth0\",\"proto\":\"ndp\",\"ndp_type\":\"ns\",\"router\":false,\"flags\":0}";
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", na, T0) == PS_DEDUPE_SEND);
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", ns, T0 + 1) == PS_DEDUPE_SEND);
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", na, T0 + 2) == PS_DEDUPE_SUPPRESS);
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", ns, T0 + 3) == PS_DEDUPE_SUPPRESS);
    CHECK(g_nemit == 0);
}

static void test_window_expiry(void) {
    init_cfg(-1, 0);
    const char *dns = "{\"query\":\"q.example\",\"type\":\"A\",\"answers\":[]}";
    CHECK(ps_obs_dedupe_window_for("discovery.dns") == 300);
    CHECK(ps_obs_dedupe_offer("discovery.dns", dns, T0) == PS_DEDUPE_SEND);
    CHECK(ps_obs_dedupe_offer("discovery.dns", dns, T0 + 299999) == PS_DEDUPE_SUPPRESS);
    /* a sighting after the window ended, before any flush: the old window is
     * closed (summary emitted first) and this one is sent */
    CHECK(ps_obs_dedupe_offer("discovery.dns", dns, T0 + 300000) == PS_DEDUPE_SEND);
    CHECK(g_nemit == 1 && field_long(g_emitted[0], "n") == 1);
    CHECK(ps_obs_dedupe_flush(T0 + 300001, 0, g_items, 64) == 0);
    /* entry without repeats expires silently */
    CHECK(ps_obs_dedupe_flush(T0 + 600000, 0, g_items, 64) == 0);
    CHECK(ps_obs_dedupe_count() == 0);

    /* flush returns at most max, the rest stays for the next call */
    init_cfg(-1, 0);
    char obs[64];
    for (int k = 0; k < 5; k++) {
        snprintf(obs, sizeof obs, "{\"group\":\"g%d\"}", k);
        CHECK(ps_obs_dedupe_offer("discovery.mld", obs, T0) == PS_DEDUPE_SEND);
        CHECK(ps_obs_dedupe_offer("discovery.mld", obs, T0 + 1000) == PS_DEDUPE_SUPPRESS);
    }
    CHECK(ps_obs_dedupe_flush(T0 + 900000, 0, g_items, 2) == 2);
    CHECK(ps_obs_dedupe_flush(T0 + 900000, 0, g_items, 2) == 2);
    CHECK(ps_obs_dedupe_flush(T0 + 900000, 0, g_items, 2) == 1);
    CHECK(ps_obs_dedupe_flush(T0 + 900000, 0, g_items, 2) == 0);
}

static void test_force_flush(void) {
    init_cfg(-1, 0);
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", NB_A, T0) == PS_DEDUPE_SEND);
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", NB_A, T0 + 5000) == PS_DEDUPE_SUPPRESS);
    CHECK(ps_obs_dedupe_offer("discovery.ssdp", "{\"usn\":\"u\"}", T0) == PS_DEDUPE_SEND);
    CHECK(ps_obs_dedupe_flush(T0 + 6000, 0, g_items, 64) == 0);
    CHECK(ps_obs_dedupe_flush(T0 + 6000, 1, g_items, 64) == 1);   /* only the one with repeats */
    CHECK(field_long(g_items[0], "n") == 1);
    CHECK(ps_obs_dedupe_count() == 0);
}

static void test_lru_eviction(void) {
    init_cfg(-1, 2);
    CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"g\":\"A\"}", T0) == PS_DEDUPE_SEND);
    CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"g\":\"B\"}", T0 + 1) == PS_DEDUPE_SEND);
    CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"g\":\"B\"}", T0 + 2) == PS_DEDUPE_SUPPRESS);
    CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"g\":\"A\"}", T0 + 3) == PS_DEDUPE_SUPPRESS);
    CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"g\":\"B\"}", T0 + 4) == PS_DEDUPE_SUPPRESS);
    /* A is now least recently seen: C evicts it, A's summary goes out first */
    CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"g\":\"C\"}", T0 + 5) == PS_DEDUPE_SEND);
    CHECK(g_nemit == 1 && has(g_emitted[0], "{\"g\":\"A\"}") && field_long(g_emitted[0], "n") == 1);
    CHECK(ps_obs_dedupe_count() == 2);
    CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"g\":\"A\"}", T0 + 6) == PS_DEDUPE_SEND);
    CHECK(g_nemit == 2 && has(g_emitted[1], "{\"g\":\"B\"}") && field_long(g_emitted[1], "n") == 2);
    struct ps_obs_dedupe_counters c;
    ps_obs_dedupe_get_counters(&c);
    CHECK(c.evicted == 2);
}

static void test_disabled_and_windows(void) {
    init_cfg(0, 0);
    for (int i = 0; i < 5; i++)
        CHECK(ps_obs_dedupe_offer("discovery.neighbor", NB_A, T0 + i) == PS_DEDUPE_SEND);
    CHECK(ps_obs_dedupe_count() == 0);
    CHECK(ps_obs_dedupe_flush(T0, 1, g_items, 64) == 0);

    struct ps_obs_dedupe_cfg c;
    ps_obs_dedupe_cfg_defaults(&c);
    c.emit = cap_emit;
    assert(ps_obs_dedupe_init(&c) == 0);
    CHECK(ps_obs_dedupe_window_for("discovery.neighbor") == 900);
    CHECK(ps_obs_dedupe_window_for("discovery.ssdp") == 900);
    CHECK(ps_obs_dedupe_window_for("discovery.dns") == 300);
    CHECK(ps_obs_dedupe_window_for("baseline.anomaly") == 900);
    c.window_s = 60;
    c.n_kinds = 3;
    snprintf(c.kinds[0].kind, sizeof c.kinds[0].kind, "dns");
    c.kinds[0].window_s = 10;
    snprintf(c.kinds[1].kind, sizeof c.kinds[1].kind, "discovery_ssdp");
    c.kinds[1].window_s = 0;
    snprintf(c.kinds[2].kind, sizeof c.kinds[2].kind, "net.iface.state");
    c.kinds[2].window_s = 5;
    assert(ps_obs_dedupe_init(&c) == 0);
    CHECK(ps_obs_dedupe_window_for("discovery.dns") == 10);
    CHECK(ps_obs_dedupe_window_for("discovery.ssdp") == 0);
    CHECK(ps_obs_dedupe_window_for("discovery.neighbor") == 60);
    CHECK(ps_obs_dedupe_window_for("net.iface.state") == 5);
    CHECK(ps_obs_dedupe_offer("discovery.ssdp", "{\"usn\":\"u\"}", T0) == PS_DEDUPE_SEND);
    CHECK(ps_obs_dedupe_offer("discovery.ssdp", "{\"usn\":\"u\"}", T0 + 1) == PS_DEDUPE_SEND);

    /* never initialised / shut down: pass-through */
    ps_obs_dedupe_shutdown();
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", NB_A, T0) == PS_DEDUPE_SEND);
    CHECK(ps_obs_dedupe_offer("discovery.neighbor", NB_A, T0 + 1) == PS_DEDUPE_SEND);
    CHECK(ps_obs_dedupe_flush(T0, 1, g_items, 64) == 0);
}

static void test_config_env(void) {
    static struct ps_config cfg;
    memset(&cfg, 0, sizeof cfg);
    unsetenv("PS_CENTRAL_DEDUPE_WINDOW_S");
    unsetenv("PS_CENTRAL_DEDUPE_TABLE_MAX");
    unsetenv("PS_CENTRAL_DEDUPE_WINDOW_DNS");
    unsetenv("PS_CENTRAL_DEDUPE_WINDOW_DISCOVERY_SSDP");
    CHECK(ps_config_parse_string(&cfg,
        "[central]\n"
        "dedupe_window_s = 120\n"
        "dedupe_table_max = 64\n"
        "dedupe_window_dns = 30\n"
        "dedupe_window_discovery_ssdp = \"0\"\n") == 0);
    ps_config_to_env(&cfg);
    CHECK(getenv("PS_CENTRAL_DEDUPE_WINDOW_S") && strcmp(getenv("PS_CENTRAL_DEDUPE_WINDOW_S"), "120") == 0);
    CHECK(getenv("PS_CENTRAL_DEDUPE_WINDOW_DNS") && strcmp(getenv("PS_CENTRAL_DEDUPE_WINDOW_DNS"), "30") == 0);
    struct ps_obs_dedupe_cfg c;
    ps_obs_dedupe_cfg_from_env(&c);
    CHECK(c.window_s == 120 && c.table_max == 64);
    c.emit = cap_emit;
    assert(ps_obs_dedupe_init(&c) == 0);
    CHECK(ps_obs_dedupe_window_for("discovery.dns") == 30);
    CHECK(ps_obs_dedupe_window_for("discovery.ssdp") == 0);
    CHECK(ps_obs_dedupe_window_for("discovery.mld") == 120);
    ps_config_free(&cfg);
}

static void test_size_bound(void) {
    init_cfg(-1, 0);
    /* an observation that fits a plain event (just) but not a summary */
    static char big[PS_OBS_ITEM_MAX];
    size_t pad = PS_OBS_ITEM_MAX - 200;
    memcpy(big, "{\"name\":\"", 9);
    memset(big + 9, 'x', pad);
    memcpy(big + 9 + pad, "\"}", 3);
    char ev[PS_OBS_ITEM_MAX];
    CHECK(ps_obs_build_event(ev, sizeof ev, "discovery.netbios", "2026-01-01T00:00:00Z", big, strlen(big)) > 0);
    CHECK(ps_obs_dedupe_offer("discovery.netbios", big, T0) == PS_DEDUPE_SEND);
    for (int i = 1; i <= 50; i++)
        CHECK(ps_obs_dedupe_offer("discovery.netbios", big, T0 + i * 1000LL * (1 + i % 3)) == PS_DEDUPE_SUPPRESS);
    CHECK(ps_obs_dedupe_flush(T0, 1, g_items, 64) == 1);
    CHECK(strlen(g_items[0]) < PS_OBS_ITEM_MAX);
    CHECK(has(g_items[0], "\"truncated\":true"));
    CHECK(has(g_items[0], "\"observation\":{\"key_sha256\":\""));
    CHECK(field_long(g_items[0], "n") == 50);

    /* medium observation: the timeline is coarsened, the observation kept */
    init_cfg(-1, 0);
    pad = PS_OBS_ITEM_MAX - 450;
    memset(big + 9, 'y', pad);
    memcpy(big + 9 + pad, "\"}", 3);
    CHECK(ps_obs_dedupe_offer("discovery.netbios", big, T0) == PS_DEDUPE_SEND);
    int64_t t = T0;
    for (int i = 1; i <= 64; i++) {
        t += 1000LL * (1 + (i * 7) % 4);
        CHECK(ps_obs_dedupe_offer("discovery.netbios", big, t) == PS_DEDUPE_SUPPRESS);
    }
    CHECK(ps_obs_dedupe_flush(T0, 1, g_items, 64) == 1);
    CHECK(strlen(g_items[0]) < PS_OBS_ITEM_MAX);
    CHECK(!has(g_items[0], "truncated"));
    CHECK(has(g_items[0], "\"seen_coarse\":true"));
    CHECK(field_long(g_items[0], "n") == 64);

    /* build_summary honours a small cap */
    struct ps_obs_dedupe_stats st;
    memset(&st, 0, sizeof st);
    st.since_ms = T0; st.first_ms = st.last_ms = T0 + 1000; st.n = 1;
    st.gap_min_ms = st.gap_max_ms = 1000; st.npairs = 1; st.seen[0][1] = 1;
    char small[64];
    CHECK(ps_obs_dedupe_build_summary(small, sizeof small, "k", "{}", 2, &st, NULL) == 0);
}

/* sum(n) + sends == N for a mixed stream with flushes, closes and evictions */
static void test_mixed_stream_accounting(void) {
    init_cfg(-1, 32);   /* 48 distinct keys: LRU evictions too */
    const char *kinds[] = { "discovery.neighbor", "discovery.dns", "discovery.ssdp", "discovery.mld" };
    unsigned s = 12345;
    long N = 0, sends = 0, repeats = 0;
    int64_t t = T0;
    for (int i = 0; i < 20000; i++) {
        s = s * 1103515245u + 12345u;
        int k = (s >> 8) % 4, v = (s >> 12) % 12;
        char obs[160];
        if (k == 0)
            snprintf(obs, sizeof obs, "{\"ip\":\"192.0.2.%d\",\"mac\":\"02:00:00:00:00:%02x\",\"interface\":\"eth0\",\"proto\":\"arp\"}", v % 4, v);
        else
            snprintf(obs, sizeof obs, "{\"v\":%d}", v);
        t += (s >> 16) % 3000;
        N++;
        if (ps_obs_dedupe_offer(kinds[k], obs, t) == PS_DEDUPE_SEND) sends++;
        if (i % 500 == 0) {
            int n;
            while ((n = ps_obs_dedupe_flush(t, 0, g_items, 64)) > 0)
                for (int j = 0; j < n; j++) repeats += field_long(g_items[j], "n");
        }
    }
    int n;
    while ((n = ps_obs_dedupe_flush(t, 1, g_items, 64)) > 0)
        for (int j = 0; j < n; j++) repeats += field_long(g_items[j], "n");
    repeats += g_emit_repeats;
    CHECK(sends + repeats == N);
    CHECK(sends < N / 2);   /* it does collapse */
    struct ps_obs_dedupe_counters c;
    ps_obs_dedupe_get_counters(&c);
    CHECK((long)c.summary_repeats == repeats);
    CHECK((long)c.suppressed == repeats);
    CHECK(c.evicted > 0 && c.closed > 0);
    fprintf(stderr, "mixed stream: N=%ld sent=%ld repeats=%ld summaries=%llu evicted=%llu closed=%llu\n",
            N, sends, repeats, (unsigned long long)c.summaries,
            (unsigned long long)c.evicted, (unsigned long long)c.closed);
}

/* the default emit target is the observation queue */
static void test_default_emit_queue(void) {
    struct ps_obs_dedupe_cfg c;
    ps_obs_dedupe_cfg_defaults(&c);
    c.table_max = 1;
    assert(ps_obs_dedupe_init(&c) == 0);
    ps_obs_queue_init();
    CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"g\":1}", T0) == PS_DEDUPE_SEND);
    CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"g\":1}", T0 + 1) == PS_DEDUPE_SUPPRESS);
    CHECK(ps_obs_dedupe_offer("discovery.mld", "{\"g\":2}", T0 + 2) == PS_DEDUPE_SEND);
    CHECK(ps_obs_queue_count() == 1);
    CHECK(ps_obs_queue_drain(g_items, 64) == 1 && field_long(g_items[0], "n") == 1);
}

int main(int argc, char **argv) {
    test_vectors(argc > 1 ? argv[1] : "tests/fixtures/dedupe_vectors.json");
    test_key_properties();
    test_send_then_suppress();
    test_hundred_repeats();
    test_irregular_gaps();
    test_mac_change_closes();
    test_window_expiry();
    test_force_flush();
    test_lru_eviction();
    test_disabled_and_windows();
    test_config_env();
    test_size_bound();
    test_mixed_stream_accounting();
    test_default_emit_queue();
    cap_reset();
    if (g_fail) { fprintf(stderr, "%d check(s) failed\n", g_fail); return 1; }
    printf("test_obs_dedupe: all passed\n");
    return 0;
}
