/* flow.status payload: bounded by the buffer it is given, complete JSON at
 * every size. publish_status used to advance its offset by each snprintf
 * return and check nothing, so a payload that did not fit ran the offset past
 * the buffer. */
#include "../src/modules/flow_tracker_mod.c"
#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

static int ends_with(const char *s, const char *suf)
{
    size_t a = strlen(s), b = strlen(suf);
    return a >= b && strcmp(s + a - b, suf) == 0;
}

int main(void)
{
    static struct flow_mod_state st;
    memset(&st, 0, sizeof st);
    for (int i = 0; i < FT_MOD_MAX_INTERFACES; i++) st.slots[i].pcap_handle = -1;

    char out[256];
    CHECK(ft_status_json(&st, out, sizeof out) > 0);
    CHECK(strcmp(out, "{\"interfaces\":[],\"active_count\":0}") == 0);

    st.slots[1].pcap_handle = 3; snprintf(st.slots[1].interface, 64, "if0");
    st.slots[4].pcap_handle = 5; snprintf(st.slots[4].interface, 64, "if1");
    st.active_count = 2;
    int n = ft_status_json(&st, out, sizeof out);
    CHECK(n == (int)strlen(out));
    CHECK(strcmp(out, "{\"interfaces\":[\"if0\",\"if1\"],\"active_count\":2}") == 0);

    /* Every slot in use with the longest interface name the slot holds. */
    for (int i = 0; i < FT_MOD_MAX_INTERFACES; i++) {
        st.slots[i].pcap_handle = i;
        memset(st.slots[i].interface, 'a' + i, 63);
        st.slots[i].interface[63] = '\0';
    }
    st.active_count = FT_MOD_MAX_INTERFACES;

    /* Every buffer size: never writes past cap (heap-exact for ASAN), and is
     * either refused (-1) or a closed payload of its returned length. */
    int saw_trunc = 0, saw_full = 0;
    for (size_t cap = 0; cap <= 800; cap++) {
        char *b = malloc(cap ? cap : 1);
        n = ft_status_json(&st, b, cap);
        if (n >= 0) {
            CHECK((size_t)n < cap && n == (int)strlen(b));
            CHECK(strncmp(b, "{\"interfaces\":[", 15) == 0);
            CHECK(ends_with(b, ",\"active_count\":8}"));
            if (strstr(b, "\"truncated\":true")) saw_trunc = 1; else saw_full = 1;
        } else {
            CHECK(cap <= 64 + 16);
        }
        free(b);
    }
    CHECK(saw_trunc && saw_full);

    printf(g_fail ? "FAILED\n" : "ok\n");
    return g_fail ? 1 : 0;
}
