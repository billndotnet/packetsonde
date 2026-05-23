#include "capture/capture_handle.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

/* Stub pcap open: hand back an incrementing fake handle id. */
static int g_next = 100;
static int fake_open(void *ctx, const char *iface,
                     const char *bpf, uint32_t snaplen) {
    (void)ctx; (void)iface; (void)bpf; (void)snaplen;
    return ++g_next;
}

/* Stub close: record the last handle we were asked to close. */
static int g_closed = -1;
static int fake_close(void *ctx, int handle_id) {
    (void)ctx;
    g_closed = handle_id;
    return 0;
}

int main(void) {
    struct ps_capture_handle ch;
    ps_capture_init(&ch);

    assert(ps_capture_open(&ch, (ps_open_pcap_fn)fake_open, NULL, "eth0") == 0);
    assert(ps_capture_open(&ch, (ps_open_pcap_fn)fake_open, NULL, "eth1") == 0);
    assert(ch.count == 2);
    int eth0_handle = ch.handle_ids[0];

    /* Close eth0: close_fn called with eth0's handle, slot removed, array compacted */
    int r = ps_capture_close_iface(&ch, "eth0", (ps_close_pcap_fn)fake_close, NULL);
    assert(r == 0);
    assert(g_closed == eth0_handle);
    assert(ch.count == 1);
    assert(strcmp(ch.iface_names[0], "eth1") == 0); /* eth1 shifted down */

    /* Close a missing iface: no-op, returns -1 */
    g_closed = -1;
    r = ps_capture_close_iface(&ch, "nope", (ps_close_pcap_fn)fake_close, NULL);
    assert(r == -1);
    assert(g_closed == -1);
    assert(ch.count == 1);

    /* Middle-element removal from a 3-element set: open eth1 is already there;
     * add eth2, eth3 -> [eth1, eth2, eth3], then close the middle (eth2). */
    assert(ps_capture_open(&ch, (ps_open_pcap_fn)fake_open, NULL, "eth2") == 0);
    assert(ps_capture_open(&ch, (ps_open_pcap_fn)fake_open, NULL, "eth3") == 0);
    assert(ch.count == 3);
    int eth2_handle = ch.handle_ids[1];
    r = ps_capture_close_iface(&ch, "eth2", (ps_close_pcap_fn)fake_close, NULL);
    assert(r == 0);
    assert(g_closed == eth2_handle);
    assert(ch.count == 2);
    assert(strcmp(ch.iface_names[0], "eth1") == 0);
    assert(strcmp(ch.iface_names[1], "eth3") == 0); /* eth3 shifted into the gap */

    /* Last-element removal: close eth3 (now the tail) -> only eth1 remains. */
    int eth3_handle = ch.handle_ids[1];
    r = ps_capture_close_iface(&ch, "eth3", (ps_close_pcap_fn)fake_close, NULL);
    assert(r == 0);
    assert(g_closed == eth3_handle);
    assert(ch.count == 1);
    assert(strcmp(ch.iface_names[0], "eth1") == 0);

    printf("test_capture_close: OK\n");
    return 0;
}
