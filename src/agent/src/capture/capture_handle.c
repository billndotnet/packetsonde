#include "capture/capture_handle.h"
#include "log.h"
#include <string.h>

static const char *COMBINED_BPF_FILTER =
    "arp"
    " or ether proto 0x88cc"
    " or (ether[0:2] = 0xaaaa and ether[2] = 0x03)"
    " or ether dst 01:80:c2:00:00:00"
    " or (ip6 and icmp6)"
    " or udp port 53"
    " or udp port 5353"
    " or udp port 67 or udp port 68"
    " or udp port 546 or udp port 547"
    " or udp port 1900"
    " or udp port 137 or udp port 138"
    " or udp port 5355"
    " or ip proto 89"
    " or ip proto 112"
    " or ether broadcast"              /* any Ethernet broadcast — passive host detection */
    " or ether multicast";             /* any Ethernet multicast — mDNS, IGMP, etc. */

void ps_capture_init(struct ps_capture_handle *ch)
{
    memset(ch, 0, sizeof(*ch));
}

int ps_capture_open(struct ps_capture_handle *ch,
                    ps_open_pcap_fn open_fn, void *ctx,
                    const char *iface)
{
    if (ch->count >= PS_CAPTURE_MAX_INTERFACES) {
        ps_error("capture_handle: max interfaces (%d)", PS_CAPTURE_MAX_INTERFACES);
        return -1;
    }
    int handle = open_fn(ctx, iface, COMBINED_BPF_FILTER, 65535);
    if (handle < 0) {
        ps_warn("capture_handle: open_pcap failed for %s", iface);
        return -1;
    }
    int idx = ch->count;
    ch->handle_ids[idx] = handle;
    strncpy(ch->iface_names[idx], iface, sizeof(ch->iface_names[idx]) - 1);
    ch->iface_names[idx][sizeof(ch->iface_names[idx]) - 1] = '\0';
    ch->count++;
    ps_info("capture_handle: opened shared handle=%d on %s", handle, iface);
    return 0;
}

int ps_capture_close_iface(struct ps_capture_handle *ch, const char *iface,
                           ps_close_pcap_fn close_fn, void *ctx)
{
    for (int i = 0; i < ch->count; i++) {
        if (strcmp(ch->iface_names[i], iface) != 0) continue;

        int handle = ch->handle_ids[i];
        if (close_fn) close_fn(ctx, handle);

        /* Compact the arrays: shift everything after i down by one. */
        for (int k = i; k < ch->count - 1; k++) {
            ch->handle_ids[k] = ch->handle_ids[k + 1];
            strncpy(ch->iface_names[k], ch->iface_names[k + 1],
                    sizeof(ch->iface_names[k]) - 1);
            ch->iface_names[k][sizeof(ch->iface_names[k]) - 1] = '\0';
        }
        ch->count--;
        ps_info("capture_handle: closed handle=%d on %s", handle, iface);
        return 0;
    }
    return -1;
}

const char *ps_capture_get_bpf_filter(void)
{
    return COMBINED_BPF_FILTER;
}
