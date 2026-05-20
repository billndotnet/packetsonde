#ifndef PS_CAPTURE_HANDLE_H
#define PS_CAPTURE_HANDLE_H

#include <stdint.h>

#define PS_CAPTURE_MAX_INTERFACES 8

struct ps_capture_handle {
    int     handle_ids[PS_CAPTURE_MAX_INTERFACES];
    char    iface_names[PS_CAPTURE_MAX_INTERFACES][64];
    int     count;
};

typedef int (*ps_open_pcap_fn)(void *ctx, const char *iface,
                                const char *bpf_filter, uint32_t snaplen);

void ps_capture_init(struct ps_capture_handle *ch);
int  ps_capture_open(struct ps_capture_handle *ch,
                     ps_open_pcap_fn open_fn, void *ctx,
                     const char *iface);
const char *ps_capture_get_bpf_filter(void);

#endif /* PS_CAPTURE_HANDLE_H */
