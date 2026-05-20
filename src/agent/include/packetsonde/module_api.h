#ifndef PS_MODULE_API_H
#define PS_MODULE_API_H

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>

#define PS_MOD_ACTIVE      0x01
#define PS_MOD_PASSIVE     0x02
#define PS_MOD_NEEDS_PCAP  0x04
#define PS_MOD_NEEDS_RAW   0x08

struct ps_job {
    char     job_id[64];
    char     destination[256];
    char     method[16];
    int      max_hops;
    int      tcp_port;
    uint8_t  af;
};

typedef struct ps_module ps_module_t;
typedef struct ps_module_ctx ps_module_ctx_t;

struct ps_module_ctx {
    void *userdata;
    const ps_module_t *module;

    int  (*open_pcap)(ps_module_ctx_t *ctx, const char *iface,
                      const char *bpf_filter, uint32_t snaplen);
    int  (*create_raw_socket)(ps_module_ctx_t *ctx, uint8_t af, uint8_t proto);
    int  (*send_raw)(ps_module_ctx_t *ctx, int handle, uint8_t ttl,
                     const struct sockaddr *dest, const uint8_t *pkt, uint32_t len);

    int  (*publish)(ps_module_ctx_t *ctx, const char *channel,
                    const char *json, uint32_t json_len);

    void (*feed_flow_tracker)(ps_module_ctx_t *ctx, const uint8_t *pkt,
                              uint32_t len, uint64_t ts_usec);

    void (*log)(ps_module_ctx_t *ctx, int level, const char *fmt, ...);
};

struct ps_module {
    const char *name;
    const char *description;
    const char *version;
    uint32_t    flags;

    int  (*init)(ps_module_ctx_t *ctx);
    void (*shutdown)(ps_module_ctx_t *ctx);

    void (*on_packet)(ps_module_ctx_t *ctx, const uint8_t *pkt,
                      uint32_t len, uint64_t ts_usec, int handle_id);

    int  (*on_job)(ps_module_ctx_t *ctx, const struct ps_job *job);

    void (*on_response)(ps_module_ctx_t *ctx, const uint8_t *pkt,
                        uint32_t len, uint64_t ts_usec, int socket_id);

    void (*tick)(ps_module_ctx_t *ctx, uint64_t now_usec);
};

int ps_module_register(const ps_module_t *mod);

#endif
