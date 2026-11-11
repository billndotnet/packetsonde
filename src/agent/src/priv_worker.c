#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
/* IPV6_RECVHOPLIMIT may not be exposed on all platforms without extensions */
#ifndef IPV6_RECVHOPLIMIT
#  ifdef __APPLE__
#    define IPV6_RECVHOPLIMIT 37  /* from netinet6/in6.h */
#  else
#    define IPV6_RECVHOPLIMIT 51  /* Linux value */
#  endif
#endif

#ifdef HAVE_PCAP
#  include <pcap.h>
#endif

#include "priv_protocol.h"
#include "priv_frame_io.h"
#include "log.h"
#include "build_config.h"
#include <pthread.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Slot arrays                                                          */
/* ------------------------------------------------------------------ */

#ifdef HAVE_PCAP
struct pcap_slot {
    pcap_t *handle;
    int     active;
};
static struct pcap_slot g_pcap[PS_MAX_PCAP_HANDLES];
#endif

struct raw_slot {
    int fd;
    int active;
};
static struct raw_slot g_raw[PS_MAX_RAW_HANDLES];

/* The socketpair fd connecting us to the brain */
static int g_brain_fd = -1;

/* Mutex that serialises all writes to g_brain_fd: the poll-loop paths
 * (send_response and pcap/raw data) share one writer fd. */
static pthread_mutex_t g_write_mu = PTHREAD_MUTEX_INITIALIZER;

/* Every frame to the brain goes through this writer (see priv_frame_io.h).
 * g_tail holds the unsent remainder of at most one started frame, finished
 * from the poll loop when the brain fd becomes writable again. */
static struct ps_frame_writer g_out;
static uint8_t g_tail[sizeof(struct ps_priv_msg) + PS_MAX_FRAME_PAYLOAD];

/* ------------------------------------------------------------------ */
/* Write helpers                                                        */
/* ------------------------------------------------------------------ */

static int read_all(int fd, uint8_t *buf, size_t n)
{
    while (n > 0) {
        ssize_t r = read(fd, buf, n);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = { .fd = fd, .events = POLLIN };
                poll(&pfd, 1, 100);
                continue;
            }
            return -1;
        }
        if (r == 0) return -1; /* EOF */
        buf += r;
        n   -= (size_t)r;
    }
    return 0;
}

static void send_response(uint8_t opcode, uint8_t status, uint16_t handle_id,
                           const uint8_t *data, uint32_t data_len)
{
    uint8_t buf[sizeof(struct ps_priv_msg) + 256];
    size_t n = ps_priv_encode_response(buf, sizeof(buf), opcode, status, handle_id,
                                        data, data_len);
    if (n == 0) {
        ps_error("priv_worker: response encode overflow");
        return;
    }
    /* A response is never dropped: it waits for any started data frame to
     * finish, then for the brain to take it. The brain is reading at this
     * point, since it sent the command and waits for this reply. */
    pthread_mutex_lock(&g_write_mu);
    int wr = ps_frame_writer_send_all(&g_out, buf, n, -1);
    int saved_errno = errno;
    pthread_mutex_unlock(&g_write_mu);
    if (wr != PS_FRAME_SENT) {
        ps_error("priv_worker: write response failed: %s", strerror(saved_errno));
    }
}

/* Async data frames (PACKET_DATA, RAW_RESPONSE) are lossy: when the brain
 * is backed up a frame is dropped whole. A frame the socket took only part of
 * keeps its remainder in g_out and is finished from the poll loop; new data
 * frames are dropped until it is. Nothing here waits for the brain, so a
 * stalled brain costs frames, never the stream or the worker. */
static unsigned long g_drops_logged;
static time_t g_drop_log_at;

#define PS_DROP_LOG_INTERVAL_S 10

static void log_drops(int force)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    if (!force && g_drop_log_at != 0 && ts.tv_sec - g_drop_log_at < PS_DROP_LOG_INTERVAL_S)
        return;
    const struct ps_frame_stats *st = &g_out.stats;
    unsigned long fresh = st->dropped - g_drops_logged;
    if (fresh == 0) return;
    ps_warn("priv_worker: brain pipe backed up, dropped %lu data frame(s) "
            "(%lu dropped, %lu of them behind an unfinished frame, %lu sent, "
            "%lu finished after a short write in total)",
            fresh, st->dropped, st->dropped_pending, st->sent, st->partial);
    g_drops_logged = st->dropped;
    g_drop_log_at  = ts.tv_sec;
}

/* Returns 0 if the frame was sent, queued or dropped whole, -1 if the brain
 * stream is unusable (the brain has gone away). */
static int send_data_frame(const uint8_t *buf, size_t n)
{
    pthread_mutex_lock(&g_write_mu);
    int rc = ps_frame_writer_send_lossy(&g_out, buf, n);
    int saved_errno = errno;
    pthread_mutex_unlock(&g_write_mu);
    if (rc == PS_FRAME_BROKEN) {
        ps_error("priv_worker: brain stream broken (%zu-byte frame: %s); exiting",
                 n, strerror(saved_errno));
        return -1;
    }
    if (rc == PS_FRAME_DROPPED) log_drops(0);
    return 0;
}

/* Finish a started frame if the brain fd has room. -1 if the stream broke. */
static int flush_pending(void)
{
    pthread_mutex_lock(&g_write_mu);
    int rc = ps_frame_writer_flush(&g_out);
    int saved_errno = errno;
    pthread_mutex_unlock(&g_write_mu);
    if (rc == PS_FRAME_BROKEN) {
        ps_error("priv_worker: brain stream broken while finishing a frame (%s); exiting",
                 strerror(saved_errno));
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Command handlers                                                     */
/* ------------------------------------------------------------------ */

static void handle_open_pcap(uint16_t handle_id,
                               const uint8_t *payload, uint32_t payload_len)
{
    (void)handle_id;

#ifndef HAVE_PCAP
    (void)payload; (void)payload_len;
    send_response(PS_OP_OPEN_PCAP, PS_STATUS_INTERNAL, 0, NULL, 0);
#else
    if (payload_len < 2) {
        send_response(PS_OP_OPEN_PCAP, PS_STATUS_INTERNAL, 0, NULL, 0);
        return;
    }

    /* Parse: iface\0filter\0snaplen(4 bytes) */
    const char *iface = (const char *)payload;
    size_t iface_len = strnlen(iface, payload_len);
    if (iface_len >= payload_len) {
        send_response(PS_OP_OPEN_PCAP, PS_STATUS_INTERNAL, 0, NULL, 0);
        return;
    }

    const char *filter = (const char *)payload + iface_len + 1;
    size_t filter_offset = iface_len + 1;
    size_t filter_len = strnlen(filter, payload_len - filter_offset);
    if (filter_offset + filter_len + 1 + 4 > payload_len) {
        send_response(PS_OP_OPEN_PCAP, PS_STATUS_INTERNAL, 0, NULL, 0);
        return;
    }

    uint32_t snaplen = 0;
    memcpy(&snaplen, payload + filter_offset + filter_len + 1, 4);

    /* Validate interface */
    if (if_nametoindex(iface) == 0) {
        ps_error("priv_worker: bad interface '%s'", iface);
        send_response(PS_OP_OPEN_PCAP, PS_STATUS_BAD_IFACE, 0, NULL, 0);
        return;
    }

    /* Find a free slot */
    int slot = -1;
    for (int i = 0; i < PS_MAX_PCAP_HANDLES; i++) {
        if (!g_pcap[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        send_response(PS_OP_OPEN_PCAP, PS_STATUS_HANDLE_LIMIT, 0, NULL, 0);
        return;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *ph = pcap_create(iface, errbuf);
    if (!ph) {
        ps_error("priv_worker: pcap_create failed: %s", errbuf);
        send_response(PS_OP_OPEN_PCAP, PS_STATUS_INTERNAL, 0, NULL, 0);
        return;
    }

    pcap_set_snaplen(ph, (int)snaplen);
    pcap_set_promisc(ph, 1);
    pcap_set_timeout(ph, 1); /* 1ms read timeout for non-blocking feel */

    if (pcap_activate(ph) != 0) {
        ps_error("priv_worker: pcap_activate failed: %s", pcap_geterr(ph));
        pcap_close(ph);
        send_response(PS_OP_OPEN_PCAP, PS_STATUS_INTERNAL, 0, NULL, 0);
        return;
    }

    /* Compile and apply BPF filter if non-empty */
    if (filter[0] != '\0') {
        struct bpf_program fp;
        if (pcap_compile(ph, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
            ps_error("priv_worker: pcap_compile failed: %s", pcap_geterr(ph));
            pcap_close(ph);
            send_response(PS_OP_OPEN_PCAP, PS_STATUS_BAD_FILTER, 0, NULL, 0);
            return;
        }
        if (pcap_setfilter(ph, &fp) < 0) {
            ps_error("priv_worker: pcap_setfilter failed: %s", pcap_geterr(ph));
            pcap_freecode(&fp);
            pcap_close(ph);
            send_response(PS_OP_OPEN_PCAP, PS_STATUS_BAD_FILTER, 0, NULL, 0);
            return;
        }
        pcap_freecode(&fp);
    }

    /* Set non-blocking */
    pcap_setnonblock(ph, 1, errbuf);

    g_pcap[slot].handle = ph;
    g_pcap[slot].active = 1;

    ps_info("priv_worker: opened pcap handle %d on %s", slot, iface);
    send_response(PS_OP_OPEN_PCAP, PS_STATUS_OK, (uint16_t)slot, NULL, 0);
#endif /* HAVE_PCAP */
}

static void handle_close_pcap(uint16_t handle_id)
{
#ifndef HAVE_PCAP
    (void)handle_id;
    send_response(PS_OP_CLOSE_PCAP, PS_STATUS_INTERNAL, handle_id, NULL, 0);
#else
    if (handle_id >= PS_MAX_PCAP_HANDLES || !g_pcap[handle_id].active) {
        send_response(PS_OP_CLOSE_PCAP, PS_STATUS_BAD_HANDLE, handle_id, NULL, 0);
        return;
    }
    pcap_close(g_pcap[handle_id].handle);
    g_pcap[handle_id].handle = NULL;
    g_pcap[handle_id].active = 0;
    ps_info("priv_worker: closed pcap handle %d", handle_id);
    send_response(PS_OP_CLOSE_PCAP, PS_STATUS_OK, handle_id, NULL, 0);
#endif
}

static void handle_create_raw_socket(const uint8_t *payload, uint32_t payload_len)
{
    if (payload_len < 2) {
        send_response(PS_OP_CREATE_RAW_SOCKET, PS_STATUS_INTERNAL, 0, NULL, 0);
        return;
    }

    uint8_t af    = payload[0];
    uint8_t proto = payload[1];

    /* Find a free slot */
    int slot = -1;
    for (int i = 0; i < PS_MAX_RAW_HANDLES; i++) {
        if (!g_raw[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        send_response(PS_OP_CREATE_RAW_SOCKET, PS_STATUS_HANDLE_LIMIT, 0, NULL, 0);
        return;
    }

    int domain = (af == AF_INET6) ? AF_INET6 : AF_INET;
    int fd = socket(domain, SOCK_RAW, proto);
    if (fd < 0) {
        ps_error("priv_worker: socket() failed: %s", strerror(errno));
        send_response(PS_OP_CREATE_RAW_SOCKET, PS_STATUS_INTERNAL, 0, NULL, 0);
        return;
    }

    /* Enlarge the receive buffer. Under high trace concurrency (many jobs x windowed sends) a burst of
     * time-exceeded/echo replies can overflow the small default rcvbuf, dropping replies -> false-silent
     * hops -> failures that ONLY appear under concurrency (single-thread trickles in fine). The priv worker
     * runs as root, so SO_RCVBUFFORCE bypasses net.core.rmem_max; fall back to SO_RCVBUF. Best-effort. */
    {
        int rcvbuf = 16 * 1024 * 1024; /* 16 MB */
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0 &&
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF,      &rcvbuf, sizeof(rcvbuf)) < 0) {
            ps_warn("priv_worker: SO_RCVBUF(FORCE) failed: %s", strerror(errno));
        }
    }

    if (domain == AF_INET && proto != IPPROTO_ICMP) {
        /* Set IP_HDRINCL for TCP/UDP raw sockets so caller constructs
         * the full IP header.  Do NOT set for ICMP — on macOS the kernel
         * ignores IP_HDRINCL for ICMP and always adds its own IP header.
         * ICMP traceroute uses setsockopt(IP_TTL) per-packet instead. */
        int one = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            ps_warn("priv_worker: IP_HDRINCL failed: %s", strerror(errno));
        }
    } else if (domain == AF_INET6) {
        /* IPv6: receive hop limit in ancillary data */
        int one = 1;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof(one)) < 0) {
            ps_warn("priv_worker: IPV6_RECVHOPLIMIT failed: %s", strerror(errno));
        }
    }

    g_raw[slot].fd     = fd;
    g_raw[slot].active = 1;

    ps_info("priv_worker: created raw socket handle %d (af=%d proto=%d)", slot, af, proto);
    send_response(PS_OP_CREATE_RAW_SOCKET, PS_STATUS_OK, (uint16_t)slot, NULL, 0);
}

static void handle_close_raw_socket(uint16_t handle_id)
{
    if (handle_id >= PS_MAX_RAW_HANDLES || !g_raw[handle_id].active) {
        send_response(PS_OP_CLOSE_RAW_SOCKET, PS_STATUS_BAD_HANDLE, handle_id, NULL, 0);
        return;
    }
    close(g_raw[handle_id].fd);
    g_raw[handle_id].fd     = -1;
    g_raw[handle_id].active = 0;
    ps_info("priv_worker: closed raw socket handle %d", handle_id);
    send_response(PS_OP_CLOSE_RAW_SOCKET, PS_STATUS_OK, handle_id, NULL, 0);
}

static void handle_send_raw(uint16_t handle_id,
                              const uint8_t *payload, uint32_t payload_len)
{
    /*
     * Payload layout (from ps_priv_encode_send_raw):
     *   1 byte  ttl
     *   2 bytes dest_len (uint16_t LE)
     *   dest_len bytes sockaddr
     *   remainder: packet data
     */
    if (payload_len < 3) {
        send_response(PS_OP_SEND_RAW, PS_STATUS_INTERNAL, handle_id, NULL, 0);
        return;
    }

    if (handle_id >= PS_MAX_RAW_HANDLES || !g_raw[handle_id].active) {
        send_response(PS_OP_SEND_RAW, PS_STATUS_BAD_HANDLE, handle_id, NULL, 0);
        return;
    }

    const uint8_t *p = payload;
    uint8_t ttl = *p++;

    uint16_t dest_len = 0;
    memcpy(&dest_len, p, 2); p += 2;

    if ((size_t)(p - payload) + dest_len > payload_len) {
        send_response(PS_OP_SEND_RAW, PS_STATUS_INTERNAL, handle_id, NULL, 0);
        return;
    }

    const struct sockaddr *dest = (const struct sockaddr *)p;
    p += dest_len;

    uint32_t pkt_len = (uint32_t)(payload_len - (uint32_t)(p - payload));
    const uint8_t *pkt = p;

    int fd = g_raw[handle_id].fd;

    /* Set TTL / hop limit via setsockopt.
     * For IPv4: macOS ignores the IP header's TTL field for ICMP raw sockets
     * even with IP_HDRINCL set. Always set IP_TTL explicitly. */
    if (dest->sa_family == AF_INET6) {
        int hops = (int)ttl;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops)) < 0) {
            ps_warn("priv_worker: IPV6_UNICAST_HOPS failed: %s", strerror(errno));
        }
    } else {
        int ttl_val = (int)ttl;
        setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl_val, sizeof(ttl_val));
    }

    ssize_t sent = sendto(fd, pkt, pkt_len, 0, dest, (socklen_t)dest_len);
    if (sent < 0) {
        ps_error("priv_worker: sendto failed: %s", strerror(errno));
        send_response(PS_OP_SEND_RAW, PS_STATUS_SEND_FAILED, handle_id, NULL, 0);
        return;
    }

    send_response(PS_OP_SEND_RAW, PS_STATUS_OK, handle_id, NULL, 0);
}

/* ------------------------------------------------------------------ */
/* Main event loop                                                      */
/* ------------------------------------------------------------------ */

/* Returns 0 when the brain disconnects, -1 on a fatal error. */
static int run_loop(void)
{
    /*
     * We poll:
     *   [0]       = brain socketpair fd
     *   [1..16]   = pcap fds (via pcap_get_selectable_fd) when HAVE_PCAP
     *   [17..48]  = raw socket fds
     * For simplicity, rebuild the pollfd array each iteration.
     */

    uint8_t cmd_buf[PS_MAX_MSG_PAYLOAD + sizeof(struct ps_priv_msg)];
    uint8_t pkt_buf[sizeof(struct ps_priv_msg) + PS_MAX_FRAME_PAYLOAD];

    for (;;) {
        struct pollfd fds[1 + PS_MAX_PCAP_HANDLES + PS_MAX_RAW_HANDLES];
        int nfds = 0;

        if (g_out.broken) {
            ps_error("priv_worker: brain stream unusable; exiting");
            return -1;
        }

        /* Brain fd always first; also wait for room while a started frame
         * is unfinished. */
        fds[nfds].fd      = g_brain_fd;
        fds[nfds].events  = POLLIN | (ps_frame_writer_pending(&g_out) ? POLLOUT : 0);
        fds[nfds].revents = 0;
        nfds++;

#ifdef HAVE_PCAP
        /* Pcap fds */
        for (int i = 0; i < PS_MAX_PCAP_HANDLES; i++) {
            if (!g_pcap[i].active) continue;
            int pfd = pcap_get_selectable_fd(g_pcap[i].handle);
            if (pfd < 0) continue;
            fds[nfds].fd      = pfd;
            fds[nfds].events  = POLLIN;
            fds[nfds].revents = 0;
            /* We stash the slot index in the user_data via a parallel array.
             * Since we rebuild every iteration, track via index offset. */
            nfds++;
        }
#endif

        /* Raw socket fds */
        int raw_fd_start = nfds;
        (void)raw_fd_start;
        for (int i = 0; i < PS_MAX_RAW_HANDLES; i++) {
            if (!g_raw[i].active) continue;
            fds[nfds].fd      = g_raw[i].fd;
            fds[nfds].events  = POLLIN;
            fds[nfds].revents = 0;
            nfds++;
        }

        int r = poll(fds, (nfds_t)nfds, 10); /* 10ms timeout */
        if (r < 0) {
            if (errno == EINTR) continue;
            ps_error("priv_worker: poll failed: %s", strerror(errno));
            return -1;
        }

        /* Check brain fd */
        if (fds[0].revents & POLLHUP) {
            ps_info("priv_worker: brain disconnected, exiting");
            break;
        }
        if ((fds[0].revents & (POLLOUT | POLLERR)) && flush_pending() < 0)
            return -1;
        if (fds[0].revents & POLLIN) {
            /* Read header */
            struct ps_priv_msg hdr;
            if (read_all(g_brain_fd, (uint8_t *)&hdr, sizeof(hdr)) < 0) {
                ps_info("priv_worker: brain closed connection");
                break;
            }

            uint32_t plen = hdr.payload_len;
            if (plen > PS_MAX_MSG_PAYLOAD) {
                ps_error("priv_worker: payload too large (%u)", plen);
                return -1;
            }

            if (plen > 0) {
                if (read_all(g_brain_fd, cmd_buf, plen) < 0) {
                    ps_error("priv_worker: read payload failed");
                    return -1;
                }
            }

            switch (hdr.opcode) {
                case PS_OP_OPEN_PCAP:
                    handle_open_pcap(hdr.handle_id, cmd_buf, plen);
                    break;
                case PS_OP_CLOSE_PCAP:
                    handle_close_pcap(hdr.handle_id);
                    break;
                case PS_OP_CREATE_RAW_SOCKET:
                    handle_create_raw_socket(cmd_buf, plen);
                    break;
                case PS_OP_CLOSE_RAW_SOCKET:
                    handle_close_raw_socket(hdr.handle_id);
                    break;
                case PS_OP_SEND_RAW:
                    handle_send_raw(hdr.handle_id, cmd_buf, plen);
                    break;
                default:
                    ps_warn("priv_worker: unknown opcode 0x%02x", hdr.opcode);
                    send_response(PS_OP_ERROR, PS_STATUS_INTERNAL, 0, NULL, 0);
                    break;
            }
        }

#ifdef HAVE_PCAP
        /* Check pcap fds — walk active slots and try pcap_next_ex */
        int pcap_poll_idx = 1; /* starts after brain fd */
        for (int i = 0; i < PS_MAX_PCAP_HANDLES; i++) {
            if (!g_pcap[i].active) continue;

            int pfd = pcap_get_selectable_fd(g_pcap[i].handle);
            if (pfd < 0) { pcap_poll_idx++; continue; }

            if (pcap_poll_idx < nfds && (fds[pcap_poll_idx].revents & POLLIN)) {
                struct pcap_pkthdr *pkthdr;
                const u_char *pktdata;
                int res = pcap_next_ex(g_pcap[i].handle, &pkthdr, &pktdata);
                if (res == 1 && pkthdr && pktdata) {
                    uint64_t ts_usec = (uint64_t)pkthdr->ts.tv_sec * 1000000ULL
                                     + (uint64_t)pkthdr->ts.tv_usec;
                    size_t n = ps_priv_encode_packet_data(pkt_buf, sizeof(pkt_buf),
                                                           (uint16_t)i, ts_usec,
                                                           pktdata, pkthdr->caplen);
                    if (n > 0) {
                        /* Lossy: dropped whole if the brain is backed up */
                        if (send_data_frame(pkt_buf, n) < 0) return -1;
                    }
                }
            }
            pcap_poll_idx++;
        }
#endif

        /* Check raw socket fds for incoming data (e.g. ICMP responses) */
        int raw_idx = 1;
#ifdef HAVE_PCAP
        /* Offset by however many pcap fds we added */
        for (int i = 0; i < PS_MAX_PCAP_HANDLES; i++) {
            if (!g_pcap[i].active) continue;
            if (pcap_get_selectable_fd(g_pcap[i].handle) >= 0) raw_idx++;
        }
#endif
        for (int i = 0; i < PS_MAX_RAW_HANDLES; i++) {
            if (!g_raw[i].active) continue;

            if (raw_idx < nfds && (fds[raw_idx].revents & POLLIN)) {
                uint8_t recv_buf[65536];
                ssize_t n = recv(g_raw[i].fd, recv_buf, sizeof(recv_buf), 0);
                if (n > 0) {
                    uint64_t ts_usec = 0; /* No timestamp for raw sockets */
                    size_t out_n = ps_priv_encode_response(
                        pkt_buf, sizeof(pkt_buf),
                        PS_OP_RAW_RESPONSE, PS_STATUS_OK, (uint16_t)i,
                        recv_buf, (uint32_t)n);
                    if (out_n > 0) {
                        (void)ts_usec;
                        /* Lossy: dropped whole if the brain is backed up */
                        if (send_data_frame(pkt_buf, out_n) < 0) return -1;
                    }
                }
            }
            raw_idx++;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Entry point                                                          */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    ps_log_set_prefix("priv");
    ps_log_set_level(PS_LOG_INFO);

    /* Parse --fd <N> */
    int fd = -1;
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--fd") == 0) {
            fd = atoi(argv[i + 1]);
            break;
        }
    }

    if (fd < 0) {
        fprintf(stderr, "packetsonde-priv: usage: --fd <socketpair_fd>\n");
        return EXIT_FAILURE;
    }

    g_brain_fd = fd;
    ps_frame_writer_init(&g_out, fd, g_tail, sizeof(g_tail));

    /* Non-blocking brain fd: data frames are never waited for (dropped whole
     * or finished from the poll loop), so a busy brain cannot stall capture.
     * Command responses wait for room (ps_frame_writer_send_all). */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* Initialize slot arrays */
#ifdef HAVE_PCAP
    memset(g_pcap, 0, sizeof(g_pcap));
#endif
    memset(g_raw, 0, sizeof(g_raw));
    for (int i = 0; i < PS_MAX_RAW_HANDLES; i++) g_raw[i].fd = -1;

    ps_info("priv_worker: started (fd=%d)", fd);

    int rc = run_loop();
    log_drops(1);   /* drops since the last rate-limited line */

    ps_info("priv_worker: exiting%s", rc < 0 ? " on error" : "");
    close(fd);
    return rc < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
