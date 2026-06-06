/*
 * broadcast_listener.c — General broadcast/multicast passive listener
 *
 * Catches ANY Ethernet broadcast (ff:ff:ff:ff:ff:ff) or multicast frame
 * and publishes the source IP + MAC. This is the most basic passive
 * discovery: if a host sends a broadcast, we know it exists.
 *
 * Does not parse payloads — just extracts source IP/MAC from the frame
 * headers. Protocol-specific parsing is handled by dedicated modules
 * (SSDP, NetBIOS, etc.); this module catches everything else.
 *
 * Publishes to channel: discovery.neighbor
 * (reuses the neighbor channel since the output format is identical)
 */

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "packetsonde/module_api.h"
#include "json.h"
#include "log.h"

#define ETH_HDR_LEN    14
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD

struct broadcast_state {
	char iface[64];
};

static uint16_t read_be16(const uint8_t *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}

static void mac_to_str(const uint8_t *mac, char *out, size_t outsz)
{
	snprintf(out, outsz, "%02x:%02x:%02x:%02x:%02x:%02x",
	         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static bool is_broadcast_or_multicast(const uint8_t *dst_mac)
{
	/* Broadcast: ff:ff:ff:ff:ff:ff */
	if (dst_mac[0] == 0xff && dst_mac[1] == 0xff && dst_mac[2] == 0xff &&
	    dst_mac[3] == 0xff && dst_mac[4] == 0xff && dst_mac[5] == 0xff)
		return true;
	/* Multicast: bit 0 of first byte is set */
	if (dst_mac[0] & 0x01)
		return true;
	return false;
}

static void broadcast_on_packet(ps_module_ctx_t *ctx,
                                 const uint8_t *pkt, uint32_t len,
                                 uint64_t ts_usec, int handle_id)
{
	(void)ts_usec;
	(void)handle_id;

	if (len < ETH_HDR_LEN + 20) return;  /* need at least IP header */

	/* Only process broadcast/multicast frames */
	if (!is_broadcast_or_multicast(pkt))
		return;

	struct broadcast_state *st = (struct broadcast_state *)ctx->userdata;

	/* Extract source MAC from Ethernet header (bytes 6-11) */
	char src_mac[24];
	mac_to_str(pkt + 6, src_mac, sizeof(src_mac));

	/* Extract source IP based on ethertype */
	uint16_t ethertype = read_be16(pkt + 12);
	char src_ip[64] = {0};

	if (ethertype == ETHERTYPE_IPV4)
	{
		if (len < ETH_HDR_LEN + 20) return;
		const uint8_t *ip_hdr = pkt + ETH_HDR_LEN;
		snprintf(src_ip, sizeof(src_ip), "%u.%u.%u.%u",
		         ip_hdr[12], ip_hdr[13], ip_hdr[14], ip_hdr[15]);

		/* Skip 0.0.0.0 (DHCP discover from unconfigured client) */
		if (strcmp(src_ip, "0.0.0.0") == 0) return;
	}
	else if (ethertype == ETHERTYPE_IPV6)
	{
		if (len < ETH_HDR_LEN + 40) return;
		const uint8_t *ip6_hdr = pkt + ETH_HDR_LEN;
		char buf[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, ip6_hdr + 8, buf, sizeof(buf));
		snprintf(src_ip, sizeof(src_ip), "%s", buf);

		/* Skip :: (unspecified) */
		if (strcmp(src_ip, "::") == 0) return;
	}
	else
	{
		/* Non-IP broadcast (e.g., raw ARP) — handled by neighbor_listener */
		return;
	}

	/* Publish as a neighbor event so the same enrichment pipeline processes it */
	char json_buf[512];
	struct ps_json j;
	ps_json_init(&j, json_buf, sizeof(json_buf));

	ps_json_object_begin(&j);
	ps_json_key_string(&j, "ip",        src_ip);
	ps_json_key_string(&j, "mac",       src_mac);
	ps_json_key_string(&j, "interface", st->iface);
	ps_json_key_string(&j, "proto",     "broadcast");
	ps_json_key_null  (&j, "ndp_type");
	ps_json_key_bool  (&j, "router",    0);
	ps_json_key_int   (&j, "flags",     0);
	ps_json_object_end(&j);

	int jlen = ps_json_finish(&j);
	if (jlen > 0)
	{
		ctx->publish(ctx, "discovery.neighbor", json_buf, (uint32_t)jlen);
	}
}

static int broadcast_init(ps_module_ctx_t *ctx)
{
	struct broadcast_state *st = calloc(1, sizeof(*st));
	if (!st) return -1;

	const char *iface = getenv("PS_CAPTURE_INTERFACE");
	if (!iface) iface = "";
	strncpy(st->iface, iface, sizeof(st->iface) - 1);

	ctx->userdata = st;
	ps_info("broadcast_listener: initialized — catching all broadcast/multicast");
	return 0;
}

static void broadcast_shutdown(ps_module_ctx_t *ctx)
{
	free(ctx->userdata);
	ctx->userdata = NULL;
	ps_info("broadcast_listener: shutdown");
}

const ps_module_t broadcast_module = {
	.name        = "broadcast",
	.description = "General broadcast/multicast passive host detection",
	.version     = "1.0",
	.flags       = PS_MOD_PASSIVE,
	.init        = broadcast_init,
	.shutdown    = broadcast_shutdown,
	.on_packet   = broadcast_on_packet,
	.on_job      = NULL,
	.on_response = NULL,
	.tick        = NULL,
};

__attribute__((constructor))
static void register_broadcast(void)
{
	ps_module_register(&broadcast_module);
}
