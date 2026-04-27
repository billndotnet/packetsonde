/*
 * netflow_export.h — NetFlow v5/v9 exporter for PacketSonde Agent
 *
 * Takes expired ps_flow records and exports them as NetFlow UDP packets
 * to a configured collector.
 */

#ifndef PS_NETFLOW_EXPORT_H
#define PS_NETFLOW_EXPORT_H

#include <stdint.h>

struct ps_flow;  /* forward decl from flow_tracker.h */

struct ps_nf_exporter;

/*
 * Create a NetFlow exporter.
 *   collector_host — hostname or IP of collector
 *   collector_port — UDP port (e.g. 2055)
 *   source_id      — source ID / engine ID for the NetFlow header
 *   version        — 5 or 9
 */
struct ps_nf_exporter *ps_nf_exporter_create(const char *collector_host,
                                               int collector_port,
                                               uint32_t source_id,
                                               int version);

/* Destroy the exporter and close its socket. */
void ps_nf_exporter_destroy(struct ps_nf_exporter *exp);

/*
 * Export an array of expired flows.
 * Returns number of UDP packets sent, or -1 on error.
 */
int ps_nf_exporter_send(struct ps_nf_exporter *exp,
                         const struct ps_flow *flows, int count);

#endif /* PS_NETFLOW_EXPORT_H */
