#ifndef PS_ACTIVITY_RING_H
#define PS_ACTIVITY_RING_H
#include <stddef.h>

#define PS_ACT_RING_CAP    256
#define PS_ACT_ITEM_MAX   8192

void ps_act_ring_init(void);
void ps_act_ring_push(const char *json, size_t len);   /* drop-oldest if full; thread-safe */
int  ps_act_ring_drain(char out_items[][PS_ACT_ITEM_MAX], int max);
int  ps_act_ring_count(void);
#endif /* PS_ACTIVITY_RING_H */
