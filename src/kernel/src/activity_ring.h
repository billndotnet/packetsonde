#ifndef PS_ACTIVITY_RING_H
#define PS_ACTIVITY_RING_H
#include <stddef.h>

#define PS_ACT_RING_CAP       256
#define PS_ACT_ITEM_MAX      8192
#define PS_ACT_MAX_CONSUMERS    8

void ps_act_ring_init(void);
int  ps_act_ring_register(void);                       /* -> consumer id >=0, or -1 if full */
void ps_act_ring_push(const char *json, size_t len);   /* fan out to ALL registered consumers */
int  ps_act_ring_drain(int consumer, char out_items[][PS_ACT_ITEM_MAX], int max);
int  ps_act_ring_count(int consumer);
#endif /* PS_ACTIVITY_RING_H */
