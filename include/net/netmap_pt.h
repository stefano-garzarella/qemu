#ifndef NETMAP_PT_H
#define NETMAP_PT_H

#include "net/net.h"

struct netmap_pt {
    struct NetmapState *netmap;
    unsigned long features;
    unsigned long acked_features;
    bool mapped;
    size_t memsize;
    void *mem;
    uint32_t offset;
    uint16_t num_tx_rings;
    uint16_t num_rx_rings;
    uint16_t num_tx_slots;
    uint16_t num_rx_slots;
};

typedef struct netmap_pt NetmapPTState;

#define NETMAP_PT_BASE  1
#define NETMAP_PT_FULL  2       /* full passthrough, requires host kernel support */

uint32_t netmap_pt_get_features(NetmapPTState *pt, uint32_t features);
void netmap_pt_ack_features(NetmapPTState *pt, uint32_t features);
int netmap_pt_get_mem(NetmapPTState *pt);
int netmap_pt_txsync(NetmapPTState *pt);
int netmap_pt_rxsync(NetmapPTState *pt);
#endif
