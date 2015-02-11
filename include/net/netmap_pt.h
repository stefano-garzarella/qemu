#ifndef NETMAP_PT_H
#define NETMAP_PT_H

#include "net/net.h"
#include "vhost_netmap_pt_user.h"

struct netmap_pt {
    bool started;
    bool full_configured;
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

/* notifications */
#define NETMAP_PT_RX    1
#define NETMAP_PT_TX    2

uint32_t netmap_pt_get_features(NetmapPTState *pt, uint32_t features);
void netmap_pt_ack_features(NetmapPTState *pt, uint32_t features);
int netmap_pt_get_mem(NetmapPTState *pt);
int netmap_pt_get_hostmemid(NetmapPTState *pt);
int netmap_pt_txsync(NetmapPTState *pt);
int netmap_pt_rxsync(NetmapPTState *pt);
int netmap_pt_start(NetmapPTState *pt);
int netmap_pt_stop(NetmapPTState *pt);
int netmap_pt_full_create(NetmapPTState *nc, struct vPT_Config *conf);
int netmap_pt_full_delete(NetmapPTState *nc);
#endif
