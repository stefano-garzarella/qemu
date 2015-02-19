#ifndef PTNETMAP_H
#define PTNETMAP_H

#include "net/net.h"
#include "exec/memory.h"
#include <net/if.h>
#include <net/netmap.h>

struct ptnetmap_state {
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
    MemoryRegion mr;
    bool mr_init;
    bool mr_alias;
};

//typedef struct ptnetmap_state PTNetmapState;

#define NETMAP_PT_BASE  1
#define NETMAP_PT_FULL  2       /* full passthrough, requires host kernel support */

/* notifications */
#define NETMAP_PT_RX    1
#define NETMAP_PT_TX    2

uint32_t ptnetmap_get_features(PTNetmapState *pt, uint32_t features);
void ptnetmap_ack_features(PTNetmapState *pt, uint32_t features);
int ptnetmap_get_mem(PTNetmapState *pt);
int ptnetmap_get_hostmemid(PTNetmapState *pt);
struct MemoryRegion *ptnetmap_init_ram_ptr(PTNetmapState *pt);
int ptnetmap_txsync(PTNetmapState *pt);
int ptnetmap_rxsync(PTNetmapState *pt);
int ptnetmap_start(PTNetmapState *pt);
int ptnetmap_stop(PTNetmapState *pt);
int ptnetmap_full_create(PTNetmapState *nc, struct ptn_cfg *conf);
int ptnetmap_full_delete(PTNetmapState *nc);

#endif /* PTNETMAP_H */
