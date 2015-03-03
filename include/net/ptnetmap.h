#ifndef PTNETMAP_H
#define PTNETMAP_H

#include "net/net.h"
#include "exec/memory.h"
#include <net/if.h>
#include <net/netmap.h>
#include "net/paravirt.h"

struct ptnetmap_state {
    bool created;                       /* ptnetmap kthreads created */
    struct NetmapState *netmap;
    unsigned long features;             /* ptnetmap features */
    unsigned long acked_features;       /* ptnetmap acked features */
    size_t memsize;                     /* netmap memory info */
    void *mem;
    uint32_t offset;
    uint16_t num_tx_rings;
    uint16_t num_rx_rings;
    uint16_t num_tx_slots;
    uint16_t num_rx_slots;
    MemoryRegion mr;                    /* shared region to guest */
    bool mr_init;
    bool mr_alias;                      /* mr is an alias of another mr */
};

uint32_t ptnetmap_get_features(PTNetmapState *pt, uint32_t features);
void ptnetmap_ack_features(PTNetmapState *pt, uint32_t features);
int ptnetmap_get_mem(PTNetmapState *pt);
int ptnetmap_get_hostmemid(PTNetmapState *pt);
struct MemoryRegion *ptnetmap_init_ram_ptr(PTNetmapState *pt);
int ptnetmap_create(PTNetmapState *nc, struct ptn_cfg *conf);
int ptnetmap_delete(PTNetmapState *nc);

#endif /* PTNETMAP_H */
