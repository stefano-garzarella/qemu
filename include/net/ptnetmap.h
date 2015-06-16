#ifndef PTNETMAP_H
#define PTNETMAP_H

#include "net/net.h"
#include "exec/memory.h"
#include <net/if.h>
#include "net/paravirt.h"

/* ptnetmap virtio register */
#define PTNETMAP_VIRTIO_IO_BASE         sizeof(struct virtio_net_config)
/* 32 bit r/w */
#define PTNETMAP_VIRTIO_IO_PTFEAT       0 /* passthrough features */
/* 32 bit w/o */
#define PTNETMAP_VIRTIO_IO_PTCTL        4 /* passthrough control */
/* 32 bit r/o */
#define PTNETMAP_VIRTIO_IO_PTSTS        8 /* passthrough status */
/* 32 bit w/o */
#define PTNETMAP_VIRTIO_IO_CSBBAH       12 /* CSB Base Address High */
/* 32 bit w/o */
#define PTNETMAP_VIRTIO_IO_CSBBAL       16 /* CSB Base Address Low */

#define PTNEMTAP_VIRTIO_IO_SIZE         20
#define PTNEMTAP_VIRTIO_IO_SIZE_32      5

struct ptnetmap_state {
    bool created;                       /* ptnetmap kthreads created */
    struct NetmapState *netmap;
    unsigned long features;             /* ptnetmap features */
    unsigned long acked_features;       /* ptnetmap acked features */
    uint32_t memsize;                     /* netmap memory info */
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
int ptnetmap_create(PTNetmapState *nc, struct ptnetmap_cfg *conf);
int ptnetmap_delete(PTNetmapState *nc);

int ptnetmap_memdev_create(void *mem_ptr, uint32_t mem_size, uint16_t mem_id);

#endif /* PTNETMAP_H */
