/*
 * ptnetmap-memdev PCI device
 *
 * Copyright (c) 2015 Stefano Garzarella
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "qemu/event_notifier.h"
#include "qemu/osdep.h"
#include "net/ptnetmap.h"

#define DEBUG

static uint64_t upper_pow2(uint32_t v) {
    /* from bit-twiddling hacks */
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;
    return v;
}

typedef struct PTNetmapMemDevState {
    /*< private >*/
    PCIDevice parent_obj;

    /*< public >*/
    MemoryRegion io_bar;        /* ptnetmap register BAR */
    MemoryRegion mem_bar;       /* ptnetmap shared memory BAR */
    MemoryRegion mem_ram;       /* ptnetmap shared memory subregion */
    void *mem_ptr;
    uint64_t mem_size;
    uint16_t mem_id;

    QTAILQ_ENTRY(PTNetmapMemDevState) next;
} PTNetmapMemDevState;

static QTAILQ_HEAD(, PTNetmapMemDevState) ptn_memdevs = QTAILQ_HEAD_INITIALIZER(ptn_memdevs);

#define TYPE_PTNETMAP_MEMDEV "ptnetmap-memdev"

#define PTNETMAP_MEMDEV(obj) \
    OBJECT_CHECK(PTNetmapMemDevState, (obj), TYPE_PTNETMAP_MEMDEV)

/* XXX: move to pci_ids.h */
#define PCI_VENDOR_ID_PTNETMAP  0x3333
#define PCI_DEVICE_ID_PTNETMAP  0x0001

/* XXX: move */
#define PTNETMAP_IO_PCI_BAR         0
#define PTNETMAP_MEM_PCI_BAR        1

/* register XXX: move */

/* 32 bit r/o */
#define PTNETMAP_IO_PCI_FEATURES        0

/* 32 bit r/o */
#define PTNETMAP_IO_PCI_MEMSIZE         4

/* 16 bit r/o */
#define PTNETMAP_IO_PCI_HOSTID          8

#define PTNETMAP_IO_SIZE                10

static void
ptnetmap_memdev_io_write(void *opaque, hwaddr addr, uint64_t val,
        unsigned size)
{
    //PTNetmapMemDevState *ptn_state = opaque;

    switch (addr) {

        default:
            printf("ptnentmap_memdev: write io reg unexpected\n");
            break;
    }


    printf("ptnentmap_memdev: io_write - addr: %lx size: %d val: %lx\n", addr, size, val);
}

static uint64_t
ptnetmap_memdev_io_read(void *opaque, hwaddr addr, unsigned size)
{
    PTNetmapMemDevState *ptn_state = opaque;
    uint64_t ret = 0;

    switch (addr) {
        case PTNETMAP_IO_PCI_MEMSIZE:
            ret = ptn_state->mem_size;
            break;
        case PTNETMAP_IO_PCI_HOSTID:
            ret = ptn_state->mem_id;
            break;
        default:
            printf("ptnentmap_memdev: read io reg unexpected\n");
            break;
    }

    printf("ptnentmap_memdev: io_read - addr: %lx size: %d ret: %lx\n", addr, size, ret);

    return ret;
}

static const MemoryRegionOps ptnetmap_memdev_io_ops = {
    .read = ptnetmap_memdev_io_read,
    .write = ptnetmap_memdev_io_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static int ptnetmap_memdev_init(PCIDevice *dev)
{
    PTNetmapMemDevState *ptn_state = PTNETMAP_MEMDEV(dev);
    uint8_t *pci_conf;
    uint64_t size;

    printf("ptnetmap_memdev: loading\n");

    pci_conf = dev->config;
    pci_conf[PCI_INTERRUPT_PIN] = 0; /* no interrupt pin */

    /* init register PCI_BAR */
    size = upper_pow2(PTNETMAP_IO_SIZE);
    memory_region_init_io(&ptn_state->io_bar, OBJECT(ptn_state),
            &ptnetmap_memdev_io_ops, ptn_state, "ptnetmap-io-bar", size);
    pci_register_bar(dev, PTNETMAP_IO_PCI_BAR, PCI_BASE_ADDRESS_SPACE_IO,
            &ptn_state->io_bar);

    /* init PCI_BAR to map netmap memory into the guest */
    if (ptn_state->mem_ptr) {
        size = upper_pow2(ptn_state->mem_size);
        printf("ptnentmap_memdev: map BAR size %lx (%lu MiB)\n", size, size >> 20);

        memory_region_init(&ptn_state->mem_bar, OBJECT(ptn_state),
                "ptnetmap-mem-bar", size);
        memory_region_init_ram_ptr(&ptn_state->mem_ram, OBJECT(ptn_state),
                "ptnetmap-mem-ram", ptn_state->mem_size, ptn_state->mem_ptr);
        memory_region_add_subregion(&ptn_state->mem_bar, 0, &ptn_state->mem_ram);
        vmstate_register_ram(&ptn_state->mem_ram, DEVICE(ptn_state));
        pci_register_bar(dev, PTNETMAP_MEM_PCI_BAR,
                PCI_BASE_ADDRESS_SPACE_MEMORY  |
                PCI_BASE_ADDRESS_MEM_PREFETCH /*  |
                PCI_BASE_ADDRESS_MEM_TYPE_64 */, &ptn_state->mem_bar);
    }

    QTAILQ_INSERT_TAIL(&ptn_memdevs, ptn_state, next);
    printf("ptnetmap_memdev: loaded\n");
    return 0;
}

static void
ptnetmap_memdev_uninit(PCIDevice *dev)
{
    PTNetmapMemDevState *ptn_state = PTNETMAP_MEMDEV(dev);

    QTAILQ_REMOVE(&ptn_memdevs, ptn_state, next);

    if (ptn_state->mem_ptr) {
        memory_region_destroy(&ptn_state->mem_bar);
    }
    memory_region_destroy(&ptn_state->io_bar);

    printf("ptnetmap_memdev: unloaded\n");
}

 /*
  * find ptn_state through mem_id
  */
static struct PTNetmapMemDevState *
ptnetmap_memdev_find(uint16_t mem_id)
{
    PTNetmapMemDevState *ptn_state;

    QTAILQ_FOREACH(ptn_state, &ptn_memdevs, next) {
        if (mem_id == ptn_state->mem_id) {
            return ptn_state;
        }
    }

    return NULL;
}

int
ptnetmap_memdev_create(void *mem_ptr, uint32_t mem_size, uint16_t mem_id)
{
    PCIBus *bus;
    PCIDevice *dev;
    PTNetmapMemDevState *ptn_state;

    printf("ptnetmap_memdev: creating\n");

    if (ptnetmap_memdev_find(mem_id)) {
        printf("ptnetmap_memdev: already created\n");
        return 0;
    }

    bus = pci_find_primary_bus();

    if (bus == NULL) {
        printf("ptnetmap_memdev: unable to find PCI BUS\n");
        return -1; /* XXX */
    }

    /* create ptnetmap PCI device */
    dev = pci_create(bus, -1, TYPE_PTNETMAP_MEMDEV);

    /* set ptnetmap shared memory parameter */
    ptn_state = PTNETMAP_MEMDEV(dev);
    ptn_state->mem_ptr = mem_ptr;
    ptn_state->mem_size = mem_size;
    ptn_state->mem_id = mem_id;

    /* init device */
    qdev_init_nofail(&dev->qdev);

    printf("ptnetmap_memdev: created\n");

    return 0;
}

static void qdev_ptnetmap_memdev_reset(DeviceState *dev)
{
}

static void ptnetmap_memdev_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->init = ptnetmap_memdev_init;
    k->exit = ptnetmap_memdev_uninit;
    k->vendor_id = PCI_VENDOR_ID_PTNETMAP;
    k->device_id = PCI_DEVICE_ID_PTNETMAP;
    k->revision = 0x00;
    k->class_id = PCI_CLASS_OTHERS;
    dc->desc = "ptnetmap memory device";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->reset = qdev_ptnetmap_memdev_reset;
    printf("ptnetmap_memdev: init\n");
}

static const TypeInfo ptnetmap_memdev_info = {
    .name          = TYPE_PTNETMAP_MEMDEV,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PTNetmapMemDevState),
    .class_init    = ptnetmap_memdev_class_init,
};

static void ptnetmap_memdev_register_types(void)
{
    type_register_static(&ptnetmap_memdev_info);
}

type_init(ptnetmap_memdev_register_types)
