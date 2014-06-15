/*
 * QEMU e1000 emulation
 *
 * Software developer's manual:
 * http://download.intel.com/design/network/manuals/8254x_GBe_SDM.pdf
 *
 * Nir Peleg, Tutis Systems Ltd. for Qumranet Inc.
 * Copyright (c) 2008 Qumranet
 * Based on work done by:
 * Copyright (c) 2007 Dan Aloni
 * Copyright (c) 2004 Antony T Curtis
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */


#define WITH_D	/* include debugging macros from qemu-common.h */
#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "net/net.h"
#include "net/checksum.h"
#include "hw/loader.h"
#include "sysemu/sysemu.h"
#include "sysemu/dma.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "qemu/iov.h"

#include "e1000_regs.h"

//#undef CONFIG_E1000_PARAVIRT
#ifdef CONFIG_E1000_PARAVIRT
/*
 * Support for virtio-like communication:
 * The VMM advertises virtio-like synchronization setting
 * the subvendor id set to 0x1101 (E1000_PARA_SUBDEV).
 */
#define E1000_PARA_SUBDEV 0x1101
/* Address registers for the Communication Status Block. */
#define E1000_CSBAL       0x02830
#define E1000_CSBAH       0x02834
#include "net/paravirt.h"
#include "net/tap.h"
#define E1000_MSIX_CTRL_VECTOR   0
#define E1000_MSIX_DATA_VECTOR   1
#define V1000   /* in-kernel e1000-paravirt accelerator */
#ifdef V1000
#include "v1000_user.h"
#endif /* V1000 */
static struct virtio_net_hdr null_tx_hdr;
#endif /* CONFIG_E1000_PARAVIRT */

//#define RATE	    /* Debug rate monitor enable. */
#ifdef RATE
#define IFRATE(x) x
#else
#define IFRATE(x)
#endif /* RATE */

#define E1000_DEBUG

#ifdef E1000_DEBUG
enum {
    DEBUG_GENERAL,	DEBUG_IO,	DEBUG_MMIO,	DEBUG_INTERRUPT,
    DEBUG_RX,		DEBUG_TX,	DEBUG_MDIC,	DEBUG_EEPROM,
    DEBUG_UNKNOWN,	DEBUG_TXSUM,	DEBUG_TXERR,	DEBUG_RXERR,
    DEBUG_RXFILTER,     DEBUG_PHY,      DEBUG_NOTYET,
};
#define DBGBIT(x)	(1<<DEBUG_##x)
static int debugflags = DBGBIT(TXERR) | DBGBIT(GENERAL);

#define	DBGOUT(what, fmt, ...) do { \
    if (debugflags & DBGBIT(what)) \
        fprintf(stderr, "e1000: " fmt, ## __VA_ARGS__); \
    } while (0)
#else
#define	DBGOUT(what, fmt, ...) do {} while (0)
#endif

#define IOPORT_SIZE       0x40
#define PNPMMIO_SIZE      0x20000
#define MIN_BUF_SIZE      60 /* Min. octets in an ethernet frame sans FCS */


/* this is the size past which hardware will drop packets when setting LPE=0 */
#define MAXIMUM_ETHERNET_VLAN_SIZE 1522
/* this is the size past which hardware will drop packets when setting LPE=1 */
#define MAXIMUM_ETHERNET_LPE_SIZE 16384

#define MAXIMUM_ETHERNET_HDR_LEN (14+4)

/*
 * HW models:
 *  E1000_DEV_ID_82540EM works with Windows, Linux, and OS X <= 10.8
 *  E1000_DEV_ID_82544GC_COPPER appears to work; not well tested
 *  E1000_DEV_ID_82545EM_COPPER works with Linux and OS X >= 10.6
 *  Others never tested
 */

#ifdef CONFIG_E1000_PARAVIRT
/*
 * map a guest region into a host region
 * if the pointer is within the region, ofs gives the displacement.
 * hi >= lo means we should try to map it.
 */
struct GuestMemoryMapping {
        uint64_t lo;
        uint64_t hi;
        uint64_t ofs;
        uint8_t *base;
};
#endif /* CONFIG_E1000_PARAVIRT */

typedef struct E1000State_st {
    /*< private >*/
    PCIDevice parent_obj;
    /*< public >*/

    NICState *nic;
    NICConf conf;
    MemoryRegion mmio;
    MemoryRegion io;

    uint32_t mac_reg[0x8000];
    uint16_t phy_reg[0x20];
    uint16_t eeprom_data[64];

    uint32_t rxbuf_size;
    uint32_t rxbuf_min_shift;
    struct e1000_tx {
        unsigned char header[256];
        unsigned char vlan_header[4];
        /* Fields vlan and data must not be reordered or separated. */
        unsigned char vlan[4];
        unsigned char data[0x10000];
        uint16_t size;
        unsigned char sum_needed;
        unsigned char vlan_needed;
        uint8_t ipcss;
        uint8_t ipcso;
        uint16_t ipcse;
        uint8_t tucss;
        uint8_t tucso;
        uint16_t tucse;
        uint8_t hdr_len;
        uint16_t mss;
        uint32_t paylen;
        uint16_t tso_frames;
        char tse;
        int8_t ip;
        int8_t tcp;
        char cptse;     // current packet tse bit
    } tx;

    struct {
        uint32_t val_in;	// shifted in from guest driver
        uint16_t bitnum_in;
        uint16_t bitnum_out;
        uint16_t reading;
        uint32_t old_eecd;
    } eecd_state;

    QEMUTimer *autoneg_timer;

    QEMUTimer *mit_timer;      /* Mitigation timer. */
    bool mit_timer_on;         /* Mitigation timer is running. */
    bool mit_irq_level;        /* Tracks interrupt pin level. */
    uint32_t mit_ide;          /* Tracks E1000_TXD_CMD_IDE bit. */

/* Compatibility flags for migration to/from qemu 1.3.0 and older */
#define E1000_FLAG_AUTONEG_BIT 0
#define E1000_FLAG_MIT_BIT 1
#define E1000_FLAG_AUTONEG (1 << E1000_FLAG_AUTONEG_BIT)
#define E1000_FLAG_MIT (1 << E1000_FLAG_MIT_BIT)
    uint32_t compat_flags;

#ifdef CONFIG_E1000_PARAVIRT
    uint32_t rxbufs;
    struct e1000_tx_desc *txring;     /* Host virtual address for the TX ring. */
    struct e1000_rx_desc *rxring;     /* Host virtual address for the RX ring. */
#define E1000_MAX_MAPPINGS  8
    struct GuestMemoryMapping mappings[E1000_MAX_MAPPINGS];
    uint32_t num_mappings;
    uint32_t iovcnt;
    uint32_t iovsize;
#define E1000_MAX_FRAGS	64
    struct iovec iov[E1000_MAX_FRAGS];
    struct paravirt_csb *csb;   /* Communication Status Block. */
    QEMUBH *tx_bh;              /* QEMU bottom-half used for transmission. */
    uint32_t tx_count;	        /* TX processed in last start_xmit round */
    uint32_t txcycles;	        /* TX bottom half spinning counter */
    uint32_t txcycles_lim;      /* Snapshot of s->csb->host_txcycles_lim */
    int host_hdr_ofs;           /* Is the host using the virtio-net header? */
    int guest_hdr_ofs;          /* Is the guest using the virtio-net header? */
    struct virtio_net_hdr *vnet_hdr;  /* Host v.a. for the headers receive ring. */
    struct virtio_net_hdr *tx_hdr;    /* Private headers transmit ring. */
    EventNotifier host_tx_notifier;
    int virq;
    bool ioeventfd;	    /* Are we using ioeventfd for guest --> host kicks? */
    bool msix;              /* Are we using MSI-X instead of IRQ interrupts? */
#ifdef V1000
    bool v1000;             /* Did the user request to use the v1000 accelerator? */
    int v1000_fd;
    EventNotifier host_rx_notifier, guest_notifier;
    struct V1000Config cfg;
#endif /* V1000 */
#endif /* CONFIG_E1000_PARAVIRT */
    uint32_t rx_count;
    bool peer_async;        /* Is the backend able to do asynchronous processing? */
    uint32_t sync_tdh;	    /* TDH register value exposed to the guest. */
    uint32_t next_tdh;
    IFRATE(QEMUTimer * rate_timer);
} E1000State;

typedef struct E1000BaseClass {
    PCIDeviceClass parent_class;
    uint16_t phy_id2;
} E1000BaseClass;

#define TYPE_E1000_BASE "e1000-base"

#define E1000(obj) \
    OBJECT_CHECK(E1000State, (obj), TYPE_E1000_BASE)

#define E1000_DEVICE_CLASS(klass) \
     OBJECT_CLASS_CHECK(E1000BaseClass, (klass), TYPE_E1000_BASE)
#define E1000_DEVICE_GET_CLASS(obj) \
    OBJECT_GET_CLASS(E1000BaseClass, (obj), TYPE_E1000_BASE)

#define	defreg(x)	x = (E1000_##x>>2)
enum {
    defreg(CTRL),	defreg(EECD),	defreg(EERD),	defreg(GPRC),
    defreg(GPTC),	defreg(ICR),	defreg(ICS),	defreg(IMC),
    defreg(IMS),	defreg(LEDCTL),	defreg(MANC),	defreg(MDIC),
    defreg(MPC),	defreg(PBA),	defreg(RCTL),	defreg(RDBAH),
    defreg(RDBAL),	defreg(RDH),	defreg(RDLEN),	defreg(RDT),
    defreg(STATUS),	defreg(SWSM),	defreg(TCTL),	defreg(TDBAH),
    defreg(TDBAL),	defreg(TDH),	defreg(TDLEN),	defreg(TDT),
    defreg(TORH),	defreg(TORL),	defreg(TOTH),	defreg(TOTL),
    defreg(TPR),	defreg(TPT),	defreg(TXDCTL),	defreg(WUFC),
    defreg(RA),		defreg(MTA),	defreg(CRCERRS),defreg(VFTA),
    defreg(VET),        defreg(RDTR),   defreg(RADV),   defreg(TADV),
    defreg(ITR),
#ifdef CONFIG_E1000_PARAVIRT
    defreg(CSBAL),      defreg(CSBAH),
#endif /* CONFIG_E1000_PARAVIRT */
};

/* Rate monitor: shows the communication statistics. */
#ifdef RATE
static int64_t rate_last_timestamp = 0;
static int rate_interval_ms = 1000;

/* rate mmio accesses */
static int rate_mmio_write = 0;
static int rate_mmio_read = 0;

/* rate interrupts */
static int rate_irq_int = 0;
static int rate_ntfy_txfull = 0;

/* rate guest notifications */
static int rate_ntfy_tx = 0;    // new TX descriptors
static int rate_ntfy_ic = 0;    // interrupt acknowledge (interrupt clear)
static int rate_ntfy_rx = 0;

/* rate tx packets */
static int rate_tx = 0;
static int rate_tx_iov = 0;
static int64_t rate_txb = 0;

/* rate rx packet */
static int rate_rx = 0;  // received packet counter
static int64_t rate_rxb = 0;

static int rate_tx_bh_len = 0;
static int rate_tx_bh_count = 0;
static int rate_txsync = 0;

#ifdef CONFIG_E1000_PARAVIRT
static void csb_dump(E1000State * s) {
    if (s->csb) {
	printf("guest_csb_on = %X\n", s->csb->guest_csb_on);
	printf("guest_tdt = %X\n", s->csb->guest_tdt);
	printf("guest_rdt = %X\n", s->csb->guest_rdt);
	printf("guest_need_txkick = %X\n", s->csb->guest_need_txkick);
	printf("guest_need_rxkick = %X\n", s->csb->guest_need_rxkick);
	printf("host_tdh = %X\n", s->csb->host_tdh);
	printf("host_rdh = %X\n", s->csb->host_rdh);
	printf("host_need_txkick = %X\n", s->csb->host_need_txkick);
	printf("host_need_rxkick = %X\n", s->csb->host_need_rxkick);
	printf("host_rxkick_at = %X\n", s->csb->host_rxkick_at);
	printf("host_txcycles_lim = %X\n", s->csb->host_txcycles_lim);
    }
}
#endif /* CONFIG_E1000_PARAVIRT */

static void rate_callback(void * opaque)
{
    E1000State* s = opaque;
    int64_t delta;

#ifdef CONFIG_E1000_PARAVIRT
    csb_dump(s);
#endif /* CONFIG_E1000_PARAVIRT */

    delta = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) - rate_last_timestamp;
    printf("Interrupt:           %4.3f KHz\n", (double)rate_irq_int/delta);
    printf("Tx packets:          %4.3f KHz\n", (double)rate_tx/delta);
    printf("Tx iov packets:      %4.3f KHz\n", (double)rate_tx_iov/delta);
    printf("Tx stream:           %4.3f Mbps\n", (double)(rate_txb*8)/delta/1000.0);
    printf("Avg BH work:         %4.3f\n", rate_tx_bh_count ? (double)rate_tx_bh_len/(double)rate_tx_bh_count : 0);
    printf("Rx packets:          %4.3f Kpps\n", (double)rate_rx/delta);
    printf("Rx stream:           %4.3f Mbps\n", (double)(rate_rxb*8)/delta/1000.0);
    printf("Tx notifications:    %4.3f KHz\n", (double)rate_ntfy_tx/delta);
    printf("TX full notif.:      %4.3f KHz\n", (double)rate_ntfy_txfull/delta);
    printf("Rx notifications:    %4.3f KHz\n", (double)rate_ntfy_rx/delta);
    printf("MMIO writes:         %4.3f KHz\n", (double)rate_mmio_write/delta);
    printf("MMIO reads:          %4.3f KHz\n", (double)rate_mmio_read/delta);
    printf("TXSYNC:		%4.3f KHz\n", (double)rate_txsync/delta);
    printf("\n");
    rate_irq_int = 0;
    rate_ntfy_txfull = 0;
    rate_ntfy_tx = rate_ntfy_ic = rate_ntfy_rx = 0;
    rate_mmio_read = rate_mmio_write = 0;
    rate_rx = rate_rxb = 0;
    rate_tx = rate_tx_iov = rate_txb = 0;
    rate_tx_bh_len = rate_tx_bh_count = 0;
    rate_txsync = 0;

    timer_mod(s->rate_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
		    rate_interval_ms);
    rate_last_timestamp = qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL);
}
#endif /* RATE */

#ifdef CONFIG_E1000_PARAVIRT
static uint8_t *translate_guest_paddr(E1000State *s, hwaddr addr, hwaddr len)
{
    struct GuestMemoryMapping *m = &s->mappings[0];
    struct GuestMemoryMapping newm;
    unsigned int i = 0;
    uint64_t lo = addr;
    uint64_t hi = addr + len;
    hwaddr wmaplen;
    hwaddr rmaplen;
    AddressSpace *as;

/*    int j;
    printf("Current mappings: \n");
    for (j=0; j<s->num_mappings; j++) {
        printf("    %p,%p\n", (void*)s->mappings[j].lo, (void*)s->mappings[j].hi);
    }*/

    for (;;) {
        /* Lookup the translation table. */
        for (; i < s->num_mappings; i++, m++) {
            if (m->lo <= lo && hi <= m->hi) {
                return (uint8_t *)(uintptr_t)(lo + m->ofs);
            }
        }
        /* Translation miss: Try to extend a previous mapping. */
        as = pci_get_address_space(PCI_DEVICE(s));
        m = &s->mappings[0];
        for (i = 0; i < s->num_mappings; i++, m++) {
            newm = *m;
            wmaplen = newm.hi - newm.lo;
            address_space_unmap(as, newm.base, wmaplen, 1, wmaplen);
            if (lo < newm.lo) {
                newm.lo = lo;
            }
            if (hi > newm.hi) {
                newm.hi = hi;
            }
            wmaplen = rmaplen = newm.hi - newm.lo;
            newm.base = address_space_map(as, newm.lo, &rmaplen, 1 /* is write */);
            newm.hi = newm.lo + rmaplen;
            newm.ofs = (uintptr_t)newm.base - newm.lo;
            if (rmaplen == wmaplen) {
                ND("Extended mapping #%d", i);
                *m = newm;
                break;
            }
            /* This entry cannot be extended anymore: Restore what was
               previously mapped. */
            rmaplen = m->hi - m->lo;
            m->base = address_space_map(as, m->lo, &rmaplen, 1);
            m->hi = m->lo + rmaplen;
            m->ofs = (uintptr_t)m->base - m->lo;
        }
        if (i == s->num_mappings) {
            /* No entry was elegible for extension: Create a new one. */
            if (i == E1000_MAX_MAPPINGS) {
                break;
            } else {
                m->lo = lo;
                m->hi = hi;
                wmaplen = rmaplen = m->hi - m->lo;
                m->base = address_space_map(as, m->lo, &rmaplen, 1);
                m->ofs = (uintptr_t)m->base - m->lo;
                if (rmaplen != wmaplen) {
                    break;
                }
                s->num_mappings++;
                ND("New mapping #%d", i);
            }
        }
    }
    D("Cannot map %p + %d", (void*)(uintptr_t)addr, (int)len);

    return NULL;
}
#endif /* CONFIG_E1000_PARAVIRT */

static void
e1000_link_down(E1000State *s)
{
    s->mac_reg[STATUS] &= ~E1000_STATUS_LU;
    s->phy_reg[PHY_STATUS] &= ~MII_SR_LINK_STATUS;
}

static void
e1000_link_up(E1000State *s)
{
    s->mac_reg[STATUS] |= E1000_STATUS_LU;
    s->phy_reg[PHY_STATUS] |= MII_SR_LINK_STATUS;
}

static void
set_phy_ctrl(E1000State *s, int index, uint16_t val)
{
    /*
     * QEMU 1.3 does not support link auto-negotiation emulation, so if we
     * migrate during auto negotiation, after migration the link will be
     * down.
     */
    if (!(s->compat_flags & E1000_FLAG_AUTONEG)) {
        return;
    }
    if ((val & MII_CR_AUTO_NEG_EN) && (val & MII_CR_RESTART_AUTO_NEG)) {
        e1000_link_down(s);
        s->phy_reg[PHY_STATUS] &= ~MII_SR_AUTONEG_COMPLETE;
        DBGOUT(PHY, "Start link auto negotiation\n");
        timer_mod(s->autoneg_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 500);
    }
}

static void
e1000_autoneg_timer(void *opaque)
{
    E1000State *s = opaque;
    if (!qemu_get_queue(s->nic)->link_down) {
        e1000_link_up(s);
    }
    s->phy_reg[PHY_STATUS] |= MII_SR_AUTONEG_COMPLETE;
    DBGOUT(PHY, "Auto negotiation is completed\n");
}

static void (*phyreg_writeops[])(E1000State *, int, uint16_t) = {
    [PHY_CTRL] = set_phy_ctrl,
};

enum { NPHYWRITEOPS = ARRAY_SIZE(phyreg_writeops) };

enum { PHY_R = 1, PHY_W = 2, PHY_RW = PHY_R | PHY_W };
static const char phy_regcap[0x20] = {
    [PHY_STATUS] = PHY_R,	[M88E1000_EXT_PHY_SPEC_CTRL] = PHY_RW,
    [PHY_ID1] = PHY_R,		[M88E1000_PHY_SPEC_CTRL] = PHY_RW,
    [PHY_CTRL] = PHY_RW,	[PHY_1000T_CTRL] = PHY_RW,
    [PHY_LP_ABILITY] = PHY_R,	[PHY_1000T_STATUS] = PHY_R,
    [PHY_AUTONEG_ADV] = PHY_RW,	[M88E1000_RX_ERR_CNTR] = PHY_R,
    [PHY_ID2] = PHY_R,		[M88E1000_PHY_SPEC_STATUS] = PHY_R
};

/* PHY_ID2 documented in 8254x_GBe_SDM.pdf, pp. 250 */
static const uint16_t phy_reg_init[] = {
    [PHY_CTRL] = 0x1140,
    [PHY_STATUS] = 0x794d, /* link initially up with not completed autoneg */
    [PHY_ID1] = 0x141, /* [PHY_ID2] configured per DevId, from e1000_reset() */
    [PHY_1000T_CTRL] = 0x0e00,			[M88E1000_PHY_SPEC_CTRL] = 0x360,
    [M88E1000_EXT_PHY_SPEC_CTRL] = 0x0d60,	[PHY_AUTONEG_ADV] = 0xde1,
    [PHY_LP_ABILITY] = 0x1e0,			[PHY_1000T_STATUS] = 0x3c00,
    [M88E1000_PHY_SPEC_STATUS] = 0xac00,
};

static const uint32_t mac_reg_init[] = {
    [PBA] =     0x00100030,
    [LEDCTL] =  0x602,
    [CTRL] =    E1000_CTRL_SWDPIN2 | E1000_CTRL_SWDPIN0 |
                E1000_CTRL_SPD_1000 | E1000_CTRL_SLU,
    [STATUS] =  0x80000000 | E1000_STATUS_GIO_MASTER_ENABLE |
                E1000_STATUS_ASDV | E1000_STATUS_MTXCKOK |
                E1000_STATUS_SPEED_1000 | E1000_STATUS_FD |
                E1000_STATUS_LU,
    [MANC] =    E1000_MANC_EN_MNG2HOST | E1000_MANC_RCV_TCO_EN |
                E1000_MANC_ARP_EN | E1000_MANC_0298_EN |
                E1000_MANC_RMCP_EN,
};

/* Helper function, *curr == 0 means the value is not set */
static inline void
mit_update_delay(uint32_t *curr, uint32_t value)
{
    if (value && (*curr == 0 || value < *curr)) {
        *curr = value;
    }
}

static void
set_interrupt_cause(E1000State *s, int index, uint32_t val)
{
    PCIDevice *d = PCI_DEVICE(s);
    uint32_t pending_ints;
    uint32_t mit_delay;

    s->mac_reg[ICR] = val;

    /*
     * Make sure ICR and ICS registers have the same value.
     * The spec says that the ICS register is write-only.  However in practice,
     * on real hardware ICS is readable, and for reads it has the same value as
     * ICR (except that ICS does not have the clear on read behaviour of ICR).
     *
     * The VxWorks PRO/1000 driver uses this behaviour.
     */
    s->mac_reg[ICS] = val;

    pending_ints = (s->mac_reg[IMS] & s->mac_reg[ICR]);
#ifdef CONFIG_E1000_PARAVIRT
    if (pending_ints && (!s->mit_irq_level || s->msix)) {
#else
    if (!s->mit_irq_level && pending_ints) {
#endif /* CONFIG_E1000_PARAVIRT */
        /*
         * Here we detect a potential raising edge. We postpone raising the
         * interrupt line if we are inside the mitigation delay window
         * (s->mit_timer_on == 1).
         * We provide a partial implementation of interrupt mitigation,
         * emulating only RADV, TADV and ITR (lower 16 bits, 1024ns units for
         * RADV and TADV, 256ns units for ITR). RDTR is only used to enable
         * RADV; relative timers based on TIDV and RDTR are not implemented.
         */
        if (s->mit_timer_on) {
            return;
        }
#ifdef CONFIG_E1000_PARAVIRT
#define E1000_PARAVIRT_INTR_OTHER (~(E1000_ICS_RXT0 | E1000_ICS_RXDMT0 | E1000_ICR_TXQE | E1000_ICR_TXDW | E1000_ICR_INT_ASSERTED))
	if (s->csb && s->csb->guest_csb_on &&
		!(pending_ints & E1000_PARAVIRT_INTR_OTHER) &&
		!(s->csb->guest_need_txkick &&
		    (pending_ints & (E1000_ICR_TXQE | E1000_ICR_TXDW))) &&
		!(s->csb->guest_need_rxkick &&
				(pending_ints & (E1000_ICS_RXT0)))) {
		return;
	}
#endif /* CONFIG_E1000_PARAVIRT */
        if (s->compat_flags & E1000_FLAG_MIT) {
            /* Compute the next mitigation delay according to pending
             * interrupts and the current values of RADV (provided
             * RDTR!=0), TADV and ITR.
             * Then rearm the timer.
             */
            mit_delay = 0;
            if (s->mit_ide &&
                    (pending_ints & (E1000_ICR_TXQE | E1000_ICR_TXDW))) {
                mit_update_delay(&mit_delay, s->mac_reg[TADV] * 4);
            }
            if (s->mac_reg[RDTR] && (pending_ints & E1000_ICS_RXT0)) {
                mit_update_delay(&mit_delay, s->mac_reg[RADV] * 4);
            }
            mit_update_delay(&mit_delay, s->mac_reg[ITR]);

            if (mit_delay) {
                s->mit_timer_on = 1;
                timer_mod(s->mit_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                          mit_delay * 256);
            }
            s->mit_ide = 0;
        }
#ifdef CONFIG_E1000_PARAVIRT
        if (s->msix) {
#define E1000_DATA_INTR (E1000_ICR_TXDW | E1000_ICR_TXQE | E1000_ICS_RXT0 \
                        | E1000_ICS_RXDMT0 | E1000_ICS_RXO)
            if (pending_ints & E1000_DATA_INTR) {
	        msix_notify(d, E1000_MSIX_DATA_VECTOR);
                /* Autoclear. */
                s->mac_reg[ICS] &= ~E1000_DATA_INTR;
                s->mac_reg[ICR] = s->mac_reg[ICS];
            }
            if (pending_ints & (E1000_ICR_LSC | E1000_ICR_MDAC))
	        msix_notify(d, E1000_MSIX_CTRL_VECTOR);
        }
#endif /* CONFIG_E1000_PARAVIRT */
	IFRATE(rate_irq_int++);
    }

#ifdef CONFIG_E1000_PARAVIRT
    if (s->msix) {
        return;
    }
#endif /* CONFIG_E1000_PARAVIRT */
    s->mit_irq_level = (pending_ints != 0);
    pci_set_irq(d, s->mit_irq_level);
}

static void
e1000_mit_timer(void *opaque)
{
    E1000State *s = opaque;

    s->mit_timer_on = 0;
    /* Call set_interrupt_cause to update the irq level (if necessary). */
    set_interrupt_cause(s, 0, s->mac_reg[ICR]);
}

static void
set_ics(E1000State *s, int index, uint32_t val)
{
    DBGOUT(INTERRUPT, "set_ics %x, ICR %x, IMR %x\n", val, s->mac_reg[ICR],
        s->mac_reg[IMS]);
    set_interrupt_cause(s, 0, val | s->mac_reg[ICR]);
}

static int
rxbufsize(uint32_t v)
{
    v &= E1000_RCTL_BSEX | E1000_RCTL_SZ_16384 | E1000_RCTL_SZ_8192 |
         E1000_RCTL_SZ_4096 | E1000_RCTL_SZ_2048 | E1000_RCTL_SZ_1024 |
         E1000_RCTL_SZ_512 | E1000_RCTL_SZ_256;
    switch (v) {
    case E1000_RCTL_BSEX | E1000_RCTL_SZ_16384:
        return 16384;
    case E1000_RCTL_BSEX | E1000_RCTL_SZ_8192:
        return 8192;
    case E1000_RCTL_BSEX | E1000_RCTL_SZ_4096:
        return 4096;
    case E1000_RCTL_SZ_1024:
        return 1024;
    case E1000_RCTL_SZ_512:
        return 512;
    case E1000_RCTL_SZ_256:
        return 256;
    }
    return 2048;
}

static void e1000_peer_async_callback(void *opaque);

#ifdef CONFIG_E1000_PARAVIRT
static bool peer_has_vnet_hdr(E1000State *s)
{
    NetClientState * nc = s->nic->ncs;

    if (!nc->peer) {
	return false;
    }

    return qemu_has_vnet_hdr(nc->peer);
}

#endif	/* CONFIG_E1000_PARAVIRT */

static void e1000_reset(void *opaque)
{
    E1000State *d = opaque;
    E1000BaseClass *edc = E1000_DEVICE_GET_CLASS(d);
    uint8_t *macaddr = d->conf.macaddr.a;
    int i;

    timer_del(d->autoneg_timer);
    timer_del(d->mit_timer);
    d->mit_timer_on = 0;
    d->mit_irq_level = 0;
    d->mit_ide = 0;
#ifdef CONFIG_E1000_PARAVIRT
    d->csb = NULL;
    qemu_bh_cancel(d->tx_bh);
    d->host_hdr_ofs = d->guest_hdr_ofs = 0;
    d->iovcnt = d->host_hdr_ofs;
    d->msix = false;
    msix_unuse_all_vectors(PCI_DEVICE(d));
    msix_vector_use(PCI_DEVICE(d), E1000_MSIX_CTRL_VECTOR);
    msix_vector_use(PCI_DEVICE(d), E1000_MSIX_DATA_VECTOR);
#endif /* CONFIG_E1000_PARAVIRT */
    d->peer_async = (qemu_register_peer_async_callback(d->nic->ncs,
				    &e1000_peer_async_callback, d) == 0);
    d->sync_tdh = 0;
    if (d->peer_async)
	D("the backend is asynchronous\n");
    else
	D("the backend is not asynchronous\n");
    memset(d->phy_reg, 0, sizeof d->phy_reg);
    memmove(d->phy_reg, phy_reg_init, sizeof phy_reg_init);
    d->phy_reg[PHY_ID2] = edc->phy_id2;
    memset(d->mac_reg, 0, sizeof d->mac_reg);
    memmove(d->mac_reg, mac_reg_init, sizeof mac_reg_init);
    d->rxbuf_min_shift = 1;
    memset(&d->tx, 0, sizeof d->tx);

    if (qemu_get_queue(d->nic)->link_down) {
        e1000_link_down(d);
    }

    /* Some guests expect pre-initialized RAH/RAL (AddrValid flag + MACaddr) */
    d->mac_reg[RA] = 0;
    d->mac_reg[RA + 1] = E1000_RAH_AV;
    for (i = 0; i < 4; i++) {
        d->mac_reg[RA] |= macaddr[i] << (8 * i);
        d->mac_reg[RA + 1] |= (i < 2) ? macaddr[i + 4] << (8 * i) : 0;
    }
    qemu_format_nic_info_str(qemu_get_queue(d->nic), macaddr);
}

static void
set_ctrl(E1000State *s, int index, uint32_t val)
{
    /* RST is self clearing */
    s->mac_reg[CTRL] = val & ~E1000_CTRL_RST;
    IFRATE(timer_mod(s->rate_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL)
		+ 1000));
}

static void
set_rx_control(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[RCTL] = val;
    s->rxbuf_size = rxbufsize(val);
    s->rxbuf_min_shift = ((val / E1000_RCTL_RDMTS_QUAT) & 3) + 1;
    DBGOUT(RX, "RCTL: %d, mac_reg[RCTL] = 0x%x\n", s->mac_reg[RDT],
           s->mac_reg[RCTL]);
    qemu_flush_queued_packets(qemu_get_queue(s->nic));
}

static void
set_mdic(E1000State *s, int index, uint32_t val)
{
    uint32_t data = val & E1000_MDIC_DATA_MASK;
    uint32_t addr = ((val & E1000_MDIC_REG_MASK) >> E1000_MDIC_REG_SHIFT);

    if ((val & E1000_MDIC_PHY_MASK) >> E1000_MDIC_PHY_SHIFT != 1) // phy #
        val = s->mac_reg[MDIC] | E1000_MDIC_ERROR;
    else if (val & E1000_MDIC_OP_READ) {
        DBGOUT(MDIC, "MDIC read reg 0x%x\n", addr);
        if (!(phy_regcap[addr] & PHY_R)) {
            DBGOUT(MDIC, "MDIC read reg %x unhandled\n", addr);
            val |= E1000_MDIC_ERROR;
        } else
            val = (val ^ data) | s->phy_reg[addr];
    } else if (val & E1000_MDIC_OP_WRITE) {
        DBGOUT(MDIC, "MDIC write reg 0x%x, value 0x%x\n", addr, data);
        if (!(phy_regcap[addr] & PHY_W)) {
            DBGOUT(MDIC, "MDIC write reg %x unhandled\n", addr);
            val |= E1000_MDIC_ERROR;
        } else {
            if (addr < NPHYWRITEOPS && phyreg_writeops[addr]) {
                phyreg_writeops[addr](s, index, data);
            }
            s->phy_reg[addr] = data;
        }
    }
    s->mac_reg[MDIC] = val | E1000_MDIC_READY;

    if (val & E1000_MDIC_INT_EN) {
        set_ics(s, 0, E1000_ICR_MDAC);
    }
}

static uint32_t
get_eecd(E1000State *s, int index)
{
    uint32_t ret = E1000_EECD_PRES|E1000_EECD_GNT | s->eecd_state.old_eecd;

    DBGOUT(EEPROM, "reading eeprom bit %d (reading %d)\n",
           s->eecd_state.bitnum_out, s->eecd_state.reading);
    if (!s->eecd_state.reading ||
        ((s->eeprom_data[(s->eecd_state.bitnum_out >> 4) & 0x3f] >>
          ((s->eecd_state.bitnum_out & 0xf) ^ 0xf))) & 1)
        ret |= E1000_EECD_DO;
    return ret;
}

static void
set_eecd(E1000State *s, int index, uint32_t val)
{
    uint32_t oldval = s->eecd_state.old_eecd;

    s->eecd_state.old_eecd = val & (E1000_EECD_SK | E1000_EECD_CS |
            E1000_EECD_DI|E1000_EECD_FWE_MASK|E1000_EECD_REQ);
    if (!(E1000_EECD_CS & val))			// CS inactive; nothing to do
	return;
    if (E1000_EECD_CS & (val ^ oldval)) {	// CS rise edge; reset state
	s->eecd_state.val_in = 0;
	s->eecd_state.bitnum_in = 0;
	s->eecd_state.bitnum_out = 0;
	s->eecd_state.reading = 0;
    }
    if (!(E1000_EECD_SK & (val ^ oldval)))	// no clock edge
        return;
    if (!(E1000_EECD_SK & val)) {		// falling edge
        s->eecd_state.bitnum_out++;
        return;
    }
    s->eecd_state.val_in <<= 1;
    if (val & E1000_EECD_DI)
        s->eecd_state.val_in |= 1;
    if (++s->eecd_state.bitnum_in == 9 && !s->eecd_state.reading) {
        s->eecd_state.bitnum_out = ((s->eecd_state.val_in & 0x3f)<<4)-1;
        s->eecd_state.reading = (((s->eecd_state.val_in >> 6) & 7) ==
            EEPROM_READ_OPCODE_MICROWIRE);
    }
    DBGOUT(EEPROM, "eeprom bitnum in %d out %d, reading %d\n",
           s->eecd_state.bitnum_in, s->eecd_state.bitnum_out,
           s->eecd_state.reading);
}

static uint32_t
flash_eerd_read(E1000State *s, int x)
{
    unsigned int index, r = s->mac_reg[EERD] & ~E1000_EEPROM_RW_REG_START;

    if ((s->mac_reg[EERD] & E1000_EEPROM_RW_REG_START) == 0)
        return (s->mac_reg[EERD]);

    if ((index = r >> E1000_EEPROM_RW_ADDR_SHIFT) > EEPROM_CHECKSUM_REG)
        return (E1000_EEPROM_RW_REG_DONE | r);

    return ((s->eeprom_data[index] << E1000_EEPROM_RW_REG_DATA) |
           E1000_EEPROM_RW_REG_DONE | r);
}

static void
putsum(uint8_t *data, uint32_t n, uint32_t sloc, uint32_t css, uint32_t cse)
{
    uint32_t sum;

    if (cse && cse < n)
        n = cse + 1;
    if (sloc < n-1) {
        sum = net_checksum_add(n-css, data+css);
        stw_be_p(data + sloc, net_checksum_finish(sum));
    }
}

typedef const struct iovec * const_iovec_ptr;
static size_t iov_skip_bytes(const_iovec_ptr *iov, int *iovcnt,
                             size_t *iov_ofs, unsigned int skip)
{
    const_iovec_ptr iv = *iov;
    int cnt = *iovcnt;
    size_t ofs = *iov_ofs + skip;

    while (iv->iov_len <= ofs) {
        ofs -= iv->iov_len;
        iv++;
        cnt--;
    }
    *iov = iv;
    *iovcnt = cnt;
    *iov_ofs = ofs;

    return 0;
}

#ifdef CONFIG_E1000_PARAVIRT
static void
putsum_iov(const struct iovec *iov, int iovcnt, uint32_t n,
		uint32_t sloc, uint32_t css, uint32_t cse)
{
    uint16_t check;
    size_t iov_ofs = 0;

    if (cse && cse < n)
        n = cse + 1;
    if (sloc < n-1) {
        check = net_checksum_finish(net_checksum_add_iov(iov, iovcnt, css, n-css));
        iov_skip_bytes(&iov, &iovcnt, &iov_ofs, sloc);
        *((uint8_t *)iov->iov_base + iov_ofs) = check >> 8;
        iov_skip_bytes(&iov, &iovcnt, &iov_ofs, 1);
        *((uint8_t *)iov->iov_base + iov_ofs) = check & 0xff;
    }
}
#endif /* CONFIG_E1000_PARAVIRT */

static inline int
vlan_enabled(E1000State *s)
{
    return ((s->mac_reg[CTRL] & E1000_CTRL_VME) != 0);
}

static inline int
vlan_rx_filter_enabled(E1000State *s)
{
    return ((s->mac_reg[RCTL] & E1000_RCTL_VFE) != 0);
}

static inline int
is_vlan_packet(E1000State *s, const uint8_t *buf)
{
    return (be16_to_cpup((uint16_t *)(buf + 12)) ==
                le16_to_cpup((uint16_t *)(s->mac_reg + VET)));
}

static inline int
is_vlan_txd(uint32_t txd_lower)
{
    return ((txd_lower & E1000_TXD_CMD_VLE) != 0);
}

/* FCS aka Ethernet CRC-32. We don't get it from backends and can't
 * fill it in, just pad descriptor length by 4 bytes unless guest
 * told us to strip it off the packet. */
static inline int
fcs_len(E1000State *s)
{
    return (s->mac_reg[RCTL] & E1000_RCTL_SECRC) ? 0 : 4;
}

#ifdef CONFIG_E1000_PARAVIRT
static void
e1000_sendv_packet(E1000State *s)
{
    NetClientState *nc = qemu_get_queue(s->nic);
    if (s->phy_reg[PHY_CTRL] & MII_CR_LOOPBACK) {
        nc->info->receive_iov(nc, s->iov, s->iovcnt);
    } else {
	qemu_sendv_packet_async_moreflags(nc, s->iov, s->iovcnt, NULL,
	    (s->mac_reg[TDT] == s->next_tdh) ? 0: QEMU_NET_PACKET_FLAG_MORE);
	IFRATE(rate_txsync += (s->mac_reg[TDT] == s->next_tdh) ? 1 : 0);
    }
    IFRATE(rate_tx_iov++; rate_txb += s->iovsize; rate_tx_bh_len++);
    s->iovcnt = s->host_hdr_ofs;  /* Reset s->iovcnt. */
    s->iovsize = 0;
}

static void
e1000_send_packet(E1000State *s, const uint8_t *buf, int size)
{
    s->iov[s->host_hdr_ofs].iov_base = (uint8_t *)buf;
    s->iov[s->host_hdr_ofs].iov_len = size;
    s->iovcnt = s->host_hdr_ofs + 1;
    s->iovsize = size;
    e1000_sendv_packet(s);
    IFRATE(rate_tx_iov--; rate_tx++);
}
#else   /* !CONFIG_E1000_PARAVIRT */
static void
e1000_send_packet(E1000State *s, const uint8_t *buf, int size)
{
    NetClientState *nc = qemu_get_queue(s->nic);
    if (s->phy_reg[PHY_CTRL] & MII_CR_LOOPBACK) {
        nc->info->receive(nc, buf, size);
    } else {
        qemu_send_packet(nc, buf, size);
    }
    IFRATE(rate_tx++; rate_txb += size; rate_tx_bh_len++);
}


#endif	/* !CONFIG_E1000_PARAVIRT */

static void
xmit_seg(E1000State *s)
{
    uint16_t len, *sp;
    unsigned int frames = s->tx.tso_frames, css, sofar, n;
    struct e1000_tx *tp = &s->tx;
    uint8_t * buf;
#ifdef CONFIG_E1000_PARAVIRT
    struct virtio_net_hdr * hdr;

    if (s->csb && s->csb->guest_csb_on) {
        if (!s->guest_hdr_ofs && (tp->tse && tp->cptse)) {
            /* We have TSO packet while not using the virtio-net header. */
            if (frames == 0) {
                uint32_t csum;
                /* Zero the IPv4 checksum field in the TSO packet,
                   because the putsum() function expect this field
                   to be zero.*/
                *((uint16_t*)(tp->header + tp->ipcso)) =
                    *((uint16_t*)(tp->data + tp->ipcso)) = 0;
                /* Compute a partial TCP checksum, including IP addresses,
                   and IP protocol, storing it into tp->header (for reuse),
                   and into tp->data (first TCP segment). This operation
                   is done by the driver in non-paravirtual mode (see
                   tcpdup_magic() in the Linux driver). */
                csum = net_checksum_add(8, &tp->header[14+12]); /* IP addrs */
                csum += tp->header[14+9];  /* IPPROTO_TCP */
                csum = (csum >> 16) + (csum & 0xffff);  /* Fold it. */
                *((uint16_t*)(tp->header + tp->tucso)) =
                    *((uint16_t*)(tp->data + tp->tucso)) = cpu_to_be16(csum);
            }
        } else {
            if (!s->guest_hdr_ofs) {
                /* We are not using the virtio-net header, and this is a
                   potentially fragmented non-TSO packet. E.g., a Linux guest
                   send TCP segments as fragmented packet when the ethtool
                   parameters "tso" is off and "sg" is on. */
                if (s->iovcnt == 1) {
                    /* TODO use only putsum_iov(), if convenient. */
                    if (tp->sum_needed & E1000_TXD_POPTS_TXSM)
                        putsum(s->iov[0].iov_base, s->iov[0].iov_len,
                                tp->tucso, tp->tucss, tp->tucse);
                    if (tp->sum_needed & E1000_TXD_POPTS_IXSM)
                        putsum(s->iov[0].iov_base, s->iov[0].iov_len,
                                tp->ipcso, tp->ipcss, tp->ipcse);
                } else {
                    if (tp->sum_needed & E1000_TXD_POPTS_TXSM)
                        putsum_iov(s->iov, s->iovcnt, s->iovsize, tp->tucso,
                                tp->tucss, tp->tucse);
                    if (tp->sum_needed & E1000_TXD_POPTS_IXSM)
                        putsum_iov(s->iov, s->iovcnt, s->iovsize, tp->ipcso,
                                tp->ipcss, tp->ipcse);
                }
            } else {
                /* We are using the virtio-net header: Let's fill it. */
                s->iov[0].iov_base = hdr = s->tx_hdr + s->mac_reg[TDH];
                s->iov[0].iov_len = sizeof(struct virtio_net_hdr);

                if (tp->sum_needed & E1000_TXD_POPTS_TXSM) {
                    hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
                    hdr->csum_start = tp->tucss;
                    hdr->csum_offset = tp->tucso - tp->tucss;
                } else {
                    hdr->flags = 0;
                    hdr->csum_start = 0;
                    hdr->csum_offset = 0;
                }
                if (tp->tse && tp->cptse) {
                    hdr->gso_type = tp->ip ? VIRTIO_NET_HDR_GSO_TCPV4 :
                        VIRTIO_NET_HDR_GSO_TCPV6;
                    hdr->gso_size = tp->mss;
                    hdr->hdr_len = tp->hdr_len;
                } else {
                    hdr->gso_type = VIRTIO_NET_HDR_GSO_NONE;
                    hdr->gso_size = 0;
                    hdr->hdr_len = 0;
                }
            }
            e1000_sendv_packet(s);
            len = s->iovsize;

            goto stats;
        }
    }
#endif	/* !CONFIG_E1000_PARAVIRT */

    if (tp->tse && tp->cptse) {
        css = tp->ipcss;
        DBGOUT(TXSUM, "frames %d size %d ipcss %d\n",
               frames, tp->size, css);
        if (tp->ip) {		// IPv4
            stw_be_p(tp->data+css+2, tp->size - css);
            stw_be_p(tp->data+css+4,
                          be16_to_cpup((uint16_t *)(tp->data+css+4))+frames);
        } else			// IPv6
            stw_be_p(tp->data+css+4, tp->size - css);
        css = tp->tucss;
        len = tp->size - css;
        DBGOUT(TXSUM, "tcp %d tucss %d len %d\n", tp->tcp, css, len);
        if (tp->tcp) {
            sofar = frames * tp->mss;
            stl_be_p(tp->data+css+4, ldl_be_p(tp->data+css+4)+sofar); /* seq */
            if (tp->paylen - sofar > tp->mss)
                tp->data[css + 13] &= ~9;		// PSH, FIN
        } else	// UDP
            stw_be_p(tp->data+css+4, len);
        if (tp->sum_needed & E1000_TXD_POPTS_TXSM) {
            unsigned int phsum;
            // add pseudo-header length before checksum calculation
            sp = (uint16_t *)(tp->data + tp->tucso);
            phsum = be16_to_cpup(sp) + len;
            phsum = (phsum >> 16) + (phsum & 0xffff);
            stw_be_p(sp, phsum);
        }
        tp->tso_frames++;
    }

    len = tp->size;
    buf = tp->data;
    if (tp->sum_needed & E1000_TXD_POPTS_TXSM)
	putsum(tp->data, tp->size, tp->tucso, tp->tucss, tp->tucse);
    if (tp->sum_needed & E1000_TXD_POPTS_IXSM)
	putsum(tp->data, tp->size, tp->ipcso, tp->ipcss, tp->ipcse);
    if (tp->vlan_needed) {
	memmove(tp->vlan, tp->data, 4);
	memmove(tp->data, tp->data + 4, 8);
	memcpy(tp->data + 8, tp->vlan_header, 4);
	buf = tp->vlan;
	len = tp->size + 4;
    }
    e1000_send_packet(s, buf, len);
#ifdef CONFIG_E1000_PARAVIRT
stats:
#endif	/* CONFIG_E1000_PARAVIRT */
    s->mac_reg[TPT]++;
    s->mac_reg[GPTC]++;
    n = s->mac_reg[TOTL];
    if ((s->mac_reg[TOTL] += len) < n)
        s->mac_reg[TOTH]++;
}

static void
process_tx_desc(E1000State *s, struct e1000_tx_desc *dp)
{
    PCIDevice *d = PCI_DEVICE(s);
    uint32_t txd_lower = le32_to_cpu(dp->lower.data);
    uint32_t dtype = txd_lower & (E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D);
    unsigned int split_size = txd_lower & 0xffff, bytes, sz, op;
    unsigned int msh = 0xfffff;
    uint64_t addr;
    struct e1000_context_desc *xp = (struct e1000_context_desc *)dp;
    struct e1000_tx *tp = &s->tx;

    s->mit_ide |= (txd_lower & E1000_TXD_CMD_IDE);
    if (dtype == E1000_TXD_CMD_DEXT) {	// context descriptor
        op = le32_to_cpu(xp->cmd_and_length);
        tp->ipcss = xp->lower_setup.ip_fields.ipcss;
        tp->ipcso = xp->lower_setup.ip_fields.ipcso;
        tp->ipcse = le16_to_cpu(xp->lower_setup.ip_fields.ipcse);
        tp->tucss = xp->upper_setup.tcp_fields.tucss;
        tp->tucso = xp->upper_setup.tcp_fields.tucso;
        tp->tucse = le16_to_cpu(xp->upper_setup.tcp_fields.tucse);
        tp->paylen = op & 0xfffff;
        tp->hdr_len = xp->tcp_seg_setup.fields.hdr_len;
        tp->mss = le16_to_cpu(xp->tcp_seg_setup.fields.mss);
        tp->ip = (op & E1000_TXD_CMD_IP) ? 1 : 0;
        tp->tcp = (op & E1000_TXD_CMD_TCP) ? 1 : 0;
        tp->tse = (op & E1000_TXD_CMD_TSE) ? 1 : 0;
        tp->tso_frames = 0;
        if (tp->tucso == 0) {	// this is probably wrong
            DBGOUT(TXSUM, "TCP/UDP: cso 0!\n");
            tp->tucso = tp->tucss + (tp->tcp ? 16 : 6);
        }
        return;
    } else if (dtype == (E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D)) {
        // data descriptor
        if (tp->size == 0) {
            tp->sum_needed = le32_to_cpu(dp->upper.data) >> 8;
        }
        tp->cptse = ( txd_lower & E1000_TXD_CMD_TSE ) ? 1 : 0;
    } else {
        // legacy descriptor
        tp->cptse = 0;
    }

    /* TODO support VLAN. */
    if (vlan_enabled(s) && is_vlan_txd(txd_lower) &&
        (tp->cptse || txd_lower & E1000_TXD_CMD_EOP)) {
        tp->vlan_needed = 1;
        stw_be_p(tp->vlan_header,
                      le16_to_cpup((uint16_t *)(s->mac_reg + VET)));
        stw_be_p(tp->vlan_header + 2,
                      le16_to_cpu(dp->upper.fields.special));
    }

    addr = le64_to_cpu(dp->buffer_addr);

#ifdef CONFIG_E1000_PARAVIRT
    if (s->csb && s->csb->guest_csb_on &&
	    (s->guest_hdr_ofs || !(tp->tse && tp->cptse))) {
	uint8_t *buf;

	buf = translate_guest_paddr(s, addr, split_size);
	if (!buf) {
	    D("SG mapping failed! (still not handled)\n");
	    exit(-1);
	}
	s->iov[s->iovcnt].iov_base = buf;
	s->iov[s->iovcnt].iov_len = split_size;
	s->iovcnt++;
	if (unlikely(s->iovcnt == E1000_MAX_FRAGS)) {
	    s->iovcnt = s->host_hdr_ofs;
	    s->iovsize = 0;
	    goto reset;
	}
	s->iovsize += split_size;
	tp->size += split_size;  /* For code that depends on tp->size. */

	if (!(txd_lower & E1000_TXD_CMD_EOP))
	    return;

	xmit_seg(s);

	goto reset;
    }
#endif	/* CONFIG_E1000_PARAVIRT */
    if (tp->tse && tp->cptse) {
        msh = tp->hdr_len + tp->mss;
        do {
            bytes = split_size;
            if (tp->size + bytes > msh)
                bytes = msh - tp->size;

            bytes = MIN(sizeof(tp->data) - tp->size, bytes);
            pci_dma_read(d, addr, tp->data + tp->size, bytes);
            sz = tp->size + bytes;
            if (sz >= tp->hdr_len && tp->size < tp->hdr_len) {
                memmove(tp->header, tp->data, tp->hdr_len);
            }
            tp->size = sz;
            addr += bytes;
            if (sz == msh) {
                xmit_seg(s);
                memmove(tp->data, tp->header, tp->hdr_len);
                tp->size = tp->hdr_len;
            }
        } while (split_size -= bytes);
    } else if (!tp->tse && tp->cptse) {
	// context descriptor TSE is not set, while data descriptor TSE is set
	DBGOUT(TXERR, "TCP segmentation error\n");
    } else {
        split_size = MIN(sizeof(tp->data) - tp->size, split_size);
        pci_dma_read(d, addr, tp->data + tp->size, split_size);
        tp->size += split_size;
    }

    if (!(txd_lower & E1000_TXD_CMD_EOP))
        return;
    if (!(tp->tse && tp->cptse && tp->size < tp->hdr_len)) {
        xmit_seg(s);
    }
#ifdef CONFIG_E1000_PARAVIRT
reset:
#endif	/* CONFIG_E1000_PARAVIRT */
    tp->tso_frames = 0;
    tp->sum_needed = 0;
    tp->vlan_needed = 0;
    tp->size = 0;
    tp->cptse = 0;
}

static uint32_t
txdesc_writeback(E1000State *s, dma_addr_t base, struct e1000_tx_desc *dp)
{
    uint32_t txd_upper, txd_lower = le32_to_cpu(dp->lower.data);

    if (!(txd_lower & (E1000_TXD_CMD_RS|E1000_TXD_CMD_RPS)))
        return 0;
    txd_upper = (le32_to_cpu(dp->upper.data) | E1000_TXD_STAT_DD) &
                ~(E1000_TXD_STAT_EC | E1000_TXD_STAT_LC | E1000_TXD_STAT_TU);
    dp->upper.data = cpu_to_le32(txd_upper);
#ifdef CONFIG_E1000_PARAVIRT
    s->txring[s->sync_tdh].upper = dp->upper;
#else /* !CONFIG_E1000_PARAVIRT */
    pci_dma_write(PCI_DEVICE(s), base + ((char *)&dp->upper - (char *)dp),
                  &dp->upper, sizeof(dp->upper));
#endif /* !CONFIG_E1000_PARAVIRT */
    return E1000_ICR_TXDW;
}

static uint64_t tx_desc_base(E1000State *s)
{
    uint64_t bah = s->mac_reg[TDBAH];
    uint64_t bal = s->mac_reg[TDBAL] & ~0xf;

    return (bah << 32) + bal;
}

static void
start_xmit(E1000State *s)
{
    dma_addr_t base;
    struct e1000_tx_desc desc;
    uint32_t tdh_start = s->mac_reg[TDH], cause = 0;

    if (!(s->mac_reg[TCTL] & E1000_TCTL_EN)) {
        DBGOUT(TX, "tx disabled\n");
        return;
    }

#ifdef CONFIG_E1000_PARAVIRT
    /* hlim prevents staying here for too long */
    uint32_t hlim = s->mac_reg[TDLEN] / sizeof(desc) / 2;
    uint32_t csb_mode = s->csb && s->csb->guest_csb_on;

    for (;;) {
        if (csb_mode) {
            if (s->mac_reg[TDH] == s->mac_reg[TDT]) {
                /* we ran dry, exchange some notifications */
                smp_mb(); /* read from guest ? */
                s->mac_reg[TDT] = s->csb->guest_tdt;
                tdh_start = s->mac_reg[TDH];
            }
            if (s->tx_count > hlim || s->mac_reg[TDH] == s->mac_reg[TDT]) {
                /* still dry, we are done */
                break;
            }
        } else if (s->mac_reg[TDH] == s->mac_reg[TDT]) {
            break;
        }
        s->tx_count++;
#else /* !CONFIG_E1000_PARAVIRT */
    while (s->mac_reg[TDH] != s->mac_reg[TDT]) {
#endif /* CONFIG_E1000_PARAVIRT */
#ifdef CONFIG_E1000_PARAVIRT
        base = 0;
        desc = s->txring[s->mac_reg[TDH]];
#else /* !CONFIG_E1000_PARAVIRT */
        base = tx_desc_base(s) +
               sizeof(struct e1000_tx_desc) * s->mac_reg[TDH];
        pci_dma_read(PCI_DEVICE(s), base, &desc, sizeof(desc));
#endif /* CONFIG_E1000_PARAVIRT */

        DBGOUT(TX, "index %d: %p : %x %x\n", s->mac_reg[TDH],
               (void *)(intptr_t)desc.buffer_addr, desc.lower.data,
               desc.upper.data);

	s->next_tdh = s->mac_reg[TDH];
        if (++s->next_tdh * sizeof(desc) >= s->mac_reg[TDLEN])
            s->next_tdh = 0;

        process_tx_desc(s, &desc);
	if (!s->peer_async) {
	    /* If the network backend is synchronous w.r.t. transmission,
	       we do the descriptor writeback now and update s->sync_tdh
	       (exposed to the guest). Otherwise these operations will
	       be done by e1000_peer_async_callback(). */
	    cause |= txdesc_writeback(s, base, &desc);
	    s->sync_tdh = s->next_tdh;
#ifdef CONFIG_E1000_PARAVIRT
	    if (csb_mode) {
		s->csb->host_tdh = s->next_tdh;
	    }
#endif /* CONFIG_E1000_PARAVIRT */
	}
	s->mac_reg[TDH] = s->next_tdh;

        /*
         * the following could happen only if guest sw assigns
         * bogus values to TDT/TDLEN.
         * there's nothing too intelligent we could do about this.
         */
        if (s->mac_reg[TDH] == tdh_start) {
            DBGOUT(TXERR, "TDH wraparound @%x, TDT %x, TDLEN %x\n",
                   tdh_start, s->mac_reg[TDT], s->mac_reg[TDLEN]);
            break;
        }
    }
    set_ics(s, 0, cause | E1000_ICS_TXQE);
}

static void e1000_peer_async_callback(void *opaque)
{
    E1000State *s = opaque;
    uint32_t cause = 0;
    struct e1000_tx_desc desc;
    dma_addr_t base = 0;

    while (s->sync_tdh != s->next_tdh) {
#ifdef CONFIG_E1000_PARAVIRT
        desc = s->txring[s->sync_tdh];
#else /* !CONFIG_E1000_PARAVIRT */
        base = tx_desc_base(s) + sizeof(struct e1000_tx_desc) * s->sync_tdh;
        pci_dma_read(PCI_DEVICE(s), base, &desc, sizeof(desc));
#endif /* CONFIG_E1000_PARAVIRT */
	cause |= txdesc_writeback(s, base, &desc);
        if (++s->sync_tdh * sizeof(desc) >= s->mac_reg[TDLEN])
            s->sync_tdh = 0;
    }
    ND("sync_tdh %d, TDH %d, TDT %d\n", s->sync_tdh, s->mac_reg[TDH], s->mac_reg[TDT]);
#ifdef CONFIG_E1000_PARAVIRT
    if (s->csb && s->csb->guest_csb_on) {
	s->csb->host_tdh = s->next_tdh;
    }
#endif	/* CONFIG_E1000_PARAVIRT */
    if (s->next_tdh == s->mac_reg[TDT])
	cause |= E1000_ICS_TXQE;
    set_ics(s, 0, cause);
}

static int
receive_filter(E1000State *s, const uint8_t *buf, int size)
{
    static const uint8_t bcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    static const int mta_shift[] = {4, 3, 2, 0};
    uint32_t f, rctl = s->mac_reg[RCTL], ra[2], *rp;

    if (is_vlan_packet(s, buf) && vlan_rx_filter_enabled(s)) {
        uint16_t vid = be16_to_cpup((uint16_t *)(buf + 14));
        uint32_t vfta = le32_to_cpup((uint32_t *)(s->mac_reg + VFTA) +
                                     ((vid >> 5) & 0x7f));
        if ((vfta & (1 << (vid & 0x1f))) == 0)
            return 0;
    }

    if (rctl & E1000_RCTL_UPE)			// promiscuous
        return 1;

    if ((buf[0] & 1) && (rctl & E1000_RCTL_MPE))	// promiscuous mcast
        return 1;

    if ((rctl & E1000_RCTL_BAM) && !memcmp(buf, bcast, sizeof bcast))
        return 1;

    for (rp = s->mac_reg + RA; rp < s->mac_reg + RA + 32; rp += 2) {
        if (!(rp[1] & E1000_RAH_AV))
            continue;
        ra[0] = cpu_to_le32(rp[0]);
        ra[1] = cpu_to_le32(rp[1]);
        if (!memcmp(buf, (uint8_t *)ra, 6)) {
            DBGOUT(RXFILTER,
                   "unicast match[%d]: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   (int)(rp - s->mac_reg - RA)/2,
                   buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
            return 1;
        }
    }
    DBGOUT(RXFILTER, "unicast mismatch: %02x:%02x:%02x:%02x:%02x:%02x\n",
           buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);

    f = mta_shift[(rctl >> E1000_RCTL_MO_SHIFT) & 3];
    f = (((buf[5] << 8) | buf[4]) >> f) & 0xfff;
    if (s->mac_reg[MTA + (f >> 5)] & (1 << (f & 0x1f)))
        return 1;
    DBGOUT(RXFILTER,
           "dropping, inexact filter mismatch: %02x:%02x:%02x:%02x:%02x:%02x MO %d MTA[%d] %x\n",
           buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
           (rctl >> E1000_RCTL_MO_SHIFT) & 3, f >> 5,
           s->mac_reg[MTA + (f >> 5)]);

    return 0;
}

static void
e1000_set_link_status(NetClientState *nc)
{
    E1000State *s = qemu_get_nic_opaque(nc);
    uint32_t old_status = s->mac_reg[STATUS];

    if (nc->link_down) {
        e1000_link_down(s);
    } else {
        e1000_link_up(s);
    }

    if (s->mac_reg[STATUS] != old_status)
        set_ics(s, 0, E1000_ICR_LSC);
}

static bool e1000_has_rxbufs(E1000State *s, size_t total_size)
{
#ifdef CONFIG_E1000_PARAVIRT
    /*
     * called by set_rdt(), e1000_can_receive(), e1000_receive().
     * If using the csb:
     * - update the RDT value from there.
     * - if there is space, clear csb->host_rxkick_at to
     *   disable further kicks. This is needed mostly in
     *   e1000_set_rdt(), and to clear the flag in the double check.
     *   Otherwise, set csb->host_rxkick_at and do the double check,
     *   possibly clearing the variable if we were wrong.
     */
#define AVAIL_RXBUFS(s) (((((s)->mac_reg[RDT] < (s)->mac_reg[RDH]) ? (s)->rxbufs : 0) + (s)->mac_reg[RDT]) -(s)->mac_reg[RDH])
    struct paravirt_csb *csb = s->csb && s->csb->guest_csb_on ? s->csb : NULL;
    bool rxq_full = (total_size > AVAIL_RXBUFS(s) * s->rxbuf_size);
    int avail;

    if (unlikely(s->v1000)) {
        return true;
    }
    if (csb) {
	if (rxq_full) {
	    /* Reload csb->guest_rdt only when necessary. */
	    smp_mb();
	    s->mac_reg[RDT] = csb->guest_rdt;
	    avail = AVAIL_RXBUFS(s);
	    if ((rxq_full = (total_size > avail * s->rxbuf_size))) {
		csb->host_rxkick_at = (s->mac_reg[RDT] + 1 +
			(s->rxbufs - avail - 1) * 3/4) % s->rxbufs;
		/* Doublecheck for more space to avoid race conditions. */
		smp_mb();
		s->mac_reg[RDT] = csb->guest_rdt;
		rxq_full = (total_size > AVAIL_RXBUFS(s) * s->rxbuf_size);
		if (unlikely(!rxq_full)) {
		    csb->host_rxkick_at = NET_PARAVIRT_NONE;
		}
	    }
	} else if (csb->host_rxkick_at != NET_PARAVIRT_NONE) {
	    /* try to minimize writes, be more cache friendly.
	     * The guest (or the host) might have already
	     * cleared the flag in a previous iteration.
	     */
	    csb->host_rxkick_at = NET_PARAVIRT_NONE;
	}
    }
    return !rxq_full;
#else /* !CONFIG_E1000_PARAVIRT */
    int bufs;

    /* Fast-path short packets */
    if (total_size <= s->rxbuf_size) {
        return s->mac_reg[RDH] != s->mac_reg[RDT];
    }
    if (s->mac_reg[RDH] < s->mac_reg[RDT]) {
        bufs = s->mac_reg[RDT] - s->mac_reg[RDH];
    } else if (s->mac_reg[RDH] > s->mac_reg[RDT]) {
        bufs = s->mac_reg[RDLEN] /  sizeof(struct e1000_rx_desc) +
            s->mac_reg[RDT] - s->mac_reg[RDH];
    } else {
        return false;
    }
    return total_size <= bufs * s->rxbuf_size;
#endif /* !CONFIG_E1000_PARAVIRT */
}

static int
e1000_can_receive(NetClientState *nc)
{
    E1000State *s = qemu_get_nic_opaque(nc);

    return (s->mac_reg[STATUS] & E1000_STATUS_LU) &&
        (s->mac_reg[RCTL] & E1000_RCTL_EN) && e1000_has_rxbufs(s, 1);
}

static uint64_t rx_desc_base(E1000State *s)
{
    uint64_t bah = s->mac_reg[RDBAH];
    uint64_t bal = s->mac_reg[RDBAL] & ~0xf;

    return (bah << 32) + bal;
}

static ssize_t
e1000_receive_iov_flags(NetClientState *nc, const struct iovec *iov, int iovcnt,
                        unsigned flags)
{
    E1000State *s = qemu_get_nic_opaque(nc);
    PCIDevice *d = PCI_DEVICE(s);
    struct e1000_rx_desc desc;
    dma_addr_t base;
    unsigned int n, rdt;
    uint32_t rdh_start;
    uint16_t vlan_special = 0;
    uint8_t vlan_status = 0;
    uint8_t min_buf[MIN_BUF_SIZE];
    struct iovec min_iov;
    uint8_t *filter_buf = iov->iov_base;
    size_t size = iov_size(iov, iovcnt);
    size_t iov_ofs = 0;
    size_t desc_offset;
    size_t desc_size;
    size_t total_size;
#ifdef CONFIG_E1000_PARAVIRT
    uint32_t csb_mode = s->csb && s->csb->guest_csb_on;
    uint8_t *guest_buf;
    const struct iovec * vnet_iov = iov;
    int vnet_iovcnt = iovcnt;

    if (s->host_hdr_ofs) {
        iov_skip_bytes(&iov, &iovcnt, &iov_ofs,
                       sizeof(struct virtio_net_hdr));
	size -= sizeof(struct virtio_net_hdr);
        filter_buf = iov->iov_base + iov_ofs;
    }
#endif

    if (!(s->mac_reg[STATUS] & E1000_STATUS_LU)) {
        return -1;
    }

    if (!(s->mac_reg[RCTL] & E1000_RCTL_EN)) {
        return -1;
    }

    /* Pad to minimum Ethernet frame length */
    if (size < sizeof(min_buf)) {
        iov_to_buf(iov, iovcnt, iov_ofs, min_buf, size);
        memset(&min_buf[size], 0, sizeof(min_buf) - size);
        min_iov.iov_base = filter_buf = min_buf;
        min_iov.iov_len = size = sizeof(min_buf);
        iovcnt = 1;
        iov_ofs = 0;
        iov = &min_iov;
    } else if (iov->iov_len - iov_ofs < MAXIMUM_ETHERNET_HDR_LEN) {
        /* This is very unlikely, but may happen. */
        iov_to_buf(iov, iovcnt, iov_ofs, min_buf, MAXIMUM_ETHERNET_HDR_LEN);
        filter_buf = min_buf;
    }

#ifndef CONFIG_E1000_PARAVIRT
    /* Discard oversized packets if !LPE and !SBP. */
    if ((size > MAXIMUM_ETHERNET_LPE_SIZE ||
        (size > MAXIMUM_ETHERNET_VLAN_SIZE
        && !(s->mac_reg[RCTL] & E1000_RCTL_LPE)))
        && !(s->mac_reg[RCTL] & E1000_RCTL_SBP)) {
        return size;
    }
#endif

    if (!receive_filter(s, filter_buf, size)) {
        return size;
    }

    if (vlan_enabled(s) && is_vlan_packet(s, filter_buf)) {
        vlan_special = cpu_to_le16(be16_to_cpup((uint16_t *)(filter_buf
                                                                + 14)));
        //iov_ofs = 4; XXX remove
        if (filter_buf == iov->iov_base + iov_ofs) {
            memmove(filter_buf + 4, filter_buf, 12);
        } else {
            iov_from_buf(iov, iovcnt, 4, filter_buf, 12); //XXX offset
            iov_skip_bytes(&iov, &iovcnt, &iov_ofs, 4);
        }
        vlan_status = E1000_RXD_STAT_VP;
        size -= 4;
    }

    rdh_start = s->mac_reg[RDH];
    desc_offset = 0;
    total_size = size + fcs_len(s);
    if (!e1000_has_rxbufs(s, total_size)) {
            set_ics(s, 0, E1000_ICS_RXO);
            return -1;
    }
    IFRATE(rate_rx++; rate_rxb += size);
#ifdef CONFIG_E1000_PARAVIRT
    if (csb_mode) {
	/* Fills in the vnet header at the same index of the first RX
	   descriptor used for the received frame. */
        if (s->guest_hdr_ofs) {
            iov_to_buf(vnet_iov, vnet_iovcnt, 0*base,
                        &s->vnet_hdr[s->mac_reg[RDH]],
                        sizeof(struct virtio_net_hdr));
        }
    }
#endif /* CONFIG_E1000_PARAVIRT */
    do {
        desc_size = total_size - desc_offset;
        if (desc_size > s->rxbuf_size) {
            desc_size = s->rxbuf_size;
        }
#ifdef CONFIG_E1000_PARAVIRT
        desc = s->rxring[s->mac_reg[RDH]];
#else /* !CONFIG_E1000_PARAVIRT */
        base = rx_desc_base(s) + sizeof(desc) * s->mac_reg[RDH];
        pci_dma_read(d, base, &desc, sizeof(desc));
#endif /* !CONFIG_E1000_PARAVIRT */
        desc.special = vlan_special;
        desc.status |= (vlan_status | E1000_RXD_STAT_DD);
        if (desc.buffer_addr) {
            if (desc_offset < size) {
                size_t iov_copy;
                hwaddr ba = le64_to_cpu(desc.buffer_addr);
                size_t copy_size = size - desc_offset;
                if (copy_size > s->rxbuf_size) {
                    copy_size = s->rxbuf_size;
                }
#ifdef CONFIG_E1000_PARAVIRT
                guest_buf = translate_guest_paddr(s, ba, copy_size);
#endif /* CONFIG_E1000_PARAVIRT */
                do {
                    iov_copy = MIN(copy_size, iov->iov_len - iov_ofs);
#ifdef CONFIG_E1000_PARAVIRT
                    if (guest_buf) {
                        memcpy(guest_buf, iov->iov_base + iov_ofs, iov_copy);
                        guest_buf += iov_copy;
                    } else {
                        pci_dma_write(d, ba, iov->iov_base + iov_ofs,
                                      iov_copy);
                    }
#else  /* !CONFIG_E1000_PARAVIRT */
                    pci_dma_write(d, ba, iov->iov_base + iov_ofs, iov_copy);
#endif /* !CONFIG_E1000_PARAVIRT */
                    copy_size -= iov_copy;
                    ba += iov_copy;
                    iov_ofs += iov_copy;
                    if (iov_ofs == iov->iov_len) {
                        iov++;
                        iov_ofs = 0;
                    }
                } while (copy_size);
            }
            desc_offset += desc_size;
            desc.length = cpu_to_le16(desc_size);
            if (desc_offset >= total_size) {
                desc.status |= E1000_RXD_STAT_EOP | E1000_RXD_STAT_IXSM;
            } else {
                /* Guest zeroing out status is not a hardware requirement.
                   Clear EOP in case guest didn't do it. */
                desc.status &= ~E1000_RXD_STAT_EOP;
            }
        } else { // as per intel docs; skip descriptors with null buf addr
            DBGOUT(RX, "Null RX descriptor!!\n");
        }
#ifdef CONFIG_E1000_PARAVIRT
        s->rxring[s->mac_reg[RDH]] = desc;
        /* XXX a barrier ? */
#else
        pci_dma_write(d, base, &desc, sizeof(desc));
#endif /* !CONFIG_E1000_PARAVIRT */

        if (++s->mac_reg[RDH] * sizeof(desc) >= s->mac_reg[RDLEN])
            s->mac_reg[RDH] = 0;
#ifdef CONFIG_E1000_PARAVIRT
	if (csb_mode) {
	    s->csb->host_rdh = s->mac_reg[RDH];
	}
#endif /* CONFIG_E1000_PARAVIRT */
        /* see comment in start_xmit; same here */
        if (s->mac_reg[RDH] == rdh_start) {
            DBGOUT(RXERR, "RDH wraparound @%x, RDT %x, RDLEN %x\n",
                   rdh_start, s->mac_reg[RDT], s->mac_reg[RDLEN]);
            set_ics(s, 0, E1000_ICS_RXO);
            return -1;
        }
    } while (desc_offset < total_size);

    s->mac_reg[GPRC]++;
    s->mac_reg[TPR]++;
    /* TOR - Total Octets Received:
     * This register includes bytes received in a packet from the <Destination
     * Address> field through the <CRC> field, inclusively.
     */
    n = s->mac_reg[TORL] + size + /* Always include FCS length. */ 4;
    if (n < s->mac_reg[TORL])
        s->mac_reg[TORH]++;
    s->mac_reg[TORL] = n;

    n = E1000_ICS_RXT0;
    if ((rdt = s->mac_reg[RDT]) < s->mac_reg[RDH])
        rdt += s->mac_reg[RDLEN] / sizeof(desc);
    if (((rdt - s->mac_reg[RDH]) * sizeof(desc)) <= s->mac_reg[RDLEN] >>
        s->rxbuf_min_shift)
        n |= E1000_ICS_RXDMT0;

    s->rx_count++;
    if (!(flags & QEMU_NET_PACKET_FLAG_MORE) ||
            s->rx_count == s->mac_reg[RDLEN] / sizeof(desc)) {
        s->rx_count = 50;
        set_ics(s, 0, n);
    }

    return size;
}

static ssize_t
e1000_receive_iov(NetClientState *nc, const struct iovec *iov, int iovcnt)
{
    return e1000_receive_iov_flags(nc, iov, iovcnt, 0);
}

static ssize_t
e1000_receive(NetClientState *nc, const uint8_t *buf, size_t size)
{
    const struct iovec iov = {
        .iov_base = (uint8_t *)buf,
        .iov_len = size
    };

    return e1000_receive_iov_flags(nc, &iov, 1, 0);
}

static uint32_t
mac_readreg(E1000State *s, int index)
{
    return s->mac_reg[index];
}

static uint32_t
mac_icr_read(E1000State *s, int index)
{
    uint32_t ret = s->mac_reg[ICR];

    DBGOUT(INTERRUPT, "ICR read: %x\n", ret);
    set_interrupt_cause(s, 0, 0);
    IFRATE(rate_ntfy_ic++);
    return ret;
}

static uint32_t
mac_read_clr4(E1000State *s, int index)
{
    uint32_t ret = s->mac_reg[index];

    s->mac_reg[index] = 0;
    return ret;
}

static uint32_t
mac_read_clr8(E1000State *s, int index)
{
    uint32_t ret = s->mac_reg[index];

    s->mac_reg[index] = 0;
    s->mac_reg[index-1] = 0;
    return ret;
}

static void
mac_writereg(E1000State *s, int index, uint32_t val)
{
    uint32_t macaddr[2];

    s->mac_reg[index] = val;

    if (index == RA + 1) {
        macaddr[0] = cpu_to_le32(s->mac_reg[RA]);
        macaddr[1] = cpu_to_le32(s->mac_reg[RA + 1]);
        qemu_format_nic_info_str(qemu_get_queue(s->nic), (uint8_t *)macaddr);
    }
}


#ifdef CONFIG_E1000_PARAVIRT
static void
e1000_tx_bh(void *opaque)
{
    E1000State *s = opaque;
    struct paravirt_csb *csb = s->csb;

    if (!csb) {
	D("This is not happening!!");
	start_xmit(s);
	return;
    }

    ND("starting tdt %d sent %d in prev.round ", csb->guest_tdt, s->tx_count);
    s->mac_reg[TDT] = csb->guest_tdt;
    s->tx_count = 0;
    start_xmit(s);
    IFRATE(rate_tx_bh_count++);
    s->txcycles = (s->tx_count > 0) ? 0 : s->txcycles+1;
    if (s->txcycles >= s->txcycles_lim) {
        /* prepare to sleep, with race avoidance */
        s->txcycles = 0;
        csb->host_need_txkick = 1;
	ND("tx bh going to sleep, set txkick");
        smp_mb();
        s->mac_reg[TDT] = csb->guest_tdt;
        if (s->mac_reg[TDH] != s->mac_reg[TDT]) {
	    ND("tx bh race avoidance, clear txkick");
            csb->host_need_txkick = 0;
        }
    }
    if (csb->host_need_txkick == 0) {
        qemu_bh_schedule(s->tx_bh);
    }
}

static void
e1000_ioeventfd_handler(EventNotifier * e)
{
    E1000State *s = container_of(e, E1000State, host_tx_notifier);

    if (event_notifier_test_and_clear(e)) {
	if (!(s->csb && s->csb->guest_csb_on)) {
	    /* This happens once when calling event_notifier_init(..., 1)
	       instead of event_notifier_init(..., 0). */
	    return;
	}

	s->mac_reg[TDT] &= s->csb->guest_tdt & 0xffff;
	IFRATE(rate_ntfy_tx++);
	s->csb->host_need_txkick = 0; /* XXX could be done by the guest */
	smp_mb(); /* XXX do we care ? */
	e1000_tx_bh(s);
    }
}

static int e1000_tx_ioeventfd_up(E1000State *s)
{
    if (!s->ioeventfd && !s->v1000)
        return 0;

    if (event_notifier_init(&s->host_tx_notifier, 0)) {
        printf("event_notifier_init() error\n");
        s->ioeventfd = false;
        return -1;
    }
    if (s->ioeventfd) {
        if (event_notifier_set_handler(&s->host_tx_notifier,
                    &e1000_ioeventfd_handler)) {
            printf("event_notifier_set_handler() error\n");
            s->ioeventfd = false;
            return -1;
        }
    }
    memory_region_add_eventfd(&s->mmio, TDT << 2, 4, false, 0,
            &s->host_tx_notifier);
    //printf("Host notifier at addr %X\n", TDT << 2);

    return 0;
}

static void e1000_tx_ioeventfd_down(E1000State *s)
{
    if (!s->ioeventfd && !s->v1000)
        return;

    memory_region_del_eventfd(&s->mmio, TDT << 2, 4, false, 0,
            &s->host_tx_notifier);
    event_notifier_set_handler(&s->host_tx_notifier, NULL);
    event_notifier_cleanup(&s->host_tx_notifier);
}

#ifdef V1000
static int e1000_v1000_up(E1000State *s)
{
    PCIDevice *d = PCI_DEVICE(s);
    AddressSpace *as = pci_get_address_space(d);
    MSIMessage msg;
    hwaddr offset, length;
    uint8_t * vaddr;
    int ret;
    int i;

    if (!s->v1000) {
        return 0;
    }

    if ((s->v1000_fd = open("/dev/v1000", O_RDWR)) < 0) {
        printf("Cannot open '/dev/v1000'\n");
        return -1;
    }

    /* Load the translation table. */
    i = 0;
    while ((ret = ram_block_get(i, &offset, &length, &vaddr)) == 0) {
        s->cfg.tr.table[i].phy = offset;
        s->cfg.tr.table[i].length = length;
        s->cfg.tr.table[i].virt = vaddr;
        i++;
    }
    if (ret < 0) {
        printf("ram_block_get() failed!\n");
        return -1;
    }
    s->cfg.tr.num = i;

    /* Create an eventfd to use as an irqfd and configure it. */
    if (event_notifier_init(&s->guest_notifier, 0)) {
        printf("Error: event_notifier_init()\n");
        s->v1000 = false;
        return -1;
    }
    msg = msix_get_message(d, E1000_MSIX_DATA_VECTOR);
    if ((s->virq = kvm_irqchip_add_msi_route(kvm_state, msg)) < 0) {
        printf("Error: kvm_irqchip_add_msi_route(): %d\n", -s->virq);
        return -s->virq;
    }
    if (kvm_irqchip_add_irqfd_notifier(kvm_state, &s->guest_notifier,
                NULL, s->virq)) {
        printf("Error: kvm_irqchip_add_irqfd()\n");
        s->v1000 = false;
        return -1;
    }

    /* Create an eventfd to use as rx ioeventfd and
       bind it to the RDT register writes. */
    if (event_notifier_init(&s->host_rx_notifier, 0)) {
        printf("event_notifier_init() error\n");
        s->v1000 = false;
        return -1;
    }
    memory_region_add_eventfd(&s->mmio, RDT << 2, 4, false, 0,
            &s->host_rx_notifier);

    /* Configure the RX ring. */
    s->cfg.rx_ring.phy = rx_desc_base(s);
    s->cfg.rx_ring.hdr.phy = ((hwaddr)s->csb->vnet_ring_high << 32) | s->csb->vnet_ring_low;
    s->cfg.rx_ring.num = s->mac_reg[RDLEN] / sizeof(struct e1000_rx_desc);
    s->cfg.rx_ring.ioeventfd = event_notifier_get_fd(&s->host_rx_notifier);
    s->cfg.rx_ring.irqfd = event_notifier_get_fd(&s->guest_notifier);
    s->cfg.rx_ring.resamplefd = ~0U;

    /* Configure the TX ring. */
    s->cfg.tx_ring.phy = tx_desc_base(s);
    s->cfg.tx_ring.hdr.virt = s->tx_hdr;
    s->cfg.tx_ring.num = s->mac_reg[TDLEN] / sizeof(struct e1000_tx_desc);
    s->cfg.tx_ring.ioeventfd = event_notifier_get_fd(&s->host_tx_notifier);
    s->cfg.tx_ring.irqfd = event_notifier_get_fd(&s->guest_notifier);
    s->cfg.tx_ring.resamplefd = ~0U;

    /* Configure the net backend. */
    s->nic->ncs->peer->info->poll(s->nic->ncs->peer, false);
    s->cfg.tapfd = qemu_peer_get_fd(s->nic->ncs);

    s->cfg.rxbuf_size = s->rxbuf_size;
    s->cfg.csb_phy = ((hwaddr)s->mac_reg[CSBAH] << 32)
        | s->mac_reg[CSBAL];

    length = 4096;
    printf("csb_phy = %lu, %p\n", s->cfg.csb_phy, address_space_map(as, s->cfg.csb_phy, &length, 1));
    length = s->cfg.tx_ring.num * sizeof(struct e1000_tx_desc);
    printf("tx_ring.phy = %lu, %p\n", s->cfg.tx_ring.phy, address_space_map(as, s->cfg.tx_ring.phy, &length, 1));
    length = s->cfg.rx_ring.num * sizeof(struct e1000_rx_desc);
    printf("rx_ring.phy = %lu, %p\n", s->cfg.rx_ring.phy, address_space_map(as, s->cfg.rx_ring.phy, &length, 1));
    length = s->cfg.rx_ring.num * sizeof(struct virtio_net_hdr);
    printf("rx_ring.hdr.phy = %lu, %p\n", s->cfg.rx_ring.hdr.phy, address_space_map(as, s->cfg.rx_ring.hdr.phy, &length, 1));
    printf("tx_hdr = %p\n", s->cfg.tx_ring.hdr.virt);

    /* Configure the v1000 device instance. */
    i = write(s->v1000_fd, &s->cfg, sizeof(s->cfg));
    if (i != sizeof(s->cfg)) {
        printf("v1000 configuration error(%d).\n", i);
        return -1;
    }

    return 0;
}

static int e1000_v1000_down(E1000State *s)
{
    if (s->v1000) {
        memory_region_del_eventfd(&s->mmio, RDT << 2, 4, false, 0,
                &s->host_rx_notifier);
        event_notifier_cleanup(&s->host_rx_notifier);

        if (kvm_irqchip_remove_irqfd_notifier(kvm_state, &s->guest_notifier,
                    s->virq)) {
            printf("Error: kvm_irqchip_remove_irqfd_notifier()\n");
            s->v1000 = false;
            return -1;
        }
        //XXX kvm_irqchip_add_msi_route()
        event_notifier_cleanup(&s->guest_notifier);

        close(s->v1000_fd);
        s->nic->ncs->peer->info->poll(s->nic->ncs->peer, true);
    }
    return 0;
}
#endif /* V1000 */

static void
set_32bit(E1000State *s, int index, uint32_t val)
{
    PCIDevice *d = PCI_DEVICE(s);

    s->mac_reg[index] = val;
    if (index == CSBAL) {
	hwaddr vnet_hdr_phi;
	hwaddr len;

	paravirt_configure_csb(&s->csb, s->mac_reg[CSBAL], s->mac_reg[CSBAH],
				s->tx_bh, pci_get_address_space(d));
	if (s->csb) {
            /* Post-allocation configuration. */
	    s->txcycles_lim = s->csb->host_txcycles_lim;
	    s->txcycles = 0;
            s->msix = !!s->csb->guest_use_msix;
            D("Using MSI-X = %d\n", s->msix);

	    if (peer_has_vnet_hdr(s)) {
		qemu_set_vnet_hdr_len(s->nic->ncs->peer, sizeof(struct virtio_net_hdr));
		qemu_using_vnet_hdr(s->nic->ncs->peer, true);
		qemu_set_offload(s->nic->ncs->peer, 1, 1, 1, 1, 1);
		s->host_hdr_ofs = s->guest_hdr_ofs = s->iovcnt = 1;
	    } else {
                s->v1000 = false;
	    }
	    D("Using VNET header = %d\n", s->guest_hdr_ofs);

            /* Map the vnet-header ring. */
            vnet_hdr_phi = ((hwaddr)s->csb->vnet_ring_high << 32) | s->csb->vnet_ring_low;
            len = (s->mac_reg[RDLEN] / sizeof(struct e1000_rx_desc)) * sizeof(struct virtio_net_hdr);
            s->vnet_hdr = address_space_map(pci_get_address_space(d),
                    vnet_hdr_phi, &len, 1 /* is_write */);
            memset(s->vnet_hdr, 0, len);
            D("vnet-header ring mapped, phi = %lu\n", vnet_hdr_phi);

            /* Create an eventfd to use as tx ioeventfd and
               bind it to the TDT register writes. */
            e1000_tx_ioeventfd_up(s);
            D("using ioeventfd = %d\n", s->ioeventfd);
#ifdef V1000
            if (!s->msix)
                /* We support v1000 only when MSI-X interrupts are used,
                   otherwise we would need to use KVM resamplefd: Since
                   it's a bit complicated, simply avoid it. */
                s->v1000 = false;
            if (e1000_v1000_up(s)) {
                printf("Error: Unable to use v1000 accelerator\n");
                exit(EXIT_FAILURE);
            }
            D("Using v1000 = %d\n", s->v1000);
#endif /* V1000 */
	} else {
            /* Post-deallocation unconfiguration. */
#ifdef V1000
            e1000_v1000_down(s);
#endif /* V1000 */
            e1000_tx_ioeventfd_down(s);
            s->msix = false;
            s->guest_hdr_ofs = 0;
            if (s->host_hdr_ofs) {
		qemu_set_offload(s->nic->ncs->peer, 0, 0, 0, 0, 0);
                /* In the past, the backend was asked to use the vnet header, and
                   s->host_hdr_ofs was set. However, we are currently in non-paravirtual mode
                   and so we must push a null header to the backend. Do this only once. */
                s->iov[0].iov_base = &null_tx_hdr;
                s->iov[0].iov_len = sizeof(struct virtio_net_hdr);
            }
        }
    }
}

static void
remap_rings(E1000State *s)
{
    PCIDevice * d = PCI_DEVICE(s);
    hwaddr desclen;

    desclen = s->mac_reg[TDLEN];
    s->txring = address_space_map(pci_get_address_space(d),
            tx_desc_base(s), &desclen, 0 /* is_write */);

    desclen = s->mac_reg[RDLEN];
    s->rxring = address_space_map(pci_get_address_space(d),
            rx_desc_base(s), &desclen, 0 /* is_write */);
}

static void
set_dba(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val;
    remap_rings(s);
}
#endif /* CONFIG_E1000_PARAVIRT */

static void
set_rdt(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val & 0xffff;
    IFRATE(rate_ntfy_rx++);
    if (e1000_has_rxbufs(s, 1)) {
        qemu_flush_queued_packets(qemu_get_queue(s->nic));
    }
}

static void
set_16bit(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val & 0xffff;
    if (index == TDH) {
	s->sync_tdh = s->mac_reg[index];
    }
}

static void
set_dlen(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val & 0xfff80;
#ifdef CONFIG_E1000_PARAVIRT
    s->rxbufs = s->mac_reg[index] / sizeof(struct e1000_rx_desc);
    if (index == TDLEN) {
        if (s->tx_hdr) {
            g_free(s->tx_hdr);
        }
        s->tx_hdr = g_malloc0(s->mac_reg[index] * sizeof(struct virtio_net_hdr)
                                                / sizeof(struct e1000_tx_desc));
    }
    remap_rings(s);
#endif
}

static void
set_tctl(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val;
    s->mac_reg[TDT] &= 0xffff;
    IFRATE(rate_ntfy_tx++);
#ifdef CONFIG_E1000_PARAVIRT
    if (s->csb && s->csb->guest_csb_on) {
	ND("kick accepted tdt %d guest-tdt %d",
		s->mac_reg[TDT], s->csb->guest_tdt);
        s->csb->host_need_txkick = 0; /* XXX could be done by the guest */
        smp_mb(); /* XXX do we care ? */
        qemu_bh_schedule(s->tx_bh);
        return;
    }
#endif /* CONFIG_E1000_PARAVIRT */
    start_xmit(s);
}

static void
set_icr(E1000State *s, int index, uint32_t val)
{
    DBGOUT(INTERRUPT, "set_icr %x\n", val);
    set_interrupt_cause(s, 0, s->mac_reg[ICR] & ~val);
}

static void
set_imc(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[IMS] &= ~val;
    set_ics(s, 0, 0);
}

static void
set_ims(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[IMS] |= val;
    set_ics(s, 0, 0);
}

static uint32_t
rd_tdh(E1000State *s, int index)
{
    return s->sync_tdh;
}

#define getreg(x)	[x] = mac_readreg
static uint32_t (*macreg_readops[])(E1000State *, int) = {
    getreg(PBA),	getreg(RCTL),	[TDH] = rd_tdh,	getreg(TXDCTL),
    getreg(WUFC),	getreg(TDT),	getreg(CTRL),	getreg(LEDCTL),
    getreg(MANC),	getreg(MDIC),	getreg(SWSM),	getreg(STATUS),
    getreg(TORL),	getreg(TOTL),	getreg(IMS),	getreg(TCTL),
    getreg(RDH),	getreg(RDT),	getreg(VET),	getreg(ICS),
    getreg(TDBAL),	getreg(TDBAH),	getreg(RDBAH),	getreg(RDBAL),
    getreg(TDLEN),      getreg(RDLEN),  getreg(RDTR),   getreg(RADV),
    getreg(TADV),       getreg(ITR),
#ifdef CONFIG_E1000_PARAVIRT
    getreg(CSBAL),      getreg(CSBAH),
#endif /* CONFIG_E1000_PARAVIRT */

    [TOTH] = mac_read_clr8,	[TORH] = mac_read_clr8,	[GPRC] = mac_read_clr4,
    [GPTC] = mac_read_clr4,	[TPR] = mac_read_clr4,	[TPT] = mac_read_clr4,
    [ICR] = mac_icr_read,	[EECD] = get_eecd,	[EERD] = flash_eerd_read,
    [CRCERRS ... MPC] = &mac_readreg,
    [RA ... RA+31] = &mac_readreg,
    [MTA ... MTA+127] = &mac_readreg,
    [VFTA ... VFTA+127] = &mac_readreg,
};
enum { NREADOPS = ARRAY_SIZE(macreg_readops) };

#define putreg(x)	[x] = mac_writereg
static void (*macreg_writeops[])(E1000State *, int, uint32_t) = {
    putreg(PBA),	putreg(EERD),	putreg(SWSM),	putreg(WUFC),
#ifdef CONFIG_E1000_PARAVIRT
    [CSBAL] = set_32bit, [CSBAH] = set_32bit, [TDBAL] = set_dba,
    [TDBAH] = set_dba,   [RDBAL] = set_dba,   [RDBAH] = set_dba,
#else
    putreg(TDBAL),	putreg(TDBAH),	putreg(RDBAL),	putreg(RDBAH),
#endif /* CONFIG_E1000_PARAVIRT */
    putreg(TXDCTL),	putreg(LEDCTL), putreg(VET),
    [RDTR] = set_16bit, [RADV] = set_16bit,     [TADV] = set_16bit,
    [ITR] = set_16bit,
    [TDLEN] = set_dlen,	[RDLEN] = set_dlen,	[TCTL] = set_tctl,
    [TDT] = set_tctl,	[MDIC] = set_mdic,	[ICS] = set_ics,
    [TDH] = set_16bit,	[RDH] = set_16bit,	[RDT] = set_rdt,
    [IMC] = set_imc,	[IMS] = set_ims,	[ICR] = set_icr,
    [EECD] = set_eecd,	[RCTL] = set_rx_control, [CTRL] = set_ctrl,
    [RDTR] = set_16bit, [RADV] = set_16bit,     [TADV] = set_16bit,
    [ITR] = set_16bit,
    [RA ... RA+31] = &mac_writereg,
    [MTA ... MTA+127] = &mac_writereg,
    [VFTA ... VFTA+127] = &mac_writereg,
};

enum { NWRITEOPS = ARRAY_SIZE(macreg_writeops) };

static void
e1000_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                 unsigned size)
{
    E1000State *s = opaque;
    unsigned int index = (addr & 0x1ffff) >> 2;

    if (index < NWRITEOPS && macreg_writeops[index]) {
        macreg_writeops[index](s, index, val);
    } else if (index < NREADOPS && macreg_readops[index]) {
        DBGOUT(MMIO, "e1000_mmio_writel RO %x: 0x%04"PRIx64"\n", index<<2, val);
    } else {
        DBGOUT(UNKNOWN, "MMIO unknown write addr=0x%08x,val=0x%08"PRIx64"\n",
               index<<2, val);
    }
    IFRATE(rate_mmio_write++);
}

static uint64_t
e1000_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    E1000State *s = opaque;
    unsigned int index = (addr & 0x1ffff) >> 2;

    IFRATE(rate_mmio_read++);
    if (index < NREADOPS && macreg_readops[index])
    {
        return macreg_readops[index](s, index);
    }
    DBGOUT(UNKNOWN, "MMIO unknown read addr=0x%08x\n", index<<2);
    return 0;
}

static const MemoryRegionOps e1000_mmio_ops = {
    .read = e1000_mmio_read,
    .write = e1000_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static uint64_t e1000_io_read(void *opaque, hwaddr addr,
                              unsigned size)
{
    E1000State *s = opaque;

    (void)s;
    return 0;
}

static void e1000_io_write(void *opaque, hwaddr addr,
                           uint64_t val, unsigned size)
{
    E1000State *s = opaque;

    (void)s;
}

static const MemoryRegionOps e1000_io_ops = {
    .read = e1000_io_read,
    .write = e1000_io_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static bool is_version_1(void *opaque, int version_id)
{
    return version_id == 1;
}

static void e1000_pre_save(void *opaque)
{
    E1000State *s = opaque;
    NetClientState *nc = qemu_get_queue(s->nic);

    /* If the mitigation timer is active, emulate a timeout now. */
    if (s->mit_timer_on) {
        e1000_mit_timer(s);
    }

    if (!(s->compat_flags & E1000_FLAG_AUTONEG)) {
        return;
    }

    /*
     * If link is down and auto-negotiation is ongoing, complete
     * auto-negotiation immediately.  This allows is to look at
     * MII_SR_AUTONEG_COMPLETE to infer link status on load.
     */
    if (nc->link_down &&
        s->phy_reg[PHY_CTRL] & MII_CR_AUTO_NEG_EN &&
        s->phy_reg[PHY_CTRL] & MII_CR_RESTART_AUTO_NEG) {
         s->phy_reg[PHY_STATUS] |= MII_SR_AUTONEG_COMPLETE;
    }
}

static int e1000_post_load(void *opaque, int version_id)
{
    E1000State *s = opaque;
    NetClientState *nc = qemu_get_queue(s->nic);

    if (!(s->compat_flags & E1000_FLAG_MIT)) {
        s->mac_reg[ITR] = s->mac_reg[RDTR] = s->mac_reg[RADV] =
            s->mac_reg[TADV] = 0;
        s->mit_irq_level = false;
    }
    s->mit_ide = 0;
    s->mit_timer_on = false;

    /* nc.link_down can't be migrated, so infer link_down according
     * to link status bit in mac_reg[STATUS].
     * Alternatively, restart link negotiation if it was in progress. */
    nc->link_down = (s->mac_reg[STATUS] & E1000_STATUS_LU) == 0;

    if (!(s->compat_flags & E1000_FLAG_AUTONEG)) {
        return 0;
    }

    if (s->phy_reg[PHY_CTRL] & MII_CR_AUTO_NEG_EN &&
        s->phy_reg[PHY_CTRL] & MII_CR_RESTART_AUTO_NEG &&
        !(s->phy_reg[PHY_STATUS] & MII_SR_AUTONEG_COMPLETE)) {
        nc->link_down = false;
        timer_mod(s->autoneg_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 500);
    }

    return 0;
}

static bool e1000_mit_state_needed(void *opaque)
{
    E1000State *s = opaque;

    return s->compat_flags & E1000_FLAG_MIT;
}

static const VMStateDescription vmstate_e1000_mit_state = {
    .name = "e1000/mit_state",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .fields    = (VMStateField[]) {
        VMSTATE_UINT32(mac_reg[RDTR], E1000State),
        VMSTATE_UINT32(mac_reg[RADV], E1000State),
        VMSTATE_UINT32(mac_reg[TADV], E1000State),
        VMSTATE_UINT32(mac_reg[ITR], E1000State),
        VMSTATE_BOOL(mit_irq_level, E1000State),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_e1000 = {
    .name = "e1000",
    .version_id = 2,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .pre_save = e1000_pre_save,
    .post_load = e1000_post_load,
    .fields      = (VMStateField []) {
        VMSTATE_PCI_DEVICE(parent_obj, E1000State),
        VMSTATE_UNUSED_TEST(is_version_1, 4), /* was instance id */
        VMSTATE_UNUSED(4), /* Was mmio_base.  */
        VMSTATE_UINT32(rxbuf_size, E1000State),
        VMSTATE_UINT32(rxbuf_min_shift, E1000State),
        VMSTATE_UINT32(eecd_state.val_in, E1000State),
        VMSTATE_UINT16(eecd_state.bitnum_in, E1000State),
        VMSTATE_UINT16(eecd_state.bitnum_out, E1000State),
        VMSTATE_UINT16(eecd_state.reading, E1000State),
        VMSTATE_UINT32(eecd_state.old_eecd, E1000State),
        VMSTATE_UINT8(tx.ipcss, E1000State),
        VMSTATE_UINT8(tx.ipcso, E1000State),
        VMSTATE_UINT16(tx.ipcse, E1000State),
        VMSTATE_UINT8(tx.tucss, E1000State),
        VMSTATE_UINT8(tx.tucso, E1000State),
        VMSTATE_UINT16(tx.tucse, E1000State),
        VMSTATE_UINT32(tx.paylen, E1000State),
        VMSTATE_UINT8(tx.hdr_len, E1000State),
        VMSTATE_UINT16(tx.mss, E1000State),
        VMSTATE_UINT16(tx.size, E1000State),
        VMSTATE_UINT16(tx.tso_frames, E1000State),
        VMSTATE_UINT8(tx.sum_needed, E1000State),
        VMSTATE_INT8(tx.ip, E1000State),
        VMSTATE_INT8(tx.tcp, E1000State),
        VMSTATE_BUFFER(tx.header, E1000State),
        VMSTATE_BUFFER(tx.data, E1000State),
        VMSTATE_UINT16_ARRAY(eeprom_data, E1000State, 64),
        VMSTATE_UINT16_ARRAY(phy_reg, E1000State, 0x20),
        VMSTATE_UINT32(mac_reg[CTRL], E1000State),
        VMSTATE_UINT32(mac_reg[EECD], E1000State),
        VMSTATE_UINT32(mac_reg[EERD], E1000State),
        VMSTATE_UINT32(mac_reg[GPRC], E1000State),
        VMSTATE_UINT32(mac_reg[GPTC], E1000State),
        VMSTATE_UINT32(mac_reg[ICR], E1000State),
        VMSTATE_UINT32(mac_reg[ICS], E1000State),
        VMSTATE_UINT32(mac_reg[IMC], E1000State),
        VMSTATE_UINT32(mac_reg[IMS], E1000State),
        VMSTATE_UINT32(mac_reg[LEDCTL], E1000State),
        VMSTATE_UINT32(mac_reg[MANC], E1000State),
        VMSTATE_UINT32(mac_reg[MDIC], E1000State),
        VMSTATE_UINT32(mac_reg[MPC], E1000State),
        VMSTATE_UINT32(mac_reg[PBA], E1000State),
        VMSTATE_UINT32(mac_reg[RCTL], E1000State),
        VMSTATE_UINT32(mac_reg[RDBAH], E1000State),
        VMSTATE_UINT32(mac_reg[RDBAL], E1000State),
        VMSTATE_UINT32(mac_reg[RDH], E1000State),
        VMSTATE_UINT32(mac_reg[RDLEN], E1000State),
        VMSTATE_UINT32(mac_reg[RDT], E1000State),
        VMSTATE_UINT32(mac_reg[STATUS], E1000State),
        VMSTATE_UINT32(mac_reg[SWSM], E1000State),
        VMSTATE_UINT32(mac_reg[TCTL], E1000State),
        VMSTATE_UINT32(mac_reg[TDBAH], E1000State),
        VMSTATE_UINT32(mac_reg[TDBAL], E1000State),
        VMSTATE_UINT32(mac_reg[TDH], E1000State),
        VMSTATE_UINT32(mac_reg[TDLEN], E1000State),
        VMSTATE_UINT32(mac_reg[TDT], E1000State),
        VMSTATE_UINT32(mac_reg[TORH], E1000State),
        VMSTATE_UINT32(mac_reg[TORL], E1000State),
        VMSTATE_UINT32(mac_reg[TOTH], E1000State),
        VMSTATE_UINT32(mac_reg[TOTL], E1000State),
        VMSTATE_UINT32(mac_reg[TPR], E1000State),
        VMSTATE_UINT32(mac_reg[TPT], E1000State),
        VMSTATE_UINT32(mac_reg[TXDCTL], E1000State),
        VMSTATE_UINT32(mac_reg[WUFC], E1000State),
        VMSTATE_UINT32(mac_reg[VET], E1000State),
        VMSTATE_UINT32_SUB_ARRAY(mac_reg, E1000State, RA, 32),
        VMSTATE_UINT32_SUB_ARRAY(mac_reg, E1000State, MTA, 128),
        VMSTATE_UINT32_SUB_ARRAY(mac_reg, E1000State, VFTA, 128),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (VMStateSubsection[]) {
        {
            .vmsd = &vmstate_e1000_mit_state,
            .needed = e1000_mit_state_needed,
        }, {
            /* empty */
        }
    }
};

/*
 * EEPROM contents documented in Tables 5-2 and 5-3, pp. 98-102.
 * Note: A valid DevId will be inserted during pci_e1000_init().
 */
static const uint16_t e1000_eeprom_template[64] = {
    0x0000, 0x0000, 0x0000, 0x0000,      0xffff, 0x0000,      0x0000, 0x0000,
    0x3000, 0x1000, 0x6403, 0 /*DevId*/, 0x8086, 0 /*DevId*/, 0x8086, 0x3040,
    0x0008, 0x2000, 0x7e14, 0x0048,      0x1000, 0x00d8,      0x0000, 0x2700,
    0x6cc9, 0x3150, 0x0722, 0x040b,      0x0984, 0x0000,      0xc000, 0x0706,
    0x1008, 0x0000, 0x0f04, 0x7fff,      0x4d01, 0xffff,      0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff,      0xffff, 0xffff,      0xffff, 0xffff,
    0x0100, 0x4000, 0x121c, 0xffff,      0xffff, 0xffff,      0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff,      0xffff, 0xffff,      0xffff, 0x0000,
};

/* PCI interface */

static void
e1000_mmio_setup(E1000State *d)
{
    int i;
    const uint32_t excluded_regs[] = {
        E1000_MDIC, E1000_ICR, E1000_ICS, E1000_IMS,
        E1000_IMC, E1000_TCTL, E1000_TDT, PNPMMIO_SIZE
    };

    memory_region_init_io(&d->mmio, OBJECT(d), &e1000_mmio_ops, d,
                          "e1000-mmio", PNPMMIO_SIZE);
    memory_region_add_coalescing(&d->mmio, 0, excluded_regs[0]);
    for (i = 0; excluded_regs[i] != PNPMMIO_SIZE; i++)
        memory_region_add_coalescing(&d->mmio, excluded_regs[i] + 4,
                                     excluded_regs[i+1] - excluded_regs[i] - 4);
    memory_region_init_io(&d->io, OBJECT(d), &e1000_io_ops, d, "e1000-io", IOPORT_SIZE);
}

static void
e1000_cleanup(NetClientState *nc)
{
    E1000State *s = qemu_get_nic_opaque(nc);

    s->nic = NULL;
}

static void
pci_e1000_uninit(PCIDevice *dev)
{
    E1000State *d = E1000(dev);

    timer_del(d->autoneg_timer);
    timer_free(d->autoneg_timer);
    timer_del(d->mit_timer);
    timer_free(d->mit_timer);
#ifdef CONFIG_E1000_PARAVIRT
    qemu_bh_delete(d->tx_bh);
    msix_unuse_all_vectors(dev);
    msix_uninit_exclusive_bar(dev);
#endif /* CONFIG_E1000_PARAVIRT */
    IFRATE(timer_del(d->rate_timer); timer_free(d->rate_timer));
    memory_region_destroy(&d->mmio);
    memory_region_destroy(&d->io);
    qemu_del_nic(d->nic);
}

static NetClientInfo net_e1000_info = {
    .type = NET_CLIENT_OPTIONS_KIND_NIC,
    .size = sizeof(NICState),
    .can_receive = e1000_can_receive,
    .receive = e1000_receive,
    .receive_iov = e1000_receive_iov,
    .receive_iov_flags = e1000_receive_iov_flags,
    .cleanup = e1000_cleanup,
    .link_status_changed = e1000_set_link_status,
};

static int pci_e1000_init(PCIDevice *pci_dev)
{
    DeviceState *dev = DEVICE(pci_dev);
    E1000State *d = E1000(pci_dev);
    PCIDeviceClass *pdc = PCI_DEVICE_GET_CLASS(pci_dev);
    uint8_t *pci_conf;
    uint16_t checksum = 0;
    int i;
    uint8_t *macaddr;

    pci_conf = pci_dev->config;

    /* TODO: RST# value should be 0, PCI spec 6.2.4 */
    pci_conf[PCI_CACHE_LINE_SIZE] = 0x10;

    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */

    e1000_mmio_setup(d);

    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &d->mmio);

    pci_register_bar(pci_dev, 1, PCI_BASE_ADDRESS_SPACE_IO, &d->io);

    memmove(d->eeprom_data, e1000_eeprom_template,
        sizeof e1000_eeprom_template);
    qemu_macaddr_default_if_unset(&d->conf.macaddr);
    macaddr = d->conf.macaddr.a;
    for (i = 0; i < 3; i++)
        d->eeprom_data[i] = (macaddr[2*i+1]<<8) | macaddr[2*i];
    d->eeprom_data[11] = d->eeprom_data[13] = pdc->device_id;
    for (i = 0; i < EEPROM_CHECKSUM_REG; i++)
        checksum += d->eeprom_data[i];
    checksum = (uint16_t) EEPROM_SUM - checksum;
    d->eeprom_data[EEPROM_CHECKSUM_REG] = checksum;

    d->nic = qemu_new_nic(&net_e1000_info, &d->conf,
                          object_get_typename(OBJECT(d)), dev->id, d);

    qemu_format_nic_info_str(qemu_get_queue(d->nic), macaddr);

    add_boot_device_path(d->conf.bootindex, dev, "/ethernet-phy@0");

    d->autoneg_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, e1000_autoneg_timer, d);
    d->mit_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, e1000_mit_timer, d);

    d->mit_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, e1000_mit_timer, d);
    IFRATE(d->rate_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, &rate_callback, d));

#ifdef CONFIG_E1000_PARAVIRT
    d->tx_bh = qemu_bh_new(e1000_tx_bh, d);
    /* Initialize the BAR register 2 to reference a MSI-X table containing
       2 entries. */
    if ((i = msix_init_exclusive_bar(pci_dev, 2, 2))) {
	D("msix_init_exclusive_bar(1) failed\n");
	return i;
    }
    d->num_mappings = 0;
#ifdef V1000
    if (d->v1000) {
        d->ioeventfd = false;
    }
#endif
    d->tx_hdr = NULL;
#endif /* CONFIG_E1000_PARAVIRT */
    return 0;
}

static void qdev_e1000_reset(DeviceState *dev)
{
    E1000State *d = E1000(dev);
    e1000_reset(d);
}

static Property e1000_properties[] = {
    DEFINE_NIC_PROPERTIES(E1000State, conf),
    DEFINE_PROP_BIT("autonegotiation", E1000State,
                    compat_flags, E1000_FLAG_AUTONEG_BIT, true),
    DEFINE_PROP_BIT("mitigation", E1000State,
                    compat_flags, E1000_FLAG_MIT_BIT, true),
#ifdef CONFIG_E1000_PARAVIRT
    DEFINE_PROP_BOOL("ioeventfd", E1000State, ioeventfd, false),
#ifdef V1000
    DEFINE_PROP_BOOL("v1000", E1000State, v1000, false),
#endif /* V1000 */
#endif /* CONFIG_E1000_PARAVIRT */
    DEFINE_PROP_END_OF_LIST(),
};

typedef struct E1000Info {
    const char *name;
    uint16_t   device_id;
    uint8_t    revision;
    uint16_t   phy_id2;
    uint16_t   subsystem_id;
} E1000Info;

static void e1000_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    E1000BaseClass *e = E1000_DEVICE_CLASS(klass);
    const E1000Info *info = data;

    k->init = pci_e1000_init;
    k->exit = pci_e1000_uninit;
    k->romfile = "efi-e1000.rom";
    k->vendor_id = PCI_VENDOR_ID_INTEL;
    k->device_id = info->device_id;
    k->subsystem_id = info->subsystem_id;
    k->revision = info->revision;
    e->phy_id2 = info->phy_id2;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    dc->desc = "Intel Gigabit Ethernet";
    dc->reset = qdev_e1000_reset;
    dc->vmsd = &vmstate_e1000;
    dc->props = e1000_properties;
}

static const TypeInfo e1000_base_info = {
    .name          = TYPE_E1000_BASE,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(E1000State),
    .class_size    = sizeof(E1000BaseClass),
    .abstract      = true,
};

static const E1000Info e1000_devices[] = {
    {
        .name      = "e1000-82540em",
        .device_id = E1000_DEV_ID_82540EM,
        .revision  = 0x03,
        .phy_id2   = E1000_PHY_ID2_8254xx_DEFAULT,
        .subsystem_id = 0,
    },
    {
        .name      = "e1000-82544gc",
        .device_id = E1000_DEV_ID_82544GC_COPPER,
        .revision  = 0x03,
        .phy_id2   = E1000_PHY_ID2_82544x,
        .subsystem_id = 0,
    },
    {
        .name      = "e1000-82545em",
        .device_id = E1000_DEV_ID_82545EM_COPPER,
        .revision  = 0x03,
        .phy_id2   = E1000_PHY_ID2_8254xx_DEFAULT,
        .subsystem_id = 0,
    },
#ifdef CONFIG_E1000_PARAVIRT
    {
        .name      = "e1000-paravirt",
        .device_id = E1000_DEV_ID_82540EM,
        .revision  = 0x03,
        .phy_id2   = E1000_PHY_ID2_8254xx_DEFAULT,
        .subsystem_id = E1000_PARA_SUBDEV,
    },
#endif  /* CONFIG_E1000_PARAVIRT */
};

static const TypeInfo e1000_default_info = {
    .name          = "e1000",
    .parent        = "e1000-82540em",
};

static void e1000_register_types(void)
{
    int i;

    type_register_static(&e1000_base_info);
    for (i = 0; i < ARRAY_SIZE(e1000_devices); i++) {
        const E1000Info *info = &e1000_devices[i];
        TypeInfo type_info = {};

        type_info.name = info->name;
        type_info.parent = TYPE_E1000_BASE;
        type_info.class_data = (void *)info;
        type_info.class_init = e1000_class_init;

        type_register(&type_info);
    }
    type_register_static(&e1000_default_info);
}

type_init(e1000_register_types)
