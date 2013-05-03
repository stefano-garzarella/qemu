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


#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "net/net.h"
#include "net/checksum.h"
#include "hw/loader.h"
#include "sysemu/sysemu.h"
#include "sysemu/dma.h"

#include "e1000_regs.h"

#define MAP_RING        /* map the buffers instead of pci_dma_rw() */
#define PARAVIRT        /* use paravirtualized driver */
//#define RATE		/* debug rate monitor */

#ifdef PARAVIRT
/*
 * Support for virtio-like communication:
 * The VMM advertises virtio-like synchronization setting
 * the subvendor id set to 0x1101 (E1000_PARA_SUBDEV).
 */
#define E1000_PARA_SUBDEV 0x1101
#define E1000_CSBAL       0x02830 /* addresses for the csb */
#define E1000_CSBAH       0x02834
#include "net/paravirt.h"
#endif /* PARAVIRT */

#ifdef RATE
#define IFRATE(x) x
#else
#define IFRATE(x) 
#endif

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

/*
 * HW models:
 *  E1000_DEV_ID_82540EM works with Windows and Linux
 *  E1000_DEV_ID_82573L OK with windoze and Linux 2.6.22,
 *	appears to perform better than 82540EM, but breaks with Linux 2.6.18
 *  E1000_DEV_ID_82544GC_COPPER appears to work; not well tested
 *  Others never tested
 */
enum { E1000_DEVID = E1000_DEV_ID_82540EM };

/*
 * May need to specify additional MAC-to-PHY entries --
 * Intel's Windows driver refuses to initialize unless they match
 */
enum {
    PHY_ID2_INIT = E1000_DEVID == E1000_DEV_ID_82573L ?		0xcc2 :
                   E1000_DEVID == E1000_DEV_ID_82544GC_COPPER ?	0xc30 :
                   /* default to E1000_DEV_ID_82540EM */	0xc20
};

/*
 * map a guest region into a host region
 * if the pointer is within the region, ofs gives the displacement.
 * valid = 0 means we should try to map it.
 */
struct guest_memreg_map {
        int      valid;
        uint64_t lo;
        uint64_t hi;
        uint64_t ofs;
};

typedef struct E1000State_st {
    PCIDevice dev;
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

/* Compatibility flags for migration to/from qemu 1.3.0 and older */
#define E1000_FLAG_AUTONEG_BIT 0
#define E1000_FLAG_AUTONEG (1 << E1000_FLAG_AUTONEG_BIT)
    uint32_t compat_flags;

    QEMUTimer *mit_timer;       /* handle for the timer          */
    uint32_t  mit_timer_on;     /* mitigation timer active       */
    uint32_t  mit_cause;        /* pending interrupt cause       */
    uint32_t  mit_on;           /* mitigation enable             */
    uint32_t  mit_ide;          /* use old tx mitigation regs    */

    /* when the rxq becomes full, disable input until half empty */
    uint32_t rxbufs, txbufs, rxq_full;
#ifdef MAP_RING
    /* used for map ring */
    uint64_t txring_phi, rxring_phi;         /* phisical address */
    struct e1000_tx_desc *txring;
    struct e1000_rx_desc *rxring;
    struct guest_memreg_map mbufs;
#endif /* MAP_RING */

#ifdef PARAVIRT
    /* used for the communication block */
    struct paravirt_csb *csb;
    QEMUBH       *tx_bh;
    uint32_t     tx_count;          /* written in last round */
#endif /* PARAVIRT */
    IFRATE(QEMUTimer * rate_timer);
} E1000State;

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
    defreg(VET),
    defreg(RDTR),       defreg(RADV),   defreg(TADV),   defreg(ITR),
#ifdef PARAVIRT
    defreg(CSBAL),      defreg(CSBAH),
#endif /* PARAVIRT */
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
static int rate_irq_level = 0;
static int rate_ntfy_txfull = 0;

/* rate guest notifications */
static int rate_ntfy_tx = 0;    // new TX descriptors
static int rate_ntfy_ic = 0;    // interrupt acknowledge (interrupt clear)
static int rate_ntfy_rx = 0;

/* rate tx packets */
static int rate_tx = 0;
static int64_t rate_txb = 0;

/* rate rx packet */
static int rate_rx = 0;  // received packet counter
static int64_t rate_rxb = 0;

static int rate_tx_bh_len = 0;
static int rate_tx_bh_count = 0;

#ifdef PARAVIRT
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
	printf("host_txcycles_lim = %X\n", s->csb->host_txcycles_lim);
	printf("host_txcycles = %X\n", s->csb->host_txcycles);
    }
}
#endif /* PARAVIRT */

static void rate_callback(void * opaque)
{
    E1000State* s = opaque;
    int64_t delta;

#ifdef PARAVIRT
    csb_dump(s);
#endif /* PARAVIRT */

    delta = qemu_get_clock_ms(vm_clock) - rate_last_timestamp;
    printf("Interrupt:           %4.3f KHz\n", (double)rate_irq_int/delta);
    printf("Tx packets:          %4.3f KHz\n", (double)rate_tx/delta);
    printf("Tx stream:           %4.3f Mbps\n", (double)(rate_txb*8)/delta/1000.0);
    if (rate_tx_bh_count)
	printf("Avg BH work:         %4.3f\n", (double)rate_tx_bh_len/(double)rate_tx_bh_count);
    printf("Rx packets:          %4.3f Kpps\n", (double)rate_rx/delta);
    printf("Rx stream:           %4.3f Mbps\n", (double)(rate_rxb*8)/delta/1000.0);
    printf("Tx notifications:    %4.3f KHz\n", (double)rate_ntfy_tx/delta);
    printf("TX full notif.:      %4.3f KHz\n", (double)rate_ntfy_txfull/delta);
    printf("Rx notifications:    %4.3f KHz\n", (double)rate_ntfy_rx/delta);
    printf("MMIO writes:         %4.3f KHz\n", (double)rate_mmio_write/delta);
    printf("MMIO reads:          %4.3f KHz\n", (double)rate_mmio_read/delta);
    printf("\n");
    rate_irq_int = 0;
    rate_ntfy_txfull = 0;
    rate_ntfy_tx = rate_ntfy_ic = rate_ntfy_rx = 0;
    rate_mmio_read = rate_mmio_write = 0;
    rate_rx = rate_rxb = 0;
    rate_tx = rate_txb = 0;
    rate_tx_bh_len = rate_tx_bh_count = 0;

    qemu_mod_timer(s->rate_timer, qemu_get_clock_ms(vm_clock) +
		    rate_interval_ms);
    rate_last_timestamp = qemu_get_clock_ms(vm_clock);
}
#endif /* RATE */

#ifdef MAP_RING
/*
 * try to extract an mbuf region
 */
static const uint8_t *map_mbufs(E1000State *s, hwaddr addr)
{
    struct guest_memreg_map *mb = &s->mbufs;
    uint64_t a = addr;
    DMAContext *dma;

    for (;;) {
        if (mb->valid && a >= mb->lo && a < mb->hi) {
            return (const uint8_t *)(uintptr_t)(a + mb->ofs);
        }
        dma = pci_dma_context(&s->dev);
        mb->valid = 1;

        D("mapping %p is unset", (void *)(uintptr_t)addr);
        if (dma_has_iommu(dma)) {
            D("iommu range, cannot set");
            break;
        }
        if (!address_space_mappable(dma->as, addr,
                  &mb->lo, &mb->hi, &mb->ofs)) {
            D("not mappable, cannot set");
            break;
        }
        D("segment [%p .. %p] delta %p",
             (void *)(uintptr_t)mb->lo,
             (void *)(uintptr_t)mb->hi,
             (void *)(uintptr_t)mb->ofs);

        D("mapping txring correct %p computed %p",
            s->txring, (void *)(uintptr_t)(s->txring_phi + mb->ofs));
    }
    mb->hi = mb->lo = 0; /* empty mapping */
    return NULL;
}
#endif /* MAP_RING */

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
        qemu_mod_timer(s->autoneg_timer, qemu_get_clock_ms(vm_clock) + 500);
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

static const uint16_t phy_reg_init[] = {
    [PHY_CTRL] = 0x1140,
    [PHY_STATUS] = 0x794d, /* link initially up with not completed autoneg */
    [PHY_ID1] = 0x141,				[PHY_ID2] = PHY_ID2_INIT,
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

static void
set_interrupt_cause(E1000State *s, int index, uint32_t val)
{
    if (val && (E1000_DEVID >= E1000_DEV_ID_82547EI_MOBILE)) {
        /* Only for 8257x */
        val |= E1000_ICR_INT_ASSERTED;
    }
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

    qemu_set_irq(s->dev.irq[0], (s->mac_reg[IMS] & s->mac_reg[ICR]) != 0);
#ifdef RATE
    if (!rate_irq_level && (s->mac_reg[IMS] & s->mac_reg[ICR])) {
	rate_irq_int++;
    }
    rate_irq_level = (s->mac_reg[IMS] & s->mac_reg[ICR]);
#endif
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

static void e1000_reset(void *opaque)
{
    E1000State *d = opaque;
    uint8_t *macaddr = d->conf.macaddr.a;
    int i;

    qemu_del_timer(d->autoneg_timer);
    qemu_del_timer(d->mit_timer);
    d->mit_timer_on = 0;
    d->mit_cause = 0;
    d->mit_ide = 0;
#ifdef PARAVIRT
    d->csb = NULL;
    qemu_bh_cancel(d->tx_bh);
#endif /* PARAVIRT */
    memset(d->phy_reg, 0, sizeof d->phy_reg);
    memmove(d->phy_reg, phy_reg_init, sizeof phy_reg_init);
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
}

static void
set_ctrl(E1000State *s, int index, uint32_t val)
{
    /* RST is self clearing */
    s->mac_reg[CTRL] = val & ~E1000_CTRL_RST;
    IFRATE(qemu_mod_timer(s->rate_timer, qemu_get_clock_ms(vm_clock)
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
        cpu_to_be16wu((uint16_t *)(data + sloc),
                      net_checksum_finish(sum));
    }
}

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

static void
e1000_send_packet(E1000State *s, const uint8_t *buf, int size)
{
    NetClientState *nc = qemu_get_queue(s->nic);
    if (s->phy_reg[PHY_CTRL] & MII_CR_LOOPBACK) {
        nc->info->receive(nc, buf, size);
    } else {
        qemu_send_packet(nc, buf, size);
    }
    IFRATE(rate_tx++; rate_txb += size);
}

static void
xmit_seg(E1000State *s)
{
    uint16_t len, *sp;
    unsigned int frames = s->tx.tso_frames, css, sofar, n;
    struct e1000_tx *tp = &s->tx;

    if (tp->tse && tp->cptse) {
        css = tp->ipcss;
        DBGOUT(TXSUM, "frames %d size %d ipcss %d\n",
               frames, tp->size, css);
        if (tp->ip) {		// IPv4
            cpu_to_be16wu((uint16_t *)(tp->data+css+2),
                          tp->size - css);
            cpu_to_be16wu((uint16_t *)(tp->data+css+4),
                          be16_to_cpup((uint16_t *)(tp->data+css+4))+frames);
        } else			// IPv6
            cpu_to_be16wu((uint16_t *)(tp->data+css+4),
                          tp->size - css);
        css = tp->tucss;
        len = tp->size - css;
        DBGOUT(TXSUM, "tcp %d tucss %d len %d\n", tp->tcp, css, len);
        if (tp->tcp) {
            sofar = frames * tp->mss;
            cpu_to_be32wu((uint32_t *)(tp->data+css+4),	// seq
                be32_to_cpupu((uint32_t *)(tp->data+css+4))+sofar);
            if (tp->paylen - sofar > tp->mss)
                tp->data[css + 13] &= ~9;		// PSH, FIN
        } else	// UDP
            cpu_to_be16wu((uint16_t *)(tp->data+css+4), len);
        if (tp->sum_needed & E1000_TXD_POPTS_TXSM) {
            unsigned int phsum;
            // add pseudo-header length before checksum calculation
            sp = (uint16_t *)(tp->data + tp->tucso);
            phsum = be16_to_cpup(sp) + len;
            phsum = (phsum >> 16) + (phsum & 0xffff);
            cpu_to_be16wu(sp, phsum);
        }
        tp->tso_frames++;
    }

    if (tp->sum_needed & E1000_TXD_POPTS_TXSM)
        putsum(tp->data, tp->size, tp->tucso, tp->tucss, tp->tucse);
    if (tp->sum_needed & E1000_TXD_POPTS_IXSM)
        putsum(tp->data, tp->size, tp->ipcso, tp->ipcss, tp->ipcse);
    if (tp->vlan_needed) {
        memmove(tp->vlan, tp->data, 4);
        memmove(tp->data, tp->data + 4, 8);
        memcpy(tp->data + 8, tp->vlan_header, 4);
        e1000_send_packet(s, tp->vlan, tp->size + 4);
    } else
        e1000_send_packet(s, tp->data, tp->size);
    s->mac_reg[TPT]++;
    s->mac_reg[GPTC]++;
    n = s->mac_reg[TOTL];
    if ((s->mac_reg[TOTL] += s->tx.size) < n)
        s->mac_reg[TOTH]++;
}

static void
process_tx_desc(E1000State *s, struct e1000_tx_desc *dp)
{
    uint32_t txd_lower = le32_to_cpu(dp->lower.data);
    uint32_t dtype = txd_lower & (E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D);
    unsigned int split_size = txd_lower & 0xffff, bytes, sz, op;
    unsigned int msh = 0xfffff, hdr = 0;
    uint64_t addr;
    struct e1000_context_desc *xp = (struct e1000_context_desc *)dp;
    struct e1000_tx *tp = &s->tx;

    s->mit_ide |= (txd_lower & E1000_TXD_CMD_IDE); // XXX check
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

    if (vlan_enabled(s) && is_vlan_txd(txd_lower) &&
        (tp->cptse || txd_lower & E1000_TXD_CMD_EOP)) {
        tp->vlan_needed = 1;
        cpu_to_be16wu((uint16_t *)(tp->vlan_header),
                      le16_to_cpup((uint16_t *)(s->mac_reg + VET)));
        cpu_to_be16wu((uint16_t *)(tp->vlan_header + 2),
                      le16_to_cpu(dp->upper.fields.special));
    }
        
    addr = le64_to_cpu(dp->buffer_addr);

#ifdef MAP_RING
    if (!tp->tse && !tp->cptse && tp->size == 0 &&
        !tp->vlan_needed && !tp->sum_needed &&
        (txd_lower & E1000_TXD_CMD_EOP)) {
            const uint8_t *x = map_mbufs(s, addr);
        if (x) {
            /* XXX optimization for netmap */
            e1000_send_packet(s, x, split_size);
            tp->tso_frames = 0;
            tp->sum_needed = 0;
            tp->vlan_needed = 0;
            tp->size = 0;
            tp->cptse = 0;
            return ;
        }
    }
#endif /* MAP_RING */

    if (tp->tse && tp->cptse) {
        hdr = tp->hdr_len;
        msh = hdr + tp->mss;
        do {
            bytes = split_size;
            if (tp->size + bytes > msh)
                bytes = msh - tp->size;

            bytes = MIN(sizeof(tp->data) - tp->size, bytes);
            pci_dma_read(&s->dev, addr, tp->data + tp->size, bytes);
            if ((sz = tp->size + bytes) >= hdr && tp->size < hdr)
                memmove(tp->header, tp->data, hdr);
            tp->size = sz;
            addr += bytes;
            if (sz == msh) {
                xmit_seg(s);
                memmove(tp->data, tp->header, hdr);
                tp->size = hdr;
            }
        } while (split_size -= bytes);
    } else if (!tp->tse && tp->cptse) {
        // context descriptor TSE is not set, while data descriptor TSE is set
        DBGOUT(TXERR, "TCP segmentation error\n");
    } else {
        split_size = MIN(sizeof(tp->data) - tp->size, split_size);
        pci_dma_read(&s->dev, addr, tp->data + tp->size, split_size);
        tp->size += split_size;
    }

    if (!(txd_lower & E1000_TXD_CMD_EOP))
        return;
    if (!(tp->tse && tp->cptse && tp->size < hdr))
        xmit_seg(s);
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
#ifdef MAP_RING
    s->txring[s->mac_reg[TDH]].upper = dp->upper;
#else /* !MAP_RING */
    pci_dma_write(&s->dev, base + ((char *)&dp->upper - (char *)dp),
                  &dp->upper, sizeof(dp->upper));
#endif /* !MAP_RING */
    return E1000_ICR_TXDW;
}

static uint64_t tx_desc_base(E1000State *s)
{
    uint64_t bah = s->mac_reg[TDBAH];
    uint64_t bal = s->mac_reg[TDBAL] & ~0xf;

    return (bah << 32) + bal;
}

/* helper function, 0 means the value is not set */
static inline void
mit_update_delay(uint32_t *curr, uint32_t value)
{
    if (value && (*curr == 0 || value < *curr)) {
        *curr = value;
    }
}

/*
 * If necessary, rearm the timer and post an interrupt.
 * Called at the end of tx/rx routines (mit_timer_on == 0),
 * and when the timer fires (mit_timer_on == 1).
 * We provide a partial implementation of interrupt mitigation,
 * emulating only RADV, TADV and ITR (lower 16 bits, 1024ns units for
 * RADV and TADV, 256ns units for ITR). RDTR is only used to enable RADV;
 * relative timers based on TIDV and RDTR are not implemented.
 */
static void
mit_rearm_and_int(void *opaque)
{
    E1000State *s = opaque;
    uint32_t mit_delay = 0;

    /*
     * Clear the flag. It is only set when the callback fires,
     * and we need to clear it anyways.
     */
    s->mit_timer_on = 0;
    if (s->mit_cause == 0) { /* no events pending, we are done */
        return;
    }
    /*
     * Compute the next mitigation delay according to pending interrupts
     * and the current values of RADV (provided RDTR!=0), TADV and ITR.
     * Then rearm the timer.
     */
    if (s->mit_ide && s->mit_cause & (E1000_ICR_TXQE | E1000_ICR_TXDW)) {
        mit_update_delay(&mit_delay, s->mac_reg[TADV] * 4);
    }
    if (s->mac_reg[RDTR] && (s->mit_cause & E1000_ICS_RXT0)) {
        mit_update_delay(&mit_delay, s->mac_reg[RADV] * 4);
    }
    mit_update_delay(&mit_delay, s->mac_reg[ITR]);

    if (mit_delay) {
        s->mit_timer_on = 1;
        qemu_mod_timer(s->mit_timer,
                qemu_get_clock_ns(vm_clock) + mit_delay * 256);
    }

    set_ics(s, 0, s->mit_cause);
    s->mit_cause = 0;
    s->mit_ide = 0;
}

static void
mit_set_ics(E1000State *s, uint32_t cause)
{
    if (s->mit_on == 0) {
        set_ics(s, 0, cause);
        return;
    }
    s->mit_cause |= cause;
    if (!s->mit_timer_on)
        mit_rearm_and_int(s);
}

static void
start_xmit(E1000State *s)
{
    dma_addr_t base;
    struct e1000_tx_desc desc;
    uint32_t tdh_start = s->mac_reg[TDH], cause = E1000_ICS_TXQE;

    if (!(s->mac_reg[TCTL] & E1000_TCTL_EN)) {
        DBGOUT(TX, "tx disabled\n");
        return;
    }

#ifdef MAP_RING
    base = tx_desc_base(s);
    if (base != s->txring_phi) {
        hwaddr desclen = s->mac_reg[TDLEN];
        s->txring_phi = base;
        s->txring = address_space_map(pci_dma_context(&s->dev)->as,
              base, &desclen, 0 /* is_write */);
        D("region size is %ld", (long int)desclen);
    }
#endif /* MAP_RING */

#ifdef PARAVIRT
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
                if (s->tx_count > 50) {
                    ND("sent %d in this iteration", s->tx_count);
                }
                smp_mb();
                if (s->csb->guest_need_txkick) {
                    mit_set_ics(s, cause);
                }
                return;
            }
        } else if (s->mac_reg[TDH] == s->mac_reg[TDT]) {
            break;
        }
        s->tx_count++;
#else /* !PARAVIRT */
    while (s->mac_reg[TDH] != s->mac_reg[TDT]) {
#endif /* PARAVIRT */
#ifdef MAP_RING
        desc = s->txring[s->mac_reg[TDH]];
#else /* !MAP_RING */
        base = tx_desc_base(s) +
               sizeof(struct e1000_tx_desc) * s->mac_reg[TDH];
        pci_dma_read(&s->dev, base, &desc, sizeof(desc));
#endif /* MAP_RING */

        DBGOUT(TX, "index %d: %p : %x %x\n", s->mac_reg[TDH],
               (void *)(intptr_t)desc.buffer_addr, desc.lower.data,
               desc.upper.data);

        process_tx_desc(s, &desc);
        cause |= txdesc_writeback(s, base, &desc);

        if (++s->mac_reg[TDH] * sizeof(desc) >= s->mac_reg[TDLEN])
            s->mac_reg[TDH] = 0;
#ifdef PARAVIRT
        if (csb_mode) {
            s->csb->host_tdh = s->mac_reg[TDH];
        }
#endif /* PARAVIRT */
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
    mit_set_ics(s, cause);
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

#define AVAIL_RXBUFS (((int)s->mac_reg[RDT] -(int)s->mac_reg[RDH]) + ((s->mac_reg[RDT] < s->mac_reg[RDH]) ? s->rxbufs : 0))

static bool e1000_has_rxbufs(E1000State *s, size_t total_size)
{
#ifdef PARAVIRT
    /*
     * called by set_rdt(), e1000_can_receive(), e1000_receive().
     * If using the csb:
     * - update the RDT value from there.
     * - if there is space, clear csb->host_need_rxkick to
     *   disable further kicks. This is needed mostly in
     *   e1000_set_rdt(), and to clear the flag in the double check.
     *   Otherwise, set csb->host_need_rxkick and do the double check,
     *   possibly clearing the variable if we were wrong.
     */
    struct paravirt_csb *csb = s->csb && s->csb->guest_csb_on ? s->csb : NULL;

    s->rxq_full = (total_size > AVAIL_RXBUFS * s->rxbuf_size);
#if 0
    if (s->rxq_full && bufs < s->rxbufs / 2) {
        return false; /* hysteresis */
    }
#endif
    if (csb) {
	if (s->rxq_full) {
doublecheck:
	    /* Reload csb->guest_rdt only when necessary. */
	    smp_mb();
	    s->mac_reg[RDT] = csb->guest_rdt;
	    s->rxq_full = (total_size > AVAIL_RXBUFS * s->rxbuf_size);
	}
        if (!s->rxq_full) {
	    /* try to minimize writes, be more cache friendly.
	     * The guest (or the host) might have already
	     * cleared the flag in a previous iteration.
	     */
	    if (csb->host_need_rxkick) {
		csb->host_need_rxkick = 0;
	    }
	} else if (!csb->host_need_rxkick) {
	    csb->host_need_rxkick = 1;
	    goto doublecheck;
	}
    }
    return !s->rxq_full;
#else /* !PARAVIRT */

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
#endif /* !PARAVIRT */
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
e1000_receive(NetClientState *nc, const uint8_t *buf, size_t size)
{
    E1000State *s = qemu_get_nic_opaque(nc);
    struct e1000_rx_desc desc;
    dma_addr_t base;
    unsigned int n, rdt;
    uint32_t rdh_start;
    uint16_t vlan_special = 0;
    uint8_t vlan_status = 0, vlan_offset = 0;
    uint8_t min_buf[MIN_BUF_SIZE];
    size_t desc_offset;
    size_t desc_size;
    size_t total_size;
#ifdef PARAVIRT
    uint32_t csb_mode = s->csb && s->csb->guest_csb_on;
#endif

    if (!(s->mac_reg[STATUS] & E1000_STATUS_LU)) {
        return -1;
    }

    if (!(s->mac_reg[RCTL] & E1000_RCTL_EN)) {
        return -1;
    }

    /* Pad to minimum Ethernet frame length */
    if (size < sizeof(min_buf)) {
        memcpy(min_buf, buf, size);
        memset(&min_buf[size], 0, sizeof(min_buf) - size);
        buf = min_buf;
        size = sizeof(min_buf);
    }

    /* Discard oversized packets if !LPE and !SBP. */
    if ((size > MAXIMUM_ETHERNET_LPE_SIZE ||
        (size > MAXIMUM_ETHERNET_VLAN_SIZE
        && !(s->mac_reg[RCTL] & E1000_RCTL_LPE)))
        && !(s->mac_reg[RCTL] & E1000_RCTL_SBP)) {
        return size;
    }

    if (!receive_filter(s, buf, size))
        return size;

    if (vlan_enabled(s) && is_vlan_packet(s, buf)) {
        vlan_special = cpu_to_le16(be16_to_cpup((uint16_t *)(buf + 14)));
        memmove((uint8_t *)buf + 4, buf, 12);
        vlan_status = E1000_RXD_STAT_VP;
        vlan_offset = 4;
        size -= 4;
    }

#ifdef PARAVIRT
    if (csb_mode) {
        smp_mb();
        s->mac_reg[RDT] = s->csb->guest_rdt;
    }
#endif /* PARAVIRT */

    rdh_start = s->mac_reg[RDH];
    desc_offset = 0;
    total_size = size + fcs_len(s);
    if (!e1000_has_rxbufs(s, total_size)) {
            set_ics(s, 0, E1000_ICS_RXO);
            return -1;
    }
    IFRATE(rate_rx++; rate_rxb += size);
#ifdef MAP_RING
    base = rx_desc_base(s);
    if (base != s->rxring_phi) {
        hwaddr desclen = s->mac_reg[RDLEN];
        s->rxring_phi = base;
        s->rxring = address_space_map(pci_dma_context(&s->dev)->as,
                base, &desclen, 0 /* is_write */);
    }
#endif /* MAP_RING */
    do {
        desc_size = total_size - desc_offset;
        if (desc_size > s->rxbuf_size) {
            desc_size = s->rxbuf_size;
        }
        base = rx_desc_base(s) + sizeof(desc) * s->mac_reg[RDH];
#ifdef MAP_RING
        desc = s->rxring[s->mac_reg[RDH]];
#else /* !MAP_RING */
        pci_dma_read(&s->dev, base, &desc, sizeof(desc));
#endif /* !MAP_RING */
        desc.special = vlan_special;
        desc.status |= (vlan_status | E1000_RXD_STAT_DD);
        if (desc.buffer_addr) {
            if (desc_offset < size) {
                size_t copy_size = size - desc_offset;
                if (copy_size > s->rxbuf_size) {
                    copy_size = s->rxbuf_size;
                }
                pci_dma_write(&s->dev, le64_to_cpu(desc.buffer_addr),
                              buf + desc_offset + vlan_offset, copy_size);
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
#ifdef MAP_RING
        s->rxring[s->mac_reg[RDH]] = desc;
        /* XXX a barrier ? */
#else
        pci_dma_write(&s->dev, base, &desc, sizeof(desc));
#endif /* !MAP_RING */

        if (++s->mac_reg[RDH] * sizeof(desc) >= s->mac_reg[RDLEN])
            s->mac_reg[RDH] = 0;
#ifdef PARAVIRT
	if (csb_mode) {
	    s->csb->host_rdh = s->mac_reg[RDH];
	}
#endif /* PARAVIRT */
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

#ifdef PARAVIRT
    // XXX in csb mode, if the guest does not need kick, we are done.
    if (csb_mode) {
	if (!s->csb->guest_need_rxkick) {
	    ND("guest_need_rxkick off, not kicking");
	    return size;
        }
    }
#endif /* PARAVIRT */
    mit_set_ics(s, n);

    return size;
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
    s->mac_reg[index] = val;
}


#ifdef PARAVIRT
static void
set_32bit(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val;
    if (index == CSBAL) {
	hwaddr len = 4096;
	hwaddr base = ((uint64_t)s->mac_reg[CSBAH] << 32) | s->mac_reg[CSBAL];
	/*
	 * We require that writes to the CSB address registers
	 * are in the order CSBAH , CSBAL so on the second one
	 * we have a valid 64-bit memory address.
         * Any previous region is unmapped, and handlers terminated.
         * The CSB is then remapped if the new pointer is != 0
         */
	if (s->csb) {
	    qemu_bh_cancel(s->tx_bh);
	    address_space_unmap(pci_dma_context(&s->dev)->as,
		    s->csb, len, 1, len);
	    s->csb = NULL;
	    D("TXBH canc + CSB release\n");
	}
	if (base) {
	    s->csb = address_space_map(pci_dma_context(&s->dev)->as,
		    base, &len, 1 /* is_write */);
	    D("CSB (re)mapping\n");
	}
    }
}

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
    IFRATE(rate_tx_bh_count++; rate_tx_bh_len += s->tx_count);
    csb->host_txcycles = (s->tx_count > 0) ? 0 : csb->host_txcycles+1;
    if (csb->host_txcycles >= csb->host_txcycles_lim) {
        /* prepare to sleep, with race avoidance */
        csb->host_txcycles = 0;
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
#endif /* PARAVIRT */

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
}

static void
set_dlen(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val & 0xfff80;
    if (index == RDLEN) {
        s->rxbufs = s->mac_reg[index] / sizeof(struct e1000_rx_desc);
        s->rxq_full = 0;
    } else {
        s->txbufs = s->mac_reg[index] / sizeof(struct e1000_tx_desc);
    }
}

static void
set_tctl(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val;
    s->mac_reg[TDT] &= 0xffff;
    IFRATE(rate_ntfy_tx++);
#ifdef PARAVIRT
    if (s->csb && s->csb->guest_csb_on) {
	ND("kick accepted tdt %d guest-tdt %d",
		s->mac_reg[TDT], s->csb->guest_tdt);
        s->csb->host_need_txkick = 0; /* XXX could be done by the guest */
        smp_mb(); /* XXX do we care ? */
        qemu_bh_schedule(s->tx_bh);
        return;
    }
#endif /* PARAVIRT */
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

#define getreg(x)	[x] = mac_readreg
static uint32_t (*macreg_readops[])(E1000State *, int) = {
    getreg(PBA),	getreg(RCTL),	getreg(TDH),	getreg(TXDCTL),
    getreg(WUFC),	getreg(TDT),	getreg(CTRL),	getreg(LEDCTL),
    getreg(MANC),	getreg(MDIC),	getreg(SWSM),	getreg(STATUS),
    getreg(TORL),	getreg(TOTL),	getreg(IMS),	getreg(TCTL),
    getreg(RDH),	getreg(RDT),	getreg(VET),	getreg(ICS),
    getreg(TDBAL),	getreg(TDBAH),	getreg(RDBAH),	getreg(RDBAL),
    getreg(TDLEN),	getreg(RDLEN),
    getreg(RDTR),       getreg(RADV),   getreg(TADV),   getreg(ITR),
#ifdef PARAVIRT
    getreg(CSBAL),      getreg(CSBAH),
#endif /* PARAVIRT */

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
    putreg(TDBAL),	putreg(TDBAH),	putreg(TXDCTL),	putreg(RDBAH),
    putreg(RDBAL),	putreg(LEDCTL), putreg(VET),
    [RDTR] = set_16bit, [RADV] = set_16bit,     [TADV] = set_16bit,
    [ITR] = set_16bit,
#ifdef PARAVIRT
    [CSBAL] = set_32bit, [CSBAH] = set_32bit,
#endif /* PARAVIRT */
    [TDLEN] = set_dlen,	[RDLEN] = set_dlen,	[TCTL] = set_tctl,
    [TDT] = set_tctl,	[MDIC] = set_mdic,	[ICS] = set_ics,
    [TDH] = set_16bit,	[RDH] = set_16bit,	[RDT] = set_rdt,
    [IMC] = set_imc,	[IMS] = set_ims,	[ICR] = set_icr,
    [EECD] = set_eecd,	[RCTL] = set_rx_control, [CTRL] = set_ctrl,
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
        qemu_mod_timer(s->autoneg_timer, qemu_get_clock_ms(vm_clock) + 500);
    }

    return 0;
}

static const VMStateDescription vmstate_e1000 = {
    .name = "e1000",
    .version_id = 2,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .pre_save = e1000_pre_save,
    .post_load = e1000_post_load,
    .fields      = (VMStateField []) {
        VMSTATE_PCI_DEVICE(dev, E1000State),
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
    }
};

static const uint16_t e1000_eeprom_template[64] = {
    0x0000, 0x0000, 0x0000, 0x0000,      0xffff, 0x0000,      0x0000, 0x0000,
    0x3000, 0x1000, 0x6403, E1000_DEVID, 0x8086, E1000_DEVID, 0x8086, 0x3040,
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

    memory_region_init_io(&d->mmio, &e1000_mmio_ops, d, "e1000-mmio",
                          PNPMMIO_SIZE);
    memory_region_add_coalescing(&d->mmio, 0, excluded_regs[0]);
    for (i = 0; excluded_regs[i] != PNPMMIO_SIZE; i++)
        memory_region_add_coalescing(&d->mmio, excluded_regs[i] + 4,
                                     excluded_regs[i+1] - excluded_regs[i] - 4);
    memory_region_init_io(&d->io, &e1000_io_ops, d, "e1000-io", IOPORT_SIZE);
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
    E1000State *d = DO_UPCAST(E1000State, dev, dev);

    qemu_del_timer(d->autoneg_timer);
    qemu_free_timer(d->autoneg_timer);
    qemu_del_timer(d->mit_timer);
    qemu_free_timer(d->mit_timer);
#ifdef PARAVIRT
    qemu_bh_delete(d->tx_bh);
#endif /* PARAVIRT */
    IFRATE(qemu_del_timer(d->rate_timer); qemu_free_timer(d->rate_timer));
    memory_region_destroy(&d->mmio);
    memory_region_destroy(&d->io);
    qemu_del_nic(d->nic);
}

static NetClientInfo net_e1000_info = {
    .type = NET_CLIENT_OPTIONS_KIND_NIC,
    .size = sizeof(NICState),
    .can_receive = e1000_can_receive,
    .receive = e1000_receive,
    .cleanup = e1000_cleanup,
    .link_status_changed = e1000_set_link_status,
};

static int pci_e1000_init(PCIDevice *pci_dev)
{
    E1000State *d = DO_UPCAST(E1000State, dev, pci_dev);
    uint8_t *pci_conf;
    uint16_t checksum = 0;
    int i;
    uint8_t *macaddr;

    pci_conf = d->dev.config;

    /* TODO: RST# value should be 0, PCI spec 6.2.4 */
    pci_conf[PCI_CACHE_LINE_SIZE] = 0x10;

    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */

    e1000_mmio_setup(d);

    pci_register_bar(&d->dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &d->mmio);

    pci_register_bar(&d->dev, 1, PCI_BASE_ADDRESS_SPACE_IO, &d->io);

    memmove(d->eeprom_data, e1000_eeprom_template,
        sizeof e1000_eeprom_template);
    qemu_macaddr_default_if_unset(&d->conf.macaddr);
    macaddr = d->conf.macaddr.a;
    for (i = 0; i < 3; i++)
        d->eeprom_data[i] = (macaddr[2*i+1]<<8) | macaddr[2*i];
    for (i = 0; i < EEPROM_CHECKSUM_REG; i++)
        checksum += d->eeprom_data[i];
    checksum = (uint16_t) EEPROM_SUM - checksum;
    d->eeprom_data[EEPROM_CHECKSUM_REG] = checksum;

    d->nic = qemu_new_nic(&net_e1000_info, &d->conf,
                          object_get_typename(OBJECT(d)), d->dev.qdev.id, d);

    qemu_format_nic_info_str(qemu_get_queue(d->nic), macaddr);

    add_boot_device_path(d->conf.bootindex, &pci_dev->qdev, "/ethernet-phy@0");

    d->autoneg_timer = qemu_new_timer_ms(vm_clock, e1000_autoneg_timer, d);

    d->mit_timer = qemu_new_timer_ns(vm_clock, mit_rearm_and_int, d);
    IFRATE(d->rate_timer = qemu_new_timer_ms(vm_clock, &rate_callback, d));

#ifdef PARAVIRT
    d->tx_bh = qemu_bh_new(e1000_tx_bh, d);
#endif /* PARAVIRT */
    return 0;
}

static void qdev_e1000_reset(DeviceState *dev)
{
    E1000State *d = DO_UPCAST(E1000State, dev.qdev, dev);
    e1000_reset(d);
}

static Property e1000_properties[] = {
    DEFINE_NIC_PROPERTIES(E1000State, conf),
    DEFINE_PROP_BIT("autonegotiation", E1000State,
                    compat_flags, E1000_FLAG_AUTONEG_BIT, true),
    DEFINE_PROP_UINT32("mit_on", E1000State, mit_on, 5),
    DEFINE_PROP_END_OF_LIST(),
};

static void e1000_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->init = pci_e1000_init;
    k->exit = pci_e1000_uninit;
    k->romfile = "efi-e1000.rom";
    k->vendor_id = PCI_VENDOR_ID_INTEL;
    k->device_id = E1000_DEVID;
#ifdef PARAVIRT
    k->subsystem_id = E1000_PARA_SUBDEV;
#endif /* PARAVIRT */
    k->revision = 0x03;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    dc->desc = "Intel Gigabit Ethernet";
    dc->reset = qdev_e1000_reset;
    dc->vmsd = &vmstate_e1000;
    dc->props = e1000_properties;
}

static const TypeInfo e1000_info = {
    .name          = "e1000",
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(E1000State),
    .class_init    = e1000_class_init,
};

static void e1000_register_types(void)
{
    type_register_static(&e1000_info);
}

type_init(e1000_register_types)
