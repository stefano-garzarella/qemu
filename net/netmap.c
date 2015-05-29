/*
 * netmap access for qemu
 *
 * Copyright (c) 2012-2013 Luigi Rizzo
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


#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap.h>
#include <net/netmap_user.h>

#include "net/net.h"
#include "net/tap.h"
#include "clients.h"
#include "sysemu/sysemu.h"
#include "qemu/error-report.h"
#include "qemu/iov.h"
#include "net/vhost_net.h"
#ifdef CONFIG_NETMAP_PASSTHROUGH
#include "net/ptnetmap.h"
#endif /* CONFIG_NETMAP_PASSTHROUGH */

/* XXX Use at your own risk: a synchronization problem in the netmap module
   can freeze your (host) machine. */
//#define USE_INDIRECT_BUFFERS

typedef struct NetmapState {
    NetClientState      nc;
    struct nm_desc      *nmd;
    char                ifname[IFNAMSIZ];
    struct netmap_ring  *txr;
    struct netmap_ring  *rxr;
    bool                read_poll;
    bool                write_poll;
    struct iovec        iov[IOV_MAX];
    PeerAsyncCallback	*txsync_callback;
    void		*txsync_callback_arg;
    VHostNetState *vhost_net;
    int                 vnet_hdr_len;  /* Current virtio-net header length. */
#ifdef CONFIG_NETMAP_PASSTHROUGH
    PTNetmapState       ptnetmap;
#endif /* CONFIG_NETMAP_PASSTHROUGH */
    QTAILQ_ENTRY(NetmapState) next;
} NetmapState;

static QTAILQ_HEAD(, NetmapState) netmap_clients = QTAILQ_HEAD_INITIALIZER(netmap_clients);
static bool netmap_clients_init = false;

#ifndef __FreeBSD__
#define pkt_copy bcopy
#else
/* A fast copy routine only for multiples of 64 bytes, non overlapped. */
static inline void
pkt_copy(const void *_src, void *_dst, int l)
{
    const uint64_t *src = _src;
    uint64_t *dst = _dst;
    if (unlikely(l >= 1024)) {
        bcopy(src, dst, l);
        return;
    }
    for (; l > 0; l -= 64) {
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
    }
}
#endif /* __FreeBSD__ */

/* Tell the event-loop if the netmap backend can send packets
   to the frontend. */
static int netmap_can_send(void *opaque)
{
    NetmapState *s = opaque;

    return qemu_can_send_packet(&s->nc);
}

static void netmap_send(void *opaque);
static void netmap_writable(void *opaque);

/* Set the event-loop handlers for the netmap backend. */
static void netmap_update_fd_handler(NetmapState *s)
{
    D("read_poll: %d, write_poll: %d", s->read_poll, s->write_poll);
    qemu_set_fd_handler2(s->nmd->fd,
                         s->read_poll  ? netmap_can_send : NULL,
                         s->read_poll  ? netmap_send     : NULL,
                         s->write_poll ? netmap_writable : NULL,
                         s);
}

/* Update the read handler. */
static void netmap_read_poll(NetmapState *s, bool enable)
{
    D("enable:%d", enable);
    if (s->read_poll != enable) { /* Do nothing if not changed. */
        s->read_poll = enable;
        netmap_update_fd_handler(s);
    }
}

/* Update the write handler. */
static void netmap_write_poll(NetmapState *s, bool enable)
{
    D("enable:%d", enable);
    if (s->write_poll != enable) {
        s->write_poll = enable;
        netmap_update_fd_handler(s);
    }
}

static void netmap_poll(NetClientState *nc, bool enable)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);

    D("enable:%d", enable);
    if (s->read_poll != enable || s->write_poll != enable) {
        s->write_poll = enable;
        s->read_poll  = enable;
        netmap_update_fd_handler(s);
    }
}

/*
 * The fd_write() callback, invoked if the fd is marked as
 * writable after a poll. Unregister the handler and flush any
 * buffered packets.
 */
static void netmap_writable(void *opaque)
{
    NetmapState *s = opaque;

    netmap_write_poll(s, false);
    qemu_flush_queued_packets(&s->nc);
}

static ssize_t netmap_receive_flags(NetClientState *nc,
      const uint8_t *buf, size_t size, unsigned flags)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);
    struct netmap_ring *ring = s->txr;
    uint32_t i;
    uint32_t idx;
    uint8_t *dst;

    if (unlikely(!ring)) {
        /* Drop. */
        return size;
    }

    if (unlikely(size > ring->nr_buf_size)) {
        RD(5, "[netmap_receive] drop packet of size %d > %d\n",
                                    (int)size, ring->nr_buf_size);
        return size;
    }

    if (nm_ring_empty(ring)) {
        /* No available slots in the netmap TX ring. */
        netmap_write_poll(s, true);
        return 0;
    }

    i = ring->cur;
    idx = ring->slot[i].buf_idx;
    dst = (uint8_t *)NETMAP_BUF(ring, idx);

    ring->slot[i].len = size;
#ifdef USE_INDIRECT_BUFFERS
    ring->slot[i].flags = NS_INDIRECT;
    *((const uint8_t **)dst) = buf;
#else
    ring->slot[i].flags = 0;
    pkt_copy(buf, dst, size);
#endif
    ring->cur = ring->head = nm_ring_next(ring, i);

    if (nm_ring_empty(ring) || !(flags & QEMU_NET_PACKET_FLAG_MORE)) {
        /* XXX should we require s->txsync_callback != NULL when
           QEMU_NET_PACKET_FLAG_MORE is set? There could be semantic
           problems, because the frontend expects the packet to be gone?
           */
        ioctl(s->nmd->fd, NIOCTXSYNC, NULL);
        if (s->txsync_callback) {
            s->txsync_callback(s->txsync_callback_arg);
        }
    }

    return size;
}

static ssize_t netmap_receive_iov_flags(NetClientState * nc,
	    const struct iovec * iov, int iovcnt, unsigned flags)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);
    struct netmap_ring *ring = s->txr;
    size_t size = iov_size(iov, iovcnt);
    uint32_t last;
    uint32_t idx;
    uint8_t *dst;
    int j;
    uint32_t i;

    if (unlikely(!ring)) {
	/* Drop the packet. */
	return size;
    }

    last = i = ring->cur;

    if (nm_ring_space(ring) < iovcnt) {
        /* Not enough netmap slots. */
        netmap_write_poll(s, true);
        size = 0;
        goto txsync;
    }

    for (j = 0; j < iovcnt; j++) {
        int iov_frag_size = iov[j].iov_len;
        int offset = 0;
        int nm_frag_size;

        /* Split each iovec fragment over more netmap slots, if
           necessary (without performing data copy). */
        while (iov_frag_size) {
            nm_frag_size = MIN(iov_frag_size, ring->nr_buf_size);

            if (unlikely(i == ring->tail)) {
                /* We run out of netmap slots while splitting the
                   iovec fragments. */
                netmap_write_poll(s, true);
                size = 0;
                goto txsync;
            }

            idx = ring->slot[i].buf_idx;
            dst = (uint8_t *)NETMAP_BUF(ring, idx);

            ring->slot[i].len = nm_frag_size;
#ifdef USE_INDIRECT_BUFFERS
            ring->slot[i].flags = NS_MOREFRAG | NS_INDIRECT;
            *((const uint8_t **)dst) = iov[j].iov_base + offset;
#else	/* !USE_INDIRECT_BUFFERS */
            ring->slot[i].flags = NS_MOREFRAG;
            pkt_copy(iov[j].iov_base + offset, dst, nm_frag_size);
#endif	/* !USING_INDIRECT_BUFFERS */

            last = i;
            i = nm_ring_next(ring, i);

            offset += nm_frag_size;
            iov_frag_size -= nm_frag_size;
        }
    }
    /* The last slot must not have NS_MOREFRAG set. */
    ring->slot[last].flags &= ~NS_MOREFRAG;

    /* Now update ring->cur and ring->head. */
    ring->cur = ring->head = i;

    if (nm_ring_empty(ring) || !(flags & QEMU_NET_PACKET_FLAG_MORE)) {
txsync:
        ioctl(s->nmd->fd, NIOCTXSYNC, NULL);
        if (s->txsync_callback) {
            s->txsync_callback(s->txsync_callback_arg);
        }
    }

    return size;
}

static ssize_t netmap_receive_iov(NetClientState * nc,
	    const struct iovec * iov, int iovcnt)
{
    return netmap_receive_iov_flags(nc, iov, iovcnt, 0);
}

static ssize_t netmap_receive(NetClientState *nc,
      const uint8_t *buf, size_t size)
{
	return netmap_receive_flags(nc, buf, size, 0);
}

/* Complete a previous send (backend --> guest) and enable the
   fd_read callback. */
static void netmap_send_completed(NetClientState *nc, ssize_t len)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);

    netmap_read_poll(s, true);
}

/*
 * netmap_send: backend -> guest
 * there is traffic available from the network, try to send it up.
 */
static void netmap_send(void *opaque)
{
    NetmapState *s = opaque;
    struct netmap_ring *ring = s->rxr;

    /* Keep sending while there are available packets into the netmap
       RX ring and the forwarding path towards the peer is open. */
    while (!nm_ring_empty(ring) && qemu_can_send_packet(&s->nc)) {
        uint32_t i;
        uint32_t idx;
	bool morefrag;
	int iovcnt = 0;
        int iovsize;

	do {
	    i = ring->cur;
	    idx = ring->slot[i].buf_idx;
	    morefrag = (ring->slot[i].flags & NS_MOREFRAG);
	    s->iov[iovcnt].iov_base = (u_char *)NETMAP_BUF(ring, idx);
	    s->iov[iovcnt].iov_len = ring->slot[i].len;
	    iovcnt++;

            ring->cur = ring->head = nm_ring_next(ring, i);
        } while (!nm_ring_empty(ring) && morefrag);

        if (unlikely(nm_ring_empty(ring) && morefrag)) {
            RD(5, "[netmap_send] ran out of slots, with a pending"
                   "incomplete packet\n");
	}

	iovsize = qemu_sendv_packet_async_moreflags(&s->nc, s->iov, iovcnt,
		    netmap_send_completed,
                    nm_ring_empty(ring) ? 0 : QEMU_NET_PACKET_FLAG_MORE);

        if (iovsize == 0) {
            /* The peer does not receive anymore. Packet is queued, stop
             * reading from the backend until netmap_send_completed()
             */
            netmap_read_poll(s, false);
            return;
        }
    }
}

#ifdef USE_INDIRECT_BUFFERS
static void netmap_register_peer_async_callback(NetClientState *nc,
		    PeerAsyncCallback *cb, void *opaque)
{
    struct NetmapState *s = DO_UPCAST(NetmapState, nc, nc);

    s->txsync_callback = cb;
    s->txsync_callback_arg = opaque;
}
#endif

/* Flush and close. */
static void netmap_cleanup(NetClientState *nc)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);

    if (s->vhost_net) {
        vhost_net_cleanup(s->vhost_net);
        s->vhost_net = NULL;
        D("vhost cleanup\n");
    }

    qemu_purge_queued_packets(nc);

#ifdef CONFIG_NETMAP_PASSTHROUGH
    if (s->ptnetmap.created) {
        ptnetmap_delete(&s->ptnetmap);
    }
#endif /* CONFIG_NETMAP_PASSTHROUGH */

    netmap_poll(nc, false);
    nm_close(s->nmd);
    s->nmd = NULL;

    QTAILQ_REMOVE(&netmap_clients, s, next);
}

/* Offloading manipulation support callbacks. */
static bool netmap_has_ufo(NetClientState *nc)
{
    return true;
}

static bool netmap_has_vnet_hdr(NetClientState *nc)
{
    return true;
}

static bool netmap_has_vnet_hdr_len(NetClientState *nc, int len)
{
    return len == 0 || len == sizeof(struct virtio_net_hdr) ||
                len == sizeof(struct virtio_net_hdr_mrg_rxbuf);
}

static void netmap_using_vnet_hdr(NetClientState *nc, bool enable)
{
}

static void netmap_set_vnet_hdr_len(NetClientState *nc, int len)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);
    int err;
    struct nmreq req;

    /* Issue a NETMAP_BDG_VNET_HDR command to change the virtio-net header
     * length for the netmap adapter associated to 'ifname'.
     */
    memset(&req, 0, sizeof(req));
    pstrcpy(req.nr_name, sizeof(req.nr_name), s->ifname);
    req.nr_version = NETMAP_API;
    req.nr_cmd = NETMAP_BDG_VNET_HDR;
    req.nr_arg1 = len;
    err = ioctl(s->nmd->fd, NIOCREGIF, &req);
    if (err) {
        error_report("Unable to execute NETMAP_BDG_VNET_HDR on %s: %s",
                     s->ifname, strerror(errno));
    } else {
        /* Keep track of the current length. */
        s->vnet_hdr_len = len;
    }
}

static void netmap_set_offload(NetClientState *nc, int csum, int tso4, int tso6,
                               int ecn, int ufo)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);

    /* Setting a virtio-net header length greater than zero automatically
     * enables the offloadings.
     */
    if (!s->vnet_hdr_len) {
        netmap_set_vnet_hdr_len(nc, sizeof(struct virtio_net_hdr));
    }
}

static int netmap_get_fd(NetClientState *nc)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);

    return s->nmd->fd;
}

static VHostNetState *netmap_get_vhost_net(NetClientState *nc)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);

    return s->vhost_net;
}

/*
 * ptnetmap routines
 */
#ifdef CONFIG_NETMAP_PASSTHROUGH
static PTNetmapState *
netmap_get_ptnetmap(NetClientState *nc)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);


    ptnetmap_memdev_create(s->nmd->mem, s->nmd->memsize, s->nmd->req.nr_arg2);

    return &s->ptnetmap;
}

/* return the subset of requested features that we support */
uint32_t
ptnetmap_get_features(PTNetmapState *ptn, uint32_t features)
{
    return ptn->features & features;
}

/* store the agreed upon features */
void
ptnetmap_ack_features(PTNetmapState *ptn, uint32_t features)
{
    ptn->acked_features |= features;
}

/* XXX: set mem info in net_init_netmap()?? */
int
ptnetmap_get_mem(PTNetmapState *ptn)
{
    NetmapState *s = ptn->netmap;

    if (s->nmd == NULL)
        return EINVAL;
    ptn->offset = s->nmd->req.nr_offset;
    ptn->num_tx_rings = s->nmd->req.nr_tx_rings;
    ptn->num_rx_rings = s->nmd->req.nr_rx_rings;
    ptn->num_tx_slots = s->nmd->req.nr_tx_slots;
    ptn->num_rx_slots = s->nmd->req.nr_rx_slots;
    return 0;
}

int
ptnetmap_get_hostmemid(PTNetmapState *ptn)
{
    NetmapState *s = ptn->netmap;

    if (s->nmd == NULL)
        return EINVAL;

    return s->nmd->req.nr_arg2;
}

/* find parent MemoryRegion */
static MemoryRegion*
ptnetmap_find_parent_mr(PTNetmapState *ptn)
{
    NetmapState *s;

    QTAILQ_FOREACH(s, &netmap_clients, next) {
        ptnetmap_get_mem(&s->ptnetmap);
        if ((s->ptnetmap.mem == ptn->mem) && (s->ptnetmap.memsize == ptn->memsize)
                && s->ptnetmap.mr_init && !s->ptnetmap.mr_alias) {
            return &s->ptnetmap.mr;
        }
    }

    return NULL;
}

/* init ram ptr to netmap allocator */
struct MemoryRegion *
ptnetmap_init_ram_ptr(PTNetmapState *ptn)
{
    MemoryRegion *parent_mr;
    char mem_name[256]; //XXX

    if (ptn->mr_init) {
        goto already_init;
    }

    ptnetmap_get_mem(ptn);

    parent_mr = ptnetmap_find_parent_mr(ptn);
    if (parent_mr) { /* create an alias of parent MemoryRegion */
        D("mapped with alias");
        snprintf(mem_name, 256, "netmap-%s-alias", ptn->netmap->ifname);
        memory_region_init_alias(&ptn->mr, NULL, mem_name, parent_mr, 0, ptn->memsize);
        ptn->mr_alias = true;
    } else { /* init a new MemoryRegion */
        /* XXX: maybe is better if the OWNER is the NIC. Now the owner is the vm */
        snprintf(mem_name, 256, "netmap-%s", ptn->netmap->ifname);
        memory_region_init_ram_ptr(&ptn->mr, NULL, mem_name, ptn->memsize, ptn->mem);
        vmstate_register_ram_global(&ptn->mr);
        D("BAR mapped - name: %s size: %lu", mem_name, (long unsigned)ptn->memsize);
    }
    ptn->mr_init = true;
already_init:
    return &ptn->mr;
}

int
ptnetmap_create(PTNetmapState *ptn, struct ptnetmap_cfg *conf)
{
    NetmapState *s = ptn->netmap;
    int err;
    struct nmreq req;

    if (!(ptn->acked_features & NET_PTN_FEATURES_BASE)) {
        error_report("ptnetmap features not acked");
        return EFAULT;
    }

    if (ptn->created)
        return 0;

    /* disable poll */
    netmap_poll(&s->nc, false);
    qemu_purge_queued_packets(&s->nc);

    /* ioctl to create ptnetmap kthreads */
    memset(&req, 0, sizeof(req));
    pstrcpy(req.nr_name, sizeof(req.nr_name), s->ifname);
    req.nr_version = NETMAP_API;
    ptnetmap_write_cfg(&req, conf);
    req.nr_cmd = NETMAP_PT_HOST_CREATE;
    err = ioctl(s->nmd->fd, NIOCREGIF, &req);
    if (err) {
        error_report("Unable to execute NETMAP_PT_HOST_CREATE on %s: %s",
                     s->ifname, strerror(errno));
    } else
        ptn->created = true;

    return err;
}

int
ptnetmap_delete(PTNetmapState *ptn)
{
    NetmapState *s = ptn->netmap;
    int err;
    struct nmreq req;

    if (!(ptn->acked_features & NET_PTN_FEATURES_BASE)) {
        error_report("ptnetmap features not acked");
        return EFAULT;
    }

    if (!ptn->created)
        return 0;

    /* ioctl to delete ptnetmap kthreads */
    memset(&req, 0, sizeof(req));
    pstrcpy(req.nr_name, sizeof(req.nr_name), s->ifname);
    req.nr_version = NETMAP_API;
    req.nr_cmd = NETMAP_PT_HOST_DELETE;
    err = ioctl(s->nmd->fd, NIOCREGIF, &req);
    if (err) {
        error_report("Unable to execute NETMAP_PT_HOST_DELETE on %s: %s",
                     s->ifname, strerror(errno));
    }

    ptn->created = false;
    /* enable poll to restore netmap port */
    netmap_poll(&s->nc, true);

    return err;
}
#endif /* CONFIG_NETMAP_PASSTHROUGH */

/* NetClientInfo methods */
static NetClientInfo net_netmap_info = {
    .type = NET_CLIENT_OPTIONS_KIND_NETMAP,
    .size = sizeof(NetmapState),
    .receive_flags = netmap_receive_flags,
    .receive = netmap_receive,
    .receive_iov_flags = netmap_receive_iov_flags,
    .receive_iov = netmap_receive_iov,
    .poll = netmap_poll,
#ifdef USE_INDIRECT_BUFFERS
    .register_peer_async_callback = netmap_register_peer_async_callback,
#endif
    .cleanup = netmap_cleanup,
    .has_ufo = netmap_has_ufo,
    .has_vnet_hdr = netmap_has_vnet_hdr,
    .has_vnet_hdr_len = netmap_has_vnet_hdr_len,
    .using_vnet_hdr = netmap_using_vnet_hdr,
    .set_offload = netmap_set_offload,
    .set_vnet_hdr_len = netmap_set_vnet_hdr_len,
    .get_fd = netmap_get_fd,
    .get_vhost_net = netmap_get_vhost_net,
#ifdef CONFIG_NETMAP_PASSTHROUGH
    .get_ptnetmap = netmap_get_ptnetmap,
#endif /* CONFIG_NETMAP_PASSTHROUGH */
};

/*
 * find nm_desc parent with same allocator
 */
static struct nm_desc*
netmap_find_parent(struct nm_desc *nmd)
{
    NetmapState *s;

    QTAILQ_FOREACH(s, &netmap_clients, next) {
        if (nmd->req.nr_arg2 == s->nmd->req.nr_arg2) {
            D("found parent - ifname: %s mem_id: %d", s->ifname, s->nmd->req.nr_arg2);
            return s->nmd;
        }
    }

    return NULL;
}

/* The exported init function
 *
 * ... -net netmap,ifname="..."
 */
int net_init_netmap(const NetClientOptions *opts,
        const char *name, NetClientState *peer)
{
    const NetdevNetmapOptions *netmap_opts = opts->netmap;
    NetClientState *nc;
    struct nm_desc *nmd;
    struct nm_desc *parent_nmd;
    NetmapState *s;
    struct nmreq req;

    /* Init netmap_clients queue */
    if (!netmap_clients_init) {
        QTAILQ_INIT(&netmap_clients);
        netmap_clients_init = true;
    }

    memset(&req, 0, sizeof(req));

    if (netmap_opts->rings) {
        req.nr_tx_rings = netmap_opts->rings;
        req.nr_rx_rings = netmap_opts->rings;
    }
    if (netmap_opts->slots) {
        req.nr_tx_slots = netmap_opts->slots;
        req.nr_rx_slots = netmap_opts->slots;
    }
    if (netmap_opts->txrings) {
	req.nr_tx_rings = netmap_opts->txrings;
    }
    if (netmap_opts->rxrings) {
	req.nr_rx_rings = netmap_opts->rxrings;
    }
    if (netmap_opts->txslots) {
	req.nr_tx_slots = netmap_opts->txslots;
    }
    if (netmap_opts->rxslots) {
	req.nr_rx_slots = netmap_opts->txslots;
    }
#ifdef CONFIG_NETMAP_PASSTHROUGH
    if (netmap_opts->passthrough) {
        req.nr_flags |= NR_PASSTHROUGH_HOST;
        D("ptnetmap required");
    }
#endif /* CONFIG_NETMAP_PASSTHROUGH */

    nmd = nm_open(netmap_opts->ifname, &req, NETMAP_NO_TX_POLL | NETMAP_DO_RX_POLL | NM_OPEN_NO_MMAP, NULL);
    if (nmd == NULL) {
        error_report("Failed to open %ss: %s", netmap_opts->ifname, strerror(errno));
        return -1;
    }
    /* check parent (nm_desc with the same allocator already mapped) */
    parent_nmd = netmap_find_parent(nmd);
    /* mmap or inherit from parent */
    if (nm_mmap(nmd, parent_nmd)) {
        error_report("failed to mmap %s: %s", netmap_opts->ifname, strerror(errno));
        nm_close(nmd);
        return -1;
    }

    D("cfg: tx %d*%d rx %d*%d",
        nmd->req.nr_tx_slots,
        nmd->req.nr_tx_rings,
        nmd->req.nr_rx_slots,
        nmd->req.nr_rx_rings);
    /* Create the object. */
    nc = qemu_new_net_client(&net_netmap_info, peer, "netmap", name);
    s = DO_UPCAST(NetmapState, nc, nc);
    s->nmd = nmd;
    s->txr = NETMAP_TXRING(nmd->nifp, 0);
    s->rxr = NETMAP_RXRING(nmd->nifp, 0);
    s->vnet_hdr_len = 0;
    netmap_read_poll(s, true); /* Initially only poll for reads. */
    pstrcpy(s->ifname, sizeof(s->ifname), netmap_opts->ifname);
    s->txsync_callback = s->txsync_callback_arg = NULL;

#ifdef CONFIG_NETMAP_PASSTHROUGH
    if (netmap_opts->passthrough) {
        s->ptnetmap.netmap = s;
        s->ptnetmap.features = NET_PTN_FEATURES_BASE;
        s->ptnetmap.acked_features = 0;
        s->ptnetmap.created = false;
    }
#endif /* CONFIG_NETMAP_PASSTHROUGH */

    if (netmap_opts->has_vhost && netmap_opts->vhost) {
        VhostNetOptions options;
        int vhostfd;

        vhostfd = open("/dev/vhost-net", O_RDWR);
        if (vhostfd < 0) {
            error_report("netmap: open vhost char device failed: %s",
                         strerror(errno));
            return -1;
        }

        memset(&options, 0, sizeof(options));
        options.backend_type = VHOST_BACKEND_TYPE_KERNEL;
        options.net_backend = &s->nc;
        options.force = 0;
        options.opaque = (void *)(uintptr_t)vhostfd;

        s->vhost_net = vhost_net_init(&options);
        if (!s->vhost_net) {
            error_report("vhost-net requested but could not be initialized");
            return -1;
        }
        D("vhost init\n");
    }

    QTAILQ_INSERT_TAIL(&netmap_clients, s, next);

    return 0;
}

