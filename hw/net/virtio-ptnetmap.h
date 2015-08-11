/*
 * ptnetmap support for virtio-net
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

#ifndef _QEMU_VIRTIO_PTNETMAP_H
#define _QEMU_VIRTIO_PTNETMAP_H


#ifdef CONFIG_NETMAP_PASSTHROUGH
/* ptnetmap virtio register BASE */
#define PTNETMAP_VIRTIO_IO_BASE         sizeof(struct virtio_net_config)

static int virtio_net_ptnetmap_up(VirtIODevice *vdev)
{
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(vdev)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    VirtIONet *n = VIRTIO_NET(vdev);
    VirtIONetQueue *q;
    VirtQueueElement elem;
    PTNetmapState *ptns = n->ptn.state;
    int i, ret, nvqs = 0;

    if (ptns == NULL) {
        printf("ERROR ptnetmap: not supported by backend\n");
        return -1;
    }

    if (n->ptn.up) {
        printf("ERROR ptnetmap: already UP\n");
        return -1;
    }

    if (n->ptn.csb == NULL) {
        printf("ERROR ptnetmap: CSB undefined\n");
        return -1;
    }

    if (!k->set_host_notifier && !k->set_guest_notifiers) {
        printf("ERROR ptnetmap: binding does not support notifiers\n");
        return -ENOSYS;
    }

    /* TODO-ste: add support for multiqueue */
    printf("max_queues: %d\n", n->max_queues);

    nvqs += 2;
    /* Stop processing guest/host IO notifications in qemu.
     * Start processing them in ptnetmap.
     */
    for (i = 0; i < nvqs; i++) {
        if (!virtio_queue_get_num(vdev, i)) {
            break;
        }
        ret = k->set_host_notifier(qbus->parent, i, true);
        if (ret < 0) {
            printf("ERROR ptnetmap: VQ %d notifier binding failed %d\n", i, -ret);
            nvqs = i - 1;
            goto err_notifiers;
        }
    }
    ret = k->set_guest_notifiers(qbus->parent, nvqs, true);
    if (ret < 0) {
        printf("ERROR ptnetmap: binding guest notifier %d", -ret);
        goto err_notifiers;
    }

    /* TODO for (i = 0; i < n->max_queues; i++) { */
    i = 0;
    q = &n->vqs[i];
#if 0
    if (q->tx_timer) {
        timer_del(q->tx_timer);
    } else {
        qemu_bh_cancel(q->tx_bh);
    }
#endif
    /* Configure the RX ring */
    n->ptn.cfg.rx_ring.ioeventfd = event_notifier_get_fd(virtio_queue_get_host_notifier(q->rx_vq));
    n->ptn.cfg.rx_ring.irqfd = event_notifier_get_fd(virtio_queue_get_guest_notifier(q->rx_vq));

    /* Configure the TX ring */
    n->ptn.cfg.tx_ring.ioeventfd = event_notifier_get_fd(virtio_queue_get_host_notifier(q->tx_vq));
    n->ptn.cfg.tx_ring.irqfd = event_notifier_get_fd(virtio_queue_get_guest_notifier(q->tx_vq));

    printf("rx [id: %d] - ioeventfd %d irqfd %d\n", virtio_get_queue_index(q->rx_vq), n->ptn.cfg.rx_ring.ioeventfd, n->ptn.cfg.rx_ring.irqfd);
    printf("tx [id: %d] - ioeventfd %d irqfd %d\n", virtio_get_queue_index(q->tx_vq), n->ptn.cfg.tx_ring.ioeventfd, n->ptn.cfg.tx_ring.irqfd);

    /* push fake-elem in the tx/rx queue to enable interrupts */
    if (virtqueue_pop(q->rx_vq, &elem)) {
        virtqueue_push(q->rx_vq, &elem, 0);
    }
    virtio_queue_set_notification(q->rx_vq, 1);
    if (virtqueue_pop(q->tx_vq, &elem)) {
        virtqueue_push(q->tx_vq, &elem, 0);
    }
    virtio_queue_set_notification(q->tx_vq, 1);

    /* Initialize CSB */
    n->ptn.cfg.csb = n->ptn.csb;
    n->ptn.csb->host_need_txkick = 1;
    n->ptn.csb->guest_need_txkick = 0;
    n->ptn.csb->guest_need_rxkick = 1;
    n->ptn.csb->host_need_rxkick = 1;

    n->ptn.cfg.features = PTNETMAP_CFG_FEAT_CSB | PTNETMAP_CFG_FEAT_EVENTFD;

    /* Configure the net backend. */
    ret = ptnetmap_create(n->ptn.state, &n->ptn.cfg);
    if (ret)
        goto err_ptn_create;

    n->ptn.up = true;
    return 0;

err_ptn_create:
    k->set_guest_notifiers(qbus->parent, nvqs, false);
err_notifiers:
    for (i = 0; i < nvqs; i++) {
        k->set_host_notifier(qbus->parent, i, false);
    }
    return ret;
}

static int virtio_net_ptnetmap_down(VirtIODevice *vdev)
{
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(vdev)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    VirtIONet *n = VIRTIO_NET(vdev);
    int i, ret, nvqs = 0;

    if (!n->ptn.state || !n->ptn.up) {
        return 0;
    }
    n->ptn.up = false;

    printf("max_queues: %d\n", n->max_queues);
    nvqs += 2;
    /* TODO for (i = 0; i < n->max_queues; i++) { */
    i = 0;
    /* Start processing guest/host IO notifications in qemu.
     */
    for (i = 0; i < nvqs; i++) {
        if (!virtio_queue_get_num(vdev, i)) {
            break;
        }
        ret = k->set_host_notifier(qbus->parent, i, false);
        if (ret < 0) {
            printf("ERROR ptnetmap: VQ %d notifier binding failed %d\n", i, -ret);
        }
    }
    ret = k->set_guest_notifiers(qbus->parent, nvqs, false);
    if (ret < 0) {
        printf("ERROR ptnetmap: binding guest notifier %d", -ret);
        return -1;
    }

    return ptnetmap_delete(n->ptn.state);
}

static int virtio_net_ptnetmap_get_mem(VirtIODevice *vdev)
{
    VirtIONet *n = VIRTIO_NET(vdev);
    PTNetmapState *ptns = n->ptn.state;
    struct paravirt_csb *csb = n->ptn.csb;
    int ret;

    ret = ptnetmap_get_mem(ptns);
    if (ret)
        return ret;

    if (csb == NULL) {
        printf("ERROR ptnetmap: csb not initialized\n");
        return ret;
    }
    csb->nifp_offset = ptns->offset;
    csb->num_tx_rings = ptns->num_tx_rings;
    csb->num_rx_rings = ptns->num_rx_rings;
    csb->num_tx_slots = ptns->num_tx_slots;
    csb->num_rx_slots = ptns->num_rx_slots;
    printf("txr %u rxr %u txd %u rxd %u nifp_offset %u\n",
            csb->num_tx_rings,
            csb->num_rx_rings,
            csb->num_tx_slots,
            csb->num_rx_slots,
            csb->nifp_offset);

    return ret;
}

static void virtio_net_ptnetmap_get_reg(VirtIODevice *vdev, uint8_t *config, uint32_t addr)
{
    VirtIONet *n = VIRTIO_NET(vdev);
    config += PTNETMAP_VIRTIO_IO_BASE;
    addr -= PTNETMAP_VIRTIO_IO_BASE;

    switch (addr) {
        case PTNETMAP_VIRTIO_IO_PTFEAT:
        case PTNETMAP_VIRTIO_IO_PTSTS:
            memcpy(config + addr, &n->ptn.reg[addr], 4);
            break;
        default:
            break;
    }
}

static void virtio_net_ptnetmap_set_reg(VirtIODevice *vdev, const uint8_t *config, uint32_t addr)
{
    VirtIONet *n = VIRTIO_NET(vdev);
    uint32_t *val, ret;

    if (n->ptn.state == NULL) {
        printf("ERROR ptnetmap: not supported by backend\n");
        return;
    }

    config += PTNETMAP_VIRTIO_IO_BASE;
    addr -= PTNETMAP_VIRTIO_IO_BASE;

    switch (addr) {
        case PTNETMAP_VIRTIO_IO_PTFEAT:
            memcpy(&n->ptn.reg[addr], config + addr, 4);
            val = (uint32_t *)(n->ptn.reg + addr);

            ret = (n->ptn.features &= *val);
            ptnetmap_ack_features(n->ptn.state, n->ptn.features);
            printf("ptnetmap acked features: %x\n", n->ptn.features);

            n->ptn.reg[PTNETMAP_VIRTIO_IO_PTFEAT] = ret;
            break;
        case PTNETMAP_VIRTIO_IO_PTCTL:
            memcpy(&n->ptn.reg[addr], config + addr, 4);
            val = (uint32_t *)(n->ptn.reg + addr);

            ret = EINVAL;

            switch(*val) {
                case NET_PARAVIRT_PTCTL_CONFIG:
                    ret = virtio_net_ptnetmap_get_mem(vdev);
                    break;
                case NET_PARAVIRT_PTCTL_REGIF:
                    ret = virtio_net_ptnetmap_up(vdev);
                    break;
                case NET_PARAVIRT_PTCTL_UNREGIF:
                    ret = virtio_net_ptnetmap_down(vdev);
                    break;
                case NET_PARAVIRT_PTCTL_HOSTMEMID:
                    ret = ptnetmap_get_hostmemid(n->ptn.state);
                    break;
                case NET_PARAVIRT_PTCTL_IFNEW:
                case NET_PARAVIRT_PTCTL_IFDELETE:
                case NET_PARAVIRT_PTCTL_FINALIZE:
                case NET_PARAVIRT_PTCTL_DEREF:
                    ret = 0;
                    break;
            }
            printf("PTSTS - ret %d\n", ret);
            n->ptn.reg[PTNETMAP_VIRTIO_IO_PTSTS] = ret;
            break;
        case PTNETMAP_VIRTIO_IO_CSBBAH:
            memcpy(&n->ptn.reg[addr], config + addr, 4);
            break;
        case PTNETMAP_VIRTIO_IO_CSBBAL:
            memcpy(&n->ptn.reg[addr], config + addr, 4);
            paravirt_configure_csb(&n->ptn.csb, *((uint32_t *)(n->ptn.reg + PTNETMAP_VIRTIO_IO_CSBBAL)),
                    *((uint32_t *)(n->ptn.reg + PTNETMAP_VIRTIO_IO_CSBBAH)), NULL, NULL);
            break;
        default:
            break;
    }
}

static PTNetmapState*
peer_get_ptnetmap(VirtIONet *n)
{
    NetClientState *nc = qemu_get_queue(n->nic);

    return qemu_peer_get_ptnetmap(nc);
}

static void virtio_net_ptnetmap_init(VirtIODevice *vdev)
{
    VirtIONet *n = VIRTIO_NET(vdev);

    n->ptn.up = false;
    n->ptn.state = peer_get_ptnetmap(n);
    if (n->ptn.state == NULL) {
        printf("ptnetmap not supported by backend\n");
        n->ptn.features = 0;
        return;
    }
    n->ptn.features = ptnetmap_get_features(n->ptn.state, NET_PTN_FEATURES_BASE);

    /* backend require ptnetmap support? */
    if (!(n->ptn.features & NET_PTN_FEATURES_BASE)) {
        printf("ptnetmap not supported/required\n");
        n->ptn.state = NULL;
        n->ptn.features = 0;
        return;
    }

    printf("ptnetmap-virtio init END\n");
}
#endif /* CONFIG_NETMAP_PASSTHROUGH */

#endif /* _QEMU_VIRTIO_PTNETMAP_H */
