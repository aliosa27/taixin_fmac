
#ifdef __RTOS__
#include <linux/types.h>
#include <linux/unaligned.h>
#include <linux/bitops.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/completion.h>
#include <linux/rcu.h>
#include <linux/semaphore.h>
#include <linux/timer.h>

#else
#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/firmware.h>
#include <linux/workqueue.h>
#include <linux/wireless.h>
#include <linux/etherdevice.h>
#include <linux/version.h>
#include <linux/rtnetlink.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif

#include "hgicf.h"
#include "ctrl.h"
#include "event.h"

static int txq_size = 1024;
static int if_test  = 0;
static int no_bootdl = 0;
static int qc_mode = 0;
static char *ifname =  "hg%d";
static int if_agg   = 0;
static char *conf_file = "/etc/hgicf.conf";
static int proc_dev = 0;
static char *fw_file = "hgicf.bin";
#ifdef __RTOS__
static hgic_init_cb  init_cb = NULL;
static hgic_event_cb event_cb = NULL;
#endif

static const u16 hgic_fmac_devid[] = {
    HGIC_WLAN_4002,
    HGIC_WLAN_8400,
};

#define TXWND_INIT_VAL (3)

#ifdef __RTOS__
void dev_queue_xmit(struct sk_buff *skb)
{
    struct net_device *ndev = skb->dev;
    if (ndev) {
        ndev->netdev_ops->ndo_start_xmit(skb, ndev);
    } else {
        kfree_skb(skb);
    }
}
#endif

static u8 hgicf_match_devid(u16 dev_id)
{
    int i = 0;
    for (i = 0; i < ARRAYSIZE(hgic_fmac_devid); i++) {
        if (dev_id == hgic_fmac_devid[i]) {
            return 1;
        }
    }
    return 0;
}

static u16 hgicf_data_cookie(struct hgicf_wdev *hg)
{
    unsigned long flags;
    uint16_t cookie = 0;

    spin_lock_irqsave(&hg->lock, flags);
    cookie = hg->data_cookie++;
    spin_unlock_irqrestore(&hg->lock, flags);
    return cookie;
}

static void hgicf_load_config(struct hgicf_wdev *hg)
{
#ifndef __RTOS__
    struct file *fp = NULL;
    struct iwreq wrqin;
    struct net_device *ndev = hg->vif->ndev;
    ssize_t ret = 0;
    char *conf = kzalloc(2048, GFP_KERNEL);
    char *ptr, *str;
    char path[64];

    if (strstr(conf_file, ".conf")) {
        strcpy(path, conf_file);
    } else {
        sprintf(path, "%s/%s.conf", conf_file, ndev->name);
    }

    fp = filp_open(path, O_RDONLY, 0);
    if (!IS_ERR(fp) && conf) {
        hgic_err("load conf file: %s\r\n", path);
        ret = _KERNEL_READ(fp, conf, 2048);
        str = conf;

        while (str) {
            ptr = strchr(str, '\n');
            if (ptr) {
                if (*(ptr - 1) == '\r') {
                    *(ptr - 1) = 0;
                }
                *ptr++ = 0;
            }

            wrqin.u.data.length = strlen(str);
            if (wrqin.u.data.length > 0) {
                hgic_dbg("param: [%s]\r\n", str);
                wrqin.u.data.pointer = str;
                ret = hgicf_ioctl_set_proc(ndev, &wrqin);
                if (ret < 0) {
                    hgic_err("invalid param:[%s]\r\n", str);
                }
            }
            str = ptr;
        }
    } else {
        hgic_err("can not open %s\r\n", path);
    }

    if (!IS_ERR(fp)) {
        filp_close(fp, NULL);
    }
    if (conf) {
        kfree(conf);
    }
#endif
}

static int hgicf_netif_open(struct net_device *dev)
{
    struct hgicf_vif *vif = (struct hgicf_vif *)netdev_priv(dev);
    if (!test_bit(HGICF_DEV_FLAGS_RUNNING, &vif->hg->flags)) {
        return 0;
    }
    vif->opened = 1;
    return hgic_fwctrl_open_dev(&(vif->hg->ctrl), vif->fwifidx);
}

static int hgicf_netif_stop(struct net_device *dev)
{
    struct hgicf_vif *vif = (struct hgicf_vif *)netdev_priv(dev);
    if (!test_bit(HGICF_DEV_FLAGS_RUNNING, &vif->hg->flags)) {
        return 0;
    }
    vif->opened = 0;
    return hgic_fwctrl_close_dev(&(vif->hg->ctrl), vif->fwifidx);
}

static void hgicf_netif_uninit(struct net_device *dev)
{
    struct hgicf_vif *vif = (struct hgicf_vif *)netdev_priv(dev);
    if (!test_bit(HGICF_DEV_FLAGS_RUNNING, &vif->hg->flags)) {
        return;
    }
}

static netdev_tx_t hgicf_netif_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct hgic_frm_hdr2 *hdr = NULL;
    struct hgicf_vif *vif = (struct hgicf_vif *)netdev_priv(dev);

    if (!test_bit(HGICF_DEV_FLAGS_RUNNING, &vif->hg->flags) || (vif->hg->tx_dataq.qlen > txq_size) ||
        test_bit(HGIC_BUS_FLAGS_SLEEP, &vif->hg->bus->flags)) {
        dev_kfree_skb(skb);
        vif->stats.tx_dropped += skb->len;
        return NETDEV_TX_OK;
    }

#ifndef __RTOS__
    if (skb_headroom(skb) < sizeof(struct hgic_frm_hdr2)) {
        struct sk_buff *nskb = skb_copy_expand(skb, skb->dev->needed_headroom,
                                               skb->dev->needed_tailroom, GFP_KERNEL);
        dev_kfree_skb(skb);
        if (nskb == NULL) {
            return NETDEV_TX_OK;
        }
        skb = nskb;
    }
#endif

    hdr = (struct hgic_frm_hdr2 *)skb_push(skb, sizeof(struct hgic_frm_hdr2));
    hdr->hdr.ifidx  = vif->fwifidx;
    hdr->hdr.length = cpu_to_le16(skb->len);
    hdr->hdr.magic  = cpu_to_le16(HGIC_HDR_TX_MAGIC);
    hdr->hdr.type   = HGIC_HDR_TYPE_FRM2;
    hdr->hdr.flags  = 0;
    skb_queue_tail(&vif->hg->tx_dataq, skb);
    queue_work(vif->hg->tx_wq, &vif->hg->tx_work);
    vif->stats.tx_bytes += skb->len;
    return NETDEV_TX_OK;
}

static int hgicf_netif_change_mac(struct net_device *dev, void *addr)
{
    int ret = 0;
#ifdef __RTOS__
    ret = hgicf_ioctl(dev, HGIC_CMD_SET_MAC, addr, 0);
#else
    struct hgicf_vif *vif = (struct hgicf_vif *)netdev_priv(dev);
    struct sockaddr  *sa  = (struct sockaddr *)addr;

    if (!test_bit(HGICF_DEV_FLAGS_RUNNING, &vif->hg->flags)) {
        return 0;
    }
    ret = hgic_fwctrl_set_mac(&(vif->hg->ctrl), vif->fwifidx, sa->sa_data);
    if (!ret) {
        ret = eth_mac_addr(dev, addr);
    }
#endif
    return ret;
}

static void hgicf_netif_set_multicast_list(struct net_device *dev)
{
    struct hgicf_vif *vif = (struct hgicf_vif *)netdev_priv(dev);
    if (!test_bit(HGICF_DEV_FLAGS_RUNNING, &vif->hg->flags)) {
        return;
    }
}

#ifdef __RTOS__
static int hgicf_netif_ioctl(struct net_device *dev, u32 cmd, u32 param1, u32 param2)
{
    return hgicf_ioctl(dev, cmd, param1, param2);
}
int hgicf_cmd(char *ifname, unsigned int cmd, unsigned int param1, unsigned int param2)
{
    struct net_device *ndev = net_device_get_by_name(ifname);
    if (ndev == NULL) {
        return -ENODEV;
    }
    return hgicf_netif_ioctl(ndev, cmd, param1, param2);
}
#else
static int hgicf_netif_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
    struct hgicf_vif *vif = (struct hgicf_vif *)netdev_priv(dev);
    if (!test_bit(HGICF_DEV_FLAGS_RUNNING, &vif->hg->flags)) {
        return 0;
    }
    return hgicf_ioctl(dev, ifr, cmd);
}
#endif

static struct net_device_stats *hgicf_netdev_get_stats(struct net_device *ndev)
{
    struct hgicf_vif *vif = (struct hgicf_vif *)netdev_priv(ndev);
    return &vif->stats;
}

static const struct net_device_ops hgicf_netif_ops = {
    .ndo_open            = hgicf_netif_open,
    .ndo_stop            = hgicf_netif_stop,
    .ndo_uninit          = hgicf_netif_uninit,
    .ndo_start_xmit      = hgicf_netif_xmit,
    .ndo_set_rx_mode     = hgicf_netif_set_multicast_list,
    .ndo_set_mac_address = hgicf_netif_change_mac,
    .ndo_do_ioctl        = hgicf_netif_ioctl,
    .ndo_get_stats       = hgicf_netdev_get_stats,
};

static void hgicf_netif_setup(struct net_device *dev)
{
#ifdef __RTOS__
    dev->netdev_ops = &hgicf_netif_ops;
#else
    ether_setup(dev);
    dev->netdev_ops = &hgicf_netif_ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
    dev->priv_destructor = free_netdev;
#else
    dev->destructor = free_netdev;
#endif
#endif
}

static int hgicf_request_txwnd(struct hgic_bus *bus)
{
    struct hgic_hdr *hdr = NULL;
    struct sk_buff *skb = dev_alloc_skb(sizeof(struct hgic_hdr) + 2);

    if (skb == NULL) {
        return -ENOMEM;
    }

    hdr = (struct hgic_hdr *)skb->data;
    hdr->magic  = cpu_to_le16(HGIC_HDR_TX_MAGIC);
    hdr->length = cpu_to_le16(sizeof(struct hgic_hdr) + 2);
    hdr->cookie = 0;
    hdr->type  = HGIC_HDR_TYPE_SOFTFC;
    hdr->ifidx = 1;
    hdr->flags = 0;
    skb_put(skb, sizeof(struct hgic_hdr) + 2);
    return bus->tx_packet(bus, skb);
}

static int hgicf_check_txwnd(struct hgicf_wdev *hg, u8 min_wnd)
{
    if (!hg->soft_fc || test_bit(HGIC_BUS_FLAGS_INBOOT, &hg->bus->flags)) {
        return 0;
    }
    
    if(test_bit(HGIC_BUS_FLAGS_SLEEP, &hg->bus->flags) ||
       test_bit(HGICF_DEV_FLAGS_SUSPEND, &hg->flags) ||
       !test_bit(HGICF_DEV_FLAGS_RUNNING, &hg->flags)){
       return -1;
    }

    if(atomic_read(&hg->txwnd) < min_wnd){
        hgicf_request_txwnd(hg->bus);
    }

    if (atomic_read(&hg->txwnd) < min_wnd) {
        return -1;
    } else {
        atomic_dec(&hg->txwnd);
    }
    return 0;
}

static void hgicf_tx_complete(void *hgobj, struct sk_buff *skb, int success)
{
    struct hgic_ctrl_hdr *hdr = (struct hgic_ctrl_hdr *)skb->data;
    struct hgicf_wdev    *hg  = (struct hgicf_wdev *)hgobj;

    if (hg->if_test) {
        hg->test_tx_len += skb->len;
    }

    if (success) {
        //hgic_err("hdr type %d, tx sucess\r\n", hdr->hdr.type);
        clear_bit(HGIC_BUS_FLAGS_ERROR, &hg->bus->flags);
    } else {
        hgic_err("tx failed\r\n");

        if (hdr->hdr.magic == cpu_to_le16(HGIC_HDR_TX_MAGIC)) {
            if ((hdr->hdr.type == HGIC_HDR_TYPE_CMD || hdr->hdr.type == HGIC_HDR_TYPE_CMD2) && HDR_CMDID(hdr) == HGIC_CMD_ENTER_SLEEP) {
                clear_bit(HGIC_BUS_FLAGS_SLEEP, &hg->bus->flags);
            }
        }

        hg->status.tx_fail++;
        set_bit(HGIC_BUS_FLAGS_ERROR, &hg->bus->flags);
        if (test_bit(HGICF_DEV_FLAGS_RUNNING, &hg->flags)) {
            schedule_work(&hg->detect_work);
        }
    }
    dev_kfree_skb_any(skb);
}

static void hgicf_test_work(struct work_struct *work)
{
    int ret    = 0;
    u32 diff_jiff = 0;
    struct hgicf_wdev *hg  = NULL;
    struct sk_buff    *skb = NULL;
    struct hgic_frm_hdr *frmhdr = NULL;

    printk("start if test ...\r\n");
    hg = container_of(work, struct hgicf_wdev, test_work);
    hg->test_jiff = jiffies;

    //set_bit(HGIC_BUS_FLAGS_DISABLE_REINIT, &hg->bus->flags);
    while (test_bit(HGICF_DEV_FLAGS_RUNNING, &hg->flags)) {
        if (time_after(jiffies, hg->test_jiff + msecs_to_jiffies(5000))) {
            diff_jiff = jiffies_to_msecs(jiffies - hg->test_jiff);
            diff_jiff /= 1000;
            if (diff_jiff == 0) { diff_jiff = 0xffff; }
            printk("HGIC IF TEST: tx:%d KB/s, rx:%d KB/s (%d %d %d)\r\n",
                   (hg->test_tx_len / 1024) / diff_jiff,
                   (hg->test_rx_len / 1024) / diff_jiff,
                   hg->test_tx_len, hg->test_rx_len, diff_jiff);
            hg->test_rx_len = 0;
            hg->test_tx_len = 0;
            hg->test_jiff = jiffies;
        }

        skb = dev_alloc_skb(1500 + hg->bus->drv_tx_headroom);
        if (skb) {
            skb_reserve(skb, hg->bus->drv_tx_headroom);
            frmhdr = (struct hgic_frm_hdr *)skb->data;
            frmhdr->hdr.magic  = cpu_to_le16(HGIC_HDR_TX_MAGIC);
            frmhdr->hdr.length = cpu_to_le16(1500);
            frmhdr->hdr.cookie = cpu_to_le16(hgicf_data_cookie(hg));
            frmhdr->hdr.type   = (hg->if_test == 1 ? HGIC_HDR_TYPE_TEST : HGIC_HDR_TYPE_TEST2);
            frmhdr->hdr.ifidx  = 0;

            if (hg->if_test == 3) {
                memset(skb->data + 8, 0xAA, 1500 - 8);
            }

            skb_put(skb, 1500);
            while (test_bit(HGICF_DEV_FLAGS_RUNNING, &hg->flags) && hgicf_check_txwnd(hg, TXWND_INIT_VAL)) {
                msleep(10);
            }

            ret = hg->bus->tx_packet(hg->bus, skb);
            if (ret) {
                msleep(10);
            }
        } else {
            msleep(10);
        }
    }
    hgic_dbg("if test stop!\r\n");
}

static void hgicf_tx_single_frm(struct hgicf_wdev *hg, struct sk_buff *skb)
{
    struct hgic_frm_hdr2 *hdr = NULL;
    hg->status.tx_data++;
    hdr = (struct hgic_frm_hdr2 *)skb->data;
    hdr->hdr.cookie = cpu_to_le16(hgicf_data_cookie(hg));
    hg->bus->tx_packet(hg->bus, skb);
}

static void hgicf_tx_agg_frm(struct hgicf_wdev *hg, struct sk_buff *skb)
{
    struct sk_buff *agg_skb;
    struct hgic_frm_hdr2 *hdr = NULL;
    struct hgic_hdr *agghdr = NULL;
    int cpylen = 0;

    agg_skb = dev_alloc_skb(hg->bus->drv_tx_headroom + if_agg);
    if (agg_skb) {
        agghdr = (struct hgic_hdr *)agg_skb->data;
        memset(agghdr, 0, sizeof(struct hgic_hdr));
        agghdr->magic  = cpu_to_le16(HGIC_HDR_TX_MAGIC);
        agghdr->type   = HGIC_HDR_TYPE_AGGFRM;
        agghdr->length = sizeof(struct hgic_hdr);
        agghdr->cookie = cpu_to_le16(hgicf_data_cookie(hg));

        do {
            hdr = (struct hgic_frm_hdr2 *)skb->data;
            cpylen = hdr->hdr.length;
            if (agghdr->length + ALIGN(cpylen, 4) > if_agg) {
                skb_queue_head(&hg->tx_dataq, skb);
                break;
            }

            hdr->hdr.length = ALIGN(cpylen, 4);

            hdr->hdr.cookie = cpu_to_le16(hgicf_data_cookie(hg));
            memcpy(agg_skb->data + agghdr->length, skb->data, cpylen);
            agghdr->length += hdr->hdr.length;
            hgicf_tx_complete(hg, skb, 1);

            skb = skb_dequeue(&hg->tx_dataq);
        } while (skb);

        if (agghdr->length > sizeof(struct hgic_hdr)) {
            hg->status.tx_data++;
            skb_put(agg_skb, agghdr->length);
            hg->bus->tx_packet(hg->bus, agg_skb);
        } else {
            hgic_err("invalid agg frm, cookie:%d\r\n", agghdr->cookie);
            dev_kfree_skb(agg_skb);
        }
    } else {
        hgicf_tx_single_frm(hg, skb);
    }
}

static void hgicf_tx_ctrl_frm(struct hgicf_wdev *hg)
{
    int err = 0;
    u8  sleep_cmd = 0;
    struct hgic_ctrl_hdr *hdr = NULL;
    struct sk_buff  *skb = skb_dequeue(&hg->ctrl.txq);
    if (skb) {
        hdr = (struct hgic_ctrl_hdr *)skb->data;
        switch (hdr->hdr.type) {
            case HGIC_HDR_TYPE_BOOTDL:
                break;
            case HGIC_HDR_TYPE_BOOTDL_DATA:
                skb_pull(skb, sizeof(struct hgic_bootdl_cmd_hdr));
                break;
            default:
                if (test_bit(HGIC_BUS_FLAGS_INBOOT, &hg->bus->flags)) {
                    kfree_skb(skb);
                    skb = NULL;
                }
                break;
        }
    }

    if (skb) {
        sleep_cmd = hgic_is_enter_sleep(skb->data);
        hg->status.tx_ctrl++;
        err = hg->bus->tx_packet(hg->bus, skb);
        if (!err && sleep_cmd) {
            hgic_err("device enter sleep ...\r\n");
            set_bit(HGIC_BUS_FLAGS_SLEEP, &hg->bus->flags);
        }
    }
}

//static int hgicf_tx_work_dump = 0;
static void hgicf_tx_work(struct work_struct *work)
{
    struct sk_buff *skb;
    struct hgicf_wdev *hg  = container_of(work, struct hgicf_wdev, tx_work);

    //hgic_dbg("Enter\n");
    //if(hgicf_tx_work_dump == 0) { dump_stack(); hgicf_tx_work_dump=1; }
_CTRLQ_TX:
    while (!skb_queue_empty(&hg->ctrl.txq)) {
        if (test_bit(HGIC_BUS_FLAGS_SLEEP, &hg->bus->flags) ||
            !test_bit(HGICF_DEV_FLAGS_RUNNING, &hg->flags)) {
            hgic_clear_queue(&hg->ctrl.txq);
            goto _CTRLQ_TX;
        }
#if 0
        if (hgicf_check_txwnd(hg, 1)) {
            msleep(10);
            continue;
        }
#endif
        hgicf_tx_ctrl_frm(hg);
    }

    while (!skb_queue_empty(&hg->tx_dataq) && hg->fw_state == STATE_FW &&
           test_bit(HGICF_DEV_FLAGS_RUNNING, &hg->flags) &&
           !test_bit(HGICF_DEV_FLAGS_SUSPEND, &hg->flags)) {

        if (test_bit(HGIC_BUS_FLAGS_SLEEP, &hg->bus->flags) ||
            test_bit(HGIC_BUS_FLAGS_INBOOT, &hg->bus->flags)) {
            hgic_clear_queue(&hg->tx_dataq);
            goto _CTRLQ_TX;
        }

        if (hgicf_check_txwnd(hg, TXWND_INIT_VAL)) {
            msleep(10);
            goto _CTRLQ_TX;
        }

        skb = skb_dequeue(&hg->tx_dataq);
        if (skb) {
            if (!skb_queue_empty(&hg->tx_dataq) && if_agg) {
                hgicf_tx_agg_frm(hg, skb);
            } else {
                hgicf_tx_single_frm(hg, skb);
            }
        }

        if (!skb_queue_empty(&hg->ctrl.txq)) {
            goto _CTRLQ_TX;
        }
    }
    //hgic_dbg("Leave\n");
}

static struct hgicf_vif *hgicf_create_iface(struct hgicf_wdev *hg)
{
    int ret = 0;
    struct net_device *ndev = NULL;
    struct hgicf_vif  *vif  = NULL;

    hgic_dbg("Enter\n");
    ndev = ALLOC_NETDEV_MQS(sizeof(struct hgicf_vif), ifname, hgicf_netif_setup, 1, 1);
    if (!ndev) {
        hgic_err("%s: alloc_netdev_mqs failed\n", __func__);
        return NULL;
    }

    vif = (struct hgicf_vif *)netdev_priv(ndev);
    vif->ndev  = ndev;
    vif->hg    = hg;
    vif->opened = 0;
    ndev->needed_headroom += (hg->bus->drv_tx_headroom + sizeof(struct hgic_frm_hdr2) + 4);
    memcpy(ndev->dev_addr, hg->fwinfo.mac, ETH_ALEN);

    ret = register_netdev(ndev);
    if (ret) {
        free_netdev(ndev);
        return NULL;
    }

    return vif;
}

static void hgicf_rx_single_frm(struct hgicf_wdev *hg, u8 *data, int len)
{
    struct sk_buff *skb;
    struct hgic_hdr *hdr = (struct hgic_hdr *)data;

    if (hg->vif && len > sizeof(struct hgic_frm_hdr2)) {
        hg->rx_cookie = hdr->cookie;
        hg->vif->stats.rx_bytes += len;
        data += sizeof(struct hgic_frm_hdr2);
        len  -= (sizeof(struct hgic_frm_hdr2) + hdr->flags);
        skb = dev_alloc_skb(len + hg->vif->ndev->needed_headroom + hg->vif->ndev->needed_tailroom);
        if (skb) {
            skb_reserve(skb, hg->vif->ndev->needed_headroom);
            memcpy(skb->data, data, len);
            skb_put(skb, len);
            skb->dev = hg->vif->ndev;
            skb->protocol = eth_type_trans(skb, skb->dev);
            if (in_interrupt()) {
                netif_rx(skb);
            } else {
                netif_rx_ni(skb);
            }
        } else {
            hg->vif->stats.rx_dropped += len;
            hgic_err("alloc skb fail, len=%d\r\n", len);
        }
    }
}

static void hgicf_rx_agg_frm(struct hgicf_wdev *hg, u8 *data, int len)
{
    struct hgic_hdr *hdr = (struct hgic_hdr *)data;

    if ((u16)(hg->rx_cookie + 1) != hdr->cookie) {
        hgic_err("cookie:%d-%d\r\n", hg->rx_cookie, hdr->cookie);
    }
    hg->rx_cookie = hdr->cookie;

    data += sizeof(struct hgic_hdr);
    len  -= sizeof(struct hgic_hdr);
    while (len > sizeof(struct hgic_frm_hdr2)) {
        hdr = (struct hgic_hdr *)data;
        hdr->magic  = le16_to_cpu(hdr->magic);
        hdr->length = le16_to_cpu(hdr->length);
        hdr->cookie = le16_to_cpu(hdr->cookie);
        if (hdr->magic == HGIC_HDR_RX_MAGIC && hdr->type == HGIC_HDR_TYPE_FRM2 && len >= hdr->length) {
            hgicf_rx_single_frm(hg, data, hdr->length);
            data += hdr->length;
            len  -= hdr->length;
        } else {
            break;
        }
    }
}

//static int hgicf_rx_data_dump = 0;
static int hgicf_rx_data(void *hgobj, u8 *data, int len)
{
    int i = 0;
    struct hgic_frm_hdr2  *hdr = NULL;
    struct hgicf_wdev     *hg  = hgobj;

    //if(hgicf_rx_data_dump == 0) { dump_stack(); hgicf_rx_data_dump=1; }
    i = hgic_skip_padding(data);
    data += i; len -= i;
    hdr = (struct hgic_frm_hdr2 *)data;
    hdr->hdr.magic  = le16_to_cpu(hdr->hdr.magic);
    hdr->hdr.length = le16_to_cpu(hdr->hdr.length);
    hdr->hdr.cookie = le16_to_cpu(hdr->hdr.cookie);

    if (hdr->hdr.magic != HGIC_HDR_RX_MAGIC) {
        hgic_err("invalid magic unmber:%x\r\n", hdr->hdr.magic);
        hgic_print_hex(data, 16);
        return -1;
    }

    if (len < hdr->hdr.length && hdr->hdr.type != HGIC_HDR_TYPE_BOOTDL) {
        hgic_err("invalid data length: %x/%x,cookie:%d\r\n", len, hdr->hdr.length, hdr->hdr.cookie);
        return -1;
    }

    len = (len < hdr->hdr.length ? len : hdr->hdr.length);
    switch (hdr->hdr.type) {
        case HGIC_HDR_TYPE_FRM2:
        case HGIC_HDR_TYPE_AGGFRM:
            hg->last_rx = jiffies;
            if (hg->vif == NULL || hg->if_test) {
                break;
            }
            if (hdr->hdr.type == HGIC_HDR_TYPE_AGGFRM) {
                hgicf_rx_agg_frm(hg, data, len);
            } else {
                hgicf_rx_single_frm(hg, data, len);
            }
            break;
        case HGIC_HDR_TYPE_CMD:
        case HGIC_HDR_TYPE_CMD2:
        case HGIC_HDR_TYPE_EVENT:
        case HGIC_HDR_TYPE_EVENT2:
        case HGIC_HDR_TYPE_OTA:
        case HGIC_HDR_TYPE_BOOTDL:
            if (hg->if_test) {
                break;
            }
            hgic_fwctrl_rx(&hg->ctrl, data, len);
            break;
        case HGIC_HDR_TYPE_TEST2:
            hg->last_rx = jiffies;
            hg->test_rx_len += len;
            if (hg->if_test == 3) {
                for (i = 8; i < 1500; i++) {
                    if (data[i] != 0xAA) {
                        hgic_err("data verify fail\r\n");
                        break;
                    }
                }
            }
            break;
        case HGIC_HDR_TYPE_SOFTFC:
            hg->last_rx = jiffies;
            atomic_set(&hg->txwnd, hdr->hdr.cookie);
            complete(&hg->txwnd_cp);
            break;
        default:
            hgic_err("invalid data:%d\r\n", hdr->hdr.type);
            break;
    }
    return 0;
}

static int hgicf_download_fw(struct hgicf_wdev *hg)
{
    int err = -1;
    int retry = 10;
    int status  = -1;

    hgic_dbg("Enter\n");
    if (no_bootdl || qc_mode) {
        status = STATE_FW;
    }

    set_bit(HGIC_BUS_FLAGS_INBOOT, &hg->bus->flags);
    while (status != STATE_FW && retry-- > 0 && err) {
        status = hgic_bootdl_cmd_enter(&hg->bootdl);
        if (status == STATE_BOOT) {
            err = hgic_bootdl_download(&hg->bootdl, fw_file);
        }
        if (status < 0 || err) {
            msleep(10);
        }
    }
    clear_bit(HGIC_BUS_FLAGS_INBOOT, &hg->bus->flags);

    if (status == STATE_BOOT && !err) {
        set_bit(HGICF_DEV_FLAGS_BOOTDL, &hg->flags);
        if (hg->bus->reinit && test_bit(HGIC_BUS_FLAGS_NOPOLL, &hg->bus->flags)) {
            retry = 50;
            while (retry-- > 0 && test_bit(HGICF_DEV_FLAGS_RUNNING, &hg->flags) && (STATE_FW != status)) {
                msleep(20);
                if(!hg->bus->reinit(hg->bus)){
                    status = hgic_bootdl_cmd_enter(&hg->bootdl);
                }
            }
        }
    }

    mod_timer(&hg->detect_tmr, jiffies + msecs_to_jiffies(HGIC_DETECT_TIMER));
    hg->fw_state = status;
    return (status == STATE_FW);
}

static void hgicf_delay_init(struct work_struct *work)
{
    int ret = 0;
    struct hgicf_wdev *hg = container_of(work, struct hgicf_wdev, delay_init);

    if(!test_bit(HGICF_DEV_FLAGS_RUNNING, &hg->flags)){
        hgic_dbg("delay_init exit, STOP RUNNING\r\n");
        return;
    }

    ret = hgicf_download_fw(hg);
    clear_bit(HGICF_DEV_FLAGS_SUSPEND, &hg->flags);

    if (ret) {
        hg->last_rx = jiffies;
        ret = hgic_fwctrl_get_fwinfo(&hg->ctrl, HGIC_WDEV_ID_STA, &hg->fwinfo);
        printk("hgic fw info:%d.%d.%d.%d, svn version:%d, %pM, smt_dat:%u\r\n",
               (hg->fwinfo.version >> 24) & 0xff, (hg->fwinfo.version >> 16) & 0xff,
               (hg->fwinfo.version >> 8) & 0xff, (hg->fwinfo.version & 0xff),
               hg->fwinfo.svn_version, hg->fwinfo.mac, hg->fwinfo.smt_dat);
		if(ret <= 0){
			goto __reinit;
		}

        hg->soft_fc = (hg->fwinfo.version < 0x2000000);
        hg->ctrl.fwinfo = &hg->fwinfo;
        if (hg->soft_fc) {
            set_bit(HGIC_BUS_FLAGS_SOFTFC, &hg->bus->flags);
        } else {
            clear_bit(HGIC_BUS_FLAGS_SOFTFC, &hg->bus->flags);
        }
        if (!test_bit(HGICF_DEV_FLAGS_INITED, &hg->flags)) {
            hg->vif = hgicf_create_iface(hg);
            if (!hg->vif) {
                hgic_err("create iface fail, ret:%d\r\n", ret);
                goto __reinit;
            }

            hg->vif->fwifidx  = HGIC_WDEV_ID_STA;
            hgicf_create_procfs(hg);
            if(hgic_fwctrl_get_conn_state(&hg->ctrl, HGIC_WDEV_ID_STA) == 9){
                netif_carrier_on(hg->vif->ndev);
            }

#ifdef __RTOS__
            if (init_cb) { init_cb(0); }
#endif

            if (if_test) {
                hg->if_test = if_test;
                queue_work(hg->tx_wq, &hg->test_work);
            }
            set_bit(HGICF_DEV_FLAGS_INITED, &hg->flags);
        }

        if (!qc_mode) {
            hgicf_load_config(hg);
        }

		hgic_dbg("Leave, ret=%d, soft_fc=%d\n", ret, hg->soft_fc);
		return;
    }

__reinit:
	if(hg->bus->reinit && test_bit(HGICF_DEV_FLAGS_RUNNING, &hg->flags)){
		msleep(100);
		schedule_work(&hg->delay_init);
		hgic_dbg("delay_int run again!\n");
	}
}

static void hgicf_detect_work(struct work_struct *work)
{
    int retry  = 4;
    int status = -1;
    struct hgicf_wdev *hg  = container_of(work, struct hgicf_wdev, detect_work);

    hg->status.detect_tmr++;
    if (!test_bit(HGIC_BUS_FLAGS_SLEEP, &hg->bus->flags) && test_bit(HGICF_DEV_FLAGS_RUNNING, &hg->flags)) {
        if (test_bit(HGICF_DEV_FLAGS_SUSPEND, &hg->flags)   ||
            test_bit(HGIC_BUS_FLAGS_ERROR, &hg->bus->flags) ||
            time_after(jiffies, hg->last_rx + msecs_to_jiffies(HGIC_DETECT_TIMER))) {
            while (retry-- > 0 && status != STATE_FW) {
                status = hgic_bootdl_cmd_enter(&hg->bootdl);
            }

            if (status != STATE_FW || hg->fw_state != STATE_FW) {
                hgic_dbg("need reload firmware ...\r\n");
                hgic_clear_queue(&hg->ctrl.txq);
                hgic_clear_queue(&hg->tx_dataq);
                if (hg->bus->reinit) {
                    hg->bus->reinit(hg->bus);
                }
                if (test_bit(HGICF_DEV_FLAGS_RUNNING, &hg->flags)) {
					hg->soft_fc = 0;
					hg->fw_state = -1;
                    set_bit(HGICF_DEV_FLAGS_SUSPEND, &hg->flags);
                    schedule_work(&hg->delay_init);
                }
            }
        }
    }
    if (test_bit(HGICF_DEV_FLAGS_RUNNING, &hg->flags)) {
        mod_timer(&hg->detect_tmr, jiffies + msecs_to_jiffies(HGIC_DETECT_TIMER));
    }
}

#if !defined(__RTOS__) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void hgicf_detect_timer(struct timer_list *t)
{
    struct hgicf_wdev *hg = from_timer(hg, t, detect_tmr);
    if (test_bit(HGICF_DEV_FLAGS_RUNNING, &hg->flags)) {
        schedule_work(&hg->detect_work);
    }
}
#else
static void hgicf_detect_timer(unsigned long arg)
{
    struct hgicf_wdev *hg = (struct hgicf_wdev *) arg;
    if (test_bit(HGICF_DEV_FLAGS_RUNNING, &hg->flags)) {
        schedule_work(&hg->detect_work);
    }
}
#endif

static void hgicf_schedule(struct hgic_fwctrl *ctrl)
{
    struct hgicf_wdev *hg = container_of(ctrl, struct hgicf_wdev, ctrl);
    queue_work(hg->tx_wq, &hg->tx_work);
}

static void hgicf_probe_post(void *priv)
{
    struct hgicf_wdev *hg  = (struct hgicf_wdev *)priv;
    schedule_work(&hg->delay_init);
}

#ifdef CONFIG_PM
static int hgicf_core_suspend(void *hgobj)
{
    int err = 0;
    u32 vals[2] = {1, 0xffffffff};
    struct hgicf_wdev *hg = (struct hgicf_wdev *)hgobj;
    if (!test_bit(HGIC_BUS_FLAGS_SLEEP, &hg->bus->flags)) {
        if(hg->fwinfo.version < 0x02000000) vals[0] = 0xffff;
        hgic_dbg("enter sleep : type:%d, sleep_ms:%d ...\r\n", vals[0], vals[1]);
        err = hgic_fwctrl_enter_sleep(&hg->ctrl, HGIC_WDEV_ID_STA, vals[0], vals[1]);
    }
    return err;
}

static int hgicf_core_resume(void *hgobj)
{
    int err = 0;
    struct hgicf_wdev *hg = (struct hgicf_wdev *)hgobj;

    clear_bit(HGIC_BUS_FLAGS_SLEEP, &hg->bus->flags);
    if (hg->bus->reinit) {
        hg->bus->reinit(hg->bus);
    }

    err = hgic_fwctrl_enter_sleep(&hg->ctrl, HGIC_WDEV_ID_STA, 0, 0);
    if (err) {
        hgic_err("exit sleep fail, ret=%d\r\n", err);
    }
    return err;
}
#endif

static void hgicf_core_remove(void *hgobj)
{
    struct hgicf_wdev *hg = hgobj;

    if (hg) {
        hgic_dbg("Enter\n");
        clear_bit(HGICF_DEV_FLAGS_RUNNING, &hg->flags);

        if (hg->vif) {
            netif_stop_queue(hg->vif->ndev);
        }   

        hgic_dbg(" trace ...\r\n");
        del_timer_sync(&hg->detect_tmr);
        hgic_dbg(" trace ...\r\n");
        cancel_work_sync(&hg->delay_init);
        hgic_dbg(" trace ...\r\n");
        cancel_work_sync(&hg->detect_work);
        hgic_dbg(" trace ...\r\n");
        cancel_work_sync(&hg->tx_work);
        hgic_dbg(" trace ...\r\n");
        cancel_work_sync(&hg->test_work);

        hgic_dbg(" trace ...\r\n");
        del_timer_sync(&hg->detect_tmr);
        hgic_dbg(" trace ...\r\n");
        cancel_work_sync(&hg->delay_init);
        hgic_dbg(" trace ...\r\n");
        cancel_work_sync(&hg->detect_work);
        hgic_dbg(" trace ...\r\n");
        cancel_work_sync(&hg->tx_work);
        hgic_dbg(" trace ...\r\n");
        cancel_work_sync(&hg->test_work);

        hgic_dbg(" trace ...\r\n");
        hgicf_delete_procfs(hg);
        hgic_dbg(" trace ...\r\n");
        hgic_fwctrl_release(&hg->ctrl);
        hgic_dbg(" trace ...\r\n");
        hgic_ota_release(&hg->ota);
        hgic_dbg(" trace ...\r\n");
        hgic_bootdl_release(&hg->bootdl, 0);
        hgic_dbg(" trace ...\r\n");
        if (hg->tx_wq) {
            flush_workqueue(hg->tx_wq);
            destroy_workqueue(hg->tx_wq);
        }
        hgic_dbg(" trace ... %p\r\n", hg->vif);
        if (hg->vif) {
            unregister_netdev(hg->vif->ndev);
        }
        hgic_dbg(" trace ...\r\n");

        hgic_clear_queue(&hg->tx_dataq);
        hgic_dbg(" trace ...\r\n");
#ifdef __RTOS__
        skb_queue_head_deinit(&hg->tx_dataq);
        deinit_completion(&hg->txwnd_cp);
        spin_lock_deinit(&hg->lock);
#else
        hgic_clear_queue(&hg->evt_list);
#endif
        kfree(hg);
        hgic_dbg("Leave\n");
    }
}

static int hgicf_core_probe(void *dev, struct hgic_bus *bus)
{
    struct hgicf_wdev *hg = NULL;

    if (!hgicf_match_devid(bus->dev_id)) {
        hgic_err("FMAC driver not support device %x\n", bus->dev_id);
        return -1;
    }

    hgic_dbg("qc_mode=%d, no_bootdl=%d, if_agg=%d, txq_size=%d\n", qc_mode, no_bootdl, if_agg, txq_size);
    hg = kzalloc(sizeof(struct hgicf_wdev), GFP_KERNEL);
    if (hg) {
        memset(hg, 0, sizeof(struct hgicf_wdev));
        hg->ctrl.qc_mode = qc_mode;
        hg->bus = bus;
        hg->dev = dev;
        hg->dev_id = bus->dev_id;
        hg->proc_dev = proc_dev;
        hg->fw_state = -1;
        hgic_fwctrl_init(&hg->ctrl, dev, bus);
        hg->ctrl.schedule = hgicf_schedule;
        hg->ctrl.rx_event = hgicf_rx_fw_event;
        hgic_ota_init(&hg->ota, &hg->ctrl, &hg->fwinfo);
        spin_lock_init(&hg->lock);
        INIT_WORK(&hg->tx_work, hgicf_tx_work);
        INIT_WORK(&hg->delay_init, hgicf_delay_init);
        INIT_WORK(&hg->detect_work, hgicf_detect_work);
        INIT_WORK(&hg->test_work, hgicf_test_work);
        init_timer(&hg->detect_tmr);
        setup_timer(&hg->detect_tmr, hgicf_detect_timer, (unsigned long)hg);
        skb_queue_head_init(&hg->tx_dataq);
        init_completion(&hg->txwnd_cp);
        hgic_bootdl_init(&hg->bootdl, hg->bus, &hg->ctrl);
#ifndef __RTOS__
        skb_queue_head_init(&hg->evt_list);
        sema_init(&hg->evt_sema, 0);
#endif

        atomic_set(&hg->txwnd, TXWND_INIT_VAL);
        hg->tx_wq = ALLOC_ORDERED_WORKQUEUE("hgicf_tx", 4096);
        if (!hg->tx_wq) {
            goto __failed;
        }

        set_bit(HGICF_DEV_FLAGS_RUNNING, &hg->flags);
        bus->tx_complete = hgicf_tx_complete;
        bus->rx_packet = hgicf_rx_data;
        bus->probe_post = hgicf_probe_post;
        bus->remove = hgicf_core_remove;
#ifdef CONFIG_PM
        bus->suspend = hgicf_core_suspend;
        bus->resume = hgicf_core_resume;
#endif
        bus->bus_priv = hg;
        hgic_dbg("ok\n");
        return 0;
    }

__failed:
    hgicf_core_remove(hg);
    hgic_dbg("fail\n");
    return -1;
}

#ifdef __RTOS__
int hgic_ifbus_reinit(const char *ifname)
{
    struct hgicf_vif *vif = NULL;
    struct net_device *ndev = net_device_get_by_name(ifname);
    if (ndev) {
        vif = (struct hgicf_vif *)netdev_priv(ndev);
        if (vif->hg->bus->reinit) {
            return vif->hg->bus->reinit(vif->hg->bus);
        }
    }
    return 0;
}
struct hgic_ota *hgic_devota(struct net_device *dev)
{
    struct hgicf_vif *vif = NULL;

    if (dev == NULL) {
        return NULL;
    }
    vif = (struct hgicf_vif *)netdev_priv(dev);
    return &(vif->hg->ota);
}
#endif

int __init hgicf_init(void)
{
    VERSOIN_SHOW("fmac");

#ifdef __RTOS__
    rcu_init();
    tasklet_core_init();
    net_device_init();
#endif

#ifdef CONFIG_HGIC_USB
    hgic_usb_init(hgicf_core_probe, if_agg);
#endif
#ifdef CONFIG_HGIC_SDIO
    hgic_sdio_init(hgicf_core_probe, if_agg);
#endif

    hgic_leave();
    return 0;
}

void __exit hgicf_exit(void)
{
#ifdef CONFIG_HGIC_USB
    hgic_usb_exit();
#endif
#ifdef CONFIG_HGIC_SDIO
    hgic_sdio_exit();
#endif
#ifdef __RTOS__
    net_device_exit();
    tasklet_core_exit();
#endif
}

#ifdef __RTOS__
const char *hgic_param_ifname(const char *name)
{
    if (name) {
        ifname = (char *)name;
    }
    return ifname;
}

void hgic_param_iftest(int iftest)
{
    if_test = iftest;
}
char *hgic_param_fwfile(const char *fw)
{
    if (fw) {
        fw_file = fw;
    }
    return fw_file;
}
void hgic_param_initcb(hgic_init_cb cb)
{
    init_cb = cb;
}
void hgic_param_eventcb(hgic_event_cb cb)
{
    event_cb = cb;
}
void hgic_param_bootdl(int enable)
{
    no_bootdl = !enable;
}

void hgicf_event(struct hgicf_wdev *hg, char *name, int event, int param1, int param2)
{
    if (event_cb) {
        event_cb(name, event, param1, param2);
    }
}
#endif

module_init(hgicf_init);
module_exit(hgicf_exit);
module_param(txq_size, int, 0);
module_param(fw_file, charp, 0644);
module_param(if_test, int, 0);
module_param(ifname, charp, 0644);
module_param(no_bootdl, int, 0);
module_param(qc_mode, int, 0);
module_param(if_agg, int, 0);
module_param(conf_file, charp, 0644);
module_param(proc_dev, int, 0);

MODULE_DESCRIPTION("HUGE-IC FullMAC Wireless Card Driver");
MODULE_AUTHOR("Dongyun");
MODULE_LICENSE("GPL");

