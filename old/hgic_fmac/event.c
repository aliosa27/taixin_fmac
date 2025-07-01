
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
#else
#include <linux/version.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#endif

#include "hgicf.h"
#include "event.h"

#define HGIC_EVENT_MAX (16)

void hgicf_rx_fw_event(struct hgic_fwctrl *ctrl, struct sk_buff *skb)
{
    char drop  = 0;
    char *data = NULL;
    u32 data_len;
    u32 evt_id = 0;
    struct hgic_ctrl_hdr *evt = NULL;
    struct hgicf_wdev *hg = container_of(ctrl, struct hgicf_wdev, ctrl);

    if (skb == NULL || skb->len < sizeof(struct hgic_ctrl_hdr)) {
        dev_kfree_skb(skb);
        return;
    }

    evt  = (struct hgic_ctrl_hdr *)skb->data;
    data = (char *)(evt + 1);
    data_len = skb->len - sizeof(struct hgic_ctrl_hdr);
    evt_id = HDR_EVTID(evt);

    //hgic_dbg("event id:%d\r\n", evt->event.event_id);
    switch (evt_id) {
        case HGIC_EVENT_FWDBG_INFO:
            drop = 1;
            printk(data);
            break;
        default:
            break;
    }

#ifdef __RTOS__
    hgicf_event(hg, hg->vif->ndev->name, evt_id, data, data_len);
    dev_kfree_skb(skb);
#else
    if (!drop) {
        if (skb_queue_len(&hg->evt_list) > HGIC_EVENT_MAX) {
            kfree_skb(skb_dequeue(&hg->evt_list));
            hgic_err("event list is full (max %d), drop old event\r\n", HGIC_EVENT_MAX);
        }
        skb_queue_tail(&hg->evt_list, skb);
        up(&hg->evt_sema);
    } else {
        dev_kfree_skb(skb);
    }
#endif

}

