
#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/skbuff.h>

#ifdef CONFIG_BT
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

#include "../hgic_def.h"
#include "fwdl.h"
#include "fwctrl.h"
#include "utils.h"

static int hgic_hcidev_open(struct hci_dev *hdev)
{
    struct hgic_fwctrl *ctrl = hci_get_drvdata(hdev);

    if (test_and_set_bit(HCI_RUNNING, &hdev->flags)) {
        return 0;
    }

    hgic_fwctrl_ble_open(ctrl, 1, 1);
    return 0;
}

static int hgic_hcidev_flush(struct hci_dev *hdev)
{
    return 0;
}

static int hgic_hcidev_close(struct hci_dev *hdev)
{
    struct hgic_fwctrl *ctrl = hci_get_drvdata(hdev);

    if (!test_and_clear_bit(HCI_RUNNING, &hdev->flags)) {
        return 0;
    }

    hgic_fwctrl_ble_open(ctrl, 1, 0);
    return 0;
}

static int hgic_hcidev_send_frame(struct sk_buff *skb)
{
    struct hci_dev *hdev = (struct hci_dev *) skb->dev;
    struct hgic_fwctrl *ctrl;

    hgic_dbg("send bt data, type:%d len %d", bt_cb(skb)->pkt_type, skb->len);

    if (!hdev) {
        hgic_err("skb->dev is NULLs\r\n");
        return -ENODEV;
    }

    if (!test_bit(HCI_RUNNING, &hdev->flags)) {
        hgic_err("bt device is not running\r\n");
        return -EBUSY;
    }

    switch (bt_cb(skb)->pkt_type) {
        case HCI_COMMAND_PKT:
            hdev->stat.cmd_tx++;
            break;
        case HCI_ACLDATA_PKT:
            hdev->stat.acl_tx++;
            break;
        case HCI_SCODATA_PKT:
            hdev->stat.sco_tx++;
            break;
    };

    ctrl = hci_get_drvdata(hdev);
    hgic_fwctrl_send_hci_data(ctrl, bt_cb(skb)->pkt_type, skb->data, skb->len);
    kfree_skb(skb);
    return 0;
}

static int hgic_hcidev_ioctl(struct hci_dev *hdev, unsigned int cmd, unsigned long arg)
{
    return -ENOIOCTLCMD;
}

int hgic_hcidev_init(struct hgic_fwctrl *ctrl, struct hci_dev *hci)
{
    int ret = -1;
    if (hci) {
        hci->bus = (ctrl->bus->type == HGIC_BUS_USB) ? HCI_USB :
                   (ctrl->bus->type == HGIC_BUS_SDIO ? HCI_SDIO : 0);
        hci_set_drvdata(hci, ctrl);
        SET_HCIDEV_DEV(hci, ctrl->dev);
        hci->open  = hgic_hcidev_open;
        hci->close = hgic_hcidev_close;
        hci->flush = hgic_hcidev_flush;
        hci->send  = hgic_hcidev_send_frame;
        hci->ioctl = hgic_hcidev_ioctl;
        ret = hci_register_dev(hci);
    }
    return ret;
}

#endif
