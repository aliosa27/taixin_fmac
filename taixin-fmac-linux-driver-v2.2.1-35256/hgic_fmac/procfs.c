#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wireless.h>
#include <linux/rtnetlink.h>

#include "hgicf.h"
#include "ctrl.h"

///////////////////////////////////////////////////////////////////////////////////////////////
static int hgicf_status_show(struct seq_file *seq, void *v)
{
    struct hgicf_wdev *hg = (struct hgicf_wdev *)seq->private;

    seq_printf(seq, "fw info:%d.%d.%d.%d, svn version:%d\r\n",
               (hg->fwinfo.version >> 24) & 0xff, (hg->fwinfo.version >> 16) & 0xff,
               (hg->fwinfo.version >> 8) & 0xff, (hg->fwinfo.version & 0xff),
               hg->fwinfo.svn_version);
    seq_printf(seq, "hgicf status:\r\n");
    seq_printf(seq, "    RADIO:%d, FW_STATE:%d, SOFT_FC:%d, TXWND:%d\r\n", hg->ctrl.radio_onoff, hg->fw_state, hg->soft_fc, atomic_read(&hg->txwnd));
    seq_printf(seq, "    FLAGS:%lx, BUS FLAGS:%lx, ALIVE_TMR:%d, TX_CTRL:%d, TX_DATA:%d, TX_FAIL:%d\r\n",
               hg->flags, hg->bus->flags, hg->status.detect_tmr, hg->status.tx_ctrl, hg->status.tx_data, hg->status.tx_fail);
    if (hg->ctrl.rxq.qlen) {
        seq_printf(seq, "    ctrl_rxq: %d\r\n", hg->ctrl.rxq.qlen);
    }
    if (hg->ctrl.txq.qlen) {
        seq_printf(seq, "    ctrl_txq: %d\r\n", hg->ctrl.txq.qlen);
    }
    if (hg->tx_dataq.qlen) {
        seq_printf(seq, "    tx_dataq : %d\r\n", hg->tx_dataq.qlen);
    }
    if (hg->evt_list.qlen) {
        seq_printf(seq, "    evt_list   : %d\r\n", hg->evt_list.qlen);
    }
    if (hg->vif) {
        seq_printf(seq, "    tx_bytes: %lu, rx_bytes: %lu, tx_dropped: %lu\r\n",
                   hg->vif->stats.tx_bytes, hg->vif->stats.rx_bytes, hg->vif->stats.tx_dropped);
    }
    return 0;
}

static int hgicf_status_open(struct inode *inode, struct file *file)
{
    return single_open(file, hgicf_status_show, PDE_DATA(inode));
}
static const struct proc_ops hgicf_pops_status = {
    .proc_open = hgicf_status_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int hgicf_ota_open(struct inode *inode, struct file *file)
{
    return single_open(file, NULL, PDE_DATA(inode));
}

static ssize_t hgicf_ota_send_data(struct file *file, const char __user *buffer,
                                   size_t count, loff_t *data)
{
    ssize_t ret = -1;
    char *fw_path = NULL;
    struct seq_file   *seq = (struct seq_file *)file->private_data;
    struct hgicf_wdev *hg  = (struct hgicf_wdev *)seq->private;

    if (file == NULL || buffer == NULL || seq == NULL || hg == NULL) {
        hgic_dbg("%s: Input para error!\r\n", __FUNCTION__);
        return -EINVAL;
    }

    fw_path = kzalloc(count + 1, GFP_KERNEL);
    if (!fw_path) {
        return -ENOMEM;
    }

    ret = copy_from_user(fw_path, buffer, count);
    if (ret) {
        hgic_dbg("%s: Error:copy_from_user:fw_path failed!\r\n", __FUNCTION__);
        kfree(fw_path);
        return -EFAULT;
    }

    hgic_strip_tail(fw_path, count);
    hgic_dbg("ota firmware: %s\r\n", fw_path);
    ret = hgic_ota_send_fw(&hg->ota, fw_path, HG_OTA_WRITE_MEM_TMO);
    kfree(fw_path);
    return (ret ? -EIO : count);
}
static const struct proc_ops hgicf_pops_ota = {
    .proc_open    = hgicf_ota_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_write   = hgicf_ota_send_data,
    .proc_release = single_release,
};

///////////////////////////////////////////////////////////////////////////////////////////
static int hgicf_iwpriv_show(struct seq_file *seq, void *v)
{
    struct hgicf_wdev *hg = (struct hgicf_wdev *)seq->private;
    if (hg->proc.iwpriv_result > 0) {
        seq_write(seq, hg->proc.iwpriv_buf, hg->proc.iwpriv_result);
    }
    return 0;
}

static int hgicf_iwpriv_open(struct inode *inode, struct file *file)
{
    return single_open(file, hgicf_iwpriv_show, PDE_DATA(inode));
}

static ssize_t hgicf_iwpriv_write(struct file *file, const char __user *buffer,
                                  size_t count, loff_t *data)
{
    int ret = 0;
    struct iwreq wrqin;
    char *buf, *ifname, *cmd, *args;
    struct seq_file   *seq = (struct seq_file *)file->private_data;
    struct hgicf_wdev *hg  = (struct hgicf_wdev *)seq->private;
    struct hgicf_vif  *vif = hg->vif;

    if (count <= 0) {
        return -1;
    }

    buf = kzalloc(count + 32, GFP_KERNEL);
    if (buf) {
        ret = copy_from_user(buf, buffer, count);
        if (ret) {
            hgic_err("copy_from_user err: %d\r\n", ret);
            kfree(buf);
            return -EINVAL;
        }

        ifname = buf;
        cmd = strchr(ifname, ' ');
        if (cmd == NULL) {
            wrqin.u.data.pointer = buf;
            wrqin.u.data.length  = count;
            ret = hgic_iwpriv_dump(&hg->ctrl, &wrqin);
            if (ret) {
                if (copy_to_user((void *)(buffer + 4), (const void *)buf, ret <= count ? ret : count)) {
                    kfree(buf);
                    hgic_err("copy_to_user fail\r\n");
                    return -EINVAL;
                }
            }

            if (copy_to_user((void *)buffer, (const void *)&ret, 4)) {
                kfree(buf);
                hgic_err("copy_to_user fail\r\n");
                return -EINVAL;
            }
            
            hgic_err("**Empty CMD**\r\n");
            kfree(buf);
            return count;
        }

        *cmd++ = 0;
        args = strchr(cmd, ' ');
        if (args) {
            *args++ = 0;
        }

        memset(&wrqin, 0, sizeof(wrqin));
        wrqin.u.data.pointer = args;
        wrqin.u.data.length  = args ? count - (args - buf) : 0;
        if (strcasecmp(cmd, "set") == 0) {
            ret = hgic_iwpriv_set_proc(&hg->ctrl, vif->fwifidx, &wrqin);
        } else if (strcasecmp(cmd, "get") == 0) {
            ret = hgic_iwpriv_get_proc(&hg->ctrl, vif->fwifidx, &wrqin);
            if (ret == 0 && wrqin.u.data.length) {
                ret = wrqin.u.data.length;
                if (copy_to_user((void *)(buffer + 4), (const void *)args, ret <= count ? ret : count)) {
                    kfree(buf);
                    hgic_err("copy_to_user fail\r\n");
                    return -EINVAL;
                }
            }
        } else if (strncasecmp(cmd, "scan", 4) == 0) {
            char *ptr = strchr(cmd, '=');
            ret = hgic_fwctrl_scan(&hg->ctrl, vif->fwifidx, (ptr ? (u8)simple_strtol(ptr+1, 0, 10) : 1));
        } else if (strcasecmp(cmd, "save") == 0) {
            ret = hgic_fwctrl_save_cfg(&hg->ctrl, vif->fwifidx);
#if 0
        } else if (strcasecmp(cmd, "open") == 0) {
            if(vif->opened == 0){
                ret = vif->ndev->netdev_ops->ndo_open(vif->ndev);
                DEV_OPEN(vif->ndev);
            }else{
                ret = 0;
            }
        } else if (strcasecmp(cmd, "close") == 0) {
            if(vif->opened == 1){
                ret = vif->ndev->netdev_ops->ndo_stop(vif->ndev);
                DEV_CLOSE(vif->ndev);
            }else{
                ret = 0;
            }
#endif
        } else {
            kfree(buf);
            hgic_err("invalid cmd: [%s]\r\n", cmd);
            return -EINVAL;
        }

        if (copy_to_user((void *)buffer, &ret, 4)) {
            kfree(buf);
            hgic_err("copy_to_user fail\r\n");
            return -EINVAL;
        }

        kfree(buf);
        return count;
    }
    return -ENOMEM;
}
static const struct proc_ops hgicf_pops_iwpriv = {
    .proc_open    = hgicf_iwpriv_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_write   = hgicf_iwpriv_write,
    .proc_release = single_release,
};

///////////////////////////////////////////////////////////////////////////////////////////

static int hgicf_fwevent_open(struct inode *inode, struct file *file)
{
    return single_open(file, NULL, PDE_DATA(inode));
}
static ssize_t hgicf_fwevent_read(struct file *file, char __user *buffer,
                                  size_t count, loff_t *data)
{
    int ret = 0;
    struct sk_buff *skb = NULL;
    struct seq_file   *seq = (struct seq_file *)file->private_data;
    struct hgicf_wdev *hg  = (struct hgicf_wdev *)seq->private;

    if (down_timeout(&hg->evt_sema, msecs_to_jiffies(100))) {
        return 0;
    }

    if (!skb_queue_empty(&hg->evt_list)) {
        skb = skb_dequeue(&hg->evt_list);
        if (skb) {
            if (!copy_to_user(buffer, skb->data, skb->len)) {
                ret = skb->len;
            }
            kfree_skb(skb);
        }
    }
    return ret;
}
static const struct proc_ops hgicf_pops_fwevent = {
    .proc_open    = hgicf_fwevent_open,
    .proc_read    = hgicf_fwevent_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/////////////////////////////////////////////////////////////////////////////////////////////////
void hgicf_create_procfs(struct hgicf_wdev *hg)
{
    hgic_dbg("enter\r\n");
    hg->proc.rootdir = proc_mkdir(hg->proc_dev ? hg->vif->ndev->name : "hgicf", NULL);
    if (hg->proc.rootdir == NULL) {
        hgic_err("create proc dir: hgic failed\r\n");
        return;
    }

    hg->proc.status = proc_create_data("status", 0x0444,
                                       hg->proc.rootdir, &hgicf_pops_status, hg);
    if (hg->proc.status == NULL) {
        hgic_err("create proc file: status failed\r\n");
    }
    hg->proc.ota = proc_create_data("ota", 0x0666, hg->proc.rootdir, &hgicf_pops_ota, hg);
    if (hg->proc.ota == NULL) {
        hgic_err("create proc file: testmode failed\r\n");
    }

    hg->proc.iwpriv = proc_create_data("iwpriv", 0x0666, hg->proc.rootdir, &hgicf_pops_iwpriv, hg);
    if (hg->proc.iwpriv == NULL) {
        hgic_err("create proc file: iwpriv failed\r\n");
    }

    hg->proc.fwevent = proc_create_data("fwevnt", 0x0444, hg->proc.rootdir, &hgicf_pops_fwevent, hg);
    if (hg->proc.fwevent == NULL) {
        hgic_err("create proc file: event failed\r\n");
    }

    hgic_dbg("leave\r\n");
}

void hgicf_delete_procfs(struct hgicf_wdev *hg)
{
    hgic_dbg("enter\r\n");
    if (hg->proc.rootdir) {
        if (hg->proc.status) {
            remove_proc_entry("status", hg->proc.rootdir);
            hg->proc.status = NULL;
        }
        if (hg->proc.ota) {
            remove_proc_entry("ota", hg->proc.rootdir);
            hg->proc.ota = NULL;
        }
        if (hg->proc.iwpriv) {
            remove_proc_entry("iwpriv", hg->proc.rootdir);
            hg->proc.iwpriv = NULL;
        }
        if (hg->proc.fwevent) {
            remove_proc_entry("fwevnt", hg->proc.rootdir);
            hg->proc.fwevent = NULL;
        }
        remove_proc_entry(hg->proc_dev ? hg->vif->ndev->name : "hgicf", NULL);
        hg->proc.rootdir = NULL;
    } else {
        hgic_err("hg->proc.rootdir is NULL\r\n");
    }
    hgic_dbg("leave\r\n");
}

