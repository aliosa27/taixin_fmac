#ifdef __RTOS__
#include <linux/module.h>
#include <linux/types.h>
#include <asm/unaligned.h>
#include <linux/skbuff.h>
#include <linux/completion.h>
#else
#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/firmware.h>
#include <linux/etherdevice.h>
#endif

#include "../hgic_def.h"
#include "fwdl.h"
#include "fwctrl.h"
#include "utils.h"

#define STR_LEN(s) ((s)?strlen(s):0)

u16 hgic_ctrl_cookie(struct hgic_fwctrl *ctrl)
{
    unsigned long flags;
    uint16_t cookie = 0;

    spin_lock_irqsave(&ctrl->lock, flags);
    cookie = ctrl->cookie++;
    ctrl->cookie &= HGIC_TX_COOKIE_MASK;
    spin_unlock_irqrestore(&ctrl->lock, flags);
    return cookie;
}

static struct sk_buff *hgic_alloc_ctrl_skb(struct hgic_fwctrl *ctrl, u32 size)
{
    struct sk_buff *skb = dev_alloc_skb(ctrl->bus->drv_tx_headroom + sizeof(struct hgic_ctrl_hdr) + size + 4);
    if (!skb) {
        return skb;
    }
    skb_reserve(skb, ctrl->bus->drv_tx_headroom);
    memset(skb->data, 0, sizeof(struct hgic_ctrl_hdr) + size);
    skb_reserve(skb, sizeof(struct hgic_ctrl_hdr));
    skb_put(skb, size);
    return skb;
}

static struct sk_buff *hgic_fwctrl_send_cmd(struct hgic_fwctrl *ctrl, u8 ifidx, u32 cmd_id, struct sk_buff *skb, bool sync)
{
    struct hgic_ctrl_hdr *hdr = NULL;
    struct hgic_cmd_response resp;
    u16 id = cmd_id - HGIC_CMD_START;

    memset(&resp, 0, sizeof(resp));
    resp.cookie = hgic_ctrl_cookie(ctrl);
    hdr = (struct hgic_ctrl_hdr *)skb_push(skb, sizeof(struct hgic_ctrl_hdr));
    memset(hdr->info, 0, sizeof(hdr->info));
    hdr->hdr.magic  = cpu_to_le16(HGIC_HDR_TX_MAGIC);
    hdr->hdr.length = cpu_to_le16(skb->len);
    hdr->hdr.cookie = cpu_to_le16(resp.cookie);
    hdr->hdr.ifidx  = ifidx;
    HDR_CMDID_SET(hdr, id);
    return hgic_fwctrl_send_data(ctrl, skb, &resp, HGIC_CMD_TIMEOUT);
}

int hgic_fwctrl_do_cmd(struct hgic_fwctrl *ctrl, u8 ifidx, u32 cmd_id, u8 *in, u32 in_len, u8 *out, u32 out_size)
{
    int ret = -1;
    struct sk_buff *skb  = NULL;
    struct sk_buff *resp = NULL;
    struct hgic_ctrl_hdr *hdr = NULL;

    if(in_len > 2000){
        hgic_err("data len is too long\r\n");
        return -EINVAL;
    }

    skb = hgic_alloc_ctrl_skb(ctrl, in_len);
    if (skb) {
        if (in && in_len > 0) {
            memcpy(skb->data, in, in_len);
            skb->data[in_len] = 0;
        }

        resp = hgic_fwctrl_send_cmd(ctrl, ifidx, cmd_id, skb, true);
        if (resp) {
            hdr = (struct hgic_ctrl_hdr *)resp->data;
            ret = (short)le16_to_cpu(hdr->cmd.status);
            if (ret > 0 && out) {
                memcpy(out, (char *)(hdr + 1), ret > out_size ? out_size : ret);
            }
            dev_kfree_skb_any(resp);
        }
        if (ret < 0) {
            printk("FWCTRL: cmd:%d, ret:%d (%s)\r\n", cmd_id, ret, resp ? "Responsed" : "No Response");
        }
    }
    return ret;
}

int hgic_fwctrl_set_byte(struct hgic_fwctrl *ctrl, u8 ifidx, u32 cmd_id, u8 val)
{
    return hgic_fwctrl_do_cmd(ctrl, ifidx, cmd_id, &val, 1, 0, 0);
}

int hgic_fwctrl_set_int_val(struct hgic_fwctrl *ctrl, u8 ifidx, u32 cmd_id, u32 val)
{
    u8 data[4];
    put_unaligned_le32(val, data);
    return hgic_fwctrl_do_cmd(ctrl, ifidx, cmd_id, data, 4, 0, 0);
}

int hgic_fwctrl_get_int_val(struct hgic_fwctrl *ctrl, u8 ifidx, u32 cmd_id)
{
    u8 data[4];
    if (hgic_fwctrl_do_cmd(ctrl, ifidx, cmd_id, 0, 0, data, 4) == 4) {
        return get_unaligned_le32(data);
    } else {
        return -1;
    }
}

short hgic_fwctrl_get_short_val(struct hgic_fwctrl *ctrl, u8 ifidx, u32 cmd_id)
{
    return hgic_fwctrl_do_cmd(ctrl, ifidx, cmd_id, 0, 0, 0, 0);
}

int hgic_fwctrl_set_bytes(struct hgic_fwctrl *ctrl, u8 ifidx, u32 cmd_id, u8 *data, u32 len)
{
    return hgic_fwctrl_do_cmd(ctrl, ifidx, cmd_id, data, len, 0, 0);
}

int hgic_fwctrl_get_bytes(struct hgic_fwctrl *ctrl, u8 ifidx, u32 cmd_id, u8 *buff, u32 len)
{
    return hgic_fwctrl_do_cmd(ctrl, ifidx, cmd_id, 0, 0, buff, len);
}

static int hgic_fwctrl_rx_response(struct hgic_fwctrl *ctrl, struct sk_buff *skb)
{
    int find = 0;
    unsigned long flags;
    struct hgic_cmd_response *resp = NULL;
    struct hgic_ctrl_hdr *cmd = (struct hgic_ctrl_hdr *)skb->data;;

    spin_lock_irqsave(&ctrl->lock, flags);
    list_for_each_entry(resp, &ctrl->pd_list, list) {
        if (resp->cookie == cmd->hdr.cookie) {
            resp->skb = skb;
            complete(&resp->cmpl);
            find = 1;
            break;
        }
    }
    spin_unlock_irqrestore(&ctrl->lock, flags);
    if (!find) {
        dev_kfree_skb_any(skb);
    }
    return 0;
}

static void hgic_fwctrl_clear_pdlist(struct hgic_fwctrl *ctrl)
{
    unsigned long flags;
    struct hgic_cmd_response *sync = NULL;

    spin_lock_irqsave(&ctrl->lock, flags);
    list_for_each_entry(sync, &ctrl->pd_list, list) {
        complete(&sync->cmpl);
    }
    spin_unlock_irqrestore(&ctrl->lock, flags);
}

static void hgic_fwctrl_work(struct work_struct *work)
{
    struct hgic_fwctrl *ctrl = NULL;
    struct sk_buff *skb = NULL;
    struct hgic_ctrl_hdr *hdr = NULL;

    ctrl = container_of(work, struct hgic_fwctrl, work);
    while (!skb_queue_empty(&ctrl->rxq)) {
        skb = skb_dequeue(&ctrl->rxq);
        hdr = (struct hgic_ctrl_hdr *)skb->data;
        switch (hdr->hdr.type) {
            case HGIC_HDR_TYPE_CMD:
            case HGIC_HDR_TYPE_CMD2:
            case HGIC_HDR_TYPE_BOOTDL:
            case HGIC_HDR_TYPE_OTA:
                hgic_fwctrl_rx_response(ctrl, skb);
                break;
            case HGIC_HDR_TYPE_EVENT:
            case HGIC_HDR_TYPE_EVENT2:
                ctrl->rx_event(ctrl, skb);
                break;
            default:
                dev_kfree_skb(skb);
                break;
        }
    }
}

struct sk_buff *hgic_fwctrl_send_data(struct hgic_fwctrl *ctrl, struct sk_buff *skb, struct hgic_cmd_response *resp, u32 timeout)
{
    unsigned long flags;

    init_completion(&resp->cmpl);
    spin_lock_irqsave(&ctrl->lock, flags);
    list_add(&resp->list, &ctrl->pd_list);
    spin_unlock_irqrestore(&ctrl->lock, flags);

    if (ctrl->txq.qlen > 4) {
        kfree_skb(skb_dequeue(&ctrl->txq));
        //hgic_err("ctrl txq full, drop data (%d)\r\n", ctrl->txq.qlen);
    }

    skb_queue_tail(&ctrl->txq, skb);
    ctrl->schedule(ctrl);
    if (timeout) {
        if (!wait_for_completion_timeout(&resp->cmpl, msecs_to_jiffies(timeout))) {
            hgic_err("timeout, ctrl->rxq:%d\r\n", skb_queue_len(&ctrl->rxq));
        }
    }
    spin_lock_irqsave(&ctrl->lock, flags);
    list_del(&resp->list);
    spin_unlock_irqrestore(&ctrl->lock, flags);
#ifdef __RTOS__
    deinit_completion(&resp->cmpl);
#endif
    return resp->skb;
}

void hgic_fwctrl_rx(struct hgic_fwctrl *ctrl, u8 *data, int len)
{
    struct sk_buff *skb;
    if (ctrl->wq) {
        skb = dev_alloc_skb(len);
        if (skb) {
            memcpy(skb->data, data, len);
            skb_put(skb, len);
            skb_queue_tail(&ctrl->rxq, skb);
            queue_work(ctrl->wq, &ctrl->work);
        } else {
            hgic_err("alloc skb fail\r\n");
        }
    } else {
        hgic_err("fwctrl workqueue is NULL\r\n");
    }
}

void hgic_fwctrl_init(struct hgic_fwctrl *ctrl, void *dev, struct hgic_bus *bus)
{
    memset(ctrl, 0, sizeof(struct hgic_fwctrl));
    ctrl->dev = dev;
    ctrl->bus = bus;
    ctrl->radio_onoff = 1;
    spin_lock_init(&ctrl->lock);
    INIT_LIST_HEAD(&ctrl->pd_list);
    skb_queue_head_init(&ctrl->rxq);
    skb_queue_head_init(&ctrl->txq);
    INIT_WORK(&ctrl->work, hgic_fwctrl_work);
    ctrl->wq = ALLOC_ORDERED_WORKQUEUE("fwctrl", 0);
}

void hgic_fwctrl_release(struct hgic_fwctrl *ctrl)
{
    cancel_work_sync(&ctrl->work);
    hgic_fwctrl_clear_pdlist(ctrl);
    hgic_clear_queue(&ctrl->txq);
    hgic_clear_queue(&ctrl->rxq);
#ifdef __RTOS__
    skb_queue_head_deinit(&ctrl->rxq);
    skb_queue_head_deinit(&ctrl->txq);
    spin_lock_deinit(&ctrl->lock);
#endif
    if (ctrl->wq) {
        flush_workqueue(ctrl->wq);
        destroy_workqueue(ctrl->wq);
    }
}

///////////////////////////////////////////////////////////////////////////////////////////
int hgic_fwctrl_testmode_cmd(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *cmd, u32 size)
{
    int ret = 0;

    ret = hgic_fwctrl_do_cmd(ctrl, ifidx, HGIC_CMD_TESTMODE_CMD, cmd, STR_LEN(cmd), cmd, size);
    if (ret < 0) {
        strcpy(cmd, "failed");
    } else {
        cmd[ret] = 0;
    }
    return ret;
}

int hgic_fwctrl_get_status(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *buff, u32 len)
{
    return hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_STATUS, buff, len);
}

int hgic_fwctrl_get_conn_state(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_do_cmd(ctrl, ifidx, HGIC_CMD_GET_CONN_STATE, NULL, 0, NULL, 0);
}

int hgic_fwctrl_get_fwinfo(struct hgic_fwctrl *ctrl, u8 ifidx, struct hgic_fw_info *info)
{
    int ret = 0;
    struct hgic_fw_info _info;
    ret = hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_FW_INFO, (u8 *)&_info, sizeof(struct hgic_fw_info));
    if (ret > 0) {
        info->version = le32_to_cpu(_info.version);
        info->svn_version = le32_to_cpu(_info.svn_version);
        info->chip_id = le16_to_cpu(_info.chip_id);
        info->cpu_id = le16_to_cpu(_info.cpu_id);
        memcpy(info->mac, _info.mac, 6);
        info->smt_dat = le32_to_cpu(_info.smt_dat);
    }
    return ret;
}

int hgic_fwctrl_set_countryregion(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *country_code)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_COUNTRY, country_code, STR_LEN(country_code));
}

int hgic_fwctrl_set_ssid(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *ssid)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_SSID, ssid, STR_LEN(ssid));
}

int hgic_fwctrl_set_bssid(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *bssid)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_BSSID, bssid, 6);
}

int hgic_fwctrl_set_channel(struct hgic_fwctrl *ctrl, u8 ifidx, u32 channel)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_CHANNEL, channel);
}

int hgic_fwctrl_set_bssid_filter(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *bssid_filter)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_BSSID_FILTER, bssid_filter, STR_LEN(bssid_filter));
}

int hgic_fwctrl_set_rts_threshold(struct hgic_fwctrl *ctrl, u8 ifidx, u32 rts_threshold)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_RTS_THRESHOLD, rts_threshold);
}

int hgic_fwctrl_set_frag_threshold(struct hgic_fwctrl *ctrl, u8 ifidx, u32 frag_threshold)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_FRG_THRESHOLD, frag_threshold);
}

int hgic_fwctrl_set_key_mgmt(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *key_mgmt)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_KEY_MGMT, key_mgmt, STR_LEN(key_mgmt));
}

int hgic_fwctrl_set_wpa_psk(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *wpa_psk)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_WPA_PSK, wpa_psk, STR_LEN(wpa_psk));
}

int hgic_fwctrl_set_wbnat(struct hgic_fwctrl *ctrl, u8 ifidx, u32 enable)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_WBNAT, enable);
}

int hgic_fwctrl_set_freq_range(struct hgic_fwctrl *ctrl, u8 ifidx, u32 freq_start, u32 freq_end, u32 bss_bw)
{
    u8 data[12];
    put_unaligned_le32(freq_start, data);
    put_unaligned_le32(freq_end, data + 4);
    put_unaligned_le32(bss_bw, data + 8);
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_FREQ_RANGE, data, 12);
}

int hgic_fwctrl_set_bss_bw(struct hgic_fwctrl *ctrl, u8 ifidx, u8 bss_bw)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_BSS_BW, bss_bw);
}

int hgic_fwctrl_set_tx_bw(struct hgic_fwctrl *ctrl, u8 ifidx, u8 tx_bw)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_TX_BW, tx_bw);
}

int hgic_fwctrl_set_tx_mcs(struct hgic_fwctrl *ctrl, u8 ifidx, u8 tx_mcs)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_TX_MCS, tx_mcs);
}

int hgic_fwctrl_set_acs(struct hgic_fwctrl *ctrl, u8 ifidx, u8 acs, u8 acs_tmo)
{
    u8 data[2] = {acs, acs_tmo};
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_ACS_ENABLE, data, 2);
}

int hgic_fwctrl_set_bgrssi(struct hgic_fwctrl *ctrl, u8 ifidx, u8 bgrssi)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_BG_RSSI, bgrssi);
}

int hgic_fwctrl_set_chan_list(struct hgic_fwctrl *ctrl, u8 ifidx, u16 *chan_list, u32 cnt)
{
    int ret = -1;
    int i = 0;
    u8 *buf = kzalloc((1 + cnt) * sizeof(u16), GFP_KERNEL);
    if (buf) {
        put_unaligned_le16(cnt, buf);
        for (i = 0; i < cnt; i++) {
            put_unaligned_le16(chan_list[i], buf + (i + 1) * sizeof(u16));
        }
        ret = hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_CHAN_LIST, buf, (1 + cnt) * sizeof(u16));
        kfree(buf);
    }
    return ret;
}

int hgic_fwctrl_set_mode(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *mode)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_WORK_MODE, mode, STR_LEN(mode));
}

int hgic_fwctrl_set_paired_stas(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *paired_stas, u32 len)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_PAIRED_STATIONS, paired_stas, len);
}

int hgic_fwctrl_set_pairing(struct hgic_fwctrl *ctrl, u8 ifidx, u32 pair_number)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_PAIRING, pair_number);
}

int hgic_fwctrl_open_dev(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_do_cmd(ctrl, ifidx, HGIC_CMD_DEV_OPEN, 0, 0, 0, 0);
}

int hgic_fwctrl_close_dev(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_do_cmd(ctrl, ifidx, HGIC_CMD_DEV_CLOSE, 0, 0, 0, 0);
}

int hgic_fwctrl_set_txpower(struct hgic_fwctrl *ctrl, u8 ifidx, u32 tx_power)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_TX_POWER, tx_power);
}

int hgic_fwctrl_get_txpower(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_get_short_val(ctrl, ifidx, HGIC_CMD_GET_TX_POWER);
}

int hgic_fwctrl_set_listen_interval(struct hgic_fwctrl *ctrl, u8 ifidx, u32 listen_interval)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_LISTEN_INTERVAL, listen_interval);
}

int hgic_fwctrl_set_center_freq(struct hgic_fwctrl *ctrl, u8 ifidx, u32 center_freq)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_CENTER_FREQ, center_freq);
}

int hgic_fwctrl_set_tx_count(struct hgic_fwctrl *ctrl, u8 ifidx, u32 short_frm_tx_count, u32 long_frm_tx_count)
{
    u8  data[8];
    put_unaligned_le32(short_frm_tx_count, data);
    put_unaligned_le32(long_frm_tx_count, data + 4);
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_TX_LCOUNT, data, 8);
}

int hgic_fwctrl_set_key(struct hgic_fwctrl *ctrl, u8 ifidx, u8 cmd, u8 *addr, u8 *key, u8 len)
{
    int ret  = -ENOMEM;
    u8 *buff = kmalloc(len + 10, GFP_KERNEL);
    if (buff) {
        buff[0] = cmd;
        buff[1] = len;
        memcpy(buff + 2, addr, 6);
        memcpy(buff + 8, key, len);
        ret = hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_KEY, buff, len + 8);
        kfree(buff);
    }
    return ret;
}

int hgic_fwctrl_add_sta(struct hgic_fwctrl *ctrl, u8 ifidx, u16 aid, u8 *addr)
{
    uint8_t sta_info[8];
    put_unaligned_le16(aid, sta_info);
    memcpy(sta_info + 2, addr, 6);
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_ADD_STA, sta_info, 8);
}

int hgic_fwctrl_del_sta(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *addr)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_REMOVE_STA, addr, 6);
}

int hgic_fwctrl_set_primary_chan(struct hgic_fwctrl *ctrl, u8 ifidx, u8 primary_chan)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_PRIMARY_CHAN, primary_chan);
}

int hgic_fwctrl_set_aid(struct hgic_fwctrl *ctrl, u8 ifidx, u32 aid)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_AID, aid);
}

int hgic_fwctrl_set_mac(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *mac)
{
    u8 mac_addr[7];
    memcpy(mac_addr, mac, 6);
    mac_addr[6] = ifidx;
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_MAC, mac_addr, 7);
}

int hgic_fwctrl_get_scan_list(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *buff, u32 size)
{
    return hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_SCAN_LIST, buff, size);
}

int hgic_fwctrl_scan(struct hgic_fwctrl *ctrl, u8 ifidx, u8 scan_cmd)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SCAN, scan_cmd);
}

int hgic_fwctrl_set_txq_param(struct hgic_fwctrl *ctrl, u8 ifidx, u8 ac, struct hgic_txq_param *param)
{
    int ret = -ENOMEM;
    u8 *txq = (u8 *)kmalloc(1 + sizeof(struct hgic_txq_param), GFP_KERNEL);
    if (txq) {
        txq[0] = ac;
        memcpy(txq + 1, param, sizeof(struct hgic_txq_param));
        ret = hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_TXQ_PARAM, txq, 1 + sizeof(struct hgic_txq_param));
        kfree(txq);
    }
    return ret;
}
int hgic_fwctrl_set_user_edca(struct hgic_fwctrl *ctrl, u8 ifidx, u8 ac, struct hgic_txq_param *param)
{
    int ret = -ENOMEM;
    u8 *txq = (u8 *)kmalloc(1 + sizeof(struct hgic_txq_param), GFP_KERNEL);
    if (txq) {
        txq[0] = ac;
        memcpy(txq + 1, param, sizeof(struct hgic_txq_param));
        ret = hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_USER_EDCA, txq, 1 + sizeof(struct hgic_txq_param));
        kfree(txq);
    }
    return ret;
}

int hgic_fwctrl_get_temperature(struct hgic_fwctrl *ctrl)
{
    return hgic_fwctrl_get_short_val(ctrl, 1, HGIC_CMD_GET_TEMPERATURE);
}

int hgic_fwctrl_enter_sleep(struct hgic_fwctrl *ctrl, u8 ifidx, u16 sleep, u32 sleep_ms)
{
    u8 buff[8];
    put_unaligned_le16(sleep, buff);
    put_unaligned_le32(sleep_ms, buff + 2);
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_ENTER_SLEEP, buff, 6);
}

int hgic_fwctrl_get_sta_list(struct hgic_fwctrl *ctrl, u8 ifidx, struct hgic_sta_info *sta_list, u32 size)
{
    int ret = hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_STA_LIST, (u8 *)sta_list, size * sizeof(struct hgic_sta_info));
    return ret > 0 ? (ret / sizeof(struct hgic_sta_info)) : ret;
}

int hgic_fwctrl_set_beacon_int(struct hgic_fwctrl *ctrl, u8 ifidx, u32 beacon_int)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_BEACON_INT, beacon_int);
}

int hgic_fwctrl_get_mode(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *mode, u32 size)
{
    return hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_MODE, mode, size);
}

int hgic_fwctrl_get_ssid(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *ssid, u32 size)
{
    return hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_SSID, ssid, size);
}

int hgic_fwctrl_get_bssid(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *bssid, u32 len)
{
    return hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_BSSID, bssid, len);
}

int hgic_fwctrl_get_wpapsk(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *psk, u32 size)
{
    return hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_WPA_PSK, psk, size);
}

int hgic_fwctrl_save_cfg(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_do_cmd(ctrl, ifidx, HGIC_CMD_SAVE_CFG, 0, 0, 0, 0);
}

int hgic_fwctrl_join_group(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *addr, u8 aid)
{
    u8 val[7];
    memcpy(val, addr, 6);
    val[6] = aid;
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_JOIN_GROUP, val, 7);
}

int hgic_fwctrl_set_ethertype(struct hgic_fwctrl *ctrl, u8 ifidx, u16 ethertype)
{
    u8 vals[2];
    put_unaligned_le16(ethertype, vals);
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_ETHER_TYPE, vals, 2);
}

int hgic_fwctrl_get_sta_count(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_do_cmd(ctrl, ifidx, HGIC_CMD_GET_STA_COUNT, 0, 0, 0, 0);
}

int hgic_fwctrl_get_agg_cnt(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *agg, u8 size)
{
    return hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_AGG_CNT, agg, size);
}

int hgic_fwctrl_set_agg_cnt(struct hgic_fwctrl *ctrl, u8 ifidx, u8 agg[2])
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_AGG_CNT, agg ,2);
}

int hgic_fwctrl_get_bss_bw(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_get_short_val(ctrl, ifidx, HGIC_CMD_GET_BSS_BW);
}

int hgic_fwctrl_get_freq_range(struct hgic_fwctrl *ctrl, u8 ifidx, u32 *freq_start, u32 *freq_end, u32 *bss_bw)
{
    int ret = 0;
    u32 vals[3];

    ret = hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_FREQ_RANGE, (u8 *)&vals, sizeof(vals));
    if (ret == 12) {
        *freq_start = le32_to_cpu(vals[0]);
        *freq_end   = le32_to_cpu(vals[1]);
        *bss_bw     = le32_to_cpu(vals[2]);
    }
    return (ret == 12);
}

int hgic_fwctrl_get_chan_list(struct hgic_fwctrl *ctrl, u8 ifidx, u16 *chan_list, u16 count)
{
    int ret = hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_CHAN_LIST, (u8 *)chan_list, count * sizeof(u16));
    return ret > 0 ? ret / sizeof(u16) : 0;
}

int hgic_fwctrl_wakeup_sta(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *addr)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_WAKEUP_STA, addr, 6);
}

int hgic_fwctrl_set_ps_heartbeat(struct hgic_fwctrl *ctrl, u8 ifidx, u32 ipaddr, u32 dport, u32 period, u32 hb_tmo)
{
    u8 val[16];
    put_unaligned_le32(ipaddr, val);
    put_unaligned_le32(dport,  val + 4);
    put_unaligned_le32(period, val + 8);
    put_unaligned_le32(hb_tmo, val + 12);
    hgic_dbg("ip:%x, port:%d, period:%d, hb_tmo:%d\r\n", ipaddr, dport, period, hb_tmo);
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_PS_HEARTBEAT, val, 16);
}

int hgic_fwctrl_set_ps_heartbeat_resp(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 size)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_PS_HEARTBEAT_RESP, data, size);
}

int hgic_fwctrl_set_ps_wakeup_data(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 size)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_PS_WAKEUP_DATA, data, size);
}

int hgic_fwctrl_set_ps_connect(struct hgic_fwctrl *ctrl, u8 ifidx, u8 period, u8 roundup)
{
    u8 val[2] = {period, roundup};
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_PS_CONNECT, val, 2);
}

int hgic_fwctrl_radio_onoff(struct hgic_fwctrl *ctrl, u8 ifidx, u8 onoff)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_RADIO_ONOFF, onoff);
}

int hgic_fwctrl_set_bss_max_idle(struct hgic_fwctrl *ctrl, u8 ifidx, u32 max_idle)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_BSS_MAX_IDLE, max_idle);
}

int hgic_fwctrl_set_wkio_mode(struct hgic_fwctrl *ctrl, u8 ifidx, u8 mode)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_WKIO_MODE, mode);
}

int hgic_fwctrl_set_dtim_period(struct hgic_fwctrl *ctrl, u8 ifidx, u32 period)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_DTIM_PERIOD, period);
}

int hgic_fwctrl_set_ps_mode(struct hgic_fwctrl *ctrl, u8 ifidx, u8 mode)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_PS_MODE, mode);
}

int hgic_fwctrl_set_load_def(struct hgic_fwctrl *ctrl, u8 ifidx, u8 rst)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_LOAD_DEF, rst);
}

int hgic_fwctrl_disassoc_sta(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *addr)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_DISASSOC_STA, addr, 6);
}

int hgic_fwctrl_set_aplost_time(struct hgic_fwctrl *ctrl, u8 ifidx, u32 aplost_time)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_APLOST_TIME, aplost_time);
}

int hgic_fwctrl_get_wkreason(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_do_cmd(ctrl, ifidx, HGIC_CMD_GET_WAKEUP_REASON, 0, 0, 0, 0);
}

int hgic_fwctrl_unpair(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *addr)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_UNPAIR, addr, 6);
}

int hgic_fwctrl_set_auto_chswitch(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_AUTO_CHAN_SWITCH, enable);
}

int hgic_fwctrl_set_mcast_key(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *mcast_key)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_MCAST_KEY, mcast_key, STR_LEN(mcast_key));
}

int hgic_fwctrl_set_reassoc_wkhost(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_REASSOC_WKHOST, enable);
}

int hgic_fwctrl_set_wakeup_io(struct hgic_fwctrl *ctrl, u8 ifidx, u8 io, u8 edge)
{
    u8 val[2] = {io, edge};
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_WAKEUP_IO, val, 2);
}

int hgic_fwctrl_set_dbginfo_output(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_DBGINFO_OUTPUT, enable);
}

int hgic_fwctrl_set_sysdbg(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *cmd)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_SYSDBG, cmd, STR_LEN(cmd));
}

int hgic_fwctrl_set_autosleep_time(struct hgic_fwctrl *ctrl, u8 ifidx, u8 time)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_AUTO_SLEEP_TIME, time);
}

int hgic_fwctrl_get_key_mgmt(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *ssid, u32 size)
{
    return hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_KEY_MGMT, ssid, size);
}

int hgic_fwctrl_set_super_pwr(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_SUPER_PWR, enable);
}

int hgic_fwctrl_set_repeater_ssid(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *ssid)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_REPEATER_SSID, ssid, STR_LEN(ssid));
}

int hgic_fwctrl_set_repeater_psk(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *wpa_psk)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_REPEATER_PSK, wpa_psk, STR_LEN(wpa_psk));
}

int hgic_fwctrl_set_auto_save(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_CFG_AUTO_SAVE, enable);
}

int hgic_fwctrl_set_pair_autostop(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_PAIR_AUTOSTOP, enable);
}

int hgic_fwctrl_send_cust_mgmt(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 len)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SEND_CUST_MGMT, data, len);
}
int hgic_fwctrl_send_mgmtframe(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 len)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SEND_MGMTFRAME, data, len);
}

int hgic_fwctrl_get_battery_level(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_get_short_val(ctrl, ifidx, HGIC_CMD_GET_BATTERY_LEVEL);
}

int hgic_fwctrl_set_dcdc13v(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_DCDC13, enable);
}

int hgic_fwctrl_set_acktmo(struct hgic_fwctrl *ctrl, u8 ifidx, u32 tmo)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_ACKTMO, tmo);
}

int hgic_fwctrl_get_module_type(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_get_short_val(ctrl, ifidx, HGIC_CMD_GET_MODULETYPE);
}

int hgic_fwctrl_set_pa_pwrctl_dis(struct hgic_fwctrl *ctrl, u8 ifidx, u8 dis)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_PA_PWRCTRL_DIS, dis);
}

int hgic_fwctrl_set_dhcpc(struct hgic_fwctrl *ctrl, u8 ifidx, u8 en)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_DHCPC, en);
}

int hgic_fwctrl_get_dhcpc_result(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *buff, int len)
{
    return hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_DHCPC_RESULT, buff, len);
}

int hgic_fwctrl_set_wkdata_mask(struct hgic_fwctrl *ctrl, u8 ifidx, u16 offset, u8 *mask, u8 mask_len)
{
    u8 data[128];
    if (mask_len > 16) mask_len = 16;
    memset(data, 0, sizeof(data));
    put_unaligned_le16(offset, data);
    memcpy(data + 2, mask, mask_len);
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_WKUPDATA_MASK, data, mask_len + 2);
}

int hgic_fwctrl_set_hbdata_mask(struct hgic_fwctrl *ctrl, u8 ifidx, u16 offset, u8 *mask, u8 mask_len)
{
    u8 data[128];
    if (mask_len > 64) mask_len = 64;
    memset(data, 0, sizeof(data));
    put_unaligned_le16(offset, data);
    put_unaligned_le16(mask_len, data + 2);
    memcpy(data + 4, mask, mask_len);
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_PS_HBDATA_MASK, data, mask_len + 4);
}

int hgic_fwctrl_get_wkdata_buff(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *buff, int len)
{
    return hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_WKDATA_BUFF, buff, len);
}

int hgic_fwctrl_get_disassoc_reason(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_get_short_val(ctrl, ifidx, HGIC_CMD_GET_DISASSOC_REASON);
}

int hgic_fwctrl_set_wkdata_save(struct hgic_fwctrl *ctrl, u8 ifidx, u8 save)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_WKUPDATA_SAVEEN, save);
}

int hgic_fwctrl_set_cust_driver_data(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 len)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_CUST_DRIVER_DATA, data, len);
}

int hgic_fwctrl_set_mcast_txparam(struct hgic_fwctrl *ctrl, u8 ifidx, struct hgic_mcast_txparam *param)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_MCAST_TXPARAM, (u8 *)param, sizeof(struct hgic_mcast_txparam));
}

int hgic_fwctrl_set_freqinfo(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 len)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_STA_FREQINFO, data, len);
}

int hgic_fwctrl_reset_sta(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *addr)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_RESET_STA, addr, 6);
}

int hgic_fwctrl_set_ant_auto(struct hgic_fwctrl *ctrl, u8 ifidx, u8 en)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_ANT_AUTO, en);
}

int hgic_fwctrl_select_ant(struct hgic_fwctrl *ctrl, u8 ifidx, u8 ant)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_ANT_SEL, ant);
}

int hgic_fwctrl_get_ant_sel(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_get_short_val(ctrl, ifidx, HGIC_CMD_GET_ANT_SEL);
}

int hgic_fwctrl_set_wkhost_reasons(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *reasons, u8 count)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_WKUP_HOST_REASON, reasons, count);
}

int hgic_fwctrl_set_mac_filter(struct hgic_fwctrl *ctrl, u8 ifidx, u8 en)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_MAC_FILTER_EN, en);
}

int hgic_fwctrl_set_atcmd(struct hgic_fwctrl *ctrl, u8 ifidx, char *atcmd)
{
    int ret = 0;
    if (strncasecmp(atcmd, "at+", 3)) {
        char *tmp = kzalloc(strlen(atcmd) + 12, GFP_KERNEL);
        if (tmp) {
            strcpy(tmp,  "at+");
            strcpy(tmp + 3, atcmd);
            ret = hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_ATCMD, tmp, strlen(tmp));
            kfree(tmp);
            return ret;
        }
        return -ENOMEM;
    } else {
        return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_ATCMD, atcmd, strlen(atcmd));
    }
}

int hgic_fwctrl_set_roaming(struct hgic_fwctrl *ctrl, u8 ifidx, s8 *vals, u8 count)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_ROAMING, vals, count);
}

int hgic_fwctrl_set_ap_hide(struct hgic_fwctrl *ctrl, u8 ifidx, u8 hide)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_AP_HIDE, hide);
}

int hgic_fwctrl_set_frm_tx_maxcnt(struct hgic_fwctrl *ctrl, u8 ifidx, u8 txcnt)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_MAX_TCNT, txcnt);
}

int hgic_fwctrl_set_assert_holdup(struct hgic_fwctrl *ctrl, u8 ifidx, u8 holdup)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_ASSERT_HOLDUP, holdup);
}

int hgic_fwctrl_set_ap_psmode_en(struct hgic_fwctrl *ctrl, u8 ifidx, u8 en)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_AP_PSMODE_EN, en);
}

int hgic_fwctrl_set_dupfilter_en(struct hgic_fwctrl *ctrl, u8 ifidx, u8 en)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_DUPFILTER_EN, en);
}

int hgic_fwctrl_set_1v1_m2u_dis(struct hgic_fwctrl *ctrl, u8 ifidx, u8 dis)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_DIS_1V1_M2U, dis);
}

int hgic_fwctrl_set_psconnect_dis(struct hgic_fwctrl *ctrl, u8 ifidx, u8 dis)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_DIS_PSCONNECT, dis);
}

int hgic_fwctrl_set_blenc_en(struct hgic_fwctrl *ctrl, u8 ifidx, u8 data[2])
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_BLENC_EN, data, 2);
}

int hgic_fwctrl_blenc_send_data(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 len)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SEND_BLENC_DATA, data, len);
}
int hgic_fwctrl_blenc_set_advdata(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 len)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SEND_BLENC_ADVDATA, data, len);
}
int hgic_fwctrl_blenc_set_scanresp(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 len)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SEND_BLENC_SCANRESP, data, len);
}
int hgic_fwctrl_blenc_set_devaddr(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *addr)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SEND_BLENC_DEVADDR, addr, 6);
}
int hgic_fwctrl_blenc_set_advinterval(struct hgic_fwctrl *ctrl, u8 ifidx, u32 interval)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SEND_BLENC_ADVINTERVAL, interval);
}
int hgic_fwctrl_blenc_start_adv(struct hgic_fwctrl *ctrl, u8 ifidx, u32 en)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SEND_BLENC_STARTADV, en);
}

int hgic_fwctrl_reset(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_do_cmd(ctrl, ifidx, HGIC_CMD_RESET, 0, 0, 0, 0);
}

int hgic_fwctrl_set_hwscan(struct hgic_fwctrl *ctrl, u8 ifidx, u16 period, u16 interval, u16 chan, u16 max)
{
    u8 val[5];
    val[0] = period;
    val[1] = interval;
    val[4] = max;
    put_unaligned_le16(chan, val + 2);
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_HWSCAN, val, 5);
}

int hgic_fwctrl_get_txq_param(struct hgic_fwctrl *ctrl, u8 ifidx, struct hgic_txq_param param[4])
{
    return hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_TXQ_PARAM, (u8 *)param, 4 * sizeof(struct hgic_txq_param));
}

int hgic_fwctrl_set_promisc(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_PROMISC, enable);
}

int hgic_fwctrl_set_fix_txrate(struct hgic_fwctrl *ctrl, u8 ifidx, u32 txrate)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_FIX_TXRATE, txrate);
}

int hgic_fwctrl_set_nav_max(struct hgic_fwctrl *ctrl, u8 ifidx, u32 nav_max)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_NAV_MAX, nav_max);
}

int hgic_fwctrl_clear_nav(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_NAV_MAX, 0);
}

int hgic_fwctrl_set_cca_param(struct hgic_fwctrl *ctrl, u8 ifidx, struct hgic_cca_ctl *cca)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_CCA_PARAM, (u8 *)cca, sizeof(struct hgic_cca_ctl));
}

int hgic_fwctrl_set_tx_modulation_gain(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *gain_table, u32 size)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_TX_MODGAIN, gain_table, size);
}

int hgic_fwctrl_get_nav(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_get_short_val(ctrl, ifidx, HGIC_CMD_GET_NAV);
}

int hgic_fwctrl_get_bgrssi(struct hgic_fwctrl *ctrl, u8 ifidx, u8 channel, s8 resp[3])
{
    return hgic_fwctrl_do_cmd(ctrl, ifidx, HGIC_CMD_GET_BGRSSI, &channel, 1, resp, 3);
}

int hgic_fwctrl_send_hci_data(struct hgic_fwctrl *ctrl, u8 type, u8 *data, u32 len)
{
    struct hgic_ctrl_hdr *hdr;
    struct sk_buff *skb = dev_alloc_skb(ctrl->bus->drv_tx_headroom + sizeof(struct hgic_ctrl_hdr) + len + 4);
    if (skb) {
        skb_reserve(skb, ctrl->bus->drv_tx_headroom);
        hdr = (struct hgic_ctrl_hdr *)skb->data;
        memcpy((u8 *)(hdr + 1), data, len);
        skb_put(skb, sizeof(struct hgic_ctrl_hdr) + len);
        memset(hdr, 0, sizeof(struct hgic_ctrl_hdr));
        hdr->hdr.magic  = cpu_to_le16(HGIC_HDR_TX_MAGIC);
        hdr->hdr.type   = HGIC_HDR_TYPE_BLUETOOTH;
        hdr->hdr.ifidx  = 1;
        hdr->hdr.length = cpu_to_le16(skb->len);
        hdr->hci.type   = type;
        skb_queue_tail(&ctrl->txq, skb);
        ctrl->schedule(ctrl);
        return 0;
    }
    return -ENOMEM;
}

int hgic_fwctrl_set_beacon_start(struct hgic_fwctrl *ctrl, u8 ifidx, u8 start)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_BEACON_START, start);
}

int hgic_fwctrl_ble_open(struct hgic_fwctrl *ctrl, u8 ifidx, u8 open)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_BLE_OPEN, open);
}

int hgic_fwctrl_set_rts_duration(struct hgic_fwctrl *ctrl, u8 ifidx, int duration)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_RTS_DURATION, duration);
}

int hgic_fwctrl_set_disable_print(struct hgic_fwctrl *ctrl, u8 ifidx, int dis)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_DISABLE_PRINT, dis);
}

int hgic_fwctrl_set_conn_paironly(struct hgic_fwctrl *ctrl, u8 ifidx, int en)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_CONNECT_PAIRONLY, en);
}

int hgic_fwctrl_get_center_freq(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_get_short_val(ctrl, ifidx, HGIC_CMD_GET_CENTER_FREQ);
}

int hgic_fwctrl_set_wait_psmode(struct hgic_fwctrl *ctrl, u8 ifidx, u8 wait_psmode)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_WAIT_PSMODE, wait_psmode);
}

int hgic_fwctrl_set_diffcust_conn(struct hgic_fwctrl *ctrl, u8 ifidx, u8 en)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_DIFFCUST_CONN, en);
}

int hgic_fwctrl_set_ap_chan_switch(struct hgic_fwctrl *ctrl, u8 ifidx, u8 chan, u8 counter)
{
    u8 val[2] = {chan, counter};
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_AP_CHAN_SWITCH, val, 2);
}

int hgic_fwctrl_set_cca_for_ce(struct hgic_fwctrl *ctrl, u8 ifidx, u8 en)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_CCA_FOR_CE, en);
}

int hgic_fwctrl_set_standby(struct hgic_fwctrl *ctrl, u8 ifidx, u8 channel, u32 sleep_period)
{
    u8 val[5];
    val[0] = channel;
    put_unaligned_le32(sleep_period, val + 1);
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_STANDBY_CFG, val, 5);
}

int hgic_fwctrl_set_rtc(struct hgic_fwctrl *ctrl, u8 ifidx, u32 rtc)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_RTC, rtc);
}

int hgic_fwctrl_get_rtc(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *rtc)
{
    return hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_RTC, rtc, 4);
}

int hgic_fwctrl_set_apep_padding(struct hgic_fwctrl *ctrl, u8 ifidx, int en)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_APEP_PADDING, en);
}

int hgic_fwctrl_get_acs_result(struct hgic_fwctrl *ctrl, u8 ifidx, struct hgic_acs_result *result, u8 size)
{
    return hgic_fwctrl_get_bytes(ctrl, ifidx, HGIC_CMD_GET_ACS_RESULT, (u8 *)result, size * sizeof(struct hgic_acs_result));
}

int hgic_fwctrl_get_reason_code(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_get_short_val(ctrl, ifidx, HGIC_CMD_GET_WIFI_REASON_CODE);
}

int hgic_fwctrl_get_status_code(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_get_short_val(ctrl, ifidx, HGIC_CMD_GET_WIFI_STATUS_CODE);
}

int hgic_fwctrl_set_watchdog(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_WATCHDOG, enable);
}

int hgic_fwctrl_set_retry_fallback_cnt(struct hgic_fwctrl *ctrl, u8 ifidx, u8 cnt)
{
    return hgic_fwctrl_set_byte(ctrl, ifidx, HGIC_CMD_SET_RETRY_FALLBACK_CNT, cnt);
}

int hgic_fwctrl_set_fallback_mcs(struct hgic_fwctrl *ctrl, u8 ifidx, struct hgic_fallback_mcs *mcs)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_FALLBACK_MCS, (u8 *)mcs, sizeof(struct hgic_fallback_mcs));
}

int hgic_fwctrl_get_xosc(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_get_int_val(ctrl, ifidx, HGIC_CMD_GET_XOSC_VALUE);
}

int hgic_fwctrl_set_xosc(struct hgic_fwctrl *ctrl, u8 ifidx, int xosc)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_XOSC_VALUE, xosc);
}

int hgic_fwctrl_get_freq_offset(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *addr)
{
    u8 data[4];
    if (hgic_fwctrl_do_cmd(ctrl, ifidx, HGIC_CMD_GET_FREQ_OFFSET, addr, 6, data, 4) == 4) {
        return get_unaligned_le32(data);
    } else {
        return -1;
    }
}

int hgic_fwctrl_set_freq_cali_period(struct hgic_fwctrl *ctrl, u8 ifidx, u16 cali_period)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_CALI_PERIOD, cali_period);
}

int hgic_fwctrl_set_blenc_adv_filter(struct hgic_fwctrl *ctrl, u8 ifidx, u32 filter)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_BLENC_ADVFILTER, filter);
}

int hgic_fwctrl_set_max_tx_delay(struct hgic_fwctrl *ctrl, u8 ifidx, u32 tmo)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_MAX_TX_DELAY, tmo);
}

int hgic_fwctrl_get_sta_info(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *mac, struct hgic_sta_info *info)
{
    return hgic_fwctrl_do_cmd(ctrl, ifidx, HGIC_CMD_GET_STA_INFO, mac, 6, (u8 *)info, sizeof(struct hgic_sta_info));
}

int hgic_fwctrl_get_signal(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_get_short_val(ctrl, ifidx, HGIC_CMD_GET_SIGNAL);
}

int hgic_fwctrl_set_heartbeat_int(struct hgic_fwctrl *ctrl, u8 ifidx, u32 val)
{
    return hgic_fwctrl_set_int_val(ctrl, ifidx, HGIC_CMD_SET_HEARTBEAT_INT, val);
}

int hgic_fwctrl_get_tx_bitrate(struct hgic_fwctrl *ctrl, u8 ifidx)
{
    return hgic_fwctrl_get_int_val(ctrl, ifidx, HGIC_CMD_GET_TX_BITRATE);
}
int hgic_fwctrl_set_sleep_roaming(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable, s8 rssi)
{
    u8 vals[2] = {enable, rssi};
    return hgic_fwctrl_set_bytes(ctrl, ifidx, HGIC_CMD_SET_SLEEP_ROAMING, vals, 2);
}

