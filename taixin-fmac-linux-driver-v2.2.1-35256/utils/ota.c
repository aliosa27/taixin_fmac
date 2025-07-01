
#ifdef __RTOS__
#include <linux/module.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#else
#include <linux/version.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#include <linux/firmware.h>
#endif

#include "../hgic_def.h"
#include "fwinfo.h"
#include "fwctrl.h"
#include "ota.h"
#include "utils.h"

static u16 hgic_ota_check_sum(u8 *addr, s32 count)
{
    s32 sum = 0;
    while (count > 1) {
        sum = sum + *(u16 *)addr;
        addr  += 2;
        count -= 2;
    }
    if (count > 0) {
        sum += *addr;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (u16)~sum;
}

static struct sk_buff *hgic_ota_send_packet_tmo(struct hgic_ota *ota, struct sk_buff *skb, u32 tmo)
{
    struct hgic_cmd_response resp;
    struct hgic_hdr *hdr = NULL;

    resp.cookie = hgic_ctrl_cookie(ota->ctrl);
    memset(&resp, 0, sizeof(resp));
    hdr = (struct hgic_hdr *)skb_push(skb, sizeof(struct hgic_hdr));
    hdr->magic  = cpu_to_le16(HGIC_HDR_TX_MAGIC);
    hdr->length = cpu_to_le16(skb->len);
    hdr->cookie = cpu_to_le16(resp.cookie);
    hdr->type   = HGIC_HDR_TYPE_OTA;
    hdr->ifidx  = HGIC_WDEV_ID_STA;
    hgic_fwctrl_send_data(ota->ctrl, skb, &resp, tmo);
    return resp.skb;
}

static void hgic_ota_release_data(struct hgic_ota *ota)
{
    hgic_dbg("Enter ...\n");
    hgic_clear_queue(&ota->fw_dataq);
    hgic_dbg("Leave ...\n");
}

void hgic_ota_release(struct hgic_ota *ota)
{
    hgic_dbg("Enter ...\n");
    if (ota->inited) {
        hgic_clear_queue(&ota->fw_dataq);
#ifdef __RTOS__
        skb_queue_head_deinit(&ota->fw_dataq);
#endif
    }
    hgic_dbg("Leave ...\n");
}

s32 hgic_ota_init(struct hgic_ota *ota, struct hgic_fwctrl *ctrl, struct hgic_fw_info *fw_info)
{
    hgic_dbg("Enter ...\n");
    memset(ota, 0, sizeof(struct hgic_ota));
    ota->frag_size = HG_OTA_FW_FLAGMENT_SIZE;
    ota->ctrl      = ctrl;
    ota->ori_fw_info   = fw_info;
    ota->inited = 1;
    skb_queue_head_init(&ota->fw_dataq);
    hgic_dbg("Leave ...\n");
    return 0;
}

static s32 hgic_ota_fill_hdr(struct hgic_ota *ota, struct sk_buff *skb, u32 offset)
{
    struct hgic_ota_hdr *hdr = NULL;
    u16 payload_len = 0;

    if (ota == NULL || skb == NULL || skb->len > ota->frag_size) {
        hgic_err("Input para error!\r\n");
        return -EINVAL;
    }
    if (ota->fw_len == 0) {
        hgic_err("ERROR:fw len is zero!\r\n");
        return -EINVAL;
    }
    payload_len = skb->len;

    hdr = (struct hgic_ota_hdr *)skb_push(skb, sizeof(struct hgic_ota_hdr));
    memset(hdr, 0, sizeof(struct hgic_ota_hdr));
    hdr->chipid     = cpu_to_le16(ota->ori_fw_info->chip_id);
    hdr->len        = cpu_to_le16(payload_len);
    hdr->tot_len    = cpu_to_le32(ota->fw_len);
    hdr->off        = cpu_to_le32(offset);
    hdr->version    = cpu_to_le32(ota->ori_fw_info->version);
    hdr->checksum   = cpu_to_le16(hgic_ota_check_sum(hdr->data, hdr->len));
    return 0;
}

static s32 hgic_ota_check_hdr_info(struct hgic_ota *ota, const u8 *data)
{
    u32 sdk_version = 0;
    u32 svn_version = 0;
    u16 chip_id  = 0;
    u8  cpu_id  = 0;
    s32 err_code = 0;

    hgic_dbg("%s:Original fw info:%d.%d.%d.%d\r\n", __FUNCTION__,
             (ota->ori_fw_info->version >> 24) & 0xff, (ota->ori_fw_info->version >> 16) & 0xff,
             (ota->ori_fw_info->version >> 8) & 0xff, (ota->ori_fw_info->version & 0xff));

    hgic_dbg("%s:Chip id:%x,cpu id:%d\r\n", __FUNCTION__,
             ota->ori_fw_info->chip_id, ota->ori_fw_info->cpu_id);

    sdk_version = hgic_get_fw_sdk_version(data, &err_code);
    if (err_code != 0) {
        hgic_err("%s:Get ota fw sdk version error!ret:%d\n", __FUNCTION__, err_code);
        return err_code;
    }
    if ((sdk_version & 0xff) != (ota->ori_fw_info->version & 0xff)) {
        hgic_err("%s:firmware version not match!%x vs %x\n", __FUNCTION__, sdk_version & 0xff, ota->ori_fw_info->version & 0xff);
        return -EFAULT;
    }

    svn_version = hgic_get_fw_svn_version(data, &err_code);
    if (err_code != 0) {
        hgic_err("%s:Get ota fw svn version error!ret:%d\n", __FUNCTION__, err_code);
        return err_code;
    }

    chip_id = hgic_get_fw_chipid(data, &err_code);
    if (err_code != 0) {
        hgic_err("%s:Get ota fw chip_id error!ret:%d\n", __FUNCTION__, err_code);
        return err_code;
    }
    if (chip_id != ota->ori_fw_info->chip_id) {
        hgic_err("%s:firmware version not match!\n", __FUNCTION__);
        return -EFAULT;
    }

    cpu_id = hgic_get_fw_cpuid(data, &err_code);
    if (err_code != 0) {
        hgic_err("%s:Get ota fw CPU id error!ret:%d\n", __FUNCTION__, err_code);
        return err_code;
    }
    if (cpu_id != ota->ori_fw_info->cpu_id) {
        hgic_err("%s:firmware CPU id not match!\n", __FUNCTION__);
        return -EFAULT;
    }

    return 0;
}

static s32 hgic_ota_parse_fw(struct hgic_ota *ota, char *fw_name)
{
    struct sk_buff *skb = NULL;
    const struct firmware *fw;
    u32 copy_len = 0;
    u32 xfer_len = 0;
    u32 addr_offset = 0;
    s32 ret = 0;
    const u8 *data;
    const u32 hdr_len = sizeof(struct hgic_ota_hdr) + sizeof(struct hgic_hdr);
    u32 fw_hdr_len = 0;
    s32 err_code = 0;
    s32 crc_result = 0;

    if (ota == NULL) {
        hgic_err("Input para error!\r\n");
        return -EINVAL;
    }

    hgic_dbg("Check para:fw_name:%s,hdr_len:%d\n", fw_name, hdr_len);

    ret = request_firmware(&fw, (const char *)fw_name, ota->ctrl->dev);
    if (ret) {
        hgic_dbg("request_firmware failed!ret:%d\n", ret);
        return -ENODEV;
    }

    ret = hgic_ota_check_hdr_info(ota, fw->data);
    if (ret != 0) {
        hgic_err("hgic_ota_check_info error!\r\n");
        return ret;
    }

    crc_result = hgic_get_fw_code_checksum(fw->data, fw->size);
    if (crc_result) {
        hgic_err("hgic_get_fw_code_checksum error!\r\n");
        return crc_result;
    }

    fw_hdr_len = hgic_get_fw_code_offset(fw->data, &err_code);
    if (err_code != 0) {
        hgic_err("hgic_get_fw_code_offset error!\r\n");
        return err_code;
    }

    //ota->fw_len = fw->size - fw_hdr_len;
    ota->fw_len = fw->size;
    copy_len   = ota->fw_len;
    data       = (char *)fw->data;
    hgic_dbg("Check fw para:fw_len:%d,each fragment size:%d\n", ota->fw_len, ota->frag_size);

    while (copy_len) {
        xfer_len = copy_len > ota->frag_size ? ota->frag_size : copy_len;
        //hgic_dbg("Check xfer para:xfer_len:%d,offset:%d\n", xfer_len, addr_offset);
        skb = dev_alloc_skb(xfer_len + hdr_len + 4);
        if (skb == NULL) {
            printk("%s: no memory\r\n", __FUNCTION__);
            release_firmware(fw);
            return -ENOMEM;
        }
        skb_reserve(skb, hdr_len);
        memcpy(skb->data, data + addr_offset, xfer_len);
        skb_put(skb, xfer_len);

        ret = hgic_ota_fill_hdr(ota, skb, addr_offset);
        if (ret) {
            hgic_err("hgic_ota_fill_frame_hdr error!\n");
            release_firmware(fw);
            return -EFAULT;
        }

        skb_queue_tail(&ota->fw_dataq, skb);
        copy_len     -= xfer_len;
        addr_offset  += xfer_len;
    }
    release_firmware(fw);
    return 0;
}

s32 hgic_ota_send_fw(struct hgic_ota *ota, char *fw_name, u32 tmo)
{
    s32 ret = 0;
    struct sk_buff *resp = NULL;
    struct hgic_ota_hdr *hdr = NULL;
    struct sk_buff *skb = NULL;

    if (ota == NULL) {
        printk("%s: Input para error!\r\n", __FUNCTION__);
        ret = -EINVAL;
        goto __failed;
    }

    ret = hgic_ota_parse_fw(ota, fw_name);
    if (ret) {
        hgic_err("Firmware parse error!\n");
        goto __failed;
    }

    while (!skb_queue_empty(&ota->fw_dataq)) {
        skb = skb_dequeue(&ota->fw_dataq);
        resp = hgic_ota_send_packet_tmo(ota, skb, tmo);
        if (resp) {
            skb_pull(resp, sizeof(struct hgic_hdr));
            hdr = (struct hgic_ota_hdr *)resp->data;
            if (hdr->err_code) {
                hgic_err("Responce Error:Error code:%d\n", le16_to_cpu(hdr->err_code));
                ret = le16_to_cpu(hdr->err_code);
                goto __failed;
            } else {
                hgic_dbg("OTA write to flash success!\n");
            }
        } else {
            hgic_err("Get responce timeout or no responce!\n");
            ret = -ENODEV;
            goto __failed;
        }
    }
    hgic_ota_release_data(ota);
    hgic_dbg("hgic_ota_send_fw success!!!\n");
    return 0;

__failed:
    hgic_ota_release_data(ota);
    hgic_dbg("hgic_ota_send_fw failed!!!\n");
    return ret;
}

#ifdef __RTOS__
int hgic_ota_start(char *ifname, char *fw_name)
{
    struct net_device *ndev = net_device_get_by_name(ifname);

    if (ndev) {
        return hgic_ota_send_fw(hgic_devota(ndev), fw_name, HG_OTA_WRITE_MEM_TMO);
    } else {
        hgic_dbg("Can not find netdev name:%s\n",ifname);
    }
    return -ENODEV;
}
#endif

