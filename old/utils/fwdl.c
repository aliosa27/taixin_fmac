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
#include "fwctrl.h"
#include "fwdl.h"
#include "fwinfo.h"
#include "utils.h"

#define BOOT_CMD_KEY        "@huge-ic"
#define BOOT_CMD_KEY_SIZE   8

void hgic_bootdl_release(struct hgic_bootdl *hg, int mode)
{
    if (hg == NULL) {
        return;
    }

    hgic_dbg("Enter ...\n");

    hgic_dbg("Leave ...\n");
}

u32 hgic_bootdl_init(struct hgic_bootdl *hg_fwdl, struct hgic_bus *bus, struct hgic_fwctrl *ctrl)
{
    if (hg_fwdl == NULL) {
        printk("%s:%d:Input para error!\n", __FUNCTION__, __LINE__);
        return -EINVAL;
    }

    hgic_dbg("Enter ...\n");
    memset(hg_fwdl, 0, sizeof(struct hgic_bootdl));
    hg_fwdl->checksum_mode = bus->bootdl_cksum;
    hg_fwdl->frag_size   = bus->bootdl_pktlen;
    hg_fwdl->ctrl        = ctrl;
    hg_fwdl->bus         = bus;
    hgic_dbg("Leave ...each packet len:%d\n", hg_fwdl->frag_size);
    return 0;
}

static u8 crc8(char *p_buf, u32 len)
{
    return 0;
}

static struct sk_buff *hgic_bootdl_alloc_cmd_skb(struct hgic_bootdl *hg, u8 cmd_id)
{
    struct sk_buff *skb = NULL;
    struct hgic_bootdl_cmd_hdr *cmd_hdr = NULL;

    skb = dev_alloc_skb(sizeof(struct hgic_bootdl_cmd_hdr) + 4);
    if (!skb) {
        return skb;
    }
    cmd_hdr           = (struct hgic_bootdl_cmd_hdr *)skb->data;
    memset(cmd_hdr, 0, sizeof(struct hgic_bootdl_cmd_hdr));
    cmd_hdr->cmd      = cmd_id;
    cmd_hdr->cmd_len  = 12;
    cmd_hdr->cmd_flag = hg->checksum_mode;
    skb_put(skb, sizeof(struct hgic_bootdl_cmd_hdr));
    return skb;
}

static u8 hgic_bootdl_cmd_check_val(u8 check_mode, u8 *p_buf, u32 len)
{
    u8   check_value    = 0;
    u32 i = 0;

    if (HGIC_BUS_BOOTDL_CHECK_SUM == check_mode) {
        for (i = 0; i < len; i++) {
            check_value += *p_buf++;
        }
    } else if (HGIC_BUS_BOOTDL_CHECK_CRC8 == check_mode) {
        check_value = crc8(p_buf, len);
    } else if (HGIC_BUS_BOOTDL_CHECK_0XFD == check_mode) {
        check_value = 0xFD;
    } else {
        return 0;
    }
    return check_value;
}

static int hgic_bootdl_cmd_rsp_handle(unsigned char cmd_flag, unsigned char cmd, struct hgic_bootdl_resp_hdr *resp)
{
    if (resp->check != hgic_bootdl_cmd_check_val(cmd_flag, (u8 *)&resp->cmd, 8)) {
        hgic_dbg("Checksum error,return HG_BOOTDL_ERR_RSP_PACKET!\r\n");
        return HG_BOOTDL_ERR_RSP_PACKET;
    }
    if (resp->cmd != cmd) {
        hgic_dbg("Cmd not match,resp_cmd:<%d>,cmd:<%d>\n", resp->cmd, cmd);
        return HG_BOOTDL_ERR_RSP_PACKET;
    }

    return resp->rsp;
}


struct sk_buff *hgic_bootdl_send_cmd(struct hgic_bootdl *hg_fwdl, struct sk_buff *skb, u32 timeout)
{
    struct hgic_bootdl_cmd_hdr *hdr = NULL;
    struct hgic_cmd_response resp;

    memset(&resp, 0, sizeof(resp));
    resp.cookie = hgic_ctrl_cookie(hg_fwdl->ctrl);
    hdr = (struct hgic_bootdl_cmd_hdr *)skb->data;
    hdr->hdr.magic  = cpu_to_le16(HGIC_HDR_TX_MAGIC);
    hdr->hdr.length = cpu_to_le16(skb->len);
    hdr->hdr.cookie = cpu_to_le16(resp.cookie);
    hdr->hdr.type   = HGIC_HDR_TYPE_BOOTDL;
    hg_fwdl->last_cookie = resp.cookie;
    return hgic_fwctrl_send_data(hg_fwdl->ctrl, skb, &resp, timeout);
}

struct sk_buff *hgic_bootdl_send_data(struct hgic_bootdl *hg_fwdl, struct sk_buff *skb, u32 timeout)
{
    struct hgic_bootdl_cmd_hdr *hdr = NULL;
    struct hgic_cmd_response resp;

    memset(&resp, 0, sizeof(struct hgic_cmd_response));
    resp.cookie = hg_fwdl->last_cookie;
    hdr = (struct hgic_bootdl_cmd_hdr *)skb_push(skb, sizeof(struct hgic_bootdl_cmd_hdr));
    memset(hdr, 0, sizeof(struct hgic_bootdl_cmd_hdr));
    hdr->hdr.magic  = cpu_to_le16(HGIC_HDR_TX_MAGIC);
    hdr->hdr.type   = HGIC_HDR_TYPE_BOOTDL_DATA;
    return hgic_fwctrl_send_data(hg_fwdl->ctrl, skb, &resp, timeout);
}

static int hgic_bootdl_parse_fw(struct hgic_bootdl *hg, const char *fw_name)
{
    const struct firmware *fw;
    int ret = 0;
    s32 err_code    = 0;

    ret = request_firmware(&fw, fw_name, hg->ctrl->dev);
    if (ret) {
        printk("%s,%d:request_firmware failed!ret:%d\n", __FUNCTION__, __LINE__, ret);
        return ret;
    }
    hg->fw = (struct firmware *)fw;

    hg->fw_info.write_addr = hgic_get_fw_dl_addr(fw->data, &err_code);
    if (err_code) {
        hgic_dbg("hgic_get_fw_dl_addr error!\n");
        return err_code;
    }

    hg->fw_info.aes_en     = hgic_get_fw_aes_en(fw->data, &err_code);
    if (err_code) {
        hgic_dbg("hgic_get_aes_en error!\n");
        return err_code;
    }

    hg->fw_info.crc_en     = hgic_get_fw_crc_en(fw->data, &err_code);
    if (err_code) {
        hgic_dbg("hgic_get_fw_crc_en error!\n");
        return err_code;
    }

    hg->fw_info.local_crc32 = hgic_get_fw_local_crc32(fw->data, &err_code);
    if (err_code) {
        hgic_dbg("hgic_get_fw_local_crc32 error!\n");
        return err_code;
    }

    hg->fw_info.hdr_len = hgic_get_fw_code_offset(fw->data, &err_code);
    if (err_code) {
        hgic_dbg("hgic_get_fw_code_offset error!\n");
        return err_code;
    }

    hg->fw_info.sp_cfg     = 1;
    hg->fw_info.fw_len     = fw->size - hg->fw_info.hdr_len;

    hgic_dbg("firmware hdr len  : %d\r\n", hg->fw_info.hdr_len);
    hgic_dbg("firmware run addr : %x\r\n", hg->fw_info.write_addr);
    hgic_dbg("firmware size     : %d\r\n", hg->fw_info.fw_len);
    hgic_dbg("firmware aes_en:%d,crc_en:%d\r\n", hg->fw_info.aes_en, hg->fw_info.crc_en);

    return 0;
}

static int hgic_bootdl_send_fw(struct hgic_bootdl *hg, struct sk_buff *skb, u32 tmo)
{
    struct sk_buff *resp_skb = NULL;
    struct hgic_bootdl_resp_hdr  *data_resp = NULL;
    int ret = 0;

    if (skb == NULL || hg == NULL) {
        hgic_dbg("input para error\n");
        return -EINVAL;
    }

    resp_skb = hgic_bootdl_send_data(hg, skb, tmo);
    if (resp_skb) {
        data_resp = (struct hgic_bootdl_resp_hdr *)resp_skb->data;
        ret       = data_resp->rsp;
        if (ret != 0) {
            hgic_dbg("Send fw data error!ret:<%d>\n", ret);
        } else {
            hgic_dbg("Send fw data success!\n");
        }
        dev_kfree_skb_any(resp_skb);
        return ret;
    } else {
        hgic_dbg("send fw data error, no resp!\n");
        return -EFAULT;
    }
}

static int hgic_bootdl_send_cmd_tmo(struct hgic_bootdl *hg,
                                    struct sk_buff *skb,
                                    u32 timeout,
                                    u32 *resp_data)
{
    struct sk_buff *resp = NULL;
    struct hgic_bootdl_cmd_hdr   *cmd_hdr = (struct hgic_bootdl_cmd_hdr *)skb->data;
    struct hgic_bootdl_resp_hdr  *boot_resp = NULL;
    int ret = 0;
    unsigned char cmd_flag = 0;
    unsigned char cmd      = 0;

    if (hg == NULL || skb == NULL) {
        if(skb) kfree_skb(skb);
        return -EINVAL;
    }

    cmd_flag = cmd_hdr->cmd_flag;
    cmd      = cmd_hdr->cmd;
    resp = hgic_bootdl_send_cmd(hg, skb, timeout);
    if (resp) {
        boot_resp = (struct hgic_bootdl_resp_hdr *)resp->data;
        ret = hgic_bootdl_cmd_rsp_handle(cmd_flag, cmd, boot_resp);
        if (ret != 0 && ret != HG_BOOTDL_RSP_ERR_IN_FW) {
            hgic_err("cmd %d, error:%d\n", cmd, ret);
            dev_kfree_skb_any(resp);
            return ret;
        }
        if (resp_data != NULL) {
            *resp_data = get_unaligned_le32(boot_resp->rsp_data);
        }
        dev_kfree_skb_any(resp);
    } else {
        hgic_err("cmd: %d, no responce!!\r\n", cmd);
        ret = -1;
    }
    return ret;
}

int hgic_bootdl_cmd_enter(struct hgic_bootdl *hg)
{
    struct sk_buff *skb  = NULL;
    struct hgic_bootdl_cmd_hdr *cmd_hdr = NULL;
    int ret = 0;

    skb = hgic_bootdl_alloc_cmd_skb(hg, HG_BOOTDL_CMD_ENTER);
    if (skb) {
        cmd_hdr = (struct hgic_bootdl_cmd_hdr *)skb->data;
        memcpy((void *)cmd_hdr->addr, (void *)BOOT_CMD_KEY, BOOT_CMD_KEY_SIZE);
        cmd_hdr->check = hgic_bootdl_cmd_check_val(hg->checksum_mode, (u8 *)&cmd_hdr->cmd, 11);
    } else {
        hgic_err("malloc skb failed!\n");
        return -ENOMEM;
    }
    ret = hgic_bootdl_send_cmd_tmo(hg, skb, HG_BOOTDL_CMD_NORMAL_TMO, NULL);
    if (ret == 0 || ret == HG_BOOTDL_RSP_ERR_IN_FW) {
        if (ret == HG_BOOTDL_RSP_ERR_IN_FW) {
            //hgic_err("In firmware state\n");
            return STATE_FW;
        } else {
            //hgic_err("In bootdl state\n");
            return STATE_BOOT;
        }
    } else {
        hgic_err("failed! ret:%d\n", ret);
        return ret;
    }
}

static int hgic_bootdl_cmd_write_memory(struct hgic_bootdl *hg, u32 write_addr, u32 data_len)
{
    struct sk_buff *skb  = NULL;
    struct hgic_bootdl_cmd_hdr *cmd_hdr = NULL;

    skb = hgic_bootdl_alloc_cmd_skb(hg, HG_BOOTDL_CMD_WRITE_MEM);
    if (skb) {
        cmd_hdr = (struct hgic_bootdl_cmd_hdr *)skb->data;
        put_unaligned_le32(write_addr, cmd_hdr->addr);
        if (hg->bus->type == HGIC_BUS_SDIO) {
            put_unaligned_le32(data_len, cmd_hdr->len);
        } else {
            put_unaligned_le32((data_len + 1024), cmd_hdr->len);
        }
        cmd_hdr->check    = hgic_bootdl_cmd_check_val(hg->checksum_mode, (u8 *)&cmd_hdr->cmd, 11);
    } else {
        hgic_dbg("malloc skb failed!\n");
        return -ENOMEM;
    }
    return hgic_bootdl_send_cmd_tmo(hg, skb, HG_BOOTDL_CMD_NORMAL_TMO, NULL);
}

static int hgic_bootdl_cmd_run(struct hgic_bootdl *hg)
{
    struct sk_buff *skb  = NULL;
    struct hgic_bootdl_cmd_hdr *cmd_hdr = NULL;
    u32 temp = 0;

    skb = hgic_bootdl_alloc_cmd_skb(hg, HG_BOOTDL_CMD_RUN);
    if (skb) {
        cmd_hdr = (struct hgic_bootdl_cmd_hdr *)skb->data;
        put_unaligned_le32(hg->fw_info.write_addr, cmd_hdr->addr);

        temp = hg->fw_info.fw_len;
        if (hg->fw_info.aes_en) {
            temp  |= HG_BOOT_CMD_RUN_PREACT_AES_DEC;
        }
        if (hg->fw_info.crc_en) {
            temp  |= HG_BOOT_CMD_RUN_PREACT_CRC_CHK;
        }
        if (hg->fw_info.sp_cfg) {
            temp  |= HG_BOOT_CMD_RUN_PREACT_SP_CFG;
        }
        put_unaligned_le32(temp, cmd_hdr->len);

        cmd_hdr->check = hgic_bootdl_cmd_check_val(hg->checksum_mode, (u8 *)&cmd_hdr->cmd, 11);
    } else {
        hgic_dbg("malloc skb failed!\n");
        return -ENOMEM;
    }
    return hgic_bootdl_send_cmd_tmo(hg, skb, HG_BOOTDL_CMD_NORMAL_TMO, NULL);
}

static unsigned int hgic_bootdl_fragment_proc(struct hgic_bootdl *hg, unsigned int copy_len)
{
    unsigned int xfer_len = 0;

    if (hg->bus->type == HGIC_BUS_SDIO) {
        if (copy_len < hg->frag_size) {
            xfer_len = ALIGN(copy_len, hg->bus->blk_size);
        } else {
            xfer_len = hg->frag_size; 
        }
    } else {
        xfer_len = copy_len > hg->frag_size ? hg->frag_size : copy_len;
    }
    return xfer_len;
}

int hgic_bootdl_download(struct hgic_bootdl *hg, const char *fw_path)
{
    int ret = 0;
    struct sk_buff *skb = NULL;
    u32 write_addr      = 0;
    s32 copy_len        = 0;
    u32 xfer_len        = 0;
    u32 addr_offset     = 0;
    char *data          = NULL;

    if (hg == NULL || fw_path == NULL) {
        printk("%s,%d:input para error!\n", __FUNCTION__, __LINE__);
        return -EINVAL;
    }

    hgic_enter();
    ret = hgic_bootdl_parse_fw(hg, fw_path);
    if (ret != 0 || !hg->fw) {
        hgic_dbg("hgic_bootdl_parse_fw error,ret:<%d>,path:%s\n", ret, fw_path);
        goto __finish;
    }

    copy_len          = hg->fw_info.fw_len;
    write_addr        = hg->fw_info.write_addr;
    data = (char *)(hg->fw->data + hg->fw_info.hdr_len);
    while (copy_len > 0) {
        //xfer_len = copy_len > hg->frag_size ? hg->frag_size : copy_len;
        xfer_len = hgic_bootdl_fragment_proc(hg, copy_len);
        skb = dev_alloc_skb(xfer_len + sizeof(struct hgic_bootdl_cmd_hdr));
        if (skb == NULL) {
            printk("%s: no memory\r\n", __FUNCTION__);
            ret = -ENOMEM;
            goto __finish;
        }

        skb_reserve(skb, sizeof(struct hgic_bootdl_cmd_hdr));
        memcpy(skb->data, data + addr_offset, xfer_len);
        skb_put(skb, xfer_len);

        ret = hgic_bootdl_cmd_write_memory(hg, write_addr, skb->len);
        if (ret != 0) {
            hgic_dbg("hgic_bootdl_cmd_write_memory error!\n");
            dev_kfree_skb_any(skb);
            goto __finish;
        }

        ret = hgic_bootdl_send_fw(hg, skb, HG_BOOTDL_CMD_WRITE_MEM_TMO);
        if (ret != 0) {
            hgic_dbg("hgic_bootdl_send_fw error!\n");
            goto __finish;
        }
        write_addr   += xfer_len;
        copy_len     -= xfer_len;
        addr_offset  += xfer_len;
        skb = NULL;
    }

    ret = hgic_bootdl_cmd_run(hg);
    if (ret) {
        printk("%s: Cmd run failed:%d\r\n", __FUNCTION__, ret);
    } else {
        hgic_dbg("Cmd run success!\n");
    }
__finish:
    if (hg->fw) {
        hgic_dbg("Release boot download firmware...\n");
        release_firmware(hg->fw);
        hg->fw = NULL;
    }
    hgic_leave();
    return ret;
}



