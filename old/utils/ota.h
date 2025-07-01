#ifndef _HGIC_OTA_H_
#define _HGIC_OTA_H_

#include "../hgic_def.h"

#define HG_OTA_WRITE_MEM_TMO               5000
#define HG_OTA_NORMAL_TMO                  100
#define HG_OTA_FW_FLAGMENT_SIZE            1500

enum HGIC_OTA_RESP_ERR_CODE{
    HGIC_OTA_RESP_ERR_OK=0,
    HGIC_OTA_RESP_ERR_CHECKSUM,
    HGIC_OTA_RESP_ERR_WRITE,
};

struct hgic_ota {
    u32  inited;
    struct sk_buff_head         fw_dataq;
    u32 frag_size;
    u32 fw_len;
    struct hgic_fwctrl *ctrl;
    struct hgic_fw_info *ori_fw_info;
};

s32 hgic_ota_init(struct hgic_ota *ota, struct hgic_fwctrl *ctrl, struct hgic_fw_info *fw_info);
void hgic_ota_release(struct hgic_ota *ota);
s32 hgic_ota_send_fw(struct hgic_ota *hg, char *fw_name, u32 tmo);

#endif
