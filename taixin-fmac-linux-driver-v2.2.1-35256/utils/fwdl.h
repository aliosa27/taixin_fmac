#ifndef _HGIC_BOOT_HOST_H_
#define _HGIC_BOOT_HOST_H_

#include "../hgic_def.h"

#define HG_BOOTDL_CMD_ENTER                   (0x00)
#define HG_BOOTDL_CMD_GET_SC                  (0x01)
#define HG_BOOTDL_CMD_WRITE_MEM               (0x02)
#define HG_BOOTDL_CMD_READ_MEM                (0x03)
#define HG_BOOTDL_CMD_RUN                     (0x04)
#define HG_BOOTDL_CMD_VERIFY_MEM              (0x05)
#define HG_BOOTDL_CMD_CHIP_RESET              (0x06)
#define HG_BOOTDL_CMD_WRITE_REG               (0x07)
#define HG_BOOTDL_CMD_READ_REG                (0x08)
#define HG_BOOTDL_CMD_SPEED                   (0x09)
#define HG_BOOTDL_CMD_EXIT                    (0xFF)

#define HG_BOOT_CMD_RUN_PREACT_AES_DEC           BIT(31)
#define HG_BOOT_CMD_RUN_PREACT_CRC_CHK           BIT(30)
#define HG_BOOT_CMD_RUN_PREACT_SP_CFG            BIT(29)

#define HG_BOOTDL_CMD_LEN                     12
#define HG_BOOTDL_CMD_WRITE_MEM_TMO           1000
#define HG_BOOTDL_CMD_NORMAL_TMO              100
#define HG_BOOTDL_INFO_HDR_SIZE               512

enum hg_device_state {
    STATE_FW = 0,
    STATE_BOOT,
};

enum hg_boot_host_check{
    HG_BOOTDL_CHECK_SUM = 0,
    HG_BOOTDL_CHECK_CRC8,
    HG_BOOTDL_CHECK_0XFD,
    HG_BOOTDL_CHECK_OFF = 0xFF
} ;

enum hg_boot_host_rsp_err{
    HG_BOOTDL_RSP_OK = 0,
    HG_BOOTDL_RSP_ERR_CMD,
    HG_BOOTDL_RSP_ERR_ADDR,
    HG_BOOTDL_RSP_ERR_LEN,
    HG_BOOTDL_RSP_ERR_PERMISSION,
    HG_BOOTDL_RSP_ERR_CMD_CHECK,
    HG_BOOTDL_RSP_ERR_DATA_CHECK,
    HG_BOOTDL_RSP_ERR_TO,
    HG_BOOTDL_RSP_ERR_IN_FW = 0xFF,
} ;

/**
  * @brief huge-ic boot state machine
  */
enum hg_boot_host_err {
    HG_BOOTDL_ERR_NONE = 0,
    HG_BOOTDL_ERR_UNSUPPORT_CMD,
    HG_BOOTDL_ERR_RSP_PACKET,
    HG_BOOTDL_ERR_XFER,
    HG_BOOTDL_ERR_TO,
} ;

struct hgic_bootdl_fw_info {    
    u32 write_addr;
    u8  aes_en;
    u8  crc_en;
    u8  sp_cfg;
    u32 fw_version;
    u32 fw_len;
    u32 local_crc32;
    u32 hdr_len;
};

struct hgic_bootdl {
    struct hgic_bootdl_fw_info  fw_info;
    u8                          checksum_mode;
    u16                         last_cookie;
    u32                         frag_size;
    struct hgic_bus            *bus;
    struct hgic_fwctrl         *ctrl;
    struct firmware            *fw;
};

u32 hgic_bootdl_init(struct hgic_bootdl *hg_fwdl, struct hgic_bus *bus, struct hgic_fwctrl *ctrl);
void hgic_bootdl_release(struct hgic_bootdl *hg,int mode);
int hgic_bootdl_download(struct hgic_bootdl *hg, const char *fw_path);
int hgic_bootdl_cmd_enter(struct hgic_bootdl *hg);
struct sk_buff *hgic_bootdl_send_cmd(struct hgic_bootdl *hg_fwdl,struct sk_buff *skb,u32 timeout);
struct sk_buff *hgic_bootdl_send_data(struct hgic_bootdl *hg_fwdl,struct sk_buff *skb,u32 timeout);

#endif
