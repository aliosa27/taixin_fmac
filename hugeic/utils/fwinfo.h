#ifndef _HGIC_FWINFO_H_
#define _HGIC_FWINFO_H_

#include "../hgic.h"

#define HGIC_FWINFO_BOOT_HDR    0x5a69
#define HGIC_FWINFO_SPI_HDR     0x1
#define HGIC_FWINFO_CODE_HDR    0x2

struct hgic_spiflash_header_boot {
    u16 boot_flag;              /* 0  :  0x5a69, header boot flag  */
    u8  version;                /* 2  :  version                  */
    u8  size;                   /* 3  :  Link to Next Header      */
    u32 boot_to_sram_addr;       /* 4  :  spi data load to sram addr   */
    u32 run_sram_addr;           /* 8  :  code execute start addr  */
    u32 boot_code_offset_addr;     /* 12 :  HeaderLen+ParamLen=4096+512        */
    u32 boot_from_flash_len;       /* 16 :         */
    u16 boot_data_crc;           /* 20 :  boot data crc check      */
    u16 flash_blk_size;       /* 22 :  flash size in 64KB(version > 1),   512B(version== 0) */
    u16 boot_baud_mhz : 14,   /* 24 :  spi clk freq in mhz(version > 1),  khz(version== 0) */
        driver_strength : 2;      /*       io driver strength */

    struct {
        u16 pll_src : 8,   /*       pll src in Mhz */
            pll_en : 1,   /*       PLL enable */
            debug : 1,   /*       debug info uart output enable */
            aes_en : 1,   /*       AES enable */
            crc_en : 1,   /*       CRC check enable */
            reserved : 4;
    } mode;                     /* 26 :  boot option */
    u16 reserved;               /* 28 :  */
    u16 head_crc16;             /*       (size+4) byte CRC16 check value */
}__packed;

struct hgic_spiflash_read_cfg {
    u8  read_cmd;                       /* read_cmd */
    u8  cmd_dummy_cycles : 4,            /* read dummy cycles */
    clock_mode : 2,            /* clock polarity & phase */
    spec_sequnce_en : 1,            /* spec sequnce to execute, maybe same with quad_wire_en */
    quad_wire_en : 1;                   /* spi D2/D3 enable */

    u8  wire_mode_cmd : 2,
    wire_mode_addr : 2,
    wire_mode_data : 2,
    quad_wire_select : 2;               /* spi D2/D3 group select */

    u8  reserved3;

    u16 sample_delay;                   /* RX sample dalay time: 0 ~ clk_divor */
}__packed;

struct hgic_spiflash_header_spi_info {
    u8 func_code;                       /* 0 : header function(0x1)  */
    u8 size;                            /* 1:  Link to Next Header   */

    struct hgic_spiflash_read_cfg read_cfg;
    u8  hgic_spiflash_spec_sequnce[64];

    u16 header_crc16;                   /*     (size+2) byte CRC16 check value */
}__packed;

/*  hgic_ah_fw_v1.0.1.1_2020.2.20.bin  ？*/

struct hgic_spiflash_header_firmware_info {
    u8 func_code;                       /* 0 : header function(0x2)  */
    u8 size;                            /* 1:  Link to Next Header   */
    u32 sdk_version;                         /* version   */
    u32 svn_version;
    u32 date;                           /* date   */
    u16 chip_id;                        /* chip_id   */
    u8 cpu_id;                         /* cpu id, fix 0  */
    u32 code_crc32;                    /* code CRC32 */
    u16 param_crc16;					   /* param CRC16 */
    u16 crc16;                   /*     (size+2) byte CRC16 check value */
}__packed;

struct hgic_fw_info_hdr {
    struct hgic_spiflash_header_boot        boot;
    struct hgic_spiflash_header_spi_info        spi_infor;      /* func1*/
    struct hgic_spiflash_header_firmware_info   fw_infor ;  /* func2*/
} __packed;

u16 hgic_crc16(const u8 *data, u32 length);
u32 hgic_crc32(const u8 *data, u32 length);
u16 hgic_get_fw_aes_en(const u8 *data, s32 *err_code);
u16 hgic_get_fw_crc_en(const u8 *data, s32 *err_code);
u32 hgic_get_fw_dl_addr(const u8 *data, s32 *err_code);
u32 hgic_get_fw_run_addr(const u8 *data, s32 *err_code);
u32 hgic_get_fw_code_offset(const u8 *data, s32 *err_code);
u32 hgic_get_fw_local_crc32(const u8 *data, s32 *err_code);
u32 hgic_get_fw_sdk_version(const u8 *data, s32 *err_code);
u32 hgic_get_fw_svn_version(const u8 *data, s32 *err_code);
u16 hgic_get_fw_chipid(const u8 *data, s32 *err_code);
u8  hgic_get_fw_cpuid(const u8 *data, s32 *err_code);
s32 hgic_get_fw_code_checksum(const u8 *data,s32 len);


#endif
