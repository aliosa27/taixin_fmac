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

/******************************************************************************
* Name:    CRC-16/MODBUS       x16+x15+x2+1
* Poly:    0x8005
* Init:    0xFFFF
* Refin:   True
* Refout:  True
* Xorout:  0x0000
* Note:
*****************************************************************************/
u16 hgic_crc16(const u8 *data, u32 length)
{
	u8  i;
	u16 crc = 0xffff;        // Initial value  
	while (length--)
	{
		crc ^= *data++;            // crc ^= *data; data++;  
		for (i = 0; i < 8; ++i)
		{
			if (crc & 1)
				crc = (crc >> 1) ^ 0xA001;        // 0xA001 = reverse 0x8005  
			else
				crc = (crc >> 1);
		}
	}
	return crc;
}


/******************************************************************************
* Name:    CRC-32  x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1
* Poly:    0x4C11DB7
* Init:    0xFFFFFFF
* Refin:   True
* Refout:  True
* Xorout:  0xFFFFFFF
* Alias:   CRC_32/ADCCP
* Use:     WinRAR,ect.
*****************************************************************************/
u32 hgic_crc32(const u8 *data, u32 length)
{
	u8 i;
	u32 crc = 0xffffffff;        // Initial value  
	while (length--)
	{
		crc ^= *data++;                // crc ^= *data; data++;  
		for (i = 0; i < 8; ++i)
		{
			if (crc & 1)
				crc = (crc >> 1) ^ 0xEDB88320;// 0xEDB88320= reverse 0x04C11DB7  
			else
				crc = (crc >> 1);
		}
	}
	return ~crc;
}


s32 hgic_check_fwinfo_hdr(const u8 *data)
{
    struct hgic_fw_info_hdr *fw_hdr = NULL;

    if (data == NULL) {
        hgic_err("%s:Input para error!\n", __FUNCTION__);
        return -EINVAL;
    }

    fw_hdr = (struct hgic_fw_info_hdr *)data;
    if (fw_hdr->boot.boot_flag != HGIC_FWINFO_BOOT_HDR) {
        hgic_err("%s:Can not find boot header!\n", __FUNCTION__);
        return -EINVAL;;
    }
    if (fw_hdr->fw_infor.func_code != HGIC_FWINFO_CODE_HDR) {
        hgic_err("%s:Can not find fw infor header!\n", __FUNCTION__);
        return -EINVAL;;
    }
    if (fw_hdr->spi_infor.func_code != HGIC_FWINFO_SPI_HDR) {
        hgic_err("%s:Can not find spi info header!\n", __FUNCTION__);
        return -EINVAL;
    }
    return 0;
}

u16 hgic_get_fw_aes_en(const u8 *data, s32 *err_code)
{
    struct hgic_fw_info_hdr *fw_hdr = NULL;
    s32 ret = 0;

    ret = hgic_check_fwinfo_hdr(data);
    if (ret) {
        hgic_err("%s:hgic_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct hgic_fw_info_hdr *)data;
    hgic_dbg("%s:Check Para:aes_en:%d\n", __FUNCTION__, fw_hdr->boot.mode.aes_en);
    *err_code = 0;
    return fw_hdr->boot.mode.aes_en;
}

u16 hgic_get_fw_crc_en(const u8 *data, s32 *err_code)
{
    struct hgic_fw_info_hdr *fw_hdr = NULL;
    s32 ret = 0;

    ret = hgic_check_fwinfo_hdr(data);
    if (ret) {
        hgic_err("%s:hgic_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct hgic_fw_info_hdr *)data;
    hgic_dbg("%s:Check Para:crc_en:%d\n", __FUNCTION__, fw_hdr->boot.mode.crc_en);
    *err_code = 0;
    return fw_hdr->boot.mode.crc_en;
}

u32 hgic_get_fw_dl_addr(const u8 *data, s32 *err_code)
{
    struct hgic_fw_info_hdr *fw_hdr = NULL;
    s32 ret = 0;

    ret = hgic_check_fwinfo_hdr(data);
    if (ret) {
        hgic_err("%s:hgic_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct hgic_fw_info_hdr *)data;
    hgic_dbg("%s:Check Para:download addr:%x\n", __FUNCTION__, fw_hdr->boot.boot_to_sram_addr);
    *err_code = 0;
    return fw_hdr->boot.boot_to_sram_addr;
}

u32 hgic_get_fw_run_addr(const u8 *data, s32 *err_code)
{
    struct hgic_fw_info_hdr *fw_hdr = NULL;
    s32 ret = 0;

    ret = hgic_check_fwinfo_hdr(data);
    if (ret) {
        hgic_err("%s:hgic_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct hgic_fw_info_hdr *)data;
    hgic_dbg("%s:Check Para:run addr:%x\n", __FUNCTION__, fw_hdr->boot.run_sram_addr);
    *err_code = 0;
    return fw_hdr->boot.run_sram_addr;
}

u32 hgic_get_fw_code_offset(const u8 *data, s32 *err_code)
{
    struct hgic_fw_info_hdr *fw_hdr = NULL;
    s32 ret = 0;

    ret = hgic_check_fwinfo_hdr(data);
    if (ret) {
        hgic_err("%s:hgic_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct hgic_fw_info_hdr *)data;
    hgic_dbg("%s:Check Para:code offset:%d\n", __FUNCTION__, fw_hdr->boot.boot_code_offset_addr);
    *err_code = 0;
    return fw_hdr->boot.boot_code_offset_addr;
}

u32 hgic_get_fw_local_crc32(const u8 *data, s32 *err_code)
{
    struct hgic_fw_info_hdr *fw_hdr = NULL;
    s32 ret = 0;

    ret = hgic_check_fwinfo_hdr(data);
    if (ret) {
        hgic_err("%s:hgic_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct hgic_fw_info_hdr *)data;
    hgic_dbg("%s:Check Para:local crc:%x\n", __FUNCTION__, fw_hdr->fw_infor.code_crc32);
    *err_code = 0;
    return fw_hdr->fw_infor.code_crc32;
}

u32 hgic_get_fw_sdk_version(const u8 *data, s32 *err_code)
{
    struct hgic_fw_info_hdr *fw_hdr = NULL;
    s32 ret = 0;

    ret = hgic_check_fwinfo_hdr(data);
    if (ret) {
        hgic_err("%s:hgic_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct hgic_fw_info_hdr *)data;
    hgic_dbg("%s:Current file sdk info:%d.%d.%d.%d\r\n", __FUNCTION__,
             (fw_hdr->fw_infor.sdk_version >> 24) & 0xff, (fw_hdr->fw_infor.sdk_version >> 16) & 0xff,
             (fw_hdr->fw_infor.sdk_version >> 8) & 0xff, (fw_hdr->fw_infor.sdk_version & 0xff));
    *err_code = 0;
    return fw_hdr->fw_infor.sdk_version;
}

u32 hgic_get_fw_svn_version(const u8 *data, s32 *err_code)
{
    struct hgic_fw_info_hdr *fw_hdr = NULL;
    s32 ret = 0;

    ret = hgic_check_fwinfo_hdr(data);
    if (ret) {
        hgic_err("%s:hgic_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct hgic_fw_info_hdr *)data;
    hgic_dbg("%s:Current file svn info:%d\n", __FUNCTION__,fw_hdr->fw_infor.svn_version);
    *err_code = 0;
    return fw_hdr->fw_infor.svn_version;
}


u16 hgic_get_fw_chipid(const u8 *data, s32 *err_code)
{
    struct hgic_fw_info_hdr *fw_hdr = NULL;
    s32 ret = 0;

    ret = hgic_check_fwinfo_hdr(data);
    if (ret) {
        hgic_err("%s:hgic_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct hgic_fw_info_hdr *)data;
    hgic_dbg("%s:Check Para:fw chipid:%x\n", __FUNCTION__, fw_hdr->fw_infor.chip_id);
    *err_code = 0;
    return fw_hdr->fw_infor.chip_id;
}

u8 hgic_get_fw_cpuid(const u8 *data, s32 *err_code)
{
    struct hgic_fw_info_hdr *fw_hdr = NULL;
    s32 ret = 0;

    ret = hgic_check_fwinfo_hdr(data);
    if (ret) {
        hgic_err("%s:hgic_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct hgic_fw_info_hdr *)data;
    hgic_dbg("%s:Check Para:cpu_id:%d\n", __FUNCTION__, fw_hdr->fw_infor.cpu_id);
    *err_code = 0;
    return fw_hdr->fw_infor.cpu_id;
}

s32 hgic_get_fw_code_checksum(const u8 *data,s32 len)
{
    u32 local_chksum = 0;
    u32 cur_crc      = 0;
    s32 err_code     = 0;
    u32 code_offset  = 0;
    const u8 *code_data    = NULL;
    s32 code_len     = 0; 

    local_chksum = hgic_get_fw_local_crc32(data, &err_code);
    if(err_code != 0) {
        hgic_err("%s:hgic_get_fw_local_crc32 error!\n", __FUNCTION__);
        return err_code;
    }

    code_offset = hgic_get_fw_code_offset(data, &err_code);
    if(err_code != 0) {
        hgic_err("%s:hgic_get_fw_code_offset error!\n", __FUNCTION__);
        return err_code;
    }

    code_data = data + code_offset;
    code_len  = len  - code_offset;
    
    if(code_len < 0) {
        hgic_err("%s:Input para error!\n", __FUNCTION__);
        return -EINVAL;
    }
    
    cur_crc = hgic_crc32(code_data, code_len);
    if(cur_crc != local_chksum && ~cur_crc != local_chksum) {
        hgic_err("%s:Check crc32 with hdr crc error,local crc:%x,cur_crc:%x\r\n", 
            __FUNCTION__, local_chksum,cur_crc);
        return -EFAULT;
    }
    hgic_dbg("%s:Checksum Success!\n",__FUNCTION__);
    return 0;
}

