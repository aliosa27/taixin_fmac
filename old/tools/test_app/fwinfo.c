#include <error.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "libota.h"
#include "fwinfo.h"

static void print_hex(char *data, int len)
{
    int i = 0;
    
    printf("\r\n");
    for(i=0;i<len;i++){
        if(i && (i%8)==0)  printf(" ");
        if(i && (i%16)==0) printf("\r\n");
        printf("%02x ", data[i]&0xff);
    }
    printf("\r\n");
}

/******************************************************************************
* Name:    CRC-16/MODBUS       x16+x15+x2+1
* Poly:    0x8005
* Init:    0xFFFF
* Refin:   True
* Refout:  True
* Xorout:  0x0000
* Note:
*****************************************************************************/
uint16 fwinfo_crc16(const uint8 *data, uint32 length)
{
    uint8  i;
    uint16 crc = 0xffff;        // Initial value
    while (length--) {
        crc ^= *data++;            // crc ^= *data; data++;
        for (i = 0; i < 8; ++i) {
            if (crc & 1)
            { crc = (crc >> 1) ^ 0xA001; }        // 0xA001 = reverse 0x8005
            else
            { crc = (crc >> 1); }
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
uint32 fwinfo_crc32(const uint8 *data, uint32 length)
{
    uint8 i;
    uint32 crc = 0xffffffff;        // Initial value
    while (length--) {
        crc ^= *data++;                // crc ^= *data; data++;
        for (i = 0; i < 8; ++i) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;// 0xEDB88320= reverse 0x04C11DB7
            } else {
                crc = (crc >> 1);
            }
        }
    }
    return ~crc;
}


int32 fwinfo_check_fwinfo_hdr(const uint8 *data)
{
    struct fwinfo_hdr  *fw_hdr = NULL;

    if (data == NULL) {
        fwinfo_err("%s:Input para error!\n", __FUNCTION__);
        return -EINVAL;
    }

    //print_hex(data, 64);

    fw_hdr = (struct fwinfo_hdr *)data;
    if (fw_hdr->boot.boot_flag != FWINFO_BOOT_HDR) {
        fwinfo_err("%s:Can not find boot header!\n", __FUNCTION__);
        return -EINVAL;;
    }
    if (fw_hdr->fw_infor.func_code != FWINFO_CODE_HDR) {
        fwinfo_err("%s:Can not find fw infor header %x!\n", __FUNCTION__, fw_hdr->fw_infor.func_code);
        return -EINVAL;;
    }
    if (fw_hdr->spi_infor.func_code != FWINFO_SPI_HDR) {
        fwinfo_err("%s:Can not find spi info header!\n", __FUNCTION__);
        return -EINVAL;
    }
    return 0;
}

uint16 fwinfo_get_fw_aes_en(const uint8 *data, int32 *err_code)
{
    struct fwinfo_hdr  *fw_hdr = NULL;
    int32 ret = 0;

    ret = fwinfo_check_fwinfo_hdr(data);
    if (ret) {
        fwinfo_err("%s:fwinfo_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct fwinfo_hdr *)data;
    fwinfo_dbg("%s:Check Para:aes_en:%d\n", __FUNCTION__, fw_hdr->boot.mode.aes_en);
    *err_code = 0;
    return fw_hdr->boot.mode.aes_en;
}

uint16 fwinfo_get_fw_crc_en(const uint8 *data, int32 *err_code)
{
    struct fwinfo_hdr  *fw_hdr = NULL;
    int32 ret = 0;

    ret = fwinfo_check_fwinfo_hdr(data);
    if (ret) {
        fwinfo_err("%s:fwinfo_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct fwinfo_hdr *)data;
    fwinfo_dbg("%s:Check Para:crc_en:%d\n", __FUNCTION__, fw_hdr->boot.mode.crc_en);
    *err_code = 0;
    return fw_hdr->boot.mode.crc_en;
}

uint32 fwinfo_get_fw_dl_addr(const uint8 *data, int32 *err_code)
{
    struct fwinfo_hdr  *fw_hdr = NULL;
    int32 ret = 0;

    ret = fwinfo_check_fwinfo_hdr(data);
    if (ret) {
        fwinfo_err("%s:fwinfo_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct fwinfo_hdr *)data;
    fwinfo_dbg("%s:Check Para:download addr:%x\n", __FUNCTION__, fw_hdr->boot.boot_to_sram_addr);
    *err_code = 0;
    return fw_hdr->boot.boot_to_sram_addr;
}

uint32 fwinfo_get_fw_run_addr(const uint8 *data, int32 *err_code)
{
    struct fwinfo_hdr  *fw_hdr = NULL;
    int32 ret = 0;

    ret = fwinfo_check_fwinfo_hdr(data);
    if (ret) {
        fwinfo_err("%s:fwinfo_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct fwinfo_hdr *)data;
    fwinfo_dbg("%s:Check Para:run addr:%x\n", __FUNCTION__, fw_hdr->boot.run_sram_addr);
    *err_code = 0;
    return fw_hdr->boot.run_sram_addr;
}

uint32 fwinfo_get_fw_code_offset(const uint8 *data, int32 *err_code)
{
    struct fwinfo_hdr  *fw_hdr = NULL;
    int32 ret = 0;

    ret = fwinfo_check_fwinfo_hdr(data);
    if (ret) {
        fwinfo_err("%s:fwinfo_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct fwinfo_hdr *)data;
    fwinfo_dbg("%s:Check Para:code offset:%d\n", __FUNCTION__, fw_hdr->boot.boot_code_offset_addr);
    *err_code = 0;
    return fw_hdr->boot.boot_code_offset_addr;
}

uint32 fwinfo_get_fw_local_crc32(const uint8 *data, int32 *err_code)
{
    struct fwinfo_hdr  *fw_hdr = NULL;
    int32 ret = 0;

    ret = fwinfo_check_fwinfo_hdr(data);
    if (ret) {
        fwinfo_err("%s:fwinfo_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct fwinfo_hdr *)data;
    fwinfo_dbg("%s:Check Para:local crc:%x\n", __FUNCTION__, fw_hdr->fw_infor.code_crc32);
    *err_code = 0;
    return fw_hdr->fw_infor.code_crc32;
}

uint32 fwinfo_get_fw_sdk_version(const uint8 *data, int32 *err_code)
{
    struct fwinfo_hdr  *fw_hdr = NULL;
    int32 ret = 0;

    ret = fwinfo_check_fwinfo_hdr(data);
    if (ret) {
        fwinfo_err("%s:fwinfo_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct fwinfo_hdr *)data;
    fwinfo_dbg("%s:Current file sdk info:%d.%d.%d.%d\r\n", __FUNCTION__,
               (fw_hdr->fw_infor.sdk_version >> 24) & 0xff, (fw_hdr->fw_infor.sdk_version >> 16) & 0xff,
               (fw_hdr->fw_infor.sdk_version >> 8) & 0xff, (fw_hdr->fw_infor.sdk_version & 0xff));
    *err_code = 0;
    return fw_hdr->fw_infor.sdk_version;
}

uint32 fwinfo_get_fw_svn_version(const uint8 *data, int32 *err_code)
{
    struct fwinfo_hdr  *fw_hdr = NULL;
    int32 ret = 0;

    ret = fwinfo_check_fwinfo_hdr(data);
    if (ret) {
        fwinfo_err("%s:fwinfo_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct fwinfo_hdr *)data;
    fwinfo_dbg("%s:Current file svn info:%d\n", __FUNCTION__, fw_hdr->fw_infor.svn_version);
    *err_code = 0;
    return fw_hdr->fw_infor.svn_version;
}


uint16 fwinfo_get_fw_chipid(const uint8 *data, int32 *err_code)
{
    struct fwinfo_hdr  *fw_hdr = NULL;
    int32 ret = 0;

    ret = fwinfo_check_fwinfo_hdr(data);
    if (ret) {
        fwinfo_err("%s:fwinfo_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct fwinfo_hdr *)data;
    fwinfo_dbg("%s:Check Para:fw chipid:%x\n", __FUNCTION__, fw_hdr->fw_infor.chip_id);
    *err_code = 0;
    return fw_hdr->fw_infor.chip_id;
}

uint8 fwinfo_get_fw_cpuid(const uint8 *data, int32 *err_code)
{
    struct fwinfo_hdr  *fw_hdr = NULL;
    int32 ret = 0;

    ret = fwinfo_check_fwinfo_hdr(data);
    if (ret) {
        fwinfo_err("%s:fwinfo_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }

    fw_hdr = (struct fwinfo_hdr *)data;
    fwinfo_dbg("%s:Check Para:cpu_id:%d\n", __FUNCTION__, fw_hdr->fw_infor.cpu_id);
    *err_code = 0;
    return fw_hdr->fw_infor.cpu_id;
}

uint32 fwinfo_get_fw_length(const uint8 *data, int32 *err_code)
{
    int32 ret = 0;
    struct fwinfo_hdr  *fw_hdr = (struct fwinfo_hdr *)data;
    
    ret = fwinfo_check_fwinfo_hdr(data);
    if (ret) {
        fwinfo_err("%s:fwinfo_check_fwinfo_hdr error!\n", __FUNCTION__);
        *err_code = ret;
        return -1;
    }
    
    *err_code = 0;
    return fw_hdr->boot.boot_from_flash_len + fw_hdr->boot.boot_code_offset_addr;
}

int32 fwinfo_get_fw_code_checksum(const uint8 *data, int32 len)
{
    uint32 local_chksum = 0;
    uint32 cur_crc      = 0;
    int32 err_code     = 0;
    uint32 code_offset  = 0;
    const uint8 *code_data    = NULL;
    int32 code_len     = 0;

    local_chksum = fwinfo_get_fw_local_crc32(data, &err_code);
    if (err_code != 0) {
        fwinfo_err("%s:fwinfo_get_fw_local_crc32 error!\n", __FUNCTION__);
        return err_code;
    }

    code_offset = fwinfo_get_fw_code_offset(data, &err_code);
    if (err_code != 0) {
        fwinfo_err("%s:fwinfo_get_fw_code_offset error!\n", __FUNCTION__);
        return err_code;
    }

    code_data = data + code_offset;
    code_len  = len  - code_offset;

    if (code_len < 0) {
        fwinfo_err("%s:Input para error!\n", __FUNCTION__);
        return -EINVAL;
    }

    cur_crc = fwinfo_crc32(code_data, code_len);
    if (cur_crc != local_chksum && ~cur_crc != local_chksum) {
        fwinfo_err("%s:Check crc32 with hdr crc error,local crc:%x,cur_crc:%x\r\n",
                   __FUNCTION__, local_chksum, cur_crc);
        return -EFAULT;
    }
    fwinfo_dbg("%s:Checksum Success!\n", __FUNCTION__);
    return 0;
}

