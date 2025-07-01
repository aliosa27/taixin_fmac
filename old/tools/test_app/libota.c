
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libota.h"

////////////////////////////////////////////////////////////////////////////////////////
struct libota LIBOTA;

static uint16 libota_check_sum(int8 *addr, int32 count)
{
    int32 sum = 0;
    while (count > 1) {
        sum = sum + *(uint16 *)addr;
        addr  += 2;
        count -= 2;
    }
    if (count > 0) {
        sum += *addr;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16)~sum;
}

static struct hgota_sta *libota_new_sta(void)
{
    int i = 0;
    for (i = 0; i < OTA_STA_COUNT; i++) {
        if (!LIBOTA.stas[i].online) {
            return &LIBOTA.stas[i];
        }
    }
    return NULL;
}

static struct hgota_sta *libota_find_sta(char *mac)
{
    int i = 0;

    if (mac == NULL) {
        return NULL;
    }

    for (i = 0; i < OTA_STA_COUNT; i++) {
        if (memcmp(LIBOTA.stas[i].addr, mac, 6) == 0) {
            return &LIBOTA.stas[i];
        }
    }
    return NULL;
}

static int libota_add_sta(struct eth_ota_scan_report *report)
{
    struct hgota_sta *sta = libota_find_sta(report->hdr.src);
    if (sta) {
        sta->chipid  = ntohs(report->chipid);
        sta->version = ntohl(report->version);
        sta->svn_version = ntohl(report->svn_version);
        sta->online  = 1;
        return 1;
    }
    sta = libota_new_sta();
    if (sta) {
        memset(sta, 0, sizeof(struct hgota_sta));
        sta->chipid  = ntohs(report->chipid);
        sta->version = ntohl(report->version);
        sta->svn_version = ntohl(report->svn_version);
        sta->online  = 1;
        memcpy(sta->addr, report->hdr.src, 6);
        LIBOTA.sta_count++;
        return 1;
    }
    return 0;
}

static void libota_clear_sta(void)
{
    LIBOTA.sta_count = 0;
    memset(LIBOTA.stas, 0, sizeof(LIBOTA.stas));
}

void libota_clear_sta_nexoff(char *sta_mac)
{
    struct hgota_sta *sta = libota_find_sta(sta_mac);
    if (sta != NULL) {
        sta->next_off = 0;
    }
}

int libota_sta_nexoff(char *sta_mac)
{
    struct hgota_sta *sta = libota_find_sta(sta_mac);
    return sta ? sta->next_off : 0;
}

int libota_reboot(char *sta_mac, int flags)
{
    struct eth_ota_reboot reboot;

    if (sta_mac) {
        memset(&reboot, 0, sizeof(reboot));
        memcpy(reboot.hdr.dest, sta_mac, 6);
        reboot.hdr.proto = htons(ETH_P_OTA);
        reboot.hdr.stype = ETH_P_OTA_REBOOT;
        reboot.flags = flags;
        return LIBOTA.send(&reboot, sizeof(reboot));
    }
    return -1;
}

int libota_scan(int clear)
{
    struct eth_ota_hdr scan;

    if (clear) {
        libota_clear_sta();
    }
    memset(&scan, 0, sizeof(scan));
    memset(scan.dest, 0xff, 6);
    scan.proto = htons(ETH_P_OTA);
    scan.stype = ETH_P_OTA_SCAN;
    return LIBOTA.send(&scan, sizeof(scan));
}

int libota_send_fw_data(char *sta_mac, struct hgota_fw_info *info, int off, char *data, int len)
{
    int ret = 0;
    struct eth_ota_fw_data *fw = NULL;
    struct hgota_sta *sta = libota_find_sta(sta_mac);

    if ((data == NULL) || (sta_mac == NULL) || (info == NULL)) {
        return 0;
    }

    if (sta) { sta->next_off = 0; }
    fw = malloc(sizeof(struct eth_ota_fw_data) + len);
    if (fw) {
        memcpy(fw->hdr.dest, sta ? sta->addr : sta_mac, 6);
        fw->hdr.proto = htons(ETH_P_OTA);
        fw->hdr.stype = ETH_P_OTA_FW_DATA;
        fw->hdr.status = 0;
        fw->version  = htonl(info->version);
        fw->tot_len  = htonl(info->tot_len);
        fw->off      = htonl(off);
        fw->len      = htons(len);
        fw->chipid   = htons(info->chipid);
        fw->checksum = htons(libota_check_sum(data, len));
        memcpy(fw->data, data, len);
        ret = LIBOTA.send(fw, sizeof(struct eth_ota_fw_data) + len);
        free(fw);
    }
    return ret;
}

int libota_query_config(char *sta_mac)
{
    struct eth_ota_hdr req;
    memset(&req, 0, sizeof(req));
    memset(req.dest, 0xff, 6);
    req.proto = htons(ETH_P_OTA);
    req.stype = ETH_P_OTA_FW_GET_PARAM;
    return LIBOTA.send(&req, sizeof(req));
}

int libota_update_config(char *sta_mac, struct eth_ota_fwparam *param)
{
    uint16 checksum = 0;
    int data_len = sizeof(struct eth_ota_fwparam);
    struct eth_ota_fwparam_hdr req;

    checksum = libota_check_sum((unsigned char *)param, data_len);
    memset(&req, 0, sizeof(req));
    memcpy(req.hdr.dest, sta_mac, 6);
    req.hdr.proto  = htons(ETH_P_OTA);
    req.hdr.stype  = ETH_P_OTA_FW_SET_PARAM;
    req.hdr.status = 0;
    req.len        = htons(data_len);
    req.checksum   = htons(checksum);
    memcpy(&req.param, param, data_len);
    return LIBOTA.send(&req, sizeof(req));
}

int libota_sta_config(char *sta_mac, struct eth_ota_fwparam *param)
{
    struct hgota_sta *sta = libota_find_sta(sta_mac);
    if (sta) {
        memcpy(param, &sta->param, sizeof(struct eth_ota_fwparam));
        return 1;
    }
    return 0;
}

int libota_rx_proc(char *buff, int len)
{
    int ret = 0;
    uint16 checksum = 0;
    struct hgota_sta *sta = NULL;
    struct eth_ota_hdr *hdr = buff;
    struct eth_ota_fw_data *data = buff;
    struct eth_ota_fwparam_hdr *param = buff;

    if (buff == NULL || len <= 0) {
        return ret;
    }

    sta = libota_find_sta(hdr->src);
    if (ETH_P_OTA == ntohs(hdr->proto)) {
        switch (hdr->stype) {
            case ETH_P_OTA_SCAN_REPORT:
                //printf("scan resp\r\n");
                if (libota_add_sta((struct eth_ota_scan_report *)buff)) {
                    ret = HGOTA_STATUS_NEW_STA;
                }
                break;
            case ETH_P_OTA_FW_DATA_RESPONE:
                //printf("fw data resp\r\n");
                if (sta && data->hdr.status != 0xff) {
                    sta->next_off = ntohl(data->off) + ntohs(data->len);
                }
                ret = HGOTA_STATUS_FW_STATUS;
                break;
            case ETH_P_OTA_FW_GET_PARAM_RESP:
                checksum = libota_check_sum(&param->param, sizeof(struct eth_ota_fwparam));
                //printf("get param, sta:"MACSTR", checksum:%x,%x\r\n", MAC2STR(hdr->src), checksum, ntohs(param->checksum));
                if (ntohs(param->checksum) == checksum && sta) {
                    memcpy(&sta->param, &param->param, sizeof(struct eth_ota_fwparam));
                    ret = HGOTA_STATUS_CONFIG_GOT;
                }
                break;
            case ETH_P_OTA_FW_SET_PARAM_RESP:
                //printf("set param resp\r\n");
                if (sta && hdr->status != 0xff) {
                    ret = HGOTA_STATUS_CONFIG_UPDATED;
                }
                break;
            default:
                break;
        }
    }
    return ret;
}

int libota_init(raw_send_hdl send)
{
    memset(&LIBOTA, 0, sizeof(struct libota));
    LIBOTA.send = send;
}

