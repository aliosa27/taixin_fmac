/**
  ******************************************************************************
  * @file    iwpriv.c
  * @author  HUGE-IC Application Team
  * @version V1.0.0
  * @date    2022-06-23
  * @brief   app library for hgic wifi driver.
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2022 HUGE-IC</center></h2>
  *
  ******************************************************************************
  */

#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>

#include "hgic.h"

#define iwpriv_dbg(fmt, ...) printf("%s:%d::"fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define __packed            __attribute__((packed))
#define le16_to_cpu(p)      (p)

#define HCI_OPCODE(ogf, ocf) ((ocf) | ((ogf) << 10))

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

#define MACSTR            "%02x:%02x:%02x:%02x:%02x:%02x"
#define MACARG(a)         (a)[0]&0xff, (a)[1]&0xff, (a)[2]&0xff, (a)[3]&0xff, (a)[4]&0xff, (a)[5]&0xff
#define IPSTR             "%d.%d.%d.%d"
#define IPARG(a)          ((a)>>24)&0xff, ((a)>>16)&0xff, ((a)>>8)&0xff, (a)&0xff
#define MAC2STR(mac, str) (sprintf((str), MACSTR, MACARG(mac)))
#define STR_EQ(s1,s2)     (strcmp(s1,s2)==0)
#define MAC_EQ(a1,a2)     (memcmp(a1,a2,6)==0)
#define MAX(a,b)          ((a)>(b)?(a):(b))

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;

#define WLAN_FC_TODS        0x0100
#define WLAN_FC_FROMDS      0x0200
struct ieee80211_hdr {
    uint16 frame_control;
    uint16 duration_id;
    uint8 addr1[6];
    uint8 addr2[6];
    uint8 addr3[6];
    uint16 seq_ctrl;
};

enum FMAC_CONNECT_REASON {
    FMAC_ASSOC_SUCCESS = 0,
    FMAC_ASSOC_REFUSED = 1,
    FMAC_ASSOC_DENIED_NO_MORE_STAS = 17,
    FMAC_ASSOC_DENIED_INSUFFICIENT_BANDWIDTH = 33,
    FMAC_ASSOC_REFUSED_AP_OUT_OF_MEMORY = 93,
    FMAC_ASSOC_NO_AP = 0xff
};

enum HGIC_MODULE_TYPE {
    HGIC_MODULE_TYPE_700M = 1,
    HGIC_MODULE_TYPE_900M = 2,
    HGIC_MODULE_TYPE_860M = 3,
    HGIC_MODULE_TYPE_810M = 5,
};

char *HGIC = "hgics";
int   blenc_mode = 0;

void hgics_dump_hex(char *str, char *data, int len, int newline)
{
    int i = 0;
    if (data && len) {
        if (str) {
            printf("%s", str);
        }

        for (i = 0; i < len; i++) {
            if (i > 0 && newline) {
                if ((i & 0x7) == 0) printf("   ");
                if ((i & 0xf) == 0) printf("\r\n");
            }
            printf("%02x ", data[i] & 0xFF);
        }

        printf("\r\n");
    }
}

static inline void put_unaligned_le16(unsigned short val, unsigned char *p)
{
    *p++ = val;
    *p++ = val >> 8;
}
static inline unsigned short get_unaligned_le16(const unsigned char *p)
{
    return p[0] | p[1] << 8;
}

char *hgic_hw_state(int state)
{
    switch (state) {
        case HGICF_HW_DISCONNECTED:
            return "Disconnect";
        case  HGICF_HW_DISABLED:
            return "DISABLED";
        case  HGICF_HW_INACTIVE:
            return "INACTIVE";
        case  HGICF_HW_SCANNING:
            return "SCANNING";
        case  HGICF_HW_AUTHENTICATING:
            return "AUTHENTICATING";
        case  HGICF_HW_ASSOCIATING:
            return "ASSOCIATING";
        case  HGICF_HW_ASSOCIATED:
            return "ASSOCIATED";
        case  HGICF_HW_4WAY_HANDSHAKE:
            return "4WAY_HANDSHAKE";
        case  HGICF_HW_GROUP_HANDSHAKE:
            return "GROUP_HANDSHAKE";
        case  HGICF_HW_CONNECTED:
            return "CONNECTED";
        default:
            return "Unknown";
    }
}

int hgic_str2mac(char *mac_str, unsigned char *mac)
{
    int tmp[6];
    if (mac_str && mac) {
        memset(tmp, 0, sizeof(tmp));
        memset(mac, 0, 6);
        if (6 == sscanf(mac_str, MACSTR, &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5])) {
            mac[0] = (unsigned char)tmp[0];
            mac[1] = (unsigned char)tmp[1];
            mac[2] = (unsigned char)tmp[2];
            mac[3] = (unsigned char)tmp[3];
            mac[4] = (unsigned char)tmp[4];
            mac[5] = (unsigned char)tmp[5];
            return 1;
        }
    }
    return 0;
}

int hgic_get_if_mac(char *ifname, char *mac)
{
    int sock;
    struct ifreq ifr;

    memset(mac, 0, 6);
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        perror("socket");
        return -1;
    }

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        perror("ioctl");
        return -1;
    }

    close(sock);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

int hgic_iwpriv_write(char *buff, int len)
{
    int ret = 0;
    int fd  = -1;
    char file[32];

    if (buff == NULL || len <= 0) {
        return 0;
    }
    memset(file, 0, sizeof(file));
    sprintf(file, "/proc/%s/iwpriv", HGIC);
    fd = open(file, O_WRONLY);
    if (fd != -1) {
        ret = write(fd, buff, len);
        close(fd);
    } else {
        printf("open %s fail\r\n", file);
    }
    return ret;
}

int hgic_iwpriv_do(char *cmd, char *in, int in_len, char *out, int out_len)
{
    int   ret  = strlen(cmd);
    int   len  = ret + MAX(in_len, out_len);
    char *ptr  = NULL;
    char *buff = NULL;
    int   set  = (strstr(cmd, " set ") != NULL);

    buff = malloc(len);
    if (buff == NULL) {
        printf("no mem, alloc %d\r\n", (ret + in_len + out_len));
        return -1;
    }

    memset(buff, 0, len);
    strcpy(buff, cmd);
    if (in && in_len) {
        memcpy(buff + ret, in, in_len);
    }

    ret = hgic_iwpriv_write(buff, len);
    if (ret > 0) {
        ret = *(int *)buff;
        if (ret > 0 && out && out_len) {
            memcpy(out, buff + 4, ret <= out_len ? ret : out_len);
        }
    }

    free(buff);
    if (ret < 0) {
        printf("hgic_iwpriv_write fail, ret=%d\r\n", ret);
    }
    return ret;
}

int hgic_iwpriv_set_int(char *ifname, char *name, int val)
{
    char cmd[64];
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "%s set %s=%d", ifname, name, val);
    return hgic_iwpriv_do(cmd, 0, 0, 0, 0);
}

int hgic_iwpriv_set_mac(char *ifname, char *name, char *mac)
{
    char cmd[64];
    memset(cmd, 0, sizeof(cmd));
    if (strlen(mac) == 17 && mac[2] == ':' && mac[5] == ':' && mac[8] == ':' && mac[11] == ':' && mac[14] == ':') {
        sprintf(cmd, "%s set %s=%s", ifname, name, mac);
    } else {
        sprintf(cmd, "%s set %s="MACSTR, ifname, name, MACARG(mac));
    }
    return hgic_iwpriv_do(cmd, 0, 0, 0, 0);
}

int hgic_iwpriv_set_ints(char *ifname, char *name, int cnt, ...)
{
    int i = 0;
    int val = 0;
    char cmd[256];
    char *ptr = cmd;
    va_list argptr;

    memset(cmd, 0, sizeof(cmd));
    sprintf(ptr, "%s set %s=", ifname, name);
    ptr += strlen(ptr);

    va_start(argptr, cnt);
    for (i = 0; i < cnt; i++) {
        val = va_arg(argptr, int);
        sprintf(ptr, (i == 0 ? "%d" : ",%d"), val);
        ptr += strlen(ptr);
    }
    va_end(argptr);
    return hgic_iwpriv_do(cmd, 0, 0, 0, 0);
}

int hgic_iwpriv_set_intarray(char *ifname, char *name, int *vals, int cnt)
{
    int i = 0;
    char cmd[512];
    char *ptr = cmd;

    memset(cmd, 0, sizeof(cmd));
    sprintf(ptr, "%s set %s=", ifname, name);
    ptr += strlen(ptr);

    for (i = 0; i < cnt; i++) {
        sprintf(ptr, (i == 0 ? "%d" : ",%d"), vals[i]);
        ptr += strlen(ptr);
    }
    return hgic_iwpriv_do(cmd, 0, 0, 0, 0);
}

int hgic_iwpriv_set_bytes(char *ifname, char *name, char *data, int len)
{
    char cmd[128];
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "%s set %s=", ifname, name);
    return hgic_iwpriv_do(cmd, data, len, 0, 0);
}

int hgic_iwpriv_get_int(char *ifname, char *name)
{
    char cmd[128];
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "%s get %s", ifname, name);
    hgic_iwpriv_do(cmd, 0, 0, cmd, sizeof(cmd));
    return atoi(cmd);
}

int hgic_iwpriv_get_bytes(char *ifname, char *name, char *buff, int count)
{
    char cmd[128];
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "%s get %s", ifname, name);
    return hgic_iwpriv_do(cmd, 0, 0, buff, count);
}

int hgic_iwpriv_get_mac(char *ifname, char *name, char *mac)
{
    int ret = 0;
    char cmd[128];

    memset(mac, 0, 6);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "%s get %s", ifname, name);
    ret = hgic_iwpriv_do(cmd, 0, 0, cmd, sizeof(cmd));
    if (ret > 0) {
        hgic_str2mac(cmd, mac);
    }
    return ret;
}

/* proc fs api */
int hgic_proc_read_bytes(char *name, char *buff, int len)
{
    char file[32];
    int  ret = 0;
    int  fd = -1;

    if (buff == NULL || len <= 0) {
        return 0;
    }

    memset(buff, 0, len);
    memset(file, 0, sizeof(file));
    sprintf(file, "/proc/%s/%s", HGIC, name);
    fd = open(file, O_RDONLY);
    if (fd != -1) {
        ret = read(fd, buff, len);
        close(fd);
    }
    return ret;
}

int hgic_proc_write_bytes(char *name, char *buff, int len)
{
    int ret = 0;
    char file[32];
    int  fd = -1;

    if (buff == NULL || len == 0) {
        return 0;
    }

    memset(file, 0, sizeof(file));
    sprintf(file, "/proc/%s/%s", HGIC, name);
    fd = open(file, O_WRONLY);
    if (fd != -1) {
        ret = write(fd, buff, len);
        close(fd);
        if (ret < 0) {
            perror("error");
        }
    }
    return ret > 0;
}

int hgic_proc_read_int(char *name)
{
    char buff[32];
    hgic_proc_read_bytes(name, buff, 32);
    return atoi(buff);
}

int hgic_proc_read_mac(char *name, char *mac)
{
    char buff[32];
    memset(mac, 0, 6);
    hgic_proc_read_bytes(name, buff, 32);
    return hgic_str2mac(buff, mac);
}

int hgic_proc_write_int(char *name, int val)
{
    char buff[12];
    memset(buff, 0, sizeof(buff));
    sprintf(buff, "%d", val);
    return hgic_proc_write_bytes(name, buff, strlen(buff));
}

int hgic_proc_write_mac(char *name, char *mac)
{
    char str[18];
    memset(str, 0, sizeof(str));
    if (strlen(mac) == 17 && mac[2] == ':' && mac[5] == ':' && mac[8] == ':' && mac[11] == ':' && mac[14] == ':') {
        strncpy(str, mac, 17);
    } else {
        MAC2STR(mac, str);
    }
    return hgic_proc_write_bytes(name, str, strlen(str));
}

int hgic_proc_write_ints(char *name, int cnt, ...)
{
    int i = 0;
    int val = 0;
    char buff[512];
    char *ptr = buff;
    va_list argptr;

    memset(buff, 0, sizeof(buff));
    va_start(argptr, cnt);
    for (i = 0; i < cnt; i++) {
        val = va_arg(argptr, int);
        sprintf(ptr, (i == 0 ? "%d" : ",%d"), val);
        ptr += strlen(ptr);
    }
    va_end(argptr);
    return hgic_proc_write_bytes(name, buff, strlen(buff));
}

int hgic_proc_write_intarray(char *name, int *values, int cnt)
{
    int i = 0;
    char buff[512];
    char *ptr = buff;

    memset(buff, 0, sizeof(buff));
    for (i = 0; i < cnt; i++) {
        sprintf(ptr, (i == 0 ? "%d" : ",%d"), values[i]);
        ptr += strlen(ptr);
    }
    return hgic_proc_write_bytes(name, buff, strlen(buff));
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
int hgic_iwpriv_open_dev(char *ifname)
{
    char cmd[32];
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "%s open", ifname);
    return hgic_iwpriv_do(cmd, NULL, 0, NULL, 0);
}
int hgic_iwpriv_close_dev(char *ifname)
{
    char cmd[32];
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "%s close", ifname);
    return hgic_iwpriv_do(cmd, NULL, 0, NULL, 0);
}
int hgic_iwpriv_set_ssid(char *ifname, char *ssid)
{
    return hgic_iwpriv_set_bytes(ifname, "ssid", ssid, strlen(ssid));
}
int hgic_iwpriv_set_bssid(char *ifname, char *bssid)
{
    return hgic_iwpriv_set_mac(ifname, "bssid", bssid);
}
int hgic_iwpriv_set_channel(char *ifname, int channel)
{
    return hgic_iwpriv_set_int(ifname, "channel", channel);
}
int hgic_iwpriv_set_keymgmt(char *ifname, char *key_mgmt)
{
    return hgic_iwpriv_set_bytes(ifname, "key_mgmt", key_mgmt, strlen(key_mgmt));
}
int hgic_iwpriv_set_wpapsk(char *ifname, char *wpa_psk)
{
    return hgic_iwpriv_set_bytes(ifname, "wpa_psk", wpa_psk, strlen(wpa_psk));
}
int hgic_iwpriv_set_freqrange(char *ifname, int freq_start, int freq_end, int bw)
{
    return hgic_iwpriv_set_ints(ifname, "freq_range", 3, freq_start, freq_end, bw);
}
int hgic_iwpriv_set_bss_bw(char *ifname, int bss_bw)
{
    return hgic_iwpriv_set_int(ifname, "bss_bw", bss_bw);
}
int hgic_iwpriv_set_tx_bw(char *ifname, int tx_bw)
{
    return hgic_iwpriv_set_int(ifname, "tx_bw", tx_bw);
}
int hgic_iwpriv_set_tx_mcs(char *ifname, int tx_mcs)
{
    return hgic_iwpriv_set_int(ifname, "tx_mcs", tx_mcs);
}
int hgic_iwpriv_set_max_txcnt(char *ifname, int max_txcnt)
{
    return hgic_iwpriv_set_int(ifname, "max_txcnt", max_txcnt);
}
int hgic_iwpriv_set_acs(char *ifname, int start, int tmo)
{
    return hgic_iwpriv_set_ints(ifname, "acs", 2, start, tmo);
}
int hgic_iwpriv_set_chan_list(char *ifname, int *chan_list, int chan_count)
{
    return hgic_iwpriv_set_intarray(ifname, "chan_list", chan_list, chan_count);
}
int hgic_iwpriv_set_mode(char *ifname, char *mode)
{
    return hgic_iwpriv_set_bytes(ifname, "mode", mode, strlen(mode));
}
int hgic_iwpriv_set_paired_stas(char *ifname, char *paired_stas)
{
    return hgic_iwpriv_set_bytes(ifname, "paired_stas", paired_stas, strlen(paired_stas));
}
int hgic_iwpriv_set_pairing(char *ifname, int pair_number)
{
    return hgic_iwpriv_set_int(ifname, "pairing", pair_number);
}
int hgic_iwpriv_set_beacon_int(char *ifname, int beacon_int)
{
    return hgic_iwpriv_set_int(ifname, "beacon_int", beacon_int);
}
int hgic_iwpriv_set_radio_onoff(char *ifname, int off)
{
    return hgic_iwpriv_set_int(ifname, "radio_onoff", off);
}
int hgic_iwpriv_set_join_group(char *ifname, char *mcast_addr, int aid)
{
    char cmd[64];
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "%s set join_group="MACSTR",%d", ifname, MACARG(mcast_addr), aid);
    return hgic_iwpriv_do(cmd, 0, 0, 0, 0);
}
int hgic_iwpriv_set_txpower(char *ifname, int txpower)
{
    return hgic_iwpriv_set_int(ifname, "txpower", txpower);
}
int hgic_iwpriv_set_ps_connect(char *ifname, int period, int roundup)
{
    return hgic_iwpriv_set_ints(ifname, "ps_connect", 2, period, roundup);
}
int hgic_iwpriv_set_bss_max_idle(char *ifname, int bss_max_idle)
{
    return hgic_iwpriv_set_int(ifname, "bss_max_idle", bss_max_idle);
}
int hgic_iwpriv_set_wkio_mode(char *ifname, int wkio_mode)
{
    return hgic_iwpriv_set_int(ifname, "wkio_mode", wkio_mode);
}
int hgic_iwpriv_set_dtim_period(char *ifname, int dtim_period)
{
    return hgic_iwpriv_set_int(ifname, "dtim_period", dtim_period);
}
int hgic_iwpriv_set_ps_mode(char *ifname, int ps_mode)
{
    return hgic_iwpriv_set_int(ifname, "ps_mode", ps_mode);
}
int hgic_iwpriv_set_aplost_time(char *ifname, int aplost_time)
{
    return hgic_iwpriv_set_int(ifname, "aplost_time", aplost_time);
}
int hgic_iwpriv_unpair(char *ifname, char *mac)
{
    return hgic_iwpriv_set_mac(ifname, "unpair", mac);
}
int hgic_iwpriv_scan(char *ifname, int scan_cmd)
{
    char cmd[32];
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "%s scan=%d", ifname, scan_cmd);
    return hgic_iwpriv_do(cmd, 0, 0, 0, 0);
}
int hgic_iwpriv_save(char *ifname)
{
    char cmd[32];
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "%s save", ifname);
    return hgic_iwpriv_do(cmd, 0, 0, 0, 0);
}
int hgic_iwpriv_set_auto_chswitch(char *ifname, int enable)
{
    return hgic_iwpriv_set_int(ifname, "auto_chswitch", enable);
}
int hgic_iwpriv_set_mcast_key(char *ifname, char *mcast_key)
{
    return hgic_iwpriv_set_bytes(ifname, "mcast_key", mcast_key, strlen(mcast_key));
}
int hgic_iwpriv_set_reassoc_wkhost(char *ifname, int enable)
{
    return hgic_iwpriv_set_int(ifname, "reassoc_wkhost", enable);
}
int hgic_iwpriv_set_wakeup_io(char *ifname, int wakeup_io, int edge)
{
    return hgic_iwpriv_set_ints(ifname, "wakeup_io", 2, wakeup_io, edge);
}
int hgic_iwpriv_set_dbginfo(char *ifname, int enable)
{
    return hgic_iwpriv_set_int(ifname, "dbginfo", enable);
}
int hgic_iwpriv_set_sysdbg(char *ifname, char *sysdbg)
{
    return hgic_iwpriv_set_bytes(ifname, "sysdbg", sysdbg, strlen(sysdbg));
}
int hgic_iwpriv_set_primary_chan(char *ifname, int primary_chan)
{
    return hgic_iwpriv_set_int(ifname, "primary_chan", primary_chan);
}
int hgic_iwpriv_set_autosleep_time(char *ifname, int autosleep_time)
{
    return hgic_iwpriv_set_int(ifname, "autosleep_time", autosleep_time);
}
int hgic_iwpriv_set_super_pwr(char *ifname, int enable)
{
    return hgic_iwpriv_set_int(ifname, "super_pwr", enable);
}
int hgic_iwpriv_set_repeater_ssid(char *ifname, char *r_ssid)
{
    return hgic_iwpriv_set_bytes(ifname, "r_ssid", r_ssid, strlen(r_ssid));
}
int hgic_iwpriv_set_repeater_psk(char *ifname, char *r_psk)
{
    return hgic_iwpriv_set_bytes(ifname, "r_psk", r_psk, strlen(r_psk));
}
int hgic_iwpriv_set_auto_save(char *ifname, int enable)
{
    return hgic_iwpriv_set_int(ifname, "auto_save", enable);
}
int hgic_iwpriv_set_pair_autostop(char *ifname, int enable)
{
    return hgic_iwpriv_set_int(ifname, "pair_autostop", enable);
}
int hgic_iwpriv_set_dcdc13(char *ifname, int enable)
{
    return hgic_iwpriv_set_int(ifname, "dcdc13", enable);
}
int hgic_iwpriv_set_acktmo(char *ifname, int acktmo)
{
    return hgic_iwpriv_set_int(ifname, "acktmo", acktmo);
}
int hgic_iwpriv_get_sta_list(char *ifname, char *buff, int size)
{
    return hgic_iwpriv_get_bytes(ifname, "sta_list=1", buff, size);//output binary structure
}
int hgic_iwpriv_get_scan_list(char *ifname, char *buff, int size)
{
    return hgic_iwpriv_get_bytes(ifname, "scan_list", buff, size);
}
int hgic_iwpriv_get_ssid(char *ifname, char *buff, int size)
{
    return hgic_iwpriv_get_bytes(ifname, "ssid", buff, size);
}
int hgic_iwpriv_get_bssid(char *ifname, char *mac)
{
    char buf[32];
    int  tmp[7];
    if(hgic_iwpriv_get_bytes(ifname, "bssid", buf, sizeof(buf)) > 0){
        if (6 == sscanf(buf, MACSTR",%d", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5], &tmp[6])) {
            mac[0] = (unsigned char)tmp[0];
            mac[1] = (unsigned char)tmp[1];
            mac[2] = (unsigned char)tmp[2];
            mac[3] = (unsigned char)tmp[3];
            mac[4] = (unsigned char)tmp[4];
            mac[5] = (unsigned char)tmp[5];
            return tmp[6];
        }
    }
    return -1;
}
int hgic_iwpriv_get_wpa_psk(char *ifname, char *buff, int size)
{
    return hgic_iwpriv_get_bytes(ifname, "wpa_psk", buff, size);
}
int hgic_iwpriv_get_txpower(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "txpower");
}
int hgic_iwpriv_get_aggcnt(char *ifname, int *tx_agg, int *rx_agg)
{
    char buff[32];
    if(hgic_iwpriv_get_bytes(ifname, "agg_cnt", buff, 32) > 0){
        sscanf(buff, "tx:%d,rx:%d", tx_agg, rx_agg);
        return 0;
    }
    return -1;
}
int hgic_iwpriv_set_aggcnt(char *ifname, int tx_agg, int rx_agg)
{
    return hgic_iwpriv_set_ints(ifname, "agg_cnt", 2, tx_agg, rx_agg);
}
int hgic_iwpriv_set_load_def(char *ifname, int reboot)
{
    return hgic_iwpriv_set_int(ifname, "loaddef", reboot);
}
int hgic_iwpriv_set_dbginfo_output(char *ifname, int enable)
{
    return hgic_iwpriv_set_int(ifname, "dbginfo", enable);
}
int hgic_iwpriv_set_unpair(char *ifname, char *sta_mac)
{
    return hgic_iwpriv_set_mac(ifname, "unpair", sta_mac);
}
int hgic_iwpriv_get_bss_bw(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "bss_bw");
}
int hgic_iwpriv_get_chan_list(char *ifname, char *buff, int size)
{
    return hgic_iwpriv_get_bytes(ifname, "chan_list", buff, size);
}
int hgic_iwpriv_get_freq_range(char *ifname, char *buff, int size)
{
    return hgic_iwpriv_get_bytes(ifname, "freq_range", buff, size);
}
int hgic_iwpriv_get_txq_param(char *ifname, char *buff, int size)
{
    return hgic_iwpriv_get_bytes(ifname, "txq_param", buff, size);
}
int hgic_iwpriv_get_key_mgmt(char *ifname, char *buff, int size)
{
    return hgic_iwpriv_get_bytes(ifname, "key_mgmt", buff, size);
}
int hgic_iwpriv_get_battery_level(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "battery_level");
}
int hgic_iwpriv_get_module_type(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "module_type");
}
int hgic_iwpriv_set_pa_pwrctrl_dis(char *ifname, int disable)
{
    return hgic_iwpriv_set_int(ifname, "pa_pwrctl_dis", disable);
}
int hgic_iwpriv_set_dhcpc(char *ifname, int enable)
{
    return hgic_iwpriv_set_int(ifname, "dhcpc", enable);
}
int hgic_iwpriv_get_disassoc_reason(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "disassoc_reason");
}
int hgic_iwpriv_set_wkdata_save(char *ifname, int enable)
{
    return hgic_iwpriv_set_int(ifname, "wkdata_save", enable);
}
int hgic_iwpriv_set_mcast_txparam(char *ifname, int dupcnt, int tx_bw, int tx_mcs, int clearch)
{
    return hgic_iwpriv_set_ints(ifname, "mcast_txparam", 4, dupcnt, tx_bw, tx_mcs, clearch);
}
int hgic_iwpriv_reset_sta(char *ifname, char *mac_addr)
{
    return hgic_iwpriv_set_mac(ifname, "reset_sta", mac_addr);
}
int hgic_iwpriv_ant_auto(char *ifname, int en)
{
    return hgic_iwpriv_set_int(ifname, "ant_auto", en);
}
int hgic_iwpriv_set_ant_sel(char *ifname, int ant)
{
    return hgic_iwpriv_set_int(ifname, "ant_sel", ant);
}
int hgic_iwpriv_get_ant_sel(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "ant_sel");
}
int hgic_iwpriv_set_macfilter(char *ifname, int enable)
{
    return hgic_iwpriv_set_int(ifname, "macfilter", enable);
}
int hgic_iwpriv_send_atcmd(char *ifname, char *atcmd)
{
    return hgic_iwpriv_set_bytes(ifname, "atcmd", atcmd, strlen(atcmd));
}
int hgic_iwpriv_set_roaming(char *ifname, int enable, int same_freq, int threshold, int rssi_diff, int rssi_interval)
{
    return hgic_iwpriv_set_ints(ifname, "roaming", 5, enable, same_freq, threshold, rssi_diff, rssi_interval);
}
int hgic_iwpriv_get_conn_state(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "conn_state");
}

int hgic_iwpriv_get_wkreason(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "wkreason");
}

int hgic_iwpriv_set_rts_threshold(char *ifname, int rts_threshold)
{
    return hgic_iwpriv_set_int(ifname, "rts_threshold", rts_threshold);
}

int hgic_iwpriv_set_frag_threshold(char *ifname, int frag_threshold)
{
    return hgic_iwpriv_set_int(ifname, "frag_threshold", frag_threshold);
}

int hgic_iwpriv_set_heartbeat(char *ifname, int ipaddr, int port, int period, int timeout)
{
    char str[64];
    struct in_addr in = { .s_addr = (in_addr_t)ipaddr };
    sprintf(str, "%s,%d,%d,%d", inet_ntoa(in), port, period, timeout);
    return hgic_iwpriv_set_bytes(ifname, "heartbeat", str, strlen(str));
}
int hgic_iwpriv_set_heartbeat_resp_data(char *ifname, char *resp_data, int len)
{
    return hgic_iwpriv_set_bytes(ifname, "heartbeat_resp", resp_data, len);
}
int hgic_iwpriv_set_wakeup_data(char *ifname, char *wakeup_data, int len)
{
    return hgic_iwpriv_set_bytes(ifname, "wakeup_data", wakeup_data, len);
}
int hgic_iwpriv_wakeup_sta(char *ifname, char *addr)
{
    return hgic_iwpriv_set_mac(ifname, "wakeup", addr);
}
int hgic_iwpriv_sleep(char *ifname, int sleep_type, unsigned int sleep_ms)
{
    return hgic_iwpriv_set_ints(ifname, "sleep", 2, sleep_type, sleep_ms);
}
int hgic_iwpriv_send_custmgmt(char *ifname, char *dest, struct hgic_tx_info *txinfo, char *data, int len)
{ /* "data" is just payload data, the firmware will build WiFi management frame. */
    int ret = -1;
    char *buf = malloc(len+sizeof(struct hgic_tx_info)+6);
    if(buf){
        memcpy(buf, dest, 6);
        memcpy(buf+6, txinfo, sizeof(struct hgic_tx_info));
        memcpy(buf+6+sizeof(struct hgic_tx_info), data, len);
        ret = hgic_iwpriv_set_bytes(ifname, "custmgmt", buf, len+6+sizeof(struct hgic_tx_info));
        free(buf);
    }
    return ret;
}
int hgic_iwpriv_send_mgmtframe(char *ifname, struct hgic_tx_info *txinfo, char *mgmt, int len)
{ /* "mgmt" should be a whole WiFi management frame. */
    int ret = -1;
    char *buf = malloc(len + sizeof(struct hgic_tx_info));
    if(buf){
        memcpy(buf, txinfo, sizeof(struct hgic_tx_info));
        memcpy(buf + sizeof(struct hgic_tx_info), mgmt, len);
        ret = hgic_iwpriv_set_bytes(ifname, "mgmtframe", buf, len + sizeof(struct hgic_tx_info));
        free(buf);
    }
    return ret;
}
int hgic_iwpriv_read_wkdata_buff(char *ifname, char *buff, int len)
{
    return hgic_iwpriv_get_bytes(ifname, "wkdata_buff", buff, len);
}
int hgic_proc_set_wkdata_mask(char *ifname, unsigned short offset, char *mask, int mask_len)
{
    char buff[128];
    if(mask_len > 16) mask_len = 16;
    memcpy(buff, &offset, 2);
    memcpy(buff+2, mask, mask_len);
    return hgic_iwpriv_set_bytes(ifname, "wkdata_mask", buff, mask_len + 2);
}
int hgic_iwpriv_set_cust_driverdata(char *ifname, char *buff, int len)
{
    if(len > 1500){
        printf("data len:%d too big\r\n", len);
        return -1;
    }
    return hgic_iwpriv_set_bytes(ifname, "driverdata", buff, len);
}
int hgic_iwpriv_set_stafreqinfo(char *ifname, char *sta_addr, struct hgic_freqinfo *freqinfo)
{
    int ret = -1;
    char *buff = malloc(6+sizeof(struct hgic_freqinfo));
    if(buff){
        memset(buff, 0, 6+sizeof(struct hgic_freqinfo));
        if(sta_addr) memcpy(buff, sta_addr, 6);
        memcpy(buff+6, freqinfo, sizeof(struct hgic_freqinfo));
        ret = hgic_iwpriv_set_bytes(ifname, "freqinfo", buff, 6+sizeof(struct hgic_freqinfo));
        free(buff);
    }
    return ret;
}
int hgic_iwpriv_blenc_start(char *ifname, int start, int channel)
{
    char str[8];
    sprintf(str, "EN:%d,%d", start, channel);
    return hgic_iwpriv_set_bytes(ifname, "blenc", str, strlen(str));
}
int hgic_iwpriv_send_blenc_data(char *ifname, char *data, int len)
{
    int ret = -1;
    char *buff = malloc(5 + len);
    if (buff) {
        strcpy(buff, "DATA:");
        memcpy(buff + 5, data, len);
        ret = hgic_iwpriv_set_bytes(ifname, "blenc", buff, 5 + len);
        free(buff);
    }
    return ret;
}
int hgic_iwpriv_blenc_send_hcidata(char *ifname, int type, char *data, int len)
{
    int ret = -1;
    char *buff = malloc(10 + len);
    if (buff) {
        strcpy(buff, "HCI_DATA:");
        buff[9] = (unsigned char)type;
        memcpy(buff + 10, data, len);
        ret = hgic_iwpriv_set_bytes(ifname, "blenc", buff, 10 + len);
        free(buff);
    }
    return ret;
}

int hgic_iwpriv_blenc_set_advdata(char *ifname, char *adv_data, int len)
{
    if(blenc_mode == 3){
        int ret = -ENOMEM;
        int cmd_len = 3 + len;
        char *cmd = malloc(cmd_len);
        if(cmd){
            put_unaligned_le16(HCI_OPCODE(0x08, 0x08), cmd);
            cmd[2] = len;
            memcpy(cmd + 3, adv_data, len);
            ret = hgic_iwpriv_blenc_send_hcidata(ifname, 0x01, cmd, cmd_len);
            free(cmd);
        }
        return ret;
    }else{
        int ret = -1;
        char *buff = malloc(9 + len);
        if (buff) {
            strcpy(buff, "ADV_DATA:");
            memcpy(buff + 9, adv_data, len);
            ret = hgic_iwpriv_set_bytes(ifname, "blenc", buff, 9 + len);
            free(buff);
        }
        return ret;
    }
}

int hgic_iwpriv_blenc_set_scanresp(char *ifname, char *scan_resp, int len)
{  
    if(blenc_mode == 3){
        int ret = -ENOMEM;
        int cmd_len = 3 + len;
        char *cmd = malloc(cmd_len);
        if(cmd){
            put_unaligned_le16(HCI_OPCODE(0x08, 0x09), cmd);
            cmd[2] = len;
            memcpy(cmd + 3, scan_resp, len);
            ret = hgic_iwpriv_blenc_send_hcidata(ifname, 0x01, cmd, cmd_len);
            free(cmd);
        }
        return ret;
    }else{
        int ret = -1;
        char *buff = malloc(10 + len);
        if (buff) {
            strcpy(buff, "SCAN_RESP:");
            memcpy(buff + 10, scan_resp, len);
            ret = hgic_iwpriv_set_bytes(ifname, "blenc", buff, 10 + len);
            free(buff);
        }
        return ret;
    }
}

int hgic_iwpriv_blenc_set_devaddr(char *ifname, char *addr)
{
    if(blenc_mode == 3){
        int ret = -ENOMEM;
        int cmd_len = 3 + 6;
        char *cmd = malloc(cmd_len);
        if(cmd){
            put_unaligned_le16(HCI_OPCODE(0x08, 0x05), cmd);
            cmd[2] = 6;
            memcpy(cmd + 3, addr, 6);
            ret = hgic_iwpriv_blenc_send_hcidata(ifname, 0x01, cmd, cmd_len);
            free(cmd);
        }
        return ret;
    }else{
        char str[16];
        strcpy(str, "DEV_ADDR:");
        memcpy(str + 9, addr, 6);
        return hgic_iwpriv_set_bytes(ifname, "blenc", str, 15);
    }
}

int hgic_iwpriv_blenc_set_adv_interval(char *ifname, int interval)
{
    if(blenc_mode == 3){
        return 0;
    }else{
        char str[16];
        sprintf(str, "ADV_INT:%d", interval);
        return hgic_iwpriv_set_bytes(ifname, "blenc", str, strlen(str));
    }
}

int hgic_iwpriv_blenc_set_adv_filter(char *ifname, int filter)
{
    if(blenc_mode == 3){
        return 0;
    }else{
        char str[16];
        sprintf(str, "ADV_FILTER:%d", filter);
        return hgic_iwpriv_set_bytes(ifname, "blenc", str, strlen(str));
    }
}

int hgic_iwpriv_blenc_start_adv(char *ifname, int start)
{
    if(blenc_mode == 3){
        int ret = -ENOMEM;
        int cmd_len = 3 + 1;
        char *cmd = malloc(cmd_len);
        if(cmd){
            put_unaligned_le16(HCI_OPCODE(0x08, 0x0A), cmd);
            cmd[2] = 1;
            cmd[3] = start;
            ret = hgic_iwpriv_blenc_send_hcidata(ifname, 0x01, cmd, cmd_len);
            free(cmd);
        }
        return ret;
    }else{
        char str[16];
        sprintf(str, "ADV_EN:%d", start);
        return hgic_iwpriv_set_bytes(ifname, "blenc", str, strlen(str));
        
    }
}

int hgic_iwpriv_blenc_send_gatt_data(char *ifname, char *att_data, int len)
{
    int ret = -ENOMEM;
    char *data = malloc(8 + len);
    if(data){
        hgics_dump_hex("SEND:\r\n", att_data, len, 1);
        // 0 - Connection handle : PB=pb : BC=00 
        put_unaligned_le16(0x1, data);
        // 2 - ACL length
        put_unaligned_le16(len + 4u, data+2);
        // 4 - L2CAP packet length
        put_unaligned_le16(len + 0u, data+4);
        // 6 - L2CAP CID
        put_unaligned_le16(0x04, data+6);
        memcpy(data+8, att_data, len);    
        ret = hgic_iwpriv_blenc_send_hcidata(ifname, 0x02, data, 8 + len);
        free(data);
    }
    return ret;
}

int hgic_iwpriv_set_hwscan(char *ifname, int period, int chan_tmo, int chan_bitmap, int max_cnt)
{
    return hgic_iwpriv_set_ints(ifname, "hwscan", 4, period, chan_tmo, chan_bitmap, max_cnt);
}
int hgic_proc_ota(char *fw_file)
{
    return hgic_proc_write_bytes("ota", fw_file, strlen(fw_file));
}
int hgic_iwpriv_set_user_edca(char *ifname, int ac, struct hgic_txq_param *txq)
{
    char buf[32];
    buf[0] = ac;
    memcpy(buf+1, txq, sizeof(struct hgic_txq_param));
    return hgic_iwpriv_set_bytes(ifname, "user_edca", buf, 1+sizeof(struct hgic_txq_param));
}
int hgic_iwpriv_set_fix_txrate(char *ifname, unsigned int txrate)
{
    return hgic_iwpriv_set_int(ifname, "fix_txrate", txrate);
}
int hgic_iwpriv_set_nav_max(char *ifname, unsigned int nav_max)
{
    return hgic_iwpriv_set_int(ifname, "nav_max", nav_max);
}
int hgic_iwpriv_clear_nav(char *ifname)
{
    return hgic_iwpriv_set_int(ifname, "clr_nav", 0);
}
int hgic_iwpriv_set_cca_param(char *ifname, struct hgic_cca_ctl *cca)
{
    return hgic_iwpriv_set_bytes(ifname, "cca_param", (char *)cca, sizeof(struct hgic_cca_ctl));
}
int hgic_iwpriv_set_tx_modulation_gain(char *ifname, char *gain_table, int size)
{
    return hgic_iwpriv_set_bytes(ifname, "tx_modgain", gain_table, size);
}

int hgic_iwpriv_get_nav(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "nav");
}

int hgic_iwpriv_get_bgrssi(char *ifname, int channel, int bgrssi[3])
{
    int ret = 0;
    char cmd[32];

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "%s get bgrssi=%d", ifname, channel);
    hgic_iwpriv_do(cmd, 0, 0, cmd, sizeof(cmd));
    if(3 == sscanf(cmd, "%d,%d,%d", bgrssi, bgrssi+1, bgrssi+2)){
        return 0;
    }
    return -1;
}

int hgic_iwpriv_reset(char *ifname)
{
    return hgic_iwpriv_set_int(ifname, "reset", 0);
}

int hgic_iwpriv_set_rts_duration(char *ifname, unsigned int duration_us)
{
    return hgic_iwpriv_set_int(ifname, "rts_duration", duration_us);
}

int hgic_iwpriv_set_disable_print(char *ifname, int disable)
{
    return hgic_iwpriv_set_int(ifname, "disable_print", disable);
}

int hgic_iwpriv_set_conn_paironly(char *ifname, int en)
{
    return hgic_iwpriv_set_int(ifname, "conn_paironly", en);
}

int hgic_iwpriv_get_center_freq(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "center_freq");
}

int hgic_iwpriv_set_wait_psmode(char *ifname, int mode)
{
    return hgic_iwpriv_set_int(ifname, "wait_psmode", mode);
}

int hgic_iwpriv_set_diffcust_conn(char *ifname, int en)
{
    return hgic_iwpriv_set_int(ifname, "diffcust_conn", en);
}

int hgic_iwpriv_set_standby(char *ifname, int channel, int sleep_period)
{
    return hgic_iwpriv_set_ints(ifname, "standby", 2, channel, sleep_period);
}

int hgic_iwpriv_set_ap_chan_switch(char *ifname, int channel, int counter)
{
    return hgic_iwpriv_set_ints(ifname, "ap_chansw", 2, channel, counter);
}

int hgic_iwpriv_set_cca_for_ce(char *ifname, int enable)
{
    return hgic_iwpriv_set_int(ifname, "cca_ce", enable);
}

int hgic_iwpriv_set_rtc(char *ifname, int rtc)
{
    return hgic_iwpriv_set_int(ifname, "rtc", rtc);
}

int hgic_iwpriv_get_rtc(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "rtc");
}

int hgic_iwpriv_set_apep_padding(char *ifname, int enable)
{
    return hgic_iwpriv_set_int(ifname, "apep_padding", enable);
}

int hgic_iwpriv_set_freqinfo(char *ifname, char *sta_addr, struct hgic_freqinfo *freqinfo)
{
    int ret = -1;
    char *data = malloc(6 + sizeof(struct hgic_freqinfo));
    if(data){
        memcpy(data, sta_addr, 6);
        memcpy(data+6, freqinfo, sizeof(struct hgic_freqinfo));
        ret = hgic_iwpriv_set_bytes(ifname, "freqinfo", data, 6 + sizeof(struct hgic_freqinfo)); 
        free(data);
    }
    return ret;
}

int hgic_iwpriv_get_acs_result(char *ifname, char *buff, int len)
{
    return hgic_iwpriv_get_bytes(ifname, "acs_result", buff, len);
}

int hgic_iwpriv_get_reason_code(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "reason_code");
}

int hgic_iwpriv_get_status_code(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "status_code");
}

int hgic_iwpriv_set_watchdog(char *ifname, int enable)
{
    return hgic_iwpriv_set_int(ifname, "watchdog", enable);
}

int hgic_iwpriv_set_retry_fallback_cnt(char *ifname, int count)
{
    return hgic_iwpriv_set_int(ifname, "retry_fallback_cnt", count);
}

int hgic_iwpriv_set_fallback_mcs(char *ifname, int original_type, int original_mcs, int fallback_type, int fallback_mcs)
{
    return hgic_iwpriv_set_ints(ifname, "fallback_mcs", 4, original_type, original_mcs, fallback_type, fallback_mcs);
}

int hgic_iwpriv_get_xosc(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "xosc");
}

int hgic_iwpriv_get_freq_offset(char *ifname, char *mac_addr)
{
    char cmd[128];
    memset(cmd, 0, sizeof(cmd));

    if(mac_addr){
        if (strlen(mac_addr) == 17 && mac_addr[2] == ':' && mac_addr[5] == ':' && mac_addr[8] == ':' && mac_addr[11] == ':' && mac_addr[14] == ':') {
            sprintf(cmd, "%s get freq_offset=%s", ifname, mac_addr);
        } else {
            sprintf(cmd, "%s get freq_offset="MACSTR, ifname, MACARG(mac_addr));
        }
    }else{
        sprintf(cmd, "%s get freq_offset=00:00:00:00:00:00", ifname);
    }
    hgic_iwpriv_do(cmd, 0, 0, cmd, sizeof(cmd));
    return atoi(cmd);
}

int hgic_iwpriv_set_xosc(char *ifname, int xosc)
{
    return hgic_iwpriv_set_int(ifname, "xosc", xosc);
}

int hgic_iwpriv_set_freq_cali_period(char *ifname, int period)
{
    return hgic_iwpriv_set_int(ifname, "freq_cali_period", period);
}

int hgic_iwpriv_set_customer_dvrdata(char *ifname, unsigned short cmd_id, char *data, int len)
{
    int ret = 0;
    char *buff = malloc(2+len);
    if(buff){
        put_unaligned_le16(cmd_id, buff);
        memcpy(buff+2, data, len);
        ret = hgic_iwpriv_set_bytes(ifname, "cust_drvdata", buff, 2+len); 
        free(buff);
        return ret;
    }
    return -ENOMEM;
}

int hgic_iwpriv_get_fwinfo(char *ifname, struct hgic_fw_info *fwifno)
{
    return hgic_iwpriv_get_bytes(ifname, "fwinfo", fwifno, sizeof(struct hgic_fw_info));
}

int hgic_iwpriv_set_disassoc_sta(char *ifname, char *sta_mac)
{
    return hgic_iwpriv_set_mac(ifname, "disassoc_sta", sta_mac);
}

int hgic_iwpriv_set_pa_pwrctl_dis(char *ifname, int disable)
{
    return hgic_iwpriv_set_int(ifname, "pa_pwrctl_dis", disable);
}

int hgic_iwpriv_set_ant_auto(char *ifname, int eanble)
{
    return hgic_iwpriv_set_int(ifname, "ant_auto", eanble);
}

int hgic_iwpriv_set_select_ant(char *ifname, int ant)
{
    return hgic_iwpriv_set_int(ifname, "ant_sel", ant);
}

int hgic_iwpriv_set_wkhost_reasons(char *ifname, int* reasons_array, int array_count)
{
    return hgic_iwpriv_set_intarray(ifname, "wkhost_reason", reasons_array, array_count);
}
int hgic_iwpriv_set_atcmd(char *ifname, char* atcmd)
{
    return hgic_iwpriv_set_bytes(ifname, "atcmd", atcmd, strlen(atcmd));
}
int hgic_iwpriv_set_ap_hide(char *ifname, int hide)
{
    return hgic_iwpriv_set_int(ifname, "ap_hide", hide);
}
int hgic_iwpriv_set_assert_holdup(char *ifname, int hold)
{
    return hgic_iwpriv_set_int(ifname, "assert_holdup", hold);
}
int hgic_iwpriv_set_ap_psmode(char *ifname, int ap_psmode)
{
    return hgic_iwpriv_set_int(ifname, "ap_psmode", ap_psmode);
}
int hgic_iwpriv_set_dupfilter_en(char *ifname, int enable)
{
    return hgic_iwpriv_set_int(ifname, "dupfilter", enable);
}
int hgic_iwpriv_set_dis_1v1m2u(char *ifname, int disable)
{
    return hgic_iwpriv_set_int(ifname, "dis_1v1m2u", disable);
}
int hgic_iwpriv_set_dis_psconnect(char *ifname, int disable)
{
    return hgic_iwpriv_set_int(ifname, "dis_psconnect", disable);
}
int hgic_iwpriv_set_wkdata_mask(char *ifname, int offset/*from IP hdr*/, char *mask, int mask_len)
{
    char buff[64];
    if(mask_len > 32) mask_len = 32;
    buff[0] = offset;
    memcpy(buff + 1, mask, mask_len);
    return hgic_iwpriv_set_bytes(ifname, "wkdata_mask", buff, mask_len + 1);
}
int hgic_iwpriv_get_mode(char *ifname, char *mode)
{
    return hgic_iwpriv_get_bytes(ifname, "mode", mode, 8);
}
int hgic_iwpriv_get_wkdata_buff(char *ifname, char *buff, int buff_size)
{
    return hgic_iwpriv_get_bytes(ifname, "wkdata_buff", buff, buff_size);
}
int hgic_iwpriv_get_temperature(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "temperature");
}
int hgic_iwpriv_get_sta_count(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "sta_count");
}
int hgic_iwpriv_get_dhcpc_result(char *ifname, struct hgic_dhcp_result *result)
{
    return hgic_iwpriv_get_bytes(ifname, "dhcpc_result", result, sizeof(struct hgic_dhcp_result));
}

int hgic_iwpriv_set_max_tx_delay(char *ifname, int tmo)
{
    return hgic_iwpriv_set_int(ifname, "max_txdelay", tmo);
}

int hgic_iwpriv_set_heartbeat_int(char *ifname, int interval_ms)
{
    return hgic_iwpriv_set_int(ifname, "heartbeat_int", interval_ms);
}

int hgic_iwpriv_get_sta_info(char *ifname, char *mac_addr, struct hgic_sta_info *stainfo)
{
    char cmd[128];
    memset(cmd, 0, sizeof(cmd));

    if(mac_addr == NULL || stainfo == NULL){
        printf("get sta_info: invalid mac address\r\n");
        return -1;
    }

    if (strlen(mac_addr) == 17 && mac_addr[2] == ':' && mac_addr[5] == ':' && mac_addr[8] == ':' && mac_addr[11] == ':' && mac_addr[14] == ':') {
        sprintf(cmd, "%s get stainfo=%s,1", ifname, mac_addr);
    } else {
        sprintf(cmd, "%s get stainfo="MACSTR",1", ifname, MACARG(mac_addr));
    }
    return hgic_iwpriv_do(cmd, 0, 0, stainfo, sizeof(struct hgic_sta_info));
}

int hgic_iwpriv_get_signal(char *ifname)
{
    return hgic_iwpriv_get_int(ifname, "signal");
}

int hgic_iwpriv_set_countryregion(char *ifname, char country[2])
{
    return hgic_iwpriv_set_bytes(ifname, "country_region", country, 2);
}
