#ifndef _HGOTA_H_
#define _HGOTA_H_
#ifdef __cplusplus
extern "C" {
#endif

typedef char s8;
typedef char int8;
typedef short s16;
typedef short int16;
typedef int s32;
typedef int int32;
typedef long long s64;
typedef long long int64;
typedef unsigned char u8;
typedef unsigned char uint8;
typedef unsigned short u16;
typedef unsigned short uint16;
typedef unsigned int u32;
typedef unsigned int uint32;
typedef unsigned long long u64;
typedef unsigned long long uint64;

#define OTA_STA_COUNT (32)
#define ETH_P_OTA     0x4847
#define IS_ETH_OTA(p) ((p)==0x4748)

#ifndef MAC2STR
#define MAC2STR(a) (a)[0]&0xff, (a)[1]&0xff, (a)[2]&0xff, (a)[3]&0xff, (a)[4]&0xff, (a)[5]&0xff
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

enum ETH_P_OTA_STYPE {
    ETH_P_OTA_REBOOT = 1,
    ETH_P_OTA_SCAN,
    ETH_P_OTA_SCAN_REPORT,
    ETH_P_OTA_FW_DATA,
    ETH_P_OTA_FW_DATA_RESPONE,
    ETH_P_OTA_FW_GET_PARAM,
    ETH_P_OTA_FW_GET_PARAM_RESP,
    ETH_P_OTA_FW_SET_PARAM,
    ETH_P_OTA_FW_SET_PARAM_RESP,
};

enum HGIC_OTA_RESP_ERR_CODE{
    HGIC_OTA_RESP_ERR_OK=0,
    HGIC_OTA_RESP_ERR_CHECKSUM,
    HGIC_OTA_RESP_ERR_WRITE,
};

typedef int (*raw_send_hdl)(char *data, int len);

struct eth_ota_hdr {
    uint8  dest[6];
    uint8  src[6];
    uint16 proto;
    uint8  stype, status;
};

struct eth_ota_scan_report {
    struct eth_ota_hdr hdr;
    uint32 version;
    uint16 chipid;
    uint8  mode, rev;
    uint32 svn_version;
};

struct eth_ota_fw_data {
    struct eth_ota_hdr hdr;
    uint32 version;
    uint32 off, tot_len;
    uint16 len, checksum;
    uint16 chipid;
    uint8  data[0];
};

struct hgota_fw_info {
    u16 chipid;
    u32 version;
    u32 svn_version;
    u32 tot_len;
};

struct eth_ota_fwparam{
    uint8  bss_bw;
    uint8  encrypt: 1,
           forward: 1,
           key_set: 1,
           mkey_set: 1;
    uint8  chan_cnt;
    uint16 freq_start, freq_end;
    uint16 chan_list[16];
    uint8  ssid[32+2];
    uint8  key[32];
    uint8  mcast_key[32];
    uint8  tx_mcs;
};

struct eth_ota_fwparam_hdr{
    struct eth_ota_hdr hdr;
    uint16 len, checksum;
    struct eth_ota_fwparam param;
};

#define BIT(a) ((u16)1 << (a))
enum ETH_P_REBOOT_FLAGS {
    ETH_P_REBOOT_FLAGS_LOADDEF = BIT(0),
};

struct eth_ota_reboot {
    struct eth_ota_hdr hdr;
    uint32 flags;
};

struct hgota_sta {
    char addr[6];
    int  chipid;
    int  version;
    int  svn_version;
    int  online;
    int  next_off;
    struct eth_ota_fwparam param;
};
struct libota {
    struct hgota_sta stas[OTA_STA_COUNT];
    int  sta_count;
    raw_send_hdl send;
};

enum{
    HGOTA_STATUS_NEW_STA = 0x1,
    HGOTA_STATUS_FW_STATUS,
    HGOTA_STATUS_CONFIG_GOT,
    HGOTA_STATUS_CONFIG_UPDATED,
};

extern struct libota LIBOTA;

void libota_clear_sta_nexoff(char *sta_mac);

int libota_sta_nexoff(char *sta_mac);

int libota_reboot(char *sta_mac, int flags);

int libota_scan(int clear);

int libota_send_fw_data(char *sta_mac, struct hgota_fw_info *info, int off, char *data, int len);

int libota_rx_proc(char *buff, int len);

int libota_init(raw_send_hdl send);

#ifdef __cplusplus
}
#endif
#endif
