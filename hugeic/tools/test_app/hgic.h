#ifndef _HUGE_IC_H_
#define _HUGE_IC_H_
#ifdef __cplusplus
extern "C" {
#endif

#ifdef __RTOS__
#define HGIC_CMD_START 100
#else
#define HGIC_CMD_START 0
#endif

#ifndef __packed
#define __packed          __attribute__((packed))
#endif

typedef void (*hgic_init_cb)(void *args);
typedef void (*hgic_event_cb)(char *ifname, int event, int param1, int param2);

struct hgic_bss_info {
    unsigned char bssid[6];
    unsigned char ssid[32];
    unsigned char encrypt;
    signed   char signal;
    unsigned short freq;
};

struct hgic_bss_info1 {
    unsigned char bssid[6];
    unsigned char ssid[32];
    unsigned char encrypt: 6, ver: 2;
    signed   char signal;
    unsigned short freq;
    unsigned char country_region[4];
    unsigned char bss_bw;
};

struct hgic_fw_info {
    unsigned int version;
    unsigned int svn_version;
    unsigned short chip_id;
    unsigned short cpu_id;
    unsigned char  mac[6];
    unsigned char  resv[2];
    unsigned int app_version;
    unsigned int  smt_dat;
};

struct hgic_sta_info {
    unsigned char aid;
    unsigned char ps:1;
    unsigned char addr[6];
    signed char rssi;
    signed char evm;
    signed char tx_snr;
    signed char rx_snr;
};

struct hgic_freqinfo {
    unsigned char  bss_bw, chan_cnt;
    unsigned short freq_start, freq_end;
    unsigned short chan_list[16];
};

struct hgic_module_hwinfo{
    union{
        struct{
            unsigned char type;
            unsigned char saw:1, rev:7;
        };
        unsigned short v;
    };
};

struct hgic_txq_param {
    unsigned short txop;
    unsigned short cw_min;
    unsigned short cw_max;
    unsigned char  aifs;
    unsigned char  acm;
};

struct hgic_mcast_txparam {
    unsigned char dupcnt;
    unsigned char tx_bw;
    unsigned char tx_mcs;
    unsigned char clearch;
};

struct hgic_rx_info {
    unsigned char  band;
    unsigned char  mcs: 4, bw: 4;
    char  evm;
    char  signal;
    unsigned short freq;
    short freq_off;
    unsigned char  rx_flags;
    unsigned char  antenna;
    unsigned char  nss : 4, s1g_nss : 4;
    unsigned char  vht_flag : 3, s1g_flag : 5;
};

struct hgic_tx_info {
    unsigned char  band;
    unsigned char  tx_bw;
    unsigned char  tx_mcs;
    unsigned char  freq_idx: 5, antenna: 3;
    unsigned int   tx_flags;
    unsigned short tx_flags2;
    unsigned char  priority;
    unsigned char  tx_power;
};

struct bt_rx_info {
    unsigned char   channel;    //current channel
    unsigned char   con_handle; //hci handle
    signed char     rssi;
    unsigned char   frm_type;
    unsigned int    rev;
};


/*data packet header*/
struct hgic_hdr {
    unsigned short magic;
    unsigned char  type;
    unsigned char  ifidx: 4, flags: 4;
    unsigned short length;
    unsigned short cookie;
} __packed;

struct hgic_frm_hdr {
    struct hgic_hdr hdr;
    union {
        struct hgic_rx_info rx_info;
        struct hgic_tx_info tx_info;
        unsigned char  rev[24];
    };
} __packed;

struct hgic_frm_hdr2 {
    struct hgic_hdr hdr;
} __packed;


/*contro pakcet header*/
struct hgic_ctrl_hdr {
    struct hgic_hdr hdr;
    union {
        struct {
            unsigned char  cmd_id;
            short status;
        } cmd;
        struct {
            unsigned short  cmd_id;
            short status;
        } cmd2;
        struct {
            unsigned char event_id;
            short value;
        } event;
        struct {
            unsigned short event_id;
            short value;
        } event2;
        struct {
            unsigned char  type;
        } hci;
        unsigned char info[4];
    };
} __packed;

struct hgic_key_conf {
    unsigned int cipher;
    unsigned int flags;
    unsigned char keyidx;
    unsigned char keylen;
    unsigned char key[0];
};

struct hgic_cca_ctl {
    char    start_th;
    char    mid_th;
    char    ed_th;
    /* CCA auto adjustment.
     * When the cca automatic adjustment takes effect, the
     * above three parameters are invalid.
     */
    char   auto_en     : 1;
};

struct hgic_acs_result{
    unsigned int  freq;//KHz
    unsigned char sync_cnt;
    signed char   min;
    signed char   max;
    signed char   avg;
};

struct hgic_fallback_mcs {
    unsigned char original_type;
    unsigned char original_mcs;
    unsigned char fallback_type;
    unsigned char fallback_mcs;
};

#define HDR_CMDID(ctl) ((ctl)->hdr.type==HGIC_HDR_TYPE_CMD2? le16_to_cpu((ctl)->cmd2.cmd_id):(ctl)->cmd.cmd_id)
#define HDR_EVTID(ctl) ((ctl)->hdr.type==HGIC_HDR_TYPE_EVENT2?le16_to_cpu((ctl)->event2.event_id):(ctl)->event.event_id)
#define HDR_CMDID_SET(ctl, id) if(id>255){\
        (ctl)->hdr.type =HGIC_HDR_TYPE_CMD2;\
        (ctl)->cmd2.cmd_id = cpu_to_le16(id);\
    }else{\
        (ctl)->hdr.type =HGIC_HDR_TYPE_CMD;\
        (ctl)->cmd.cmd_id = id;\
    }
#define HDR_EVTID_SET(ctl, id) if(id>255){\
        (ctl)->hdr.type =HGIC_HDR_TYPE_EVENT2;\
        (ctl)->event2.event_id = cpu_to_le16(id);\
    }else{\
        (ctl)->hdr.type =HGIC_HDR_TYPE_EVENT;\
        (ctl)->event.event_id = id;\
    }

enum hgic_hdr_type {
    HGIC_HDR_TYPE_ACK         = 1,
    HGIC_HDR_TYPE_FRM         = 2,
    HGIC_HDR_TYPE_CMD         = 3,
    HGIC_HDR_TYPE_EVENT       = 4,
    HGIC_HDR_TYPE_FIRMWARE    = 5,
    HGIC_HDR_TYPE_NLMSG       = 6,
    HGIC_HDR_TYPE_BOOTDL      = 7,
    HGIC_HDR_TYPE_TEST        = 8,
    HGIC_HDR_TYPE_FRM2        = 9,
    HGIC_HDR_TYPE_TEST2       = 10,
    HGIC_HDR_TYPE_SOFTFC      = 11,
    HGIC_HDR_TYPE_OTA         = 12,
    HGIC_HDR_TYPE_CMD2        = 13,
    HGIC_HDR_TYPE_EVENT2      = 14,
    HGIC_HDR_TYPE_BOOTDL_DATA = 15,
    HGIC_HDR_TYPE_IFBR        = 16,
    HGIC_HDR_TYPE_BEACON      = 17,
    HGIC_HDR_TYPE_AGGFRM      = 18,
    HGIC_HDR_TYPE_BLUETOOTH   = 19,

    HGIC_HDR_TYPE_MAX,
};

enum hgic_cmd {
    HGIC_CMD_DEV_OPEN               =  1,   /* fmac/smac */
    HGIC_CMD_DEV_CLOSE              =  2,   /* fmac/smac */
    HGIC_CMD_SET_MAC                =  3,   /* fmac/smac */
    HGIC_CMD_SET_SSID               =  4,   /* fmac */
    HGIC_CMD_SET_BSSID              =  5,   /* fmac */
    HGIC_CMD_SET_COUNTRY           	=  6,   /* fmac */
    HGIC_CMD_SET_CHANNEL            =  7,   /* fmac */
    HGIC_CMD_SET_CENTER_FREQ        =  8,   /* smac */
    HGIC_CMD_SET_RTS_THRESHOLD      =  9,   /* smac */
    HGIC_CMD_SET_FRG_THRESHOLD      =  10,  /* smac */
    HGIC_CMD_SET_KEY_MGMT           =  11,  /* fmac */
    HGIC_CMD_SET_WPA_PSK            =  12,  /* fmac */
    HGIC_CMD_SET_KEY                =  13,  /* smac */
    HGIC_CMD_SCAN                   =  14,  /* fmac */
    HGIC_CMD_GET_SCAN_LIST          =  15,  /* fmac */
    HGIC_CMD_SET_BSSID_FILTER       =  16,  /* fmac */
    HGIC_CMD_DISCONNECT             =  17,  /* fmac */
    HGIC_CMD_GET_BSSID              =  18,  /* fmac */
    HGIC_CMD_SET_WBNAT              =  19,  /* unused */
    HGIC_CMD_GET_STATUS             =  20,  /* fmac */
    HGIC_CMD_SET_LISTEN_INTERVAL    =  21,  /* smac */
    HGIC_CMD_SET_TX_POWER           =  22,  /* fmac/smac */
    HGIC_CMD_GET_TX_POWER           =  23,  /* fmac/smac */
    HGIC_CMD_SET_TX_LCOUNT          =  24,  /* unused */
    HGIC_CMD_SET_TX_SCOUNT          =  25,  /* unused */
    HGIC_CMD_ADD_STA                =  26,  /* smac */
    HGIC_CMD_REMOVE_STA             =  27,  /* smac */
    HGIC_CMD_SET_TX_BW              =  28,  /* fmac */
    HGIC_CMD_SET_TX_MCS             =  29,  /* fmac/smac */
    HGIC_CMD_SET_FREQ_RANGE         =  30,  /* fmac */
    HGIC_CMD_ACS_ENABLE             =  31,  /* fmac */
    HGIC_CMD_SET_PRIMARY_CHAN       =  32,  /* fmac */
    HGIC_CMD_SET_BG_RSSI            =  33,  /* fmac */
    HGIC_CMD_SET_BSS_BW             =  34,  /* fmac/smac */
    HGIC_CMD_TESTMODE_CMD           =  35,  /* fmac/smac */
    HGIC_CMD_SET_AID                =  36,  /* smac */
    HGIC_CMD_GET_FW_STATE           =  37,  /* unused */
    HGIC_CMD_SET_TXQ_PARAM          =  38,  /* smac */
    HGIC_CMD_SET_CHAN_LIST          =  39,  /* fmac */
    HGIC_CMD_GET_CONN_STATE         =  40,  /* fmac */
    HGIC_CMD_SET_WORK_MODE          =  41,  /* fmac */
    HGIC_CMD_SET_PAIRED_STATIONS    =  42,  /* fmac */
    HGIC_CMD_GET_FW_INFO            =  43,  /* fmac/smac */
    HGIC_CMD_PAIRING                =  44,  /* fmac */
    HGIC_CMD_GET_TEMPERATURE        =  45,  /* fmac/smac */
    HGIC_CMD_ENTER_SLEEP            =  46,  /* fmac */
    HGIC_CMD_OTA                    =  47,  /* fmac */
    HGIC_CMD_GET_SSID               =  48,  /* fmac */
    HGIC_CMD_GET_WPA_PSK            =  49,  /* fmac */
    HGIC_CMD_GET_SIGNAL             =  50,  /* fmac */
    HGIC_CMD_GET_TX_BITRATE         =  51,  /* fmac */
    HGIC_CMD_SET_BEACON_INT         =  52,  /* fmac */
    HGIC_CMD_GET_STA_LIST           =  53,  /* fmac */
    HGIC_CMD_SAVE_CFG               =  54,  /* fmac */
    HGIC_CMD_JOIN_GROUP             =  55,  /* unused */
    HGIC_CMD_SET_ETHER_TYPE         =  56,  /* unused */
    HGIC_CMD_GET_STA_COUNT          =  57,  /* fmac */
    HGIC_CMD_SET_HEARTBEAT_INT      =  58,  /* fmac */
    HGIC_CMD_SET_MCAST_KEY          =  59,  /* unused */
    HGIC_CMD_SET_AGG_CNT            =  60,  /* fmac/smac */
    HGIC_CMD_GET_AGG_CNT            =  61,  /* fmac/smac */
    HGIC_CMD_GET_BSS_BW             =  62,  /* fmac/smac */
    HGIC_CMD_GET_FREQ_RANGE         =  63,  /* fmac */
    HGIC_CMD_GET_CHAN_LIST          =  64,  /* fmac */
    HGIC_CMD_RADIO_ONOFF            =  65,  /* fmac/smac */
    HGIC_CMD_SET_PS_HEARTBEAT       =  66,  /* fmac */
    HGIC_CMD_SET_WAKEUP_STA         =  67,  /* fmac */
    HGIC_CMD_SET_PS_HEARTBEAT_RESP  =  68,  /* fmac */
    HGIC_CMD_SET_PS_WAKEUP_DATA     =  69,  /* fmac */
    HGIC_CMD_SET_PS_CONNECT         =  70,  /* fmac */
    HGIC_CMD_SET_BSS_MAX_IDLE       =  71,  /* fmac */
    HGIC_CMD_SET_WKIO_MODE          =  72,  /* fmac */
    HGIC_CMD_SET_DTIM_PERIOD        =  73,  /* fmac */
    HGIC_CMD_SET_PS_MODE            =  74,  /* fmac */
    HGIC_CMD_LOAD_DEF               =  75,  /* fmac */
    HGIC_CMD_DISASSOC_STA           =  76,  /* fmac */
    HGIC_CMD_SET_APLOST_TIME        =  77,  /* fmac */
    HGIC_CMD_GET_WAKEUP_REASON      =  78,  /* fmac */
    HGIC_CMD_UNPAIR                 =  79,  /* fmac */
    HGIC_CMD_SET_AUTO_CHAN_SWITCH   =  80,  /* fmac */
    HGIC_CMD_SET_REASSOC_WKHOST     =  81,  /* fmac */
    HGIC_CMD_SET_WAKEUP_IO          =  82,  /* fmac */
    HGIC_CMD_DBGINFO_OUTPUT         =  83,  /* fmac/smac */
    HGIC_CMD_SET_SYSDBG             =  84,  /* fmac/smac */
    HGIC_CMD_SET_AUTO_SLEEP_TIME    =  85,  /* fmac */
    HGIC_CMD_GET_KEY_MGMT           =  86,  /* fmac */
    HGIC_CMD_SET_PAIR_AUTOSTOP      =  87,  /* fmac */
    HGIC_CMD_SET_SUPER_PWR          =  88,  /* fmac */
    HGIC_CMD_SET_REPEATER_SSID      =  89,  /* fmac */
    HGIC_CMD_SET_REPEATER_PSK       =  90,  /* fmac */
    HGIC_CMD_CFG_AUTO_SAVE          =  91,  /* fmac */
    HGIC_CMD_SEND_CUST_MGMT         =  92,  /* fmac */
    HGIC_CMD_GET_BATTERY_LEVEL      =  93,  /* unused */
    HGIC_CMD_SET_DCDC13             =  94,  /* fmac */
    HGIC_CMD_SET_ACKTMO             =  95,  /* fmac/smac */
    HGIC_CMD_GET_MODULETYPE         =  96,  /* fmac/smac */
    HGIC_CMD_PA_PWRCTRL_DIS         =  97,  /* fmac */
    HGIC_CMD_SET_DHCPC              =  98,  /* fmac */
    HGIC_CMD_GET_DHCPC_RESULT       =  99,  /* fmac */
    HGIC_CMD_SET_WKUPDATA_MASK      =  100, /* fmac */
    HGIC_CMD_GET_WKDATA_BUFF        =  101, /* fmac */
    HGIC_CMD_GET_DISASSOC_REASON    =  102, /* fmac */
    HGIC_CMD_SET_WKUPDATA_SAVEEN    =  103, /* fmac */
    HGIC_CMD_SET_CUST_DRIVER_DATA   =  104, /* fmac */
    HGIC_CMD_SET_MCAST_TXPARAM      =  105, /* unused */
    HGIC_CMD_SET_STA_FREQINFO       =  106, /* fmac */
    HGIC_CMD_SET_RESET_STA          =  107, /* fmac */
    HGIC_CMD_SET_UART_FIXLEN        =  108, /* unused */
    HGIC_CMD_GET_UART_FIXLEN        =  109, /* unused */
    HGIC_CMD_SET_ANT_AUTO           =  110, /* fmac */
    HGIC_CMD_SET_ANT_SEL            =  111, /* fmac */
    HGIC_CMD_GET_ANT_SEL            =  112, /* fmac */
    HGIC_CMD_SET_WKUP_HOST_REASON   =  113, /* fmac */
    HGIC_CMD_SET_MAC_FILTER_EN      =  114, /* unused */
    HGIC_CMD_SET_ATCMD              =  115, /* fmac/smac */
    HGIC_CMD_SET_ROAMING            =  116, /* fmac */
    HGIC_CMD_SET_AP_HIDE            =  117, /* fmac */
    HGIC_CMD_SET_DUAL_ANT           =  118, /* fmac */
    HGIC_CMD_SET_MAX_TCNT           =  119, /* fmac/smac */
    HGIC_CMD_SET_ASSERT_HOLDUP      =  120, /* fmac/smac */
    HGIC_CMD_SET_AP_PSMODE_EN       =  121, /* fmac */
    HGIC_CMD_SET_DUPFILTER_EN       =  122, /* fmac */
    HGIC_CMD_SET_DIS_1V1_M2U        =  123, /* fmac */
    HGIC_CMD_SET_DIS_PSCONNECT      =  124, /* fmac */
    HGIC_CMD_SET_RTC                =  125, /* fmac */
    HGIC_CMD_GET_RTC                =  126, /* fmac */
    HGIC_CMD_SET_KICK_ASSOC         =  127, /* fmac */
    HGIC_CMD_START_ASSOC            =  128, /* fmac */
    HGIC_CMD_SET_AUTOSLEEP          =  129, /* fmac */
    HGIC_CMD_SEND_BLENC_DATA        =  130, /* smac */
    HGIC_CMD_SET_BLENC_EN           =  131, /* smac */
    HGIC_CMD_RESET                  =  132, /* fmac/smac */
    HGIC_CMD_SET_HWSCAN             =  133, /* smac */
    HGIC_CMD_GET_TXQ_PARAM          =  134, /* smac */
    HGIC_CMD_SET_PROMISC            =  135, /* smac */
    HGIC_CMD_SET_USER_EDCA          =  136, /* fmac */
    HGIC_CMD_SET_FIX_TXRATE         =  137, /* smac */
    HGIC_CMD_SET_NAV_MAX            =  138, /* smac */
    HGIC_CMD_CLEAR_NAV              =  139, /* smac */
    HGIC_CMD_SET_CCA_PARAM          =  140, /* smac */
    HGIC_CMD_SET_TX_MODGAIN         =  141, /* smac */
    HGIC_CMD_GET_NAV                =  142, /* smac */
    HGIC_CMD_SET_BEACON_START       =  143, /* smac */
    HGIC_CMD_SET_BLE_OPEN           =  144, /* smac */
    HGIC_CMD_GET_MODE               =  145, /* fmac */
    HGIC_CMD_GET_BGRSSI             =  146, /* fmac */
    HGIC_CMD_SEND_BLENC_ADVDATA     =  147, /* smac */
    HGIC_CMD_SEND_BLENC_SCANRESP    =  148, /* smac */
    HGIC_CMD_SEND_BLENC_DEVADDR     =  149, /* smac */
    HGIC_CMD_SEND_BLENC_ADVINTERVAL =  150, /* smac */
    HGIC_CMD_SEND_BLENC_STARTADV    =  151, /* smac */
    HGIC_CMD_SET_RTS_DURATION       =  152, /* smac */
    HGIC_CMD_STANDBY_CFG            =  153, /* fmac */
    HGIC_CMD_SET_CONNECT_PAIRONLY   =  154, /* fmac */
    HGIC_CMD_SET_DIFFCUST_CONN      =  155, /* fmac */
    HGIC_CMD_GET_CENTER_FREQ        =  156, /* smac */
	HGIC_CMD_SET_WAIT_PSMODE        =  157, /* fmac */
	HGIC_CMD_SET_AP_CHAN_SWITCH     =  158, /* fmac */
	HGIC_CMD_SET_CCA_FOR_CE         =  159, /* fmac */
	HGIC_CMD_SET_DISABLE_PRINT      =  160, /* fmac/smac */	
	HGIC_CMD_SET_APEP_PADDING       =  161, /* smac */
	HGIC_CMD_GET_ACS_RESULT         =  162, /* fmac/smac */		
	HGIC_CMD_GET_WIFI_STATUS_CODE   =  163, /* fmac */
	HGIC_CMD_GET_WIFI_REASON_CODE   =  164, /* fmac */
	HGIC_CMD_SET_WATCHDOG           =  165, /* fmac/smac */	
	HGIC_CMD_SET_RETRY_FALLBACK_CNT =  166, /* smac */
	HGIC_CMD_SET_FALLBACK_MCS       =  167, /* smac */
	HGIC_CMD_GET_XOSC_VALUE         =  168, /* smac */
	HGIC_CMD_SET_XOSC_VALUE         =  169, /* smac */
	HGIC_CMD_GET_FREQ_OFFSET        =  170, /* smac */
	HGIC_CMD_SET_CALI_PERIOD        =  171, /* smac */
    HGIC_CMD_SET_BLENC_ADVFILTER    =  172, /* smac */
    HGIC_CMD_SET_MAX_TX_DELAY       =  173, /* smac */
    HGIC_CMD_GET_STA_INFO           =  174, /* fmac */
    HGIC_CMD_SEND_MGMTFRAME         =  175, /* fmac */    

};

enum hgic_event {
    HGIC_EVENT_STATE_CHG           = 1,
    HGIC_EVENT_CH_SWICH            = 2,
    HGIC_EVENT_DISCONNECT_REASON   = 3,
    HGIC_EVENT_ASSOC_STATUS        = 4,
    HGIC_EVENT_SCANNING            = 5,
    HGIC_EVENT_SCAN_DONE           = 6,
    HGIC_EVENT_TX_BITRATE          = 7,
    HGIC_EVENT_PAIR_START          = 8,
    HGIC_EVENT_PAIR_SUCCESS        = 9,
    HGIC_EVENT_PAIR_DONE           = 10,
    HGIC_EVENT_CONECT_START        = 11,
    HGIC_EVENT_CONECTED            = 12,
    HGIC_EVENT_DISCONECTED         = 13,
    HGIC_EVENT_SIGNAL              = 14,
    HGIC_EVENT_DISCONNET_LOG       = 15,
    HGIC_EVENT_REQUEST_PARAM       = 16,
    HGIC_EVENT_TESTMODE_STATE      = 17,
    HGIC_EVENT_FWDBG_INFO          = 18,
    HGIC_EVENT_CUSTOMER_MGMT       = 19,
    HGIC_EVENT_SLEEP_FAIL          = 20,
    HGIC_EVENT_DHCPC_DONE          = 21,
    HGIC_EVENT_CONNECT_FAIL        = 22,
    HGIC_EVENT_CUST_DRIVER_DATA    = 23,
    HGIC_EVENT_UNPAIR_STA          = 24,
    HGIC_EVENT_BLENC_DATA          = 25,
    HGIC_EVENT_HWSCAN_RESULT       = 26,
    HGIC_EVENT_EXCEPTION_INFO      = 27,
	HGIC_EVENT_DSLEEP_WAKEUP       = 28,
    HGIC_EVENT_STA_MIC_ERROR       = 29,
    HGIC_EVENT_ACS_DONE            = 30,
    HGIC_EVENT_FW_INIT_DONE        = 31,
    HGIC_EVENT_ROAM_CONECTED       = 32,
    HGIC_EVENT_MGMT_FRAME          = 33,        
};

enum hgicf_hw_state {
    HGICF_HW_DISCONNECTED     = 0,
    HGICF_HW_DISABLED         = 1,
    HGICF_HW_INACTIVE         = 2,
    HGICF_HW_SCANNING         = 3,
    HGICF_HW_AUTHENTICATING   = 4,
    HGICF_HW_ASSOCIATING      = 5,
    HGICF_HW_ASSOCIATED       = 6,
    HGICF_HW_4WAY_HANDSHAKE   = 7,
    HGICF_HW_GROUP_HANDSHAKE  = 8,
    HGICF_HW_CONNECTED        = 9,
};

enum HGIC_EXCEPTION_NUM{
    HGIC_EXCEPTION_CPU_USED_OVERTOP         = 1,
    HGIC_EXCEPTION_HEAP_USED_OVERTOP        = 2,
    HGIC_EXCEPTION_WIFI_BUFFER_USED_OVERTOP = 3,
    HGIC_EXCEPTION_TX_BLOCKED               = 4,
    HGIC_EXCEPTION_TXDELAY_TOOLONG          = 5,
    HGIC_EXCEPTION_STRONG_BGRSSI            = 6,
    HGIC_EXCEPTION_TEMPERATURE_OVERTOP      = 7,
    HGIC_EXCEPTION_WRONG_PASSWORD           = 8,
};

struct hgic_exception_info {
    int num;
    union {
        struct  {
            int max, avg, min;
        } txdelay;
        struct  {
            int max, avg, min;
        } bgrssi;
        struct  {
            int total, used;
        } buffer_usage;
        struct  {
            int total, used;
        } heap_usage;
        struct  {
            int temp;
        } temperature;
    } info;
};

struct hgic_dhcp_result {
    unsigned int ipaddr, netmask, svrip, router, dns1, dns2;
};

#ifdef __RTOS__
struct firmware {
    unsigned char *data;
    unsigned int size;
};
int request_firmware(const struct firmware **fw, const char *name, void *dev);
void release_firmware(struct firmware *fw);

extern int hgicf_init(void);
extern int hgicf_cmd(char *ifname, unsigned int cmd, unsigned int param1, unsigned int param2);
extern int  hgics_init(void);
extern void hgics_exit(void);
extern int wpas_init(void);
extern int wpas_start(char *ifname);
extern int wpas_stop(char *ifname);
extern int wpas_cli(char *ifname, char *cmd, char *reply_buff, int reply_len);
extern int wpas_passphrase(char *ssid, char *passphrase, char psk[32]);
extern int hapd_init(void);
extern int hapd_start(char *ifname);
extern int hapd_stop(char *ifname);
extern int hapd_cli(char *ifname, char *cmd, char *reply_buff, int reply_len);
extern void hgic_param_iftest(int iftest);
extern const char *hgic_param_ifname(const char *name);
extern char *hgic_param_fwfile(const char *fw);
extern int hgic_param_ifcount(int count);
extern void hgic_param_initcb(hgic_init_cb cb);
extern void hgic_param_eventcb(hgic_event_cb cb);
extern int hgic_ota_start(char *ifname, char *fw_name);

void hgic_raw_init(void);
int hgic_raw_send(char *dest, char *data, int len);
int hgic_raw_rcev(char *buf, int size, char *src);

#ifdef HGIC_SMAC
#include "umac_config.h"
#endif
#endif

#ifdef __cplusplus
}
#endif
#endif
