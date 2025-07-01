#ifndef _HUGE_IC_DEF_H_
#define _HUGE_IC_DEF_H_
#include "hgic.h"
#include "version.h"

#define HGIC_VERSION "v2.2.1"

#ifndef SVN_VERSION
#error "SVN_VERSION undefined"
#endif

#define VERSOIN_SHOW(name) do{\
        printk("** HUGE-IC WLAN Card Driver("name") "HGIC_VERSION"-"SVN_VERSION"\r\n");\
    }while(0)

#define HGIC_WDEV_ID_AP   2
#define HGIC_WDEV_ID_STA  1
#define HGIC_SCAN_MAX_NUM 32

#define HGIC_HDR_TX_MAGIC 0x1A2B
#define HGIC_HDR_RX_MAGIC 0x2B1A

#define HGIC_VENDOR_ID  (0xA012)
#define HGIC_WLAN_4002  (0x4002)
#define HGIC_WLAN_4104  (0x4104)
#define HGIC_WLAN_8400  (0x8400)


#define HGIC_CTRL_TIMEOUT 100
#define HGIC_CMD_PRIORITY 0
#define HGIC_TX_WINDOW    20
#define HGIC_TX_COOKIE_MASK 0x7FFF
#define HGIC_BLOCK_ACK_CNT  256

#define hgic_dbg(fmt, ...) printk("%s:%d::"fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define hgic_err(fmt, ...) printk("%s:%d::"fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define hgic_enter()       printk("enter %s\r\n", __FUNCTION__)
#define hgic_leave()       printk("leave %s\r\n", __FUNCTION__)

#ifndef ARRAYSIZE
#define ARRAYSIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define HGIC_CMD_TIMEOUT 500
#define HGIC_TX_TIMEOUT  10
#define HGIC_DETECT_TIMER 2000

enum hgic_bus_type {
    HGIC_BUS_SDIO = 0x1,
    HGIC_BUS_USB,
    HGIC_BUS_HWSIM,
    HGIC_BUS_WLOE,
    HGIC_BUS_SDSPI,
};

enum hgic_hdr_flags2 {
    HGIC_HDR_FLAGS2_AFT_BEACON = BIT(0),
};

enum hgic_bus_flag {
    HGIC_BUS_FLAGS_DISABLE_REINIT,
    HGIC_BUS_FLAGS_SLEEP,
    HGIC_BUS_FLAGS_INBOOT,
    HGIC_BUS_FLAGS_NOPOLL,
    HGIC_BUS_FLAGS_SOFTFC,
    HGIC_BUS_FLAGS_ERROR,
};

#define hgic_pick_values(pick_type, str, array, size) do{\
        char *__ptr = NULL;\
        char *__str = str; \
        memset(array, 0, size*sizeof(pick_type));\
        if((str) && strlen((str)) > 0){\
            while ((__ptr = strsep((char **)&(__str), ",")) != NULL) {\
                if (argcnt >= size) break;\
                array[argcnt++] = (pick_type)simple_strtol(__ptr, 0, 0);\
            }\
        }\
    }while(0)


//ack packet
struct hgic_dack_hdr {
    struct hgic_hdr hdr;
    uint16_t cookies[0];
} __packed;

struct hgic_nlmsg_hdr {
    struct hgic_hdr hdr;
    uint32_t group;
    uint32_t portid;
};

struct hgic_bootdl_resp_hdr {
    struct hgic_hdr hdr;
    unsigned char   cmd;
    unsigned char   rsp;
    unsigned char   rsp_data[4];
    unsigned char   reserved;
    unsigned char   check;
} __attribute__((packed));


struct hgic_bootdl_cmd_hdr {
    struct hgic_hdr      hdr;
    unsigned char   cmd;
    unsigned char   cmd_len;
    unsigned char   cmd_flag;
    unsigned char   addr[4];
    unsigned char   len[4];
    unsigned char   check;
} __attribute__((packed));

struct hgic_ota_hdr {
    unsigned int version;
    unsigned int off;
    unsigned int tot_len;
    unsigned short len;
    unsigned short checksum;
    unsigned short chipid;
    unsigned short err_code;
    unsigned char  data[0];
};

///////////////////////////////////////////////////////////////////////////////////////////////////
enum hgic_rom_cmd {
    HGIC_ROM_CMD_ENTER = 0,
    HGIC_ROM_CMD_LDFW,
    HGIC_ROM_CMD_RUN,
};

struct hgic_fw_ldinfo {
    unsigned int run_addr;
    unsigned int encrypt: 1,
             resv: 31;
};

struct hgic_rom_hdr {
    unsigned char cmd;
    unsigned char subcmd;
    unsigned char data[0];
};

struct hgic_sta_status {
    unsigned short aid;
    unsigned char  addr[6];
    char           rssi;
    char           evm;
    char           evm_std;
    unsigned char  tx_mcs;
    unsigned char  tx_bw;
};

struct hgic_fw_status {
    unsigned short rxq;
    unsigned short txq;
    unsigned short acq[4];
    unsigned short sta_count;
    struct hgic_sta_status sta[0];
};

enum HGIC_BUS_BOOTDL_CKSUM {
    HGIC_BUS_BOOTDL_CHECK_SUM = 0,
    HGIC_BUS_BOOTDL_CHECK_CRC8,
    HGIC_BUS_BOOTDL_CHECK_0XFD,
    HGIC_BUS_BOOTDL_CHECK_OFF = 0xFF
} ;

struct hgic_bus {
    int type;
    int dev_id;
    int drv_tx_headroom;
    void *bus_priv;
    unsigned long flags;
    int bootdl_pktlen;
    int bootdl_cksum;
    int blk_size;
    int (*probe)(void *dev, struct hgic_bus *bus);
    int (*tx_packet)(void *bus, struct sk_buff *skb);
    void (*tx_complete)(void *hg, struct sk_buff *skb, int success);
    int (*rx_packet)(void *hg, u8 *data, int len);
    int (*reinit)(void *bus);
    void (*probe_post)(void *priv);
    void (*remove)(void *priv);
    int (*suspend)(void *priv);
    int (*resume)(void *priv);
};

#ifdef __RTOS__
#define ALLOC_ORDERED_WORKQUEUE alloc_ordered_workqueue
#define ALLOC_NETDEV_MQS alloc_netdev_mqs
#define netif_queue_stopped(n) (0)
#define netif_start_queue(n)
#define netif_stop_queue(n)
#else
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,36)
#define ALLOC_ORDERED_WORKQUEUE alloc_ordered_workqueue
#else
#define ALLOC_ORDERED_WORKQUEUE(n,f) create_singlethread_workqueue(n)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
#define ALLOC_NETDEV_MQS(size,name,setup,txqs,rxqs) alloc_netdev_mqs(size,name,0,setup,txqs,rxqs)
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,36)
#define ALLOC_NETDEV_MQS(size,name,setup,txqs,rxqs) alloc_netdev_mq(size,name,setup,txqs)
#else
#define ALLOC_NETDEV_MQS(size,name,setup,txqs,rxqs) alloc_netdev_mqs(size,name,setup,txqs,rxqs)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,42)
#define _KERNEL_READ(fp, buff, size) ({ \
            ssize_t __ret__ = 0; \
            unsigned long long offset = 0;\
            __ret__ = kernel_read(fp, buff, size, &offset); \
            __ret__;\
        })
#else
#define _KERNEL_READ(fp, buff, size) kernel_read(fp, 0, buff, size)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
#define setup_timer(a, b, c) timer_setup(a, b, 0)
#define init_timer(...)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
#define ACCESS_OK(type, addr, size) access_ok(addr, size)
#define DEV_OPEN(x)  do { rtnl_lock(); dev_open(x, NULL); rtnl_unlock(); } while(0)
#define DEV_CLOSE(x) do { rtnl_lock(); dev_close(x); rtnl_unlock(); } while(0)
#else
#define ACCESS_OK(type, addr, size) access_ok(type, addr, size)
#define DEV_OPEN(x)  do { rtnl_lock(); dev_open(x); rtnl_unlock(); } while(0)
#define DEV_CLOSE(x) do { rtnl_lock(); dev_close(x); rtnl_unlock(); } while(0)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0) && defined CONFIG_HGIC_2G
#define IEEE80211_NUM_BANDS NUM_NL80211_BANDS
#define IEEE80211_BAND_2GHZ NL80211_BAND_2GHZ
#define IEEE80211_BAND_5GHZ NL80211_BAND_5GHZ
#endif

#ifndef IEEE80211_NUM_ACS
#define IEEE80211_NUM_ACS 4
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0) && defined CONFIG_HGIC_2G
#define vht_nss nss
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0) && defined CONFIG_HGIC_2G
#define IEEE80211_CHAN_NO_IBSS IEEE80211_CHAN_NO_IR
#define IEEE80211_CHAN_PASSIVE_SCAN IEEE80211_CHAN_NO_IR
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,5,0)
#define proc_ops file_operations
#define proc_open open
#define proc_read read
#define proc_lseek llseek
#define proc_write write
#define proc_release release
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
#define ieee80211_free_txskb(hw, skb) dev_kfree_skb_any(skb)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
#define RX_FLAG_MACTIME_START RX_FLAG_MACTIME_MPDU
#define IEEE80211_ITERATE_ACTIVE_INTERFACES_ATOMIC(hw, flags, iterator, vif) ieee80211_iterate_active_interfaces_atomic(hw, iterator, vif)
#else
#define IEEE80211_ITERATE_ACTIVE_INTERFACES_ATOMIC(hw, flags, iterator, vif) ieee80211_iterate_active_interfaces_atomic(hw, flags, iterator, vif)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static inline void *__PDE_DATA(const struct inode *inode)
{
    return PDE(inode)->data;
}
static inline void *PDE_DATA(const struct inode *inode)
{
    return __PDE_DATA(inode);
}
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
#define tasklet_hrtimer hrtimer
#define tasklet_hrtimer_cancel hrtimer_cancel
#define tasklet_hrtimer_start hrtimer_start
#endif

typedef int (*hgic_probe)(void *dev, struct hgic_bus *bus);
extern int  hgic_sdio_init(hgic_probe probe, u32 max_pkt);
extern void hgic_sdio_exit(void);
extern int  hgic_usb_init(hgic_probe probe, u32 max_pkt);
extern void hgic_usb_exit(void);
#endif
