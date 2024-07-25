
#ifndef _HGIC_FMAC_H_
#define _HGIC_FMAC_H_

#ifndef __RTOS__
#include <linux/version.h>
#endif
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/netdevice.h>
#include "../hgic_def.h"
#include "../utils/utils.h"
#include "../utils/fwdl.h"
#include "../utils/fwctrl.h"
#include "../utils/iwpriv.h"
#include "../utils/ota.h"
#include "procfs.h"

#define FWEVNTQ_SIZE (128)
enum hgicf_dev_flags {
    HGICF_DEV_FLAGS_INITED,
    HGICF_DEV_FLAGS_RUNNING,
    HGICF_DEV_FLAGS_SUSPEND,
    HGICF_DEV_FLAGS_BOOTDL,
};

enum hgicf_state {
    HGICF_STATE_NONE = 0,
    HGICF_STATE_START,
    HGICF_STATE_FW_LD,
    HGICF_STATE_STOP,
    HGICF_STATE_PAUSE,
    HGICF_STATE_QUEUE_STOPPED,
};

struct hgicf_wdev;

struct hgicf_vif {
    u8 fwifidx;
    u32 opened;
    struct net_device *ndev;
    struct hgicf_wdev *hg;
	struct net_device_stats stats;    
};

struct hgicf_status {
    u32 tx_bitrate;
    s8  signal;
    s8  evm;
    s8  pair_state;
    u8  conntect_fail;
    u32 detect_tmr;
    u32 tx_ctrl;
    u32 tx_data;
    u32 tx_fail;
};

struct hgicf_wdev {
    void             *dev;
    u32               dev_id;
    unsigned long     flags;
    u16               data_cookie;
    u16               ctrl_cookie;
    u16               rx_cookie;
    u8                fw_state;
    spinlock_t        lock;
    char *conf_file;
    struct hgic_fw_info fwinfo;
    struct hgic_bus  *bus;
    struct hgicf_vif *vif;
    struct sk_buff_head tx_dataq;
    struct work_struct  tx_work;
    struct work_struct  delay_init;   /*delay init work*/
    struct work_struct  detect_work;
    struct workqueue_struct *tx_wq;
    struct hgic_fwctrl    ctrl;
    struct hgic_bootdl  bootdl;
    struct hgicf_procfs proc;
    struct hgicf_status status;
    struct timer_list   detect_tmr;
    unsigned long last_rx;
    /*if test*/
    struct work_struct test_work;
    u32 test_rx_len, test_tx_len;
    u32 test_jiff, if_test;
    /*soft fc*/
    int soft_fc;
    int proc_dev;
    atomic_t txwnd;
    struct completion txwnd_cp;
    struct hgic_ota ota;
    u8  radio_off;

#ifndef __RTOS__
    struct sk_buff_head evt_list;
    struct semaphore    evt_sema;
#endif
};

struct hgicf_hw_status {
    uint32_t rssi;
    uint32_t per;
} __packed;

extern void hgic_print_hex(char *buf, int len);

#endif
