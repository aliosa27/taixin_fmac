#ifndef _HGIC_UTILS_H_
#define _HGIC_UTILS_H_

#define AC_NUM                4
#define MAX_CHANS_NUM         16

struct hgic_fwstat_chaninfo {
    u32   freq;
    u8    pri_chan;
    s8    bgrssi_min;
    s8    bgrssi_max;
    s8    bgrssi_avg;
    s32   bgrssi_acc;
    s32   cnt;
    s32   rxsync_cnt;
    s32   noise_factor;
};

struct hgic_fwstat_testmode {
    u32 test_tx_start : 1, bss_freq : 24;
    s32 freq_dev;
    s32 chip_temp;
    s32 tx_frms;
    s32 tx_fail;
    s32 tx_mcs;
    s32 tx_sig_bw;
    s32 rx_pkts;
    s32 rx_firm;
    s32 rx_err;
    s32 rx_rssi;
    s32 agc;
    s32 rx_evm;
    u8 chip_vcc[8];
};

struct hgic_fwstat_qa {
    u8 dut_mac[6];
    u16 svn_version;
    s8 result_per;
    s8 cfg_per;
    s8 rssi;
    s8 tssi;
    s8 rx_evm;
    s8 tx_evm;
    s8 rx_freq_dev;
    s8 tx_freq_dev;
    s8 rx_rssi_th;
    s8 tx_tssi_th;
    s8 rx_evm_th;
    s8 tx_evm_th;
    s8 rx_freq_dev_th;
    s8 tx_freq_dev_th;
};

struct hgic_fwstat_stainfo {
    u8 addr[6];
    s32 tx_frms;
    s32 tx_frms_success;
    s32 tx_cnt;
    s32 tx_apep;
    s32 tx_cca;
    s32 tx_apep_success;
    s32 tx_apep_droped;
    s32 tx_frms_droped;
    s32 tx_symbols;
    s32 freq_offset;
    u32 rx_cnt;
    u32 rx_pkts;
    u32 rx_bytes;
    u32 rx_fcs_err;
    u32 rx_symbols;

    u8 tx_bw : 3, tx_mcs : 4;
    u8 rx_bw : 4, rx_mcs : 4;
    s8 evm_avg, evm_std, rssi, tx_snr;
    u16 aid, agc;
    u16 fade_bw_ind[4];
    u64 tx_jiffies;
};

struct hgic_fwstat {
    u8 mode;
    u8 mac_address[6];
    u16 aid;
    u32 bss_freq_idx : 8, bss_freq : 24;
    u32 pri1m_start : 16, pri2m_start : 16;
    u32 pri1m_mid : 16, pri2m_mid : 16;
    u32 sec2m_mid : 16, sec4m_mid : 16;
    u32 pri1m_ed : 16, pri2m_ed : 16;
    u32 sec2m_ed : 16, sec4m_ed : 16;
    u8  tx_power_auto_adjust_en : 1, tx_pwr_adj : 5;
    u8  chan_cnt;
    u8  rx_duty_cycle;
    u8  tx_pwr;
    s8  bg_rssi;
    s32 bgrssi_iqacc;
    s32 demod_dly_max;
    s32 sifs_dly_max;
    s32 resp_dly_max;
    s32 resp_sifs_to;
    s32 resp_ack_to;
    s32 frms_ack_to;
    s32 rx_ovf_cnt;
    s32 rx_nobuf_cnt;
    s32 rx_bus_max;
    s16 bgrssi_spur_thd;
    s16 bgrssi_spur_det;
    s16 bgrssi_spurs;
    s16 bgrssi_iqmax;
    s16 rx_dc_i;
    s16 rx_dc_q;
    u32 lo_kick_cnt : 16, chan_switch_cnt : 16;
    s32 soft_rest;
    u32 lmac_txsq_count;
    u32 lmac_txq_count;
    u32 lmac_acq_count[AC_NUM];
    u32 lmac_txagg_count[AC_NUM];
    u32 lmac_statq_count;
    s32 lmac_rx_data_queue_count;
    s32 ac_irq_cnt;
    s32 ac_dly_max;
    s32 tx_irq_rts;
    s32 bo_irq_cnt[AC_NUM];
    s32 cts_tmo_cnt;
    s32 resp_tmo_cnt;
    s32 rx_irq_cnt;
    s32 tx_cnt;
    s32 tx_cts_bw_acc;
    s32 tx_cts_cnt;
    s32 tx_cts_evm_acc;
    s32 tx_frms;
    s32 tx_sq_empty;
    s32 agg_no_data;
    s32 agg_check_fail;
    s32 tx_apep;
    s32 tx_symbols;
    s32 tx_cca;
    s32 tx_fail;
    s32 tx_drop;
    s32 rx_cnt;
    s32 rx_cts_bw_acc;
    s32 rx_cts_cnt;
    s32 rx_cts_mcs_acc;
    s32 rx_pkts;
    s32 rx_bytes;
    s32 rx_symbols;
    s32 rx_phy_err;
    s32 rx_fcs_err;
    s32 phy_err_code;
    s32 tx_irq_bkn;

    u8 lmac_doze : 1, cca_obsv_dur : 3;

    s32 sta_tx_syms;
    s32 sta_rx_syms;
    u32 est_tx_bitrate;
    u32 sta_num;
    u8 fixed_tx_mcs;
    int skb_free_count;

    struct hgic_fwstat_chaninfo chan_list[MAX_CHANS_NUM];
    struct hgic_fwstat_testmode test_mode;
    struct hgic_fwstat_qa qa_stat;
    struct hgic_fwstat_stainfo sta_info[0];
};

char *hgic_fwstat_print(u8 *stat_buf);
int hgic_skip_padding(u8 *data);
int hgic_aligned_padding(struct sk_buff *skb);
void hgic_print_hex(char *buf, int len);
int hgic_config_read_u32_array(char *conf, char *field, u32 *arr, int count);
int hgic_config_read_u16_array(char *conf, char *field, u16 *arr, int count);
int hgic_config_read_str(char *conf, char *field, char *str, int size);
int hgic_config_read_int(char *conf, char *field);
void hgic_clear_queue(struct sk_buff_head *q);
int hgic_hex2num(char c);
void hgic_strip_tail(char *str, u32 len);

int hgic_hex2byte(const char *hex);
int hgic_pick_macaddr(char *mac_str, u8 *addr);

#endif
