
#ifndef _HGIC_FWCTRL_H_
#define _HGIC_FWCTRL_H_

struct hgic_fw_info;

#include <linux/completion.h>
#include <linux/workqueue.h>

//command response
struct hgic_cmd_response {
    struct list_head list;
    unsigned short cookie;
    struct completion cmpl;
    struct sk_buff   *skb;
};

struct hgic_fwctrl {
    struct device      *dev;
    u16                 cookie;
    spinlock_t          lock;    /*ctrl packet pending lock*/
    struct list_head    pd_list; /*ctrl packet pending queue (for sync cmd)*/
    struct sk_buff_head rxq;   /*fw ctrl packet rx queue*/
    struct sk_buff_head txq;   /*fw ctrl packet tx queue*/
    struct work_struct  work;  /*fw ctrl rx packet process work*/
    struct workqueue_struct *wq;
    u8                  qc_mode;
    u8                  radio_onoff;
    struct hgic_fw_info *fwinfo;
    struct hgic_bus *bus;
    void (*schedule)(struct hgic_fwctrl *ctrl);
    void (*rx_event)(struct hgic_fwctrl *ctrl, struct sk_buff *skb);
};

/*
int hgic_fwctrl_set_byte(struct hgic_fwctrl *ctrl, int cmd_id, u8 val);
int hgic_fwctrl_set_int_val(struct hgic_fwctrl *ctrl, int cmd_id, int val);
int hgic_fwctrl_get_int_val(struct hgic_fwctrl *ctrl, int cmd_id);
int hgic_fwctrl_get_bytes(struct hgic_fwctrl *ctrl, int cmd_id, char *buff, int len);
int hgic_fwctrl_do_cmd(struct hgic_fwctrl *ctrl, int cmd_id, char *data, int len, char *buff, int size);
int hgic_fwctrl_rx_proc(struct hgic_fwctrl *ctrl, struct sk_buff *skb);
struct sk_buff *hgic_fwctrl_send_data(struct hgic_fwctrl *ctrl, struct sk_buff *skb, struct hgic_cmd_response *resp, u32 timeout);
void hgic_fwctrl_clear_pdlist(struct hgic_fwctrl *ctrl);
int hgic_fwctrl_set_bytes(struct hgic_fwctrl *ctrl, int cmd_id, char *data, int len);
*/
u16 hgic_ctrl_cookie(struct hgic_fwctrl *ctrl);
struct sk_buff *hgic_fwctrl_send_data(struct hgic_fwctrl *ctrl, struct sk_buff *skb, struct hgic_cmd_response *resp, u32 timeout);
int hgic_fwctrl_do_cmd(struct hgic_fwctrl *ctrl, u8 ifidx, u32 cmd_id, u8 *in, u32 in_len, u8 *out, u32 out_size);
int hgic_fwctrl_set_byte(struct hgic_fwctrl *ctrl, u8 ifidx, u32 cmd_id, u8 val);
int hgic_fwctrl_set_int_val(struct hgic_fwctrl *ctrl, u8 ifidx, u32 cmd_id, u32 val);
int hgic_fwctrl_get_int_val(struct hgic_fwctrl *ctrl, u8 ifidx, u32 cmd_id);
short hgic_fwctrl_get_short_val(struct hgic_fwctrl *ctrl, u8 ifidx, u32 cmd_id);
int hgic_fwctrl_set_bytes(struct hgic_fwctrl *ctrl, u8 ifidx, u32 cmd_id, u8 *data, u32 len);
int hgic_fwctrl_get_bytes(struct hgic_fwctrl *ctrl, u8 ifidx, u32 cmd_id, u8 *buff, u32 len);

void hgic_fwctrl_init(struct hgic_fwctrl *ctrl, void *dev, struct hgic_bus *bus);
void hgic_fwctrl_release(struct hgic_fwctrl *ctrl);
void hgic_fwctrl_rx(struct hgic_fwctrl *ctrl, u8 *data, int len);
void hgic_fwctrl_flush_param(struct hgic_fwctrl *ctrl);
int hgic_fwctrl_testmode_cmd(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *cmd, u32 size);
int hgic_fwctrl_get_status(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *buff, u32 len);
int hgic_fwctrl_get_conn_state(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_get_fwinfo(struct hgic_fwctrl *ctrl, u8 ifidx, struct hgic_fw_info *info);
int hgic_fwctrl_set_countryregion(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *country_code);
int hgic_fwctrl_set_ssid(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *ssid);
int hgic_fwctrl_set_bssid(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *bssid);
int hgic_fwctrl_set_channel(struct hgic_fwctrl *ctrl, u8 ifidx, u32 channel);
int hgic_fwctrl_set_bssid_filter(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *filter);
int hgic_fwctrl_set_rts_threshold(struct hgic_fwctrl *ctrl, u8 ifidx, u32 rts_threshold);
int hgic_fwctrl_set_frag_threshold(struct hgic_fwctrl *ctrl, u8 ifidx, u32 frag_threshold);
int hgic_fwctrl_set_key_mgmt(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *key_mgmt);
int hgic_fwctrl_set_wpa_psk(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *psk);
int hgic_fwctrl_set_wbnat(struct hgic_fwctrl *ctrl, u8 ifidx, u32 enable);
int hgic_fwctrl_set_freq_range(struct hgic_fwctrl *ctrl, u8 ifidx, u32 freq_start, u32 freq_end, u32 bss_bw);
int hgic_fwctrl_set_bss_bw(struct hgic_fwctrl *ctrl, u8 ifidx, u8 bss_bw);
int hgic_fwctrl_set_tx_bw(struct hgic_fwctrl *ctrl, u8 ifidx, u8 tx_bw);
int hgic_fwctrl_set_tx_mcs(struct hgic_fwctrl *ctrl, u8 ifidx, u8 tx_mcs);
int hgic_fwctrl_set_acs(struct hgic_fwctrl *ctrl, u8 ifidx, u8 acs, u8 acs_tm);
int hgic_fwctrl_set_bgrssi(struct hgic_fwctrl *ctrl, u8 ifidx, u8 bgrssi);
int hgic_fwctrl_set_chan_list(struct hgic_fwctrl *ctrl, u8 ifidx, u16 *chan_list, u32 cnt);
int hgic_fwctrl_set_mode(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *mode);
int hgic_fwctrl_set_paired_stas(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *stas, u32 len);
int hgic_fwctrl_set_pairing(struct hgic_fwctrl *ctrl, u8 ifidx, u32 start);
int hgic_fwctrl_open_dev(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_close_dev(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_set_txpower(struct hgic_fwctrl *ctrl, u8 ifidx, u32 tx_power);
int hgic_fwctrl_get_txpower(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_set_listen_interval(struct hgic_fwctrl *ctrl, u8 ifidx, u32 listen_interval);
int hgic_fwctrl_set_center_freq(struct hgic_fwctrl *ctrl, u8 ifidx, u32 channel);
int hgic_fwctrl_set_tx_count(struct hgic_fwctrl *ctrl, u8 ifidx, u32 short_frm_tx_count, u32 long_frm_tx_count);
int hgic_fwctrl_set_key(struct hgic_fwctrl *ctrl, u8 ifidx, u8 cmd, u8 *addr, u8 *key, u8 len);
int hgic_fwctrl_add_sta(struct hgic_fwctrl *ctrl, u8 ifidx, u16 aid, u8 *addr);
int hgic_fwctrl_del_sta(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *addr);
int hgic_fwctrl_set_primary_chan(struct hgic_fwctrl *ctrl, u8 ifidx, u8 primary_chan);
int hgic_fwctrl_set_aid(struct hgic_fwctrl *ctrl, u8 ifidx, u32 aid);
int hgic_fwctrl_set_mac(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *mac_addr);
int hgic_fwctrl_get_scan_list(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *buff, u32 size);
int hgic_fwctrl_scan(struct hgic_fwctrl *ctrl, u8 ifidx, u8 scan_cmd);
int hgic_fwctrl_set_txq_param(struct hgic_fwctrl *ctrl, u8 ifidx, u8 ac, struct hgic_txq_param *param);
int hgic_fwctrl_set_user_edca(struct hgic_fwctrl *ctrl, u8 ifidx, u8 ac, struct hgic_txq_param *param);
int hgic_fwctrl_get_temperature(struct hgic_fwctrl *ctrl);
int hgic_fwctrl_enter_sleep(struct hgic_fwctrl *ctrl, u8 ifidx, u16 sleep, u32 sleep_ms);
int hgic_fwctrl_get_sta_list(struct hgic_fwctrl *ctrl, u8 ifidx, struct hgic_sta_info *sta_list, u32 size);
int hgic_fwctrl_set_beacon_int(struct hgic_fwctrl *ctrl, u8 ifidx, u32 beacon_int);
int hgic_fwctrl_get_ssid(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *ssid, u32 size);
int hgic_fwctrl_get_mode(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *mode, u32 size);
int hgic_fwctrl_get_wpapsk(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *psk, u32 size);
int hgic_fwctrl_save_cfg(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_join_group(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *addr, u8 aid);
int hgic_fwctrl_set_ethertype(struct hgic_fwctrl *ctrl, u8 ifidx, u16 type);
int hgic_fwctrl_get_sta_count(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_get_bss_bw(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_get_freq_range(struct hgic_fwctrl *ctrl, u8 ifidx, u32 *freq_start, u32 *freq_end, u32 *bss_bw);
int hgic_fwctrl_get_chan_list(struct hgic_fwctrl *ctrl, u8 ifidx, u16 *chan_list, u16 count);
int hgic_fwctrl_get_agg_cnt(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *agg, u8 size);
int hgic_fwctrl_set_agg_cnt(struct hgic_fwctrl *ctrl, u8 ifidx, u8 agg[2]);
int hgic_fwctrl_set_ps_addr(struct hgic_fwctrl *ctrl, u8 ifidx, u32 dport);
int hgic_fwctrl_wakeup_sta(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *addr);
int hgic_fwctrl_set_ps_heartbeat(struct hgic_fwctrl *ctrl, u8 ifidx, u32 ipaddr, u32 dport, u32 period, u32 hb_tmo);
int hgic_fwctrl_set_ps_heartbeat_resp(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 size);
int hgic_fwctrl_set_ps_wakeup_data(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 size);
int hgic_fwctrl_set_ps_connect(struct hgic_fwctrl *ctrl, u8 ifidx, u8 period, u8 roundup);
int hgic_fwctrl_set_ps_connect_count(struct hgic_fwctrl *ctrl, u8 ifidx, u8 try_cnt);
int hgic_fwctrl_set_ps_connect_time(struct hgic_fwctrl *ctrl, u8 ifidx, u32 time);
int hgic_fwctrl_get_ps_connect(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_get_ps_connect_count(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_get_ps_connect_time(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_radio_onoff(struct hgic_fwctrl *ctrl, u8 ifidx, u8 onoff);
int hgic_fwctrl_set_bss_max_idle(struct hgic_fwctrl *ctrl, u8 ifidx, u32 max_idle);
int hgic_fwctrl_set_wkio_mode(struct hgic_fwctrl *ctrl, u8 ifidx, u8 mode);
int hgic_fwctrl_set_ps_mode(struct hgic_fwctrl *ctrl, u8 ifidx, u8 mode);
int hgic_fwctrl_set_load_def(struct hgic_fwctrl *ctrl, u8 ifidx, u8 rst);
int hgic_fwctrl_disassoc_sta(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *addr);
int hgic_fwctrl_set_dtim_period(struct hgic_fwctrl *ctrl, u8 ifidx, u32 period);
int hgic_fwctrl_set_aplost_time(struct hgic_fwctrl *ctrl, u8 ifidx, u32 aplost_time);
int hgic_fwctrl_get_wkreason(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_unpair(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *addr);
int hgic_fwctrl_set_auto_chswitch(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable);
int hgic_fwctrl_set_mcast_key(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *mcast_key);
int hgic_fwctrl_set_reassoc_wkhost(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable);
int hgic_fwctrl_set_wakeup_io(struct hgic_fwctrl *ctrl, u8 ifidx, u8 io, u8 edge);
int hgic_fwctrl_set_dbginfo_output(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable);
int hgic_fwctrl_set_sysdbg(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *cmd);
int hgic_fwctrl_set_autosleep_time(struct hgic_fwctrl *ctrl, u8 ifidx, u8 time);
int hgic_fwctrl_get_key_mgmt(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *ssid, u32 size);
int hgic_fwctrl_get_bssid(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *bssid, u32 len);
int hgic_fwctrl_set_super_pwr(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable);
int hgic_fwctrl_set_repeater_ssid(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *ssid);
int hgic_fwctrl_set_repeater_psk(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *wpa_psk);
int hgic_fwctrl_set_auto_save(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable);
int hgic_fwctrl_set_pair_autostop(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable);
int hgic_fwctrl_send_cust_mgmt(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 len);
int hgic_fwctrl_send_mgmtframe(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 len);
int hgic_fwctrl_get_battery_level(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_set_dcdc13v(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable);
int hgic_fwctrl_set_acktmo(struct hgic_fwctrl *ctrl, u8 ifidx, u32 tmo);
int hgic_fwctrl_get_module_type(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_set_pa_pwrctl_dis(struct hgic_fwctrl *ctrl, u8 ifidx, u8 dis);
int hgic_fwctrl_set_dhcpc(struct hgic_fwctrl *ctrl, u8 ifidx, u8 en);
int hgic_fwctrl_get_dhcpc_result(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *buff, int len);
int hgic_fwctrl_set_wkdata_mask(struct hgic_fwctrl *ctrl, u8 ifidx, u16 offset, u8 *mask, u8 mask_len);
int hgic_fwctrl_get_wkdata_buff(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *buff, int len);
int hgic_fwctrl_get_disassoc_reason(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_set_wkdata_save(struct hgic_fwctrl *ctrl, u8 ifidx, u8 save);
int hgic_fwctrl_set_cust_driver_data(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 len);
int hgic_fwctrl_set_mcast_txparam(struct hgic_fwctrl *ctrl, u8 ifidx, struct hgic_mcast_txparam *param);
int hgic_fwctrl_set_freqinfo(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 len);
int hgic_fwctrl_reset_sta(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *addr);
int hgic_fwctrl_set_ant_auto(struct hgic_fwctrl *ctrl, u8 ifidx, u8 en);
int hgic_fwctrl_select_ant(struct hgic_fwctrl *ctrl, u8 ifidx, u8 ant);
int hgic_fwctrl_get_ant_sel(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_set_wkhost_reasons(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *reasons, u8 len);
int hgic_fwctrl_set_mac_filter(struct hgic_fwctrl *ctrl, u8 ifidx, u8 en);
int hgic_fwctrl_set_atcmd(struct hgic_fwctrl *ctrl, u8 ifidx, char *atcmd);
int hgic_fwctrl_set_roaming(struct hgic_fwctrl *ctrl, u8 ifidx, s8 *vals, u8 count);
int hgic_fwctrl_set_ap_hide(struct hgic_fwctrl *ctrl, u8 ifidx, u8 hide);
int hgic_fwctrl_set_frm_tx_maxcnt(struct hgic_fwctrl *ctrl, u8 ifidx, u8 txcnt);
int hgic_fwctrl_set_assert_holdup(struct hgic_fwctrl *ctrl, u8 ifidx, u8 holdup);
int hgic_fwctrl_set_ap_psmode_en(struct hgic_fwctrl *ctrl, u8 ifidx, u8 en);
int hgic_fwctrl_set_dupfilter_en(struct hgic_fwctrl *ctrl, u8 ifidx, u8 en);
int hgic_fwctrl_set_1v1_m2u_dis(struct hgic_fwctrl *ctrl, u8 ifidx, u8 dis);
int hgic_fwctrl_set_psconnect_dis(struct hgic_fwctrl *ctrl, u8 ifidx, u8 dis);
int hgic_fwctrl_set_blenc_en(struct hgic_fwctrl *ctrl, u8 ifidx, u8 data[3]);
int hgic_fwctrl_blenc_send_data(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 len);
int hgic_fwctrl_reset(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_set_hwscan(struct hgic_fwctrl *ctrl, u8 ifidx, u16 period, u16 interval, u16 chan, u16 max);
int hgic_fwctrl_get_txq_param(struct hgic_fwctrl *ctrl, u8 ifidx, struct hgic_txq_param param[4]);
int hgic_fwctrl_set_promisc(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable);
int hgic_fwctrl_set_fix_txrate(struct hgic_fwctrl *ctrl, u8 ifidx, u32 txrate);
int hgic_fwctrl_set_nav_max(struct hgic_fwctrl *ctrl, u8 ifidx, u32 nav_max);
int hgic_fwctrl_clear_nav(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_set_cca_param(struct hgic_fwctrl *ctrl, u8 ifidx, struct hgic_cca_ctl *cca);
int hgic_fwctrl_set_tx_modulation_gain(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *gain_table, u32 size);
int hgic_fwctrl_get_nav(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_send_hci_data(struct hgic_fwctrl *ctrl, u8 type, u8 *data, u32 len);
int hgic_fwctrl_set_beacon_start(struct hgic_fwctrl *ctrl, u8 ifidx, u8 start);
int hgic_fwctrl_ble_open(struct hgic_fwctrl *ctrl, u8 ifidx, u8 open);
int hgic_fwctrl_get_bgrssi(struct hgic_fwctrl *ctrl, u8 ifidx, u8 channel, s8 resp[3]);
int hgic_fwctrl_blenc_set_advdata(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 len);
int hgic_fwctrl_blenc_set_scanresp(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *data, u32 len);
int hgic_fwctrl_blenc_set_devaddr(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *addr);
int hgic_fwctrl_blenc_set_advinterval(struct hgic_fwctrl *ctrl, u8 ifidx, u32 interval);
int hgic_fwctrl_blenc_start_adv(struct hgic_fwctrl *ctrl, u8 ifidx, u32 en);
int hgic_fwctrl_set_rts_duration(struct hgic_fwctrl *ctrl, u8 ifidx, int duration);
int hgic_fwctrl_set_disable_print(struct hgic_fwctrl *ctrl, u8 ifidx, int dis);
int hgic_fwctrl_set_conn_paironly(struct hgic_fwctrl *ctrl, u8 ifidx, int en);
int hgic_fwctrl_get_center_freq(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_set_wait_psmode(struct hgic_fwctrl *ctrl, u8 ifidx, u8 wait_psmode);
int hgic_fwctrl_set_diffcust_conn(struct hgic_fwctrl *ctrl, u8 ifidx, u8 en);
int hgic_fwctrl_set_ap_chan_switch(struct hgic_fwctrl *ctrl, u8 ifidx, u8 chan, u8 counter);
int hgic_fwctrl_set_cca_for_ce(struct hgic_fwctrl *ctrl, u8 ifidx, u8 en);
int hgic_fwctrl_set_standby(struct hgic_fwctrl *ctrl, u8 ifidx, u8 channel, u32 sleep_period);
int hgic_fwctrl_set_rtc(struct hgic_fwctrl *ctrl, u8 ifidx, u32 rtc);
int hgic_fwctrl_get_rtc(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *rtc);
int hgic_fwctrl_set_apep_padding(struct hgic_fwctrl *ctrl, u8 ifidx, int en);
int hgic_fwctrl_get_reason_code(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_get_status_code(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_get_acs_result(struct hgic_fwctrl *ctrl, u8 ifidx, struct hgic_acs_result *result, u8 size);
int hgic_fwctrl_set_watchdog(struct hgic_fwctrl *ctrl, u8 ifidx, u8 enable);
int hgic_fwctrl_set_retry_fallback_cnt(struct hgic_fwctrl *ctrl, u8 ifidx, u8 cnt);
int hgic_fwctrl_set_fallback_mcs(struct hgic_fwctrl *ctrl, u8 ifidx, struct hgic_fallback_mcs *mcs);
int hgic_fwctrl_get_xosc(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_set_xosc(struct hgic_fwctrl *ctrl, u8 ifidx, int xosc);
int hgic_fwctrl_get_freq_offset(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *addr);
int hgic_fwctrl_set_freq_cali_period(struct hgic_fwctrl *ctrl, u8 ifidx, u16 cali_period);
int hgic_fwctrl_set_blenc_adv_filter(struct hgic_fwctrl *ctrl, u8 ifidx, u32 filter);
int hgic_fwctrl_set_max_tx_delay(struct hgic_fwctrl *ctrl, u8 ifidx, u32 tmo);
int hgic_fwctrl_get_sta_info(struct hgic_fwctrl *ctrl, u8 ifidx, u8 *mac, struct hgic_sta_info *info);
int hgic_fwctrl_get_signal(struct hgic_fwctrl *ctrl, u8 ifidx);
int hgic_fwctrl_set_heartbeat_int(struct hgic_fwctrl *ctrl, u8 ifidx, u32 val);

#endif

