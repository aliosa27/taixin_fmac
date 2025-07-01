#include <linux/version.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>

#include "../hgic_def.h"
#include "utils.h"
#include "fwctrl.h"

struct fwctrl_cfgset {
    char *name;
    int (*set)(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count);
};
struct fwctrl_cfgget {
    char *name;
    int (*get)(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin);
};

static int hgic_copyfrom_iwreq(struct iwreq *wrqin, char *buf, int len)
{
    int ret = 0;
    if (len > 0) {
        memset(buf, 0, len);
        len = (len <= wrqin->u.data.length ? len : wrqin->u.data.length);
        if (ACCESS_OK(VERIFY_READ, wrqin->u.data.pointer, wrqin->u.data.length)) {
            ret = copy_from_user(buf, wrqin->u.data.pointer, len);
        } else {
            memcpy(buf, wrqin->u.data.pointer, len);
        }
    }
    return ret;
}

static void hgic_copyto_iwreq(struct iwreq *wrqin, char *buf, int len)
{
    len = (len <= wrqin->u.data.length ? len : wrqin->u.data.length);
    if (ACCESS_OK(VERIFY_WRITE, wrqin->u.data.pointer, len)) {
        if (len > 0 && !__copy_to_user(wrqin->u.data.pointer, buf, len)) {
            wrqin->u.data.length = (u16)len;
        } else {
            wrqin->u.data.length = 0;
        }
    } else {
        if (len > 0) {
            memcpy(wrqin->u.data.pointer, buf, len);
            wrqin->u.data.length = (u16)len;
        } else {
            wrqin->u.data.length = 0;
        }
    }
}

static int hgic_iwpriv_set_countryregion(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    if (data == NULL || strlen(data) != 2) {
        return -EINVAL;
    }
    return hgic_fwctrl_set_countryregion(ctrl, ifidx, data);
}

static int hgic_iwpriv_set_ssid(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_set_ssid(ctrl, ifidx, data);
}

static int hgic_iwpriv_set_bssid(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8  bssid[6];
    if (data == NULL || ifidx != HGIC_WDEV_ID_STA) {
        return -EINVAL;
    }
    hgic_pick_macaddr(data, bssid);
    return hgic_fwctrl_set_bssid(ctrl, ifidx, bssid);
}

static int hgic_iwpriv_set_channel(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    if (data == NULL) {
        return -EINVAL;
    }
    return hgic_fwctrl_set_channel(ctrl, ifidx, simple_strtol(data, 0, 10));
}

static int hgic_iwpriv_set_bssid_filter(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_set_bssid_filter(ctrl, ifidx, data);
}

static int hgic_iwpriv_set_rts_threshold(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    if (data == NULL) {
        return -EINVAL;
    }
    return hgic_fwctrl_set_rts_threshold(ctrl, ifidx, simple_strtol(data, 0, 10));
}

static int hgic_iwpriv_set_frag_threshold(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    if (data == NULL) {
        return -EINVAL;
    }
    return hgic_fwctrl_set_frag_threshold(ctrl, ifidx, simple_strtol(data, 0, 10));
}

static int hgic_iwpriv_set_key_mgmt(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_set_key_mgmt(ctrl, ifidx, data);
}

static int hgic_iwpriv_set_wpa_psk(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_set_wpa_psk(ctrl, ifidx, data);
}

static int hgic_iwpriv_set_freq_range(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 vals[3] = {0, 0, 0};
    u32 argcnt = 0;

    if (data == NULL || strlen(data) == 0) {
        return -EINVAL;
    }
    hgic_pick_values(u32, data, vals, 3);
    return hgic_fwctrl_set_freq_range(ctrl, ifidx, vals[0], vals[1], vals[2]);
}

static int hgic_iwpriv_set_bss_bw(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8 bss_bw = (u8)simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_bss_bw(ctrl, ifidx, bss_bw);
}

static int hgic_iwpriv_set_tx_bw(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8 tx_bw = (u8)simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_tx_bw(ctrl, ifidx, tx_bw);
}

static int hgic_iwpriv_set_tx_mcs(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8 tx_mcs = (u8)simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_tx_mcs(ctrl, ifidx, tx_mcs);
}

static int hgic_iwpriv_set_acs(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u16 vals[2] = {0, 0};
    u32 argcnt = 0;

    if (data == NULL || strlen(data) == 0) {
        return -EINVAL;
    }
    hgic_pick_values(u16, data, vals, 2);
    return hgic_fwctrl_set_acs(ctrl, ifidx, vals[0], vals[1]);
}

static int hgic_iwpriv_set_bgrssi(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8 rssi = (u8)simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_bgrssi(ctrl, ifidx, rssi);
}

static int hgic_iwpriv_set_chan_list(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u16 vals[32] = {0};
    u32 argcnt = 0;

    if (data == NULL || strlen(data) == 0) {
        return -EINVAL;
    }
    hgic_pick_values(u16, data, vals, 32);
    return hgic_fwctrl_set_chan_list(ctrl, ifidx, vals, argcnt);
}

static int hgic_iwpriv_set_mode(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    if (data == NULL) {
        return -EINVAL;
    }
    return hgic_fwctrl_set_mode(ctrl, ifidx, data);
}

static int hgic_iwpriv_set_paired_stas(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8 *mac = NULL;
    int len = 0;
    int ret = 0, i = 0;
    char *ptr = data;
    char *p   = data;

    if (data == NULL || strlen(data) == 0) {
        return -EINVAL;
    }

    len = strlen(data);
    mac = kzalloc(len, GFP_KERNEL);
    if (mac == NULL) {
        return -ENOMEM;
    }

    hgic_dbg("set paired stas: %s\r\n", data);
    while (p && *ptr) {
        p = strchr(ptr, ',');
        if(p) *p++ = 0;
        if (hgic_pick_macaddr(ptr, mac + i * 6)) {
            i++;
        } else {
            break;
        }
        ptr = p;
    }
    hgic_dbg("%d paired stas\r\n", i);

    ret = hgic_fwctrl_set_paired_stas(ctrl, ifidx, mac, i * 6);
    kfree(mac);
    return ret;
}

static int hgic_iwpriv_set_pairing(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 number = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    number = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_pairing(ctrl, ifidx, number);
}

static int hgic_iwpriv_set_beacon_int(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 beacon_int = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_beacon_int(ctrl, ifidx, beacon_int);
}

static int hgic_iwpriv_set_radio_onoff(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    ctrl->radio_onoff = (u8)simple_strtol(data, 0, 10);
    return hgic_fwctrl_radio_onoff(ctrl, ifidx, ctrl->radio_onoff);
}

static int hgic_iwpriv_join_group(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8  addr[6];
    u32 aid = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    hgic_pick_macaddr(data, addr);
    aid = simple_strtol(data + 18, 0, 10);
    return  hgic_fwctrl_join_group(ctrl, ifidx, addr, aid);
}

static int hgic_iwpriv_set_ethertype(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u16 type = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    type = simple_strtol(data, 0, 16);
    return  hgic_fwctrl_set_ethertype(ctrl, ifidx, type);
}

static int hgic_iwpriv_set_txpower(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u16 type = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    type = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_txpower(ctrl, ifidx, type);
}

static int hgic_iwpriv_set_aggcnt(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8 agg[2]; //tx agg, rx agg
    u32 argcnt = 0;

    if (data == NULL) {
        return -EINVAL;
    }

    hgic_pick_values(u8, data, agg, 2);
    return hgic_fwctrl_set_agg_cnt(ctrl, ifidx, agg);
}
static int hgic_iwpriv_set_ps_connect(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8 vals[2];
    u32 argcnt = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    hgic_pick_values(u8, data, vals, 2);
    return  hgic_fwctrl_set_ps_connect(ctrl, ifidx, vals[0], vals[1]);
}

static int hgic_iwpriv_set_bss_max_idle(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 max_idle = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    max_idle = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_bss_max_idle(ctrl, ifidx, max_idle);
}

static int hgic_iwpriv_set_dtim_period(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 period = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    period = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_dtim_period(ctrl, ifidx, period);
}

static int hgic_iwpriv_set_wkio_mode(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 mode = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    mode = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_wkio_mode(ctrl, ifidx, mode);
}

static int hgic_iwpriv_set_load_def(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 rst = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    rst = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_load_def(ctrl, ifidx, rst);
}

static int hgic_iwpriv_set_disassoc_sta(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8  addr[6];

    if (data == NULL) {
        return -EINVAL;
    }
    hgic_pick_macaddr(data, addr);
    return  hgic_fwctrl_disassoc_sta(ctrl, ifidx, addr);
}

static int hgic_iwpriv_set_ps_mode(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 mode = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    mode = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_ps_mode(ctrl, ifidx, mode);
}

static int hgic_iwpriv_set_aplost_time(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 time = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    time = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_aplost_time(ctrl, ifidx, time);
}

static int hgic_iwpriv_set_unpair(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8  addr[6];
    hgic_pick_macaddr(data, addr);
    return  hgic_fwctrl_unpair(ctrl, ifidx, addr);
}

static int hgic_iwpriv_set_auto_chswitch(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 enable = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    enable = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_auto_chswitch(ctrl, ifidx, enable == 1);
}

static int hgic_iwpriv_set_mcast_key(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    if (data == NULL) {
        return -EINVAL;
    }
    return hgic_fwctrl_set_mcast_key(ctrl, ifidx, data);
}

static int hgic_iwpriv_set_reassoc_wkhost(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 enable = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    enable = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_reassoc_wkhost(ctrl, ifidx, enable == 1);
}

static int hgic_iwpriv_set_wakeup_io(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8 vals[2] = {0, 0};
    u32 argcnt = 0;

    hgic_pick_values(u8, data, vals, 2);
    return hgic_fwctrl_set_wakeup_io(ctrl, ifidx, vals[0], vals[1]);
}

static int hgic_iwpriv_set_dbginfo_output(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 enable = 0;

    if (data) {
        enable = simple_strtol(data, 0, 10);
    }
    return  hgic_fwctrl_set_dbginfo_output(ctrl, ifidx, enable == 1);
}

static int hgic_iwpriv_set_sysdbg(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    if (data == NULL) {
        return -EINVAL;
    }
    return  hgic_fwctrl_set_sysdbg(ctrl, ifidx, data);
}

static int hgic_iwpriv_set_primary_chan(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 chan = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    chan = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_primary_chan(ctrl, ifidx, chan);
}

static int hgic_iwpriv_set_autosleep_time(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 time = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    time = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_autosleep_time(ctrl, ifidx, time);
}

static int hgic_iwpriv_set_super_pwr(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 enable = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    enable = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_super_pwr(ctrl, ifidx, enable);
}

static int hgic_iwpriv_set_repeater_ssid(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_set_repeater_ssid(ctrl, ifidx, data);
}

static int hgic_iwpriv_set_repeater_psk(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_set_repeater_psk(ctrl, ifidx, data);
}

static int hgic_iwpriv_set_auto_save(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 enable = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    enable = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_auto_save(ctrl, ifidx, enable);
}
static int hgic_iwpriv_set_pair_autostop(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 enable = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    enable = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_pair_autostop(ctrl, ifidx, enable);
}
static int hgic_iwpriv_set_dcdc13v(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 enable = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    enable = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_dcdc13v(ctrl, ifidx, enable);
}
static int hgic_iwpriv_set_acktmo(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 tmo = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    tmo = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_acktmo(ctrl, ifidx, tmo);
}
static int hgic_iwpriv_set_pa_pwrctl_dis(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 dis = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    dis = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_pa_pwrctl_dis(ctrl, ifidx, dis);
}
static int hgic_iwpriv_set_dhcpc(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 en = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    en = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_dhcpc(ctrl, ifidx, en);
}
static int hgic_iwpriv_set_wkdata_save(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 en = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    en = simple_strtol(data, 0, 10);
    return  hgic_fwctrl_set_wkdata_save(ctrl, ifidx, en);
}
static int hgic_iwpriv_set_mcast_txparam(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    struct hgic_mcast_txparam txparam;
    u8 *vals = (u8 *)&txparam;
    u32 argcnt = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    hgic_pick_values(u8, data, vals, 4);
    return hgic_fwctrl_set_mcast_txparam(ctrl, ifidx, &txparam);
}

static int hgic_iwpriv_set_resetsta(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8  addr[6];

    if (data == NULL || ifidx != HGIC_WDEV_ID_STA) {
        return -EINVAL;
    }
    hgic_pick_macaddr(data, addr);
    return hgic_fwctrl_reset_sta(ctrl, ifidx, addr);
}

static int hgic_iwpriv_set_ant_auto(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 en = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    en = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_ant_auto(ctrl, ifidx, en);
}
static int hgic_iwpriv_set_select_ant(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 ant = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    ant = simple_strtol(data, 0, 10);
    return hgic_fwctrl_select_ant(ctrl, ifidx, ant);
}
static int hgic_iwpriv_set_wkhost_reasons(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 argcnt = 0;
    u8  reasons[33];

    if (data == NULL) {
        return -EINVAL;
    }
    memset(reasons, 0, sizeof(reasons));
    hgic_pick_values(u8, data, reasons, 32);
    return hgic_fwctrl_set_wkhost_reasons(ctrl, ifidx, reasons, argcnt + 1); //keep last one is 0.
}

static int hgic_iwpriv_set_mac_filter(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 en = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    en = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_mac_filter(ctrl, ifidx, en);
}

static int hgic_iwpriv_set_atcmd(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_set_atcmd(ctrl, ifidx, data);
}

static int hgic_iwpriv_set_roaming(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    s8 vals[8];
    u32 argcnt = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    hgic_pick_values(s8, data, vals, sizeof(vals));
    return hgic_fwctrl_set_roaming(ctrl, ifidx, vals, argcnt);
}

static int hgic_iwpriv_set_ap_hide(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 hide = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    hide = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_ap_hide(ctrl, ifidx, hide);
}

static int hgic_iwpriv_set_max_txcnt(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 txcnt = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    txcnt = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_frm_tx_maxcnt(ctrl, ifidx, txcnt);
}
static int hgic_iwpriv_set_assert_holdup(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 holdup = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    holdup = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_assert_holdup(ctrl, ifidx, holdup);
}
static int hgic_iwpriv_set_ap_psmode(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 en = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    en = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_ap_psmode_en(ctrl, ifidx, en);
}
static int hgic_iwpriv_set_dupfilter_en(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 en = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    en = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_dupfilter_en(ctrl, ifidx, en);
}
static int hgic_iwpriv_set_dis_1v1m2u(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 en = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    en = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_1v1_m2u_dis(ctrl, ifidx, en);
}
static int hgic_iwpriv_set_dis_psconnect(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 en = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    en = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_psconnect_dis(ctrl, ifidx, en);
}
static int hgic_iwpriv_reset(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_reset(ctrl, ifidx);
}
static int hgic_iwpriv_set_heartbeat(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 ip[4]  = {0};
    u32 port   = 0;
    u32 ipaddr = 0;
    u32 period = 0;
    u32 hb_tmo = 300;

    sscanf(data, "%d.%d.%d.%d,%d,%d,%d", &ip[0], &ip[1], &ip[2], &ip[3], &port, &period, &hb_tmo);
    ipaddr = ((ip[0] & 0xff) << 24) | ((ip[1] & 0xff) << 16) | (((ip[2] & 0xff) << 8)) | (ip[3] & 0xff);
    return hgic_fwctrl_set_ps_heartbeat(ctrl, ifidx, ipaddr, port, period, hb_tmo);
}
static int hgic_iwpriv_set_heartbeat_resp(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_set_ps_heartbeat_resp(ctrl, ifidx, data, count);
}
static int hgic_iwpriv_set_wakeup_data(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_set_ps_wakeup_data(ctrl, ifidx, data, count);
}
static int hgic_iwpriv_wakeup_sta(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8 mac[6];
    hgic_pick_macaddr(data, mac);
    hgic_err("wakeup sta: %pM\r\n", mac);
    return hgic_fwctrl_wakeup_sta(ctrl, ifidx, mac);
}
static int hgic_iwpriv_send_custmgmt(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_send_cust_mgmt(ctrl, ifidx, data, count);
}
static int hgic_iwpriv_send_mgmtframe(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_send_mgmtframe(ctrl, ifidx, data, count);
}
static int hgic_iwpriv_set_wkdata_mask(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8 len = count > 128 ? 128 : count;
    return hgic_fwctrl_set_wkdata_mask(ctrl, ifidx, data[0], (u8 *)(data + 1), len - 1);
}
static int hgic_iwpriv_set_hbdata_mask(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8 len = count > 128 ? 128 : count;
    return hgic_fwctrl_set_hbdata_mask(ctrl, ifidx, data[0], (u8 *)(data + 2), len - 2);
}
static int hgic_iwpriv_set_driverdata(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_set_cust_driver_data(ctrl, ifidx, data, count);
}
static int hgic_iwpriv_set_freqinfo(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_set_freqinfo(ctrl, ifidx, data, count);
}
static int hgic_iwpriv_set_blenc(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    int ret = 0;
    u8  vals[2];
    char *args;
    u32 argcnt = 0;

    if (memcmp(data, "EN:", 3) == 0) {
        args = data + 3;
        hgic_pick_values(u8, args, vals, 2);
        ret = hgic_fwctrl_set_blenc_en(ctrl, ifidx, vals);
    } else if (memcmp(data, "DATA:", 5) == 0) {
        ret = hgic_fwctrl_blenc_send_data(ctrl, ifidx, data + 5, count - 5);
    } else if (memcmp(data, "DEV_ADDR:", 9) == 0) {
        ret = hgic_fwctrl_blenc_set_devaddr(ctrl, ifidx, data + 9);
    } else if (memcmp(data, "ADV_DATA:", 9) == 0) {
        ret = hgic_fwctrl_blenc_set_advdata(ctrl, ifidx, data + 9, count - 9);
    } else if (memcmp(data, "SCAN_RESP:", 10) == 0) {
        ret = hgic_fwctrl_blenc_set_scanresp(ctrl, ifidx, data + 10, count - 10);
    } else if (memcmp(data, "ADV_INT:", 8) == 0) {
        ret = hgic_fwctrl_blenc_set_advinterval(ctrl, ifidx, simple_strtol(data + 8, 0, 10));
    } else if (memcmp(data, "ADV_EN:", 7) == 0) {
        ret = hgic_fwctrl_blenc_start_adv(ctrl, ifidx, simple_strtol(data + 7, 0, 10));
    } else if (memcmp(data, "HCI_DATA:", 9) == 0) {
        ret = hgic_fwctrl_send_hci_data(ctrl, data[9], data + 10, count - 10);
    } else if (memcmp(data, "ADV_FILTER:", 11) == 0) {
        ret = hgic_fwctrl_set_blenc_adv_filter(ctrl, ifidx, simple_strtol(data + 11, 0, 10));
    } else {
        ret = -1;
    }
    return ret ? -EINVAL : 0;
}
static int hgic_iwpriv_enter_sleep(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    int err = 0;
    u32 vals[2] = {1, 0xffffffff};
    u32 argcnt = 0;

    if (data == NULL) {
        return -EINVAL;
    }
    hgic_pick_values(u32, data, vals, 2);
    if (vals[0]) {
        if (!test_bit(HGIC_BUS_FLAGS_SLEEP, &ctrl->bus->flags)) {
            if(ctrl->fwinfo->version < 0x02000000) vals[0] = 0xffff;
            hgic_dbg("enter sleep : type:%d, sleep_ms:%d ...\r\n", vals[0], vals[1]);
            err = hgic_fwctrl_enter_sleep(ctrl, ifidx, vals[0], vals[1]);
            if (err) {
                clear_bit(HGIC_BUS_FLAGS_SLEEP, &ctrl->bus->flags);
                hgic_err("sleep fail, ret=%d\r\n", err);
            }
        }
    } else {
        hgic_dbg("exit sleep, SLEEP=%d\r\n", test_bit(HGIC_BUS_FLAGS_SLEEP, &ctrl->bus->flags));
        if (test_bit(HGIC_BUS_FLAGS_SLEEP, &ctrl->bus->flags)) {
            clear_bit(HGIC_BUS_FLAGS_SLEEP, &ctrl->bus->flags);
            if (ctrl->bus->reinit) {
                ctrl->bus->reinit(ctrl->bus);
            }
            err = hgic_fwctrl_enter_sleep(ctrl, ifidx, 0, 0);
            if (err) {
                hgic_err("exit sleep fail, ret=%d\r\n", err);
            }
        }
    }
    return err ? -EINVAL : 0;
}
static int hgic_iwpriv_set_hwscan(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8 argcnt = 0;
    u16 vals[4];
    hgic_pick_values(u16, data, vals, 4);
    return hgic_fwctrl_set_hwscan(ctrl, ifidx, vals[0], vals[1], vals[2], vals[3]);
}
static int hgic_iwpriv_set_user_edca(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8  ac = data[0];
    struct hgic_txq_param txq;
    memcpy(&txq, data + 1, sizeof(txq));
    return hgic_fwctrl_set_user_edca(ctrl, ifidx, ac, &txq);
}
static int hgic_iwpriv_set_fix_txrate(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 txrate = simple_strtoul(data, 0, 10);
    return hgic_fwctrl_set_fix_txrate(ctrl, ifidx, txrate);
}
static int hgic_iwpriv_set_nav_max(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 nav = simple_strtoul(data, 0, 10);
    return hgic_fwctrl_set_nav_max(ctrl, ifidx, nav);
}
static int hgic_iwpriv_clear_nav(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_clear_nav(ctrl, ifidx);
}
static int hgic_iwpriv_set_cca_param(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_set_cca_param(ctrl, ifidx, (struct hgic_cca_ctl *)data);
}
static int hgic_iwpriv_set_tx_modulation_gain(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_set_tx_modulation_gain(ctrl, ifidx, data, count);
}
static int hgic_iwpriv_set_rts_duration(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    int duration = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_rts_duration(ctrl, ifidx, duration);
}
static int hgic_iwpriv_set_disable_print(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    int dis = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_disable_print(ctrl, ifidx, dis);
}
static int hgic_iwpriv_set_conn_paironly(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    int dis = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_conn_paironly(ctrl, ifidx, dis);
}
static int hgic_iwpriv_set_wait_psmode(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    int mode = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_wait_psmode(ctrl, ifidx, mode);
}
static int hgic_iwpriv_set_diffcust_conn(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    int en = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_diffcust_conn(ctrl, ifidx, en);
}
static int hgic_iwpriv_set_standby(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8 argcnt = 0;
    u32 vals[2];

    if (data == NULL) {
        return -EINVAL;
    }
    hgic_pick_values(u32, data, vals, 2);
    return hgic_fwctrl_set_standby(ctrl, ifidx, (u8)vals[0], vals[1]);
}
static int hgic_iwpriv_set_ap_chan_switch(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8 argcnt = 0;
    u8 vals[2];

    if (data == NULL) {
        return -EINVAL;
    }
    hgic_pick_values(u8, data, vals, 2);
    return hgic_fwctrl_set_ap_chan_switch(ctrl, ifidx, vals[0], vals[1]);
}
static int hgic_iwpriv_set_cca_for_ce(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    int en = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_cca_for_ce(ctrl, ifidx, en);
}
static int hgic_iwpriv_set_rtc(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 rtc = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_rtc(ctrl, ifidx, rtc);
}
static int hgic_iwpriv_set_apep_padding(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 en = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_apep_padding(ctrl, ifidx, en);
}
static int hgic_iwpriv_set_watchdog(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u32 en = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_watchdog(ctrl, ifidx, en);
}
static int hgic_iwpriv_set_retry_fallback_cnt(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    int cnt = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_retry_fallback_cnt(ctrl, ifidx, cnt);
}
static int hgic_iwpriv_set_fallback_mcs(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    struct hgic_fallback_mcs mcs;
    u8 argcnt = 0;
    u8 vals[4];
    hgic_pick_values(u8, data, vals, 4);
    mcs.original_type = vals[0];
    mcs.original_mcs  = vals[1];
    mcs.fallback_type = vals[2];
    mcs.fallback_mcs  = vals[3];
    return hgic_fwctrl_set_fallback_mcs(ctrl, ifidx, &mcs);
}
static int hgic_iwpriv_set_xosc(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    int val = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_xosc(ctrl, ifidx, val);
}
static int hgic_iwpriv_set_freq_cali_period(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    int val = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_freq_cali_period(ctrl, ifidx, val);
}
static int hgic_iwpriv_set_customer_dvrdata(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    return hgic_fwctrl_set_bytes(ctrl, ifidx, get_unaligned_le16(data), data + 2, count - 2);
}
static int hgic_iwpriv_set_max_tx_delay(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    int val = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_max_tx_delay(ctrl, ifidx, val);
}
static int hgic_iwpriv_set_heartbeat_int(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    int val = simple_strtol(data, 0, 10);
    return hgic_fwctrl_set_heartbeat_int(ctrl, ifidx, val);
}
static int hgic_iwpriv_set_sleep_roaming(struct hgic_fwctrl *ctrl, u8 ifidx, char *data, u32 count)
{
    u8 argcnt = 0;
    s8 vals[2];
    hgic_pick_values(s8, data, vals, 2);
    hgic_err("set sleep roaming: en=%d, rssi=%d\r\n", vals[0], vals[1]);
    return hgic_fwctrl_set_sleep_roaming(ctrl, ifidx, vals[0], vals[1]);
}

static struct fwctrl_cfgset hgpriv_sets[] = {
    {"country_region",              hgic_iwpriv_set_countryregion},
    {"ssid",                        hgic_iwpriv_set_ssid},
    {"bssid",                       hgic_iwpriv_set_bssid},
    {"channel",                     hgic_iwpriv_set_channel},
    {"rts_threshold",               hgic_iwpriv_set_rts_threshold},
    {"frag_threshold",              hgic_iwpriv_set_frag_threshold},
    {"key_mgmt",                    hgic_iwpriv_set_key_mgmt},
    {"wpa_psk",                     hgic_iwpriv_set_wpa_psk},
    {"bssid_filter",                hgic_iwpriv_set_bssid_filter},
    {"freq_range",                  hgic_iwpriv_set_freq_range},
    {"bss_bw",                      hgic_iwpriv_set_bss_bw},
    {"tx_bw",                       hgic_iwpriv_set_tx_bw},
    {"tx_mcs",                      hgic_iwpriv_set_tx_mcs},
    {"acs",                         hgic_iwpriv_set_acs},
    {"bgrssi",                      hgic_iwpriv_set_bgrssi},
    {"chan_list",                   hgic_iwpriv_set_chan_list},
    {"mode",                        hgic_iwpriv_set_mode},
    {"paired_stas",                 hgic_iwpriv_set_paired_stas},
    {"pairing",                     hgic_iwpriv_set_pairing},
    {"beacon_int",                  hgic_iwpriv_set_beacon_int},
    {"radio_onoff",                 hgic_iwpriv_set_radio_onoff},
    {"join_group",                  hgic_iwpriv_join_group},
    {"ether_type",                  hgic_iwpriv_set_ethertype},
    {"txpower",                     hgic_iwpriv_set_txpower},
    {"agg_cnt",                     hgic_iwpriv_set_aggcnt},
    {"ps_connect",                  hgic_iwpriv_set_ps_connect},
    {"bss_max_idle",                hgic_iwpriv_set_bss_max_idle},
    {"wkio_mode",                   hgic_iwpriv_set_wkio_mode},
    {"loaddef",                     hgic_iwpriv_set_load_def},
    {"disassoc_sta",                hgic_iwpriv_set_disassoc_sta},
    {"dtim_period",                 hgic_iwpriv_set_dtim_period},
    {"ps_mode",                     hgic_iwpriv_set_ps_mode},
    {"aplost_time",                 hgic_iwpriv_set_aplost_time},
    {"unpair",                      hgic_iwpriv_set_unpair},
    {"auto_chswitch",               hgic_iwpriv_set_auto_chswitch},
    {"mcast_key",                   hgic_iwpriv_set_mcast_key},
    {"reassoc_wkhost",              hgic_iwpriv_set_reassoc_wkhost},
    {"wakeup_io",                   hgic_iwpriv_set_wakeup_io},
    {"dbginfo",                     hgic_iwpriv_set_dbginfo_output},
    {"sysdbg",                      hgic_iwpriv_set_sysdbg},
    {"primary_chan",                hgic_iwpriv_set_primary_chan},
    {"autosleep_time",              hgic_iwpriv_set_autosleep_time},
    {"super_pwr",                   hgic_iwpriv_set_super_pwr},
    {"r_ssid",                      hgic_iwpriv_set_repeater_ssid},
    {"r_psk",                       hgic_iwpriv_set_repeater_psk},
    {"auto_save",                   hgic_iwpriv_set_auto_save},
    {"pair_autostop",               hgic_iwpriv_set_pair_autostop},
    {"dcdc13",                      hgic_iwpriv_set_dcdc13v},
    {"acktmo",                      hgic_iwpriv_set_acktmo},
    {"pa_pwrctl_dis",               hgic_iwpriv_set_pa_pwrctl_dis},
    {"dhcpc",                       hgic_iwpriv_set_dhcpc},
    {"wkdata_save",                 hgic_iwpriv_set_wkdata_save},
    {"mcast_txparam",               hgic_iwpriv_set_mcast_txparam},
    {"reset_sta",                   hgic_iwpriv_set_resetsta},
    {"ant_auto",                    hgic_iwpriv_set_ant_auto},
    {"ant_sel",                     hgic_iwpriv_set_select_ant},
    {"wkhost_reason",               hgic_iwpriv_set_wkhost_reasons},
    {"macfilter",                   hgic_iwpriv_set_mac_filter},
    {"atcmd",                       hgic_iwpriv_set_atcmd},
    {"roaming",                     hgic_iwpriv_set_roaming},
    {"ap_hide",                     hgic_iwpriv_set_ap_hide},
    {"max_txcnt",                   hgic_iwpriv_set_max_txcnt},
    {"assert_holdup",               hgic_iwpriv_set_assert_holdup},
    {"ap_psmode",                   hgic_iwpriv_set_ap_psmode},
    {"dupfilter",                   hgic_iwpriv_set_dupfilter_en},
    {"dis_1v1m2u",                  hgic_iwpriv_set_dis_1v1m2u},
    {"dis_psconnect",               hgic_iwpriv_set_dis_psconnect},
    {"reset",                       hgic_iwpriv_reset},
    {"heartbeat",                   hgic_iwpriv_set_heartbeat},
    {"heartbeat_resp",              hgic_iwpriv_set_heartbeat_resp},
    {"wakeup_data",                 hgic_iwpriv_set_wakeup_data},
    {"wakeup",                      hgic_iwpriv_wakeup_sta},
    {"custmgmt",                    hgic_iwpriv_send_custmgmt},
    {"mgmtframe",                   hgic_iwpriv_send_mgmtframe},
    {"wkdata_mask",                 hgic_iwpriv_set_wkdata_mask},
    {"hbdata_mask",                 hgic_iwpriv_set_hbdata_mask},
    {"driverdata",                  hgic_iwpriv_set_driverdata},
    {"freqinfo",                    hgic_iwpriv_set_freqinfo},
    {"blenc",                       hgic_iwpriv_set_blenc},
    {"sleep",                       hgic_iwpriv_enter_sleep},
    {"hwscan",                      hgic_iwpriv_set_hwscan},
    {"user_edca",                   hgic_iwpriv_set_user_edca},
    {"fix_txrate",                  hgic_iwpriv_set_fix_txrate},
    {"nav_max",                     hgic_iwpriv_set_nav_max},
    {"clr_nav",                     hgic_iwpriv_clear_nav},
    {"cca_param",                   hgic_iwpriv_set_cca_param},
    {"tx_modgain",                  hgic_iwpriv_set_tx_modulation_gain},
    {"rts_duration",                hgic_iwpriv_set_rts_duration},
    {"disable_print",               hgic_iwpriv_set_disable_print},
    {"conn_paironly",               hgic_iwpriv_set_conn_paironly},
    {"diffcust_conn",               hgic_iwpriv_set_diffcust_conn},
    {"wait_psmode",                 hgic_iwpriv_set_wait_psmode},
    {"standby",                     hgic_iwpriv_set_standby},
    {"ap_chansw",                   hgic_iwpriv_set_ap_chan_switch},
    {"cca_ce",                      hgic_iwpriv_set_cca_for_ce},
    {"rtc",                         hgic_iwpriv_set_rtc},
    {"apep_padding",                hgic_iwpriv_set_apep_padding},
    {"watchdog",                    hgic_iwpriv_set_watchdog},
    {"retry_fallback_cnt",          hgic_iwpriv_set_retry_fallback_cnt},
    {"fallback_mcs",                hgic_iwpriv_set_fallback_mcs},
    {"xosc",                        hgic_iwpriv_set_xosc},
    {"freq_cali_period",            hgic_iwpriv_set_freq_cali_period},
    {"cust_drvdata",                hgic_iwpriv_set_customer_dvrdata},
    {"max_txdelay",                 hgic_iwpriv_set_max_tx_delay},
    {"heartbeat_int",               hgic_iwpriv_set_heartbeat_int},
    {"sleep_roaming",               hgic_iwpriv_set_sleep_roaming},
    {NULL,}
};

int hgic_iwpriv_set_proc(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    int ret = -ENOTSUPP;
    char *ptr;
    struct fwctrl_cfgset *set = NULL;
    char *buff = kmalloc(wrqin->u.data.length + 1, GFP_KERNEL);

    if (buff == NULL) {
        hgic_err("kmalloc fail\r\n");
        return -ENOMEM;
    }

    if (hgic_copyfrom_iwreq(wrqin, buff, wrqin->u.data.length + 1) == 0) {
        ptr = strchr(buff, '=');
        if (ptr) {
            *ptr++ = 0;
            for (set = hgpriv_sets; set->name; set++) {
                if (strcmp(buff, set->name) == 0) {
                    ret = set->set(ctrl, ifidx, ptr, wrqin->u.data.length - (ptr - buff));
                    break;
                }
            }
        } else {
            hgic_err("invalid set cmd [%s]\r\n", buff);
        }
    } else {
        hgic_err("copy_from_user fail\r\n");
    }

    kfree(buff);
    return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////
static int hgic_iwpriv_get_scan_list(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    int ret = 0;
    int i = 0;
    int count = 0;
    int len = 0;
    struct hgic_bss_info *bss = NULL;
    struct hgic_bss_info1 *bss1 = NULL;
    char *buf = kzalloc(1024, GFP_ATOMIC);
    char *print_buf = kzalloc(4096, GFP_ATOMIC);

    if (buf == NULL || print_buf == NULL) {
        if (buf) { kfree(buf); }
        if (print_buf) { kfree(print_buf); }
        return -ENOMEM;
    }

    ret = hgic_fwctrl_get_scan_list(ctrl, ifidx, buf, 1024);
    if (ret > 0) {
        bss = (struct hgic_bss_info *)buf;
        bss1 = (struct hgic_bss_info1 *)buf;
        if (bss1[0].ver != 1) {
            count = ret / sizeof(struct hgic_bss_info);
            len += sprintf(print_buf + len, "\r\nBSSID            \tSSID      \tEncryption\tFrequence\tSignal\n");
            for (i = 0; i < count; i++) {
                len += sprintf(print_buf + len, "%pM\t%s\t %10s\t  %10d\t%d\n",
                               bss[i].bssid, bss[i].ssid,
                               bss[i].encrypt ? (bss[i].encrypt == 1 ? "WPA" : "WPA2") : "NONE",
                               bss[i].freq, bss[i].signal);
            }
        } else {
            count = ret / sizeof(struct hgic_bss_info1);
            len += sprintf(print_buf + len, "\r\nBSSID            \tSSID      \tEncryption\tFrequence\tSignal\tCountry_region\tBSS_BW\n");
            for (i = 0; i < count; i++) {
                len += sprintf(print_buf + len, "%pM\t%s\t %10s\t  %10d\t%10d\t%10s\t%d\n",
                               bss1[i].bssid, bss1[i].ssid,
                               bss1[i].encrypt ? (bss1[i].encrypt == 1 ? "WPA" : "WPA2") : "NONE",
                               bss1[i].freq, bss1[i].signal,
                               bss1[i].country_region, bss1[i].bss_bw);
            }
        }
        wrqin->u.data.length = (u16)len;
    } else {
        len = 2;
    }
    hgic_copyto_iwreq(wrqin, print_buf, len);
    kfree(buf);
    kfree(print_buf);
    return (0);
}

static int hgic_iwpriv_get_sta_list(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    int count = 0;
    int len = 0;
    int format = 0;
    char *ptr;
    char *buf = kzalloc(4096, GFP_ATOMIC);
    char *print_buf = kzalloc(8192, GFP_ATOMIC);
    struct hgic_sta_info *sta = (struct hgic_sta_info *)buf;

    if (buf == NULL || print_buf == NULL) {
        if (buf) { kfree(buf); }
        if (print_buf) { kfree(print_buf); }
        return -ENOMEM;
    }

    hgic_copyfrom_iwreq(wrqin, buf, 8);
    ptr = strchr(buf, '=');
    if (ptr) {
        format = simple_strtol(ptr + 1, 0, 10);
    }

    count = hgic_fwctrl_get_sta_list(ctrl, ifidx, (struct hgic_sta_info *)buf, (4096 / sizeof(struct hgic_sta_info)));
    hgic_err("sta list count=%d\r\n", count);
    if (format == 1) {
        hgic_copyto_iwreq(wrqin, buf, count * sizeof(struct hgic_sta_info));
    } else {
        if (count > 0) {
            len += sprintf(print_buf, "%d sta:\r\n", count);
            while (count-- > 0 && (len + 80) < 8192) {
                len += sprintf(print_buf + len, "aid:%d, %pM, ps:%d, rssi:%d, evm:%d, tx_snr:%d, rx_snr:%d\r\n",
                               sta->aid, sta->addr, sta->ps, (s8)sta->rssi, (s8)sta->evm, (s8)sta->tx_snr, (s8)sta->rx_snr);
                sta++;
            }
        }
        hgic_err("sta list len=%d\r\n", len);
        hgic_copyto_iwreq(wrqin, print_buf, len);
    }

    kfree(buf);
    kfree(print_buf);
    return (0);
}
static int hgic_iwpriv_get_mode(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    int len = 0;
    char mode[13];
    len = hgic_fwctrl_get_mode(ctrl, ifidx, mode, 12);
    hgic_copyto_iwreq(wrqin, mode, len);
    return (0);
}
static int hgic_iwpriv_get_ssid(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    int len = 0;
    char ssid[33];
    len = hgic_fwctrl_get_ssid(ctrl, ifidx, ssid, 32);
    hgic_copyto_iwreq(wrqin, ssid, len);
    return (0);
}
static int hgic_iwpriv_get_bssid(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char buf[24];
    char bssid[7];

    memset(buf, 0, sizeof(buf));
    memset(bssid, 0, sizeof(bssid));
    if (hgic_fwctrl_get_bssid(ctrl, ifidx, bssid, 7) > 0) {
        sprintf(buf, "%pM,%d", bssid, bssid[6]);
    }
    hgic_copyto_iwreq(wrqin, buf, strlen(buf));
    return (0);
}

static int hgic_iwpriv_get_wpa_psk(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    int len = 0;
    char *buf = kzalloc(80, GFP_ATOMIC);

    if (buf == NULL) {
        return -ENOMEM;
    }
    len = hgic_fwctrl_get_wpapsk(ctrl, ifidx, buf, 64);
    hgic_copyto_iwreq(wrqin, buf, len);
    kfree(buf);
    return (0);
}

static int hgic_iwpriv_get_txpower(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[4];
    int txpower = 0;
    txpower = hgic_fwctrl_get_txpower(ctrl, ifidx);
    sprintf(str, "%d", txpower);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}

static int hgic_iwpriv_get_bss_bw(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[4];
    int bss_bw = 0;
    bss_bw = hgic_fwctrl_get_bss_bw(ctrl, ifidx);
    sprintf(str, "%d", bss_bw);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}

static int hgic_iwpriv_get_aggcnt(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[32];
    int ret = 0;
    u8 agg[2];

    memset(agg, 0, sizeof(agg));
    ret = hgic_fwctrl_get_agg_cnt(ctrl, ifidx, agg, 2);
    if (ret == 0xff) {
        sprintf(str, "tx:%d,rx:%d", agg[0], agg[1]);
    } else {
        sprintf(str, "tx:%d,rx:0", ret);
    }
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}

static int hgic_iwpriv_get_chan_list(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    int cnt = 0, i = 0;
    int len = 0;
    u16  chan_list[16];
    char *buf = kzalloc(128, GFP_KERNEL);

    if (buf) {
        cnt = hgic_fwctrl_get_chan_list(ctrl, ifidx, chan_list, 16);
        for (i = 0; i < cnt; i++) {
            len += sprintf(buf + len, "%d,", chan_list[i]);
        }
        hgic_copyto_iwreq(wrqin, buf, len - 1);
        kfree(buf);
    }
    return (0);
}

static int hgic_iwpriv_get_freq_range(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[32] = {0};
    int ret;
    u32 vals[3];

    ret = hgic_fwctrl_get_freq_range(ctrl, ifidx, &vals[0], &vals[1], &vals[2]);
    if (ret) {
        sprintf(str, "%d,%d,%d", vals[0], vals[1], vals[2]);
    }
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}

static int hgic_iwpriv_get_key_mgmt(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    int len = 0;
    char str[32];
    len = hgic_fwctrl_get_key_mgmt(ctrl, ifidx, str, 32);
    hgic_copyto_iwreq(wrqin, str, len);
    return (0);
}

static int hgic_iwpriv_get_battery_level(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[4];
    int val = 0;

    val = hgic_fwctrl_get_battery_level(ctrl, ifidx);
    sprintf(str, "%d", val);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}

static int hgic_iwpriv_get_module_type(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    u16 type = 0;
    char str[12];

    type = (u16)hgic_fwctrl_get_module_type(ctrl, ifidx);
    if (type) {
        sprintf(str, "%d", type);
        hgic_copyto_iwreq(wrqin, str, strlen(str));
    }
    return (0);
}

static int hgic_iwpriv_get_disassoc_reason(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[12];
    int reason = 0;

    reason = hgic_fwctrl_get_disassoc_reason(ctrl, ifidx);
    sprintf(str, "%d", reason);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}

static int hgic_iwpriv_get_ant_sel(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[12];
    int ant = 0;

    ant = hgic_fwctrl_get_ant_sel(ctrl, ifidx);
    sprintf(str, "%d", ant);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}

static int hgic_iwpriv_get_wkreason(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[12];
    int reason = 0;
    reason = hgic_fwctrl_get_wkreason(ctrl, ifidx);
    sprintf(str, "%d", reason);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}

static int hgic_iwpriv_get_wkdata_buff(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    int ret;
    char *buff = kmalloc(4096, GFP_KERNEL);
    if (buff) {
        ret = hgic_fwctrl_get_wkdata_buff(ctrl, ifidx, buff, 4096);
        hgic_copyto_iwreq(wrqin, buff, ret);
        kfree(buff);
    }
    return (0);
}

static int hgic_iwpriv_get_temperature(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[12];
    int temp = hgic_fwctrl_get_temperature(ctrl);
    sprintf(str, "%d", temp);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}

static int hgic_iwpriv_get_conn_state(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[12];
    int temp = hgic_fwctrl_get_conn_state(ctrl, ifidx);
    sprintf(str, "%d", temp);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}

static int hgic_iwpriv_get_sta_count(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[12];
    int temp = hgic_fwctrl_get_sta_count(ctrl, ifidx);
    sprintf(str, "%d", temp);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}

static int hgic_iwpriv_get_txq_param(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    int ret = -1;
    struct hgic_txq_param param[4];
    ret = hgic_fwctrl_get_txq_param(ctrl, ifidx, param);
    if (ret == sizeof(param)) {
        //printk("txq0: %d,%d,%d,%d\r\n", param[0].aifs, param[0].cw_min, param[0].cw_max, param[0].txop);
        //printk("txq1: %d,%d,%d,%d\r\n", param[1].aifs, param[1].cw_min, param[1].cw_max, param[1].txop);
        //printk("txq2: %d,%d,%d,%d\r\n", param[2].aifs, param[2].cw_min, param[2].cw_max, param[2].txop);
        //printk("txq3: %d,%d,%d,%d\r\n", param[3].aifs, param[3].cw_min, param[3].cw_max, param[3].txop);
        hgic_copyto_iwreq(wrqin, (char *)param, sizeof(param));
    }
    return (ret == sizeof(param)) ? 0 : ret;
}

static int hgic_iwpriv_get_nav(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[12];
    int temp = hgic_fwctrl_get_nav(ctrl, ifidx);
    sprintf(str, "%d", temp);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}

static int hgic_iwpriv_get_rtc(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[12];
    u32 rtc = 0;
    hgic_fwctrl_get_rtc(ctrl, ifidx, (u8 *)&rtc);
    sprintf(str, "%u", rtc);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}

static int hgic_iwpriv_get_bgrssi(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    int ret;
    char buff[64];
    char *ptr;
    s8 resp[3] = { 0, 0, 0};

    ret = hgic_copyfrom_iwreq(wrqin, buff, 64);
    ptr = strchr(buff, '=');
    if(ptr == NULL || ret)
        return -EINVAL;

    ret = simple_strtoul(ptr + 1, 0, 10);
    ret = hgic_fwctrl_get_bgrssi(ctrl, ifidx, ret, resp);
    if (ret == 3) {
        sprintf(buff, "%d,%d,%d", resp[0], resp[1], resp[2]);
        hgic_copyto_iwreq(wrqin, buff, strlen(buff));
    }
    return (0);
}

static int hgic_iwpriv_get_center_freq(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[12];
    int temp = hgic_fwctrl_get_center_freq(ctrl, ifidx);
    sprintf(str, "%d", temp);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}

static int hgic_iwpriv_get_acs_result(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    int cnt = 0;
    struct hgic_acs_result *result = kzalloc(32 * sizeof(struct hgic_acs_result), GFP_KERNEL);
    if (result) {
        cnt = hgic_fwctrl_get_acs_result(ctrl, ifidx, result, 32);
        hgic_copyto_iwreq(wrqin, (char *)result, cnt);
        kfree(result);
    }
    return (0);
}

static int hgic_iwpriv_get_reason_code(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[12];
    int temp = hgic_fwctrl_get_reason_code(ctrl, ifidx);
    sprintf(str, "%d", temp);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}

static int hgic_iwpriv_get_status_code(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[12];
    int temp = hgic_fwctrl_get_status_code(ctrl, ifidx);
    sprintf(str, "%d", temp);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}
static int hgic_iwpriv_get_dhcpc_result(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    u32 result[6];
    int ret = hgic_fwctrl_get_dhcpc_result(ctrl, ifidx, (u8 *)result, sizeof(result));
    if (ret == 24) {
        hgic_copyto_iwreq(wrqin, (char *)result, sizeof(result));
        return (0);
    }
    return ret;
}
static int hgic_iwpriv_get_xosc(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[12];
    int temp = hgic_fwctrl_get_xosc(ctrl, ifidx);
    sprintf(str, "%d", temp);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}
static int hgic_iwpriv_get_freq_offset(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    int ret;
    char buff[64];
    char *ptr;
    char addr[6];

    ret = hgic_copyfrom_iwreq(wrqin, buff, 64);
    ptr = strchr(buff, '=');
    if (ptr == NULL || ret) {
        return -EINVAL;
    }

    hgic_pick_macaddr(ptr + 1, addr);
    ret = hgic_fwctrl_get_freq_offset(ctrl, ifidx, addr);
    sprintf(buff, "%d", ret);
    hgic_copyto_iwreq(wrqin, buff, strlen(buff));
    return (0);
}
static int hgic_iwpriv_get_fwinfo(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    hgic_copyto_iwreq(wrqin, (char *)ctrl->fwinfo, sizeof(struct hgic_fw_info));
    return (0);
}
static int hgic_iwpriv_get_sta_info(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    int ret;
    char *ptr;
    char buff[64];
    char addr[6];
    char format = 0;
    struct hgic_sta_info stainfo;
    char *print_buf = kzalloc(512, GFP_ATOMIC);

    if (print_buf == NULL) {
        return -ENOMEM;
    }

    ret = hgic_copyfrom_iwreq(wrqin, buff, 64);
    ptr = strchr(buff, '=');
    if (ptr == NULL || ret) {
        kfree(print_buf);
        return -EINVAL;
    }

    hgic_pick_macaddr(ptr + 1, addr);
    ptr = strchr(ptr, ',');
    if (ptr) {
        format = simple_strtol(ptr + 1, 0, 10);
    }

    ret = hgic_fwctrl_get_sta_info(ctrl, ifidx, addr, &stainfo);
    if (format == 1) {
        hgic_copyto_iwreq(wrqin, (char *)&stainfo, ret);
    } else {
        if (ret > 0) {
            ret = sprintf(print_buf, "aid:%d, %pM, ps:%d, rssi:%d, evm:%d, tx_snr:%d, rx_snr:%d\r\n",
                          stainfo.aid, stainfo.addr, stainfo.ps, (s8)stainfo.rssi,
                          (s8)stainfo.evm, (s8)stainfo.tx_snr, (s8)stainfo.rx_snr);
        }
        hgic_copyto_iwreq(wrqin, print_buf, ret);
    }
    kfree(print_buf);
    return (0);
}
static int hgic_iwpriv_get_signal(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[12];
    int signal = hgic_fwctrl_get_signal(ctrl, ifidx);
    //sprintf(str, "%d", signal);
    sprintf(str, "%d", signal - 0x1000);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}
static int hgic_iwpriv_get_tx_bitrate(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    char str[12];
    int temp = hgic_fwctrl_get_tx_bitrate(ctrl, ifidx);
    sprintf(str, "%d", temp);
    hgic_copyto_iwreq(wrqin, str, strlen(str));
    return (0);
}

static struct fwctrl_cfgget hgpriv_gets[] = {
    {"mode",                        hgic_iwpriv_get_mode},
    {"sta_list",                    hgic_iwpriv_get_sta_list},
    {"scan_list",                   hgic_iwpriv_get_scan_list},
    {"ssid",                        hgic_iwpriv_get_ssid},
    {"bssid",                       hgic_iwpriv_get_bssid},
    {"wpa_psk",                     hgic_iwpriv_get_wpa_psk},
    {"txpower",                     hgic_iwpriv_get_txpower},
    {"agg_cnt",                     hgic_iwpriv_get_aggcnt},
    {"bss_bw",                      hgic_iwpriv_get_bss_bw},
    {"chan_list",                   hgic_iwpriv_get_chan_list},
    {"freq_range",                  hgic_iwpriv_get_freq_range},
    {"key_mgmt",                    hgic_iwpriv_get_key_mgmt},
    {"battery_level",               hgic_iwpriv_get_battery_level},
    {"module_type",                 hgic_iwpriv_get_module_type},
    {"disassoc_reason",             hgic_iwpriv_get_disassoc_reason},
    {"ant_sel",                     hgic_iwpriv_get_ant_sel},
    {"wkreason",                    hgic_iwpriv_get_wkreason},
    {"wkdata_buff",                 hgic_iwpriv_get_wkdata_buff},
    {"temperature",                 hgic_iwpriv_get_temperature},
    {"conn_state",                  hgic_iwpriv_get_conn_state},
    {"sta_count",                   hgic_iwpriv_get_sta_count},
    {"txq_param",                   hgic_iwpriv_get_txq_param},
    {"nav",                         hgic_iwpriv_get_nav},
    {"rtc",                         hgic_iwpriv_get_rtc},
    {"bgrssi",                      hgic_iwpriv_get_bgrssi},
    {"center_freq",                 hgic_iwpriv_get_center_freq},
    {"acs_result",                  hgic_iwpriv_get_acs_result},
    {"reason_code",                 hgic_iwpriv_get_reason_code},
    {"status_code",                 hgic_iwpriv_get_status_code},
    {"dhcpc_result",                hgic_iwpriv_get_dhcpc_result},
    {"xosc",                        hgic_iwpriv_get_xosc},
    {"freq_offset",                 hgic_iwpriv_get_freq_offset},
    {"fwinfo",                      hgic_iwpriv_get_fwinfo},
    {"stainfo",                     hgic_iwpriv_get_sta_info},
    {"signal",                      hgic_iwpriv_get_signal},
    {"tx_bitrate",                  hgic_iwpriv_get_tx_bitrate},
    {NULL,}
};

int hgic_iwpriv_get_proc(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin)
{
    struct fwctrl_cfgget *get = NULL;
    char *ptr;
    char field[130];

    memset(field, 0, sizeof(field));
    if (hgic_copyfrom_iwreq(wrqin, field, 128) == 0) {
        ptr = strchr(field, '=');
        if(ptr) *ptr = 0;
        for (get = hgpriv_gets; get->name; get++) {
            if (strcmp(field, get->name) == 0) {
                return get->get(ctrl, ifidx, wrqin);
            }
        }
        hgic_err("not support: [%s]\r\n", field);
    } else {
        hgic_err("copy_from_user fail\r\n");
    }
    return -ENOTSUPP;
}

int hgic_iwpriv_dump(struct hgic_fwctrl *ctrl, struct iwreq *wrqin)
{
    int len = 0;
    struct fwctrl_cfgget *get = NULL;
    struct fwctrl_cfgset *set = NULL;

    u8 *buf = kmalloc(4096, GFP_KERNEL);
    if (buf) {
        len += snprintf(buf + len, 4096 - len, "\r\nset:\r\n");
        for (set = hgpriv_sets; set->name; set++) {
            len += snprintf(buf + len, 4096 - len, "  %s\r\n", set->name);
        }
        len += snprintf(buf + len, 4096 - len, "get:\r\n");
        for (get = hgpriv_gets; get->name; get++) {
            len += snprintf(buf + len, 4096 - len, "  %s\r\n", get->name);
        }
        hgic_copyto_iwreq(wrqin, buf, len);
        kfree(buf);
    }
    return len;
}

