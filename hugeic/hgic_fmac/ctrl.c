#include <linux/version.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>

#include "hgicf.h"
#include "ctrl.h"
#include "event.h"

/* cmd id, Odd : get (world access), even : set (root access) */
#define HG_PRIV_IOCTL_GET        (SIOCIWFIRSTPRIV + 0x01)
#define HG_PRIV_IOCTL_SET        (SIOCIWFIRSTPRIV + 0x02)
#define HG_PRIV_IOCTL_STAT       (SIOCIWFIRSTPRIV + 0x03)
#define HG_PRIV_IOCTL_SCAN       (SIOCIWFIRSTPRIV + 0x04)
#define HG_PRIV_IOCTL_E2P        (SIOCIWFIRSTPRIV + 0x05)
#define HG_PRIV_IOCTL_SAVE       (SIOCIWFIRSTPRIV + 0x06)

struct iw_priv_args hgicf_privtab[] = {
    {HG_PRIV_IOCTL_SET, IW_PRIV_TYPE_CHAR | 1536,  0,  "set"},
    {HG_PRIV_IOCTL_GET, IW_PRIV_TYPE_CHAR | 1024, IW_PRIV_TYPE_CHAR | 1024,  "get"},
    {HG_PRIV_IOCTL_SCAN, IW_PRIV_TYPE_CHAR | 1536, 0,  "scan"},
    {HG_PRIV_IOCTL_E2P, IW_PRIV_TYPE_CHAR | 1024, IW_PRIV_TYPE_CHAR | 1024,  "e2p"},
    {HG_PRIV_IOCTL_STAT, 0, IW_PRIV_TYPE_CHAR | 1024,  "stat"},
    {HG_PRIV_IOCTL_SAVE, IW_PRIV_TYPE_CHAR | 1024, 0,  "save"},
};

int hgicf_ioctl_set_proc(struct net_device *dev, struct iwreq *wrqin)
{
    struct hgicf_vif *vif = (struct hgicf_vif *)netdev_priv(dev);
    return hgic_iwpriv_set_proc(&(vif->hg->ctrl), vif->fwifidx, wrqin);
}

int hgicf_ioctl_get_proc(struct net_device *dev, struct iwreq *wrqin)
{
    struct hgicf_vif *vif = (struct hgicf_vif *)netdev_priv(dev);
    return hgic_iwpriv_get_proc(&(vif->hg->ctrl), vif->fwifidx, wrqin);
}

int hgicf_ioctl_stat(struct net_device *dev, struct iwreq *wrqin)
{
    return 0;
}

int hgicf_ioctl_e2p(struct net_device *dev, struct iwreq *wrqin)
{
    return 0;
}

int hgicf_ioctl_savecfg(struct net_device *dev, struct iwreq *wrqin)
{
    struct hgicf_vif *vif = (struct hgicf_vif *)netdev_priv(dev);
    return hgic_fwctrl_save_cfg(&(vif->hg->ctrl), vif->fwifidx);
}

int hgicf_ioctl_scan(struct net_device *dev, struct iwreq *wrqin)
{
    struct hgicf_vif *vif = (struct hgicf_vif *)netdev_priv(dev);
    return hgic_fwctrl_scan(&(vif->hg->ctrl), vif->fwifidx, 1);
}

int hgicf_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
    int ret = 0;
    struct iwreq     *wrqin = (struct iwreq *) ifr;

    switch (cmd) {
        case SIOCGIWPRIV:
            if (wrqin->u.data.pointer) {
                if (!ACCESS_OK(VERIFY_WRITE, wrqin->u.data.pointer, sizeof(hgicf_privtab))) {
                    break;
                }
                if ((sizeof(hgicf_privtab) / sizeof(hgicf_privtab[0])) <= wrqin->u.data.length) {
                    wrqin->u.data.length = sizeof(hgicf_privtab) / sizeof(hgicf_privtab[0]);
                    ret = copy_to_user(wrqin->u.data.pointer, hgicf_privtab, sizeof(hgicf_privtab));
                }
            }
            break;
        case HG_PRIV_IOCTL_SET:
            ret = hgicf_ioctl_set_proc(dev, wrqin);
            break;
        case HG_PRIV_IOCTL_GET:
            ret = hgicf_ioctl_get_proc(dev, wrqin);
            break;
        case HG_PRIV_IOCTL_SCAN:
            ret = hgicf_ioctl_scan(dev, wrqin);
            break;
        case HG_PRIV_IOCTL_E2P:
            ret = hgicf_ioctl_e2p(dev, wrqin);
            break;
        case HG_PRIV_IOCTL_STAT:
            ret = hgicf_ioctl_stat(dev, wrqin);
            break;
        case HG_PRIV_IOCTL_SAVE:
            ret = hgicf_ioctl_savecfg(dev, wrqin);
            break;
    }

    return ret;
}

