
#ifndef _HGICF_CTRL_H_
#define _HGICF_CTRL_H_

#ifdef __RTOS__
int hgicf_ioctl(struct net_device *dev, u32 cmd, u32 param1, u32 param2);
#else
int hgicf_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd);
int hgicf_ioctl_set_proc(struct net_device *dev, struct iwreq *wrqin);
int hgicf_ioctl_get_proc(struct net_device *dev, struct iwreq *wrqin);
int hgicf_ioctl_stat(struct net_device *dev, struct iwreq *wrqin);
int hgicf_ioctl_e2p(struct net_device *dev, struct iwreq *wrqin);
int hgicf_ioctl_savecfg(struct net_device *dev, struct iwreq *wrqin);
int hgicf_ioctl_scan(struct net_device *dev, struct iwreq *wrqin);
#endif


#endif

