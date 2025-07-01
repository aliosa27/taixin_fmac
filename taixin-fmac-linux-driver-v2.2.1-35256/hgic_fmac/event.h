
#ifndef _HGICF_EVENT_H_
#define _HGICF_EVENT_H_

void hgicf_rx_fw_event(struct hgic_fwctrl *ctrl, struct sk_buff *skb);
void hgicf_event(struct hgicf_wdev *hg, char *name, int event, int param1, int param2);

#endif

