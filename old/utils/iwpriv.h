
#ifndef _HGICF_CFG_H_
#define _HGICF_CFG_H_
#ifndef __RTOS__
int hgic_iwpriv_set_proc(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin);
int hgic_iwpriv_get_proc(struct hgic_fwctrl *ctrl, u8 ifidx, struct iwreq *wrqin);
int hgic_iwpriv_dump(struct hgic_fwctrl *ctrl, struct iwreq *wrqin);

#endif
#endif

