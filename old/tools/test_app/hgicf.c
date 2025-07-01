/**
  ******************************************************************************
  * @file    hgicf.c
  * @author  HUGE-IC Application Team
  * @version V1.0.0
  * @date    2021-06-23
  * @brief   hgic fmac driver daemon.
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2022 HUGE-IC</center></h2>
  *
  ******************************************************************************
  */

#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#include "hgic.h"

#include "iwpriv.c"

///////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////
#define IFNAME "hg0"


static void hgic_test_read_wakeupdata()
{
    int i = 0;
    char *buff = malloc(4096);
    do {
        i = hgic_iwpriv_read_wkdata_buff(IFNAME, buff, 4096);
        if (i > 0) {
            buff[i] = 0;
            printf("get wkdata, len:%d, %s\r\n", i, buff + 42);
        }
    } while (i > 0);
    free(buff);
}

int hgicf_fwevent_parse(u8 *event_data, u32 event_len)
{
    int i = 0;
    u32   data_len = 0;
    u32   evt_id   = 0;
    char *data     = NULL;
    char *buff;
    struct hgic_exception_info *exp;    
    struct hgic_dhcp_result *dhcpc;
    struct hgic_ctrl_hdr *evt = (struct hgic_ctrl_hdr *)event_data;

    data     = (char *)(evt + 1);
    data_len = event_len - sizeof(struct hgic_ctrl_hdr);
    evt_id   = HDR_EVTID(evt);

    printf("recv firmware event %d\r\n", evt_id);
    buff = malloc(4096);
    if (buff == NULL) {
        return -1;
    }

    switch (evt_id) {
        case HGIC_EVENT_SCANNING:
            printf("start scan ...\r\n");
            break;
        case HGIC_EVENT_SCAN_DONE:
            printf("scan done!\r\n");
            hgic_iwpriv_get_scan_list(IFNAME, buff, 4096);
            printf("%s\r\n", buff);
            break;
        case HGIC_EVENT_TX_BITRATE:
            printf("estimate tx bitrate:%dKbps\r\n", *(unsigned int *)data);
            break;
        case HGIC_EVENT_PAIR_START:
            printf("start pairing ...\r\n");
            break;
        case HGIC_EVENT_PAIR_SUCCESS:
            printf("pairing success! ["MACSTR"]\r\n", MACARG(data));
            hgic_iwpriv_set_pairing(IFNAME, 0); //stop pair
            break;
        case HGIC_EVENT_PAIR_DONE:
            printf("pairing done!\r\n");
            for(i=0; i*6 < data_len;i++){
                printf("  sta%d:"MACSTR"\r\n", i, MACARG(data+6*i));
            }
            break;
        case HGIC_EVENT_CONECT_START:
            printf("start connecting ...\r\n");
            break;
        case HGIC_EVENT_CONECTED:
            printf("new sta "MACSTR" connected!\r\n", MACARG(data));
            hgic_test_read_wakeupdata();
            break;
        case HGIC_EVENT_ROAM_CONECTED:
            printf("roam success to "MACSTR"!\r\n", MACARG(data));
            break;
        case HGIC_EVENT_DISCONECTED:
            printf("sta "MACSTR" disconnected, reason_code=%d\r\n", MACARG(data), get_unaligned_le16(data+6));
            break;
        case HGIC_EVENT_SIGNAL:
            printf("signal changed: rssi:%d, evm:%d\r\n", (signed char)data[0], (signed char)data[1]);
            break;
        case HGIC_EVENT_CUSTOMER_MGMT:
            printf("rx customer mgmt frame from "MACSTR", %d bytes \r\n", MACARG(data), data_len-6);
            break;
        case HGIC_EVENT_DHCPC_DONE:
            dhcpc = (struct hgic_dhcp_result *)data;
            printf("fw dhcpc result: ipaddr:"IPSTR", netmask:"IPSTR", svrip:"IPSTR", router:"IPSTR", dns:"IPSTR"/"IPSTR"\r\n",
                IPARG(dhcpc->ipaddr), IPARG(dhcpc->netmask), IPARG(dhcpc->svrip),
                IPARG(dhcpc->router), IPARG(dhcpc->dns1), IPARG(dhcpc->dns2));
            break;
        case HGIC_EVENT_CONNECT_FAIL:
            printf("connect fail, status_code=%d\r\n", get_unaligned_le16(data));
            break;
        case HGIC_EVENT_CUST_DRIVER_DATA:
            printf("rx customer driver data %d bytes\r\n", data_len);
            break;
        case HGIC_EVENT_UNPAIR_STA:
            printf("unpair sta:"MACSTR"\r\n", MACARG(data));
            break;
        case HGIC_EVENT_EXCEPTION_INFO:
            exp = (struct hgic_exception_info *)data;
            switch(exp->num){
                case HGIC_EXCEPTION_TX_BLOCKED:
                    printf("*wireless tx blocked, maybe need reset wifi module*\r\n");
                    break;
                case HGIC_EXCEPTION_TXDELAY_TOOLONG:
                    printf("*wireless txdelay too loog, %d:%d:%d *\r\n", 
                            exp->info.txdelay.max, exp->info.txdelay.min, exp->info.txdelay.avg);
                    break;
                case HGIC_EXCEPTION_STRONG_BGRSSI:
                    printf("*detect strong backgroud noise. %d:%d:%d *\r\n", 
                            exp->info.bgrssi.max, exp->info.bgrssi.min, exp->info.bgrssi.avg);
                    break;
                case HGIC_EXCEPTION_TEMPERATURE_OVERTOP:
                    printf("*chip temperature too overtop: %d *\r\n", exp->info.temperature.temp);
                    break;
                case HGIC_EXCEPTION_WRONG_PASSWORD:
                    printf("*password maybe is wrong *\r\n");
                    break;
            }
            break;
    }
    
    free(buff); 
}

int main(int argc, char *argv[])
{
    int  ret = 0;
    int  fd  = -1;
    u8 *buff = malloc(4096);

    HGIC = "hgicf";
    if (buff == NULL) {
        printf("malloc fail\r\n");
        return -1;
    }

__open:
    fd = open("/proc/hgicf/fwevnt", O_RDONLY);
    if (fd == -1) {
        //printf("open /proc/hgicf/fwevnt fail\r\n");
        sleep(1);
        goto __open;
    }

    while (1) {
        ret = read(fd, buff, 4096);
        if (ret > 0) {
            hgicf_fwevent_parse(buff, ret);
        }else if(ret < 0){
            close(fd);
            goto __open;
        }
    }

    close(fd);
    free(buff);
    return 0;
}

