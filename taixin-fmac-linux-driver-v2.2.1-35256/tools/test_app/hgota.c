#include <error.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include "libota.h"

struct hgicOTA {
    uint8 rxbuf[2048];
    uint8 mac_addr[6];
    int   sock;
    int   if_index;
} hgOTA;


static void hgic_show_device(void)
{
    int i = 0;
    printf("\r\n------------------------------------------------------------------\r\n");
    for (i = 0; i < OTA_STA_COUNT; i++) {
        if (LIBOTA.stas[i].online) {
            printf("| "MACSTR", chipid:%x, version:%d.%d.%d.%d-%d |\r\n",
                   MAC2STR(LIBOTA.stas[i].addr),
                   LIBOTA.stas[i].chipid,
                   (LIBOTA.stas[i].version >> 24) & 0xff,
                   (LIBOTA.stas[i].version >> 16) & 0xff,
                   (LIBOTA.stas[i].version >> 8) & 0xff,
                   (LIBOTA.stas[i].version) & 0xff,
                   LIBOTA.stas[i].svn_version);
        }
    }
    printf("------------------------------------------------------------------\r\n");
}

static struct hgota_sta *hgic_get_device(u8 *addr)
{
    int i = 0;
    for (i = 0; i < OTA_STA_COUNT; i++) {
        if (memcmp(LIBOTA.stas[i].addr, addr, 6) ==0) {
            return &LIBOTA.stas[i];
        }
    }
    return NULL;
}


static void hgic_save_device(void)
{
    FILE *fp = fopen("/tmp/hgota.tmp", "w+");
    if (fp) {
        fwrite(LIBOTA.stas, 1, sizeof(LIBOTA.stas), fp);
        fclose(fp);
        printf("save scan result into /tmp/hgota.tmp\r\n");
    }
}

static void hgic_read_device(void)
{
    int i = 0;

    FILE *fp = fopen("/tmp/hgota.tmp", "r");
    if (fp) {
        fread(LIBOTA.stas, 1, sizeof(LIBOTA.stas), fp);
        fclose(fp);
        printf("load device info from /tmp/hgota.tmp\r\n");
        hgic_show_device();
    }
}

static int hgic_sock_init(char *ifname)
{
    int ret = 0;
    struct ifreq req;

    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        goto __fail;
    }
    memset(&req, 0, sizeof(struct ifreq));
    strncpy(req.ifr_name, ifname, strlen(ifname));
    ret = ioctl(sock, SIOCGIFINDEX, &req);
    if (sock == -1) {
        goto __fail;
    }
    hgOTA.if_index = req.ifr_ifindex;

    ret = ioctl(sock, SIOCGIFHWADDR, &req);
    if (sock == -1) {
        goto __fail;
    }
    memcpy(hgOTA.mac_addr, req.ifr_hwaddr.sa_data, 6);
    close(sock);

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_OTA));
    hgOTA.sock =  sock;
    //printf("%d, %s: "MACSTR"\r\n", hgOTA.if_index, ifname, MAC2STR(hgOTA.mac_addr));
    return (sock != -1);
__fail:
    if (sock != -1) {
        close(sock);
    }
    return 0;
}

static int hgic_sock_recv(int tmo)
{
    int ret = 0;
    int recv_len = 0;
    fd_set  rfd;
    struct timeval timeout;

    FD_ZERO(&rfd);
    FD_SET(hgOTA.sock, &rfd);
    timeout.tv_sec  = tmo / 1000;
    timeout.tv_usec = (tmo % 1000) * 1000;
    ret = select(hgOTA.sock + 1, &rfd, NULL, NULL, &timeout);
    if (ret > 0 && FD_ISSET(hgOTA.sock, &rfd)) {
        recv_len = recvfrom(hgOTA.sock, hgOTA.rxbuf, 2048, 0, NULL, NULL);
    }
    return (recv_len);
}

int raw_sock_send(char *data, int len)
{
    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(struct sockaddr_ll));
    dest.sll_family   = AF_PACKET;
    dest.sll_protocol = htons(ETH_P_OTA);
    dest.sll_ifindex  = hgOTA.if_index;
    dest.sll_pkttype  = PACKET_OUTGOING;
    dest.sll_halen    = 6;
    memcpy(dest.sll_addr, data, 6);
    memcpy(data + 6, hgOTA.mac_addr, 6);
    return sendto(hgOTA.sock, data, len, 0, (const struct sockaddr *)&dest, sizeof(struct sockaddr_ll));
}

void hgic_scan_device(void)
{
    int i = 0;
    int recv_len = 0;
    FILE *fp = NULL;

    libota_scan(1);
    while (i++ < 10) {
        if ((i & 0xf) == 0) { libota_scan(0); }
        recv_len = hgic_sock_recv(50);
        if (recv_len > 0) {
            libota_rx_proc(hgOTA.rxbuf, recv_len);
        }
    }
    hgic_save_device();
    printf("OTA SCAN:%d devices:\r\n", LIBOTA.sta_count);
    hgic_show_device();
}

void hgic_reboot_device(char *addr)
{
    uint8 mac[6];
    printf("reboot sta %s\r\n", addr);
    if (6 == sscanf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", mac, mac + 1, mac + 2, mac + 3, mac + 4, mac + 5)) {
        libota_reboot(mac, 0);
    }
}

void hgic_loaddef_device(char *addr)
{
    uint8 mac[6];

    printf("load default sta %s config\r\n", addr);
    if (6 == sscanf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", mac, mac + 1, mac + 2, mac + 3, mac + 4, mac + 5)) {
        libota_reboot(mac, ETH_P_REBOOT_FLAGS_LOADDEF);
    }
}

static uint8 *hgic_read_firmware(char *path, struct hgota_fw_info *fwinfo)
{
    int err = 0;
    uint32 file_len = 0;
    uint8 *fwdata = NULL;
    uint32 rlen = 0;
    FILE *fp = fopen(path, "r");

    if (fp) {
        fseek(fp, 0, SEEK_END);
        file_len = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        fwdata = malloc(file_len);
        if (fwdata) {
            rlen = fread(fwdata, 1, file_len, fp);
        }
        fclose(fp);

        if (file_len == rlen && fwdata) {
            fwinfo->chipid = fwinfo_get_fw_chipid(fwdata, &err);
            fwinfo->tot_len = fwinfo_get_fw_length(fwdata, &err);
            fwinfo->version = fwinfo_get_fw_sdk_version(fwdata, &err);
            fwinfo->svn_version = fwinfo_get_fw_svn_version(fwdata, &err);
            if (!fwinfo_get_fw_code_checksum(fwdata, fwinfo->tot_len)) {
                printf("firmware Info:\r\n");
                printf("    chipid:%x\r\n", fwinfo->chipid);
                printf("    version:%d.%d.%d.%d-%d\r\n", (fwinfo->version >> 24) & 0xff,
                       (fwinfo->version >> 16) & 0xff,
                       (fwinfo->version >> 8) & 0xff,
                       (fwinfo->version) & 0xff,
                       fwinfo->svn_version);
                printf("    size:%d\r\n", fwinfo->tot_len);
                return fwdata;
            }
        }
        printf("invalid firmware\r\n");
    } else {
        printf("open file %s fail\r\n", path);
    }
    if (fwdata) {
        free(fwdata);
    }
    return NULL;
}

void hgic_ota_device(char *addr, char *fw)
{
    uint8 mac[6];
    uint32 ota_off = 0;
    uint8 *fwdata = NULL;
    uint32 rx_len = 0;
    uint32 err = 0;
    int32  retry = 0;
    struct hgota_fw_info fwinfo;
    struct hgota_sta *sta = NULL;

    printf("ota sta %s, fw:%s\r\n", addr, fw);
    memset(&fwinfo, 0, sizeof(fwinfo));
    if (6 == sscanf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", mac, mac + 1, mac + 2, mac + 3, mac + 4, mac + 5)) {
        sta    = hgic_get_device(mac);
        fwdata = hgic_read_firmware(fw, &fwinfo);
        if (fwdata) {
            if(sta && sta->svn_version == fwinfo.svn_version){
                printf("same version, do not OTA\r\n");
                return;
            }
            while (ota_off < fwinfo.tot_len && retry < 10) {
                libota_send_fw_data(mac, &fwinfo, ota_off, fwdata + ota_off,
                                    (fwinfo.tot_len - ota_off) > 1460 ? 1460 : (fwinfo.tot_len - ota_off));
                rx_len = hgic_sock_recv(500);
                if (rx_len > 0 && (libota_rx_proc(hgOTA.rxbuf, rx_len) == HGOTA_STATUS_FW_STATUS)) {
                    retry = 0;
                } else {
                    retry++;
                }
                ota_off = libota_sta_nexoff(mac);
                printf("OTA: %d%%\r", (ota_off * 100) / fwinfo.tot_len);
                fflush(stdout);
            }
            free(fwdata);
        }
    }
    printf("\r\n");
    if (fwinfo.tot_len > 0) {
        printf("OTA Exit: %d%% upgraded\r\n", (ota_off * 100) / fwinfo.tot_len);
    }
}

void hgic_get_config(char *addr)
{
    int i = 0;
    char mac[6];
    uint32  rx_len = 0;
    struct eth_ota_fwparam param;

    if (6 == sscanf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", mac, mac + 1, mac + 2, mac + 3, mac + 4, mac + 5)) {
        libota_query_config(mac);
        rx_len = hgic_sock_recv(500);
        if (rx_len > 0) {
            if (HGOTA_STATUS_CONFIG_GOT == libota_rx_proc(hgOTA.rxbuf, rx_len)) {
                libota_sta_config(mac, &param);
                printf("BSS BW :%d\r\n", param.bss_bw);
                printf("TX MCS :%d\r\n", param.tx_mcs);
                printf("ENCRYPT:%d\r\n", param.encrypt);
                printf("FORWARD:%d\r\n", param.forward);
                printf("SSID   :%s\r\n", param.ssid);
                printf("KEY_SET:%d\r\n", param.key_set);
                printf("MACST_KEY_SET:%d\r\n", param.mkey_set);
                printf("FREQ RANGE:%d - %d\r\n", param.freq_start, param.freq_end);
                printf("CHAN LIST:");
                for (i = 0; i < param.chan_cnt; i++) {
                    if (param.chan_list[0]) { printf("%d ", param.chan_list[0]); }
                }
                printf("\r\n");
            }
        }
    }
}

int main(int argc, char *argv[])
{
    char *ifname;
    char *cmd;
    FILE *fp = NULL;

    if (argc < 3) {
        printf("invalid params\r\n    hgota ifname cmd [args]\r\n");
        return -1;
    }
    ifname = argv[1];
    cmd    = argv[2];

    libota_init(raw_sock_send);
    hgic_read_device();

    if (!hgic_sock_init(ifname)) {
        printf("create socket fail\r\n");
        return -1;
    }

    if (strcmp(cmd, "SCAN") == 0) {
        hgic_scan_device();
    } else if (strcmp(cmd, "REBOOT") == 0) {
        if (argc == 3 + 1) {
            hgic_reboot_device(argv[3]);
        }
    } else if (strcmp(cmd, "LDDEF") == 0) {
        if (argc == 3 + 1) {
            hgic_loaddef_device(argv[3]);
        }
    } else if (strcmp(cmd, "OTA") == 0) {
        if (argc == 3 + 2) {
            hgic_ota_device(argv[3], argv[4]);
        }
    } else if (strcmp(cmd, "GETCFG") == 0) {
        if (argc == 3 + 1) {
            hgic_get_config(argv[3]);
        }
    }
    close(hgOTA.sock);
    return 0;
}

