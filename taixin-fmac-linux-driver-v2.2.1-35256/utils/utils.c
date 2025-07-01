#ifdef __RTOS__
#include <linux/module.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#ifdef HGIC_SMAC
#include "umac_config.h"
#endif
#else
#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/firmware.h>
#include <linux/etherdevice.h>
#endif
#include "utils.h"
#include "../hgic_def.h"

#define aSymbolLength  40
#define STATBUF_SIZE   (64*1024)
#define SAFE_DIV(a, b) (((b) == 0) ? 0 : ((a) / (b)))

int hgic_skip_padding(u8* data)
{
    int i = 0;
    for (i = 0; i < 3 && data[i] == 0xFF; i++);
    return i;
}

#if 0
int hgic_aligned_padding(struct sk_buff *skb)
{
    uint32_t i     = 0;
    uint32_t count = 0;
    uint8_t *data  = skb->data - 4;
    if (!IS_ALIGNED((uint32_t)skb->data, 4)) {
        count = (uint32_t)skb->data - (uint32_t)ALIGN((uint32_t)data, 4);
        if (count > 0) {
            skb_push(skb, count);
            for (i = 0; i < count; i++) {
                skb->data[i] = 0xFF;
            }
        }
    }
    return count;
}
#endif

void hgic_print_hex(char *buf, int len)
{
    int i = 0;

    for (i = 0; i < len; i++) {
        if (i > 0 && i % 16 == 0) { printk("\r\n"); }
        else if (i > 0 && i % 8 == 0) { printk("  "); }
        printk("%02x ", buf[i] & 0xff);
    }
    printk("\r\n\r\n");
}

int hgic_config_read_int(char *conf, char *field)
{
    char *ptr = strstr(conf, field);
    if (ptr) {
        return simple_strtol(ptr + strlen(field) + 1, 0, 10);
    }
    return 0;
}

int hgic_config_read_str(char *conf, char *field, char *str, int size)
{
    char *ptr = strstr(conf, field);
    if (ptr) {
        ptr += strlen(field) + 1;
        while (*ptr && *ptr != '\r' && *ptr != '\n' && size > 0) {
            *str++ = *ptr++;
            size--;
        }
        return 0;
    }
    return -1;
}

int hgic_config_read_u32_array(char *conf, char *field, u32 *arr, int count)
{
    int cnt = 0;
    int val = 0;
    char *ptr = strstr(conf, field);

    if (ptr) {
        ptr += strlen(field) + 1;
        while (cnt < count) {
            while (*ptr >= '0' && *ptr <= '9') {
                val *= 10;
                val += (*ptr - 0x30);
                ptr++;
            }
            if (val) {
                arr[cnt++] = val;
            }

            if (*ptr != ',' || val == 0) {
                break;
            }
            ptr++;
            val = 0;
        }
    }

    return cnt;
}

int hgic_config_read_u16_array(char *conf, char *field, u16 *arr, int count)
{
    int cnt = 0;
    int val = 0;
    char *ptr = strstr(conf, field);

    if (ptr) {
        ptr += strlen(field) + 1;
        while (cnt < count) {
            while (*ptr >= '0' && *ptr <= '9') {
                val *= 10;
                val += (*ptr - 0x30);
                ptr++;
            }
            if (val) {
                arr[cnt++] = val;
            }

            if (*ptr != ',' || val == 0) {
                break;
            }
            ptr++;
            val = 0;
        }
    }

    return cnt;
}

void hgic_clear_queue(struct sk_buff_head *q)
{
#if 0
    ulong flags = 0;
    struct sk_buff *skb = NULL;
    struct sk_buff *tmp = NULL;

    spin_lock_irqsave(&q->lock, flags);
    if (!skb_queue_empty(q)) {
        skb_queue_walk_safe(q, skb, tmp) {
            __skb_unlink(skb, q);
            kfree_skb(skb);
        }
    }
    spin_unlock_irqrestore(&q->lock, flags);
#else
    struct sk_buff *skb = skb_dequeue(q);
    while(skb){
        kfree_skb(skb);
        skb = skb_dequeue(q);
    }
#endif
}

int hgic_hex2num(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return 0;
}

int hgic_hex2byte(const char *hex)
{
    int a, b;
    a = hgic_hex2num(*hex++);
    b = hgic_hex2num(*hex++);
    return (a << 4) | b;
}

int hgic_pick_macaddr(char *mac_str, u8 *addr)
{
    int  i = 0;
    char tmp[20];
    char *ptr = tmp;
    char *p   = tmp;

    memset(addr, 0, 6);
    memcpy(tmp, mac_str, 17);
    while (ptr && *ptr && i < 6) {
        p = strchr(ptr, ':');
        if(p) *p++ = 0;
        addr[i++] = hgic_hex2byte(ptr);
        ptr = p;
    }
    return (i == 6);
}

void hgic_strip_tail(char *str, u32 len)
{
    u32 i = len - 1;
    while (str[i] == '\r' || str[i] == '\n') {
        str[i--] = 0;
    }
}

int hgic_is_enter_sleep(u8 *data)
{
    struct hgic_ctrl_hdr *hdr = (struct hgic_ctrl_hdr *)data;
    if (hdr->hdr.magic == cpu_to_le16(HGIC_HDR_TX_MAGIC) || hdr->hdr.magic == cpu_to_le16(HGIC_HDR_RX_MAGIC)) {
        if (hdr->hdr.type == HGIC_HDR_TYPE_CMD || hdr->hdr.type == HGIC_HDR_TYPE_CMD2) {
            if (HDR_CMDID(hdr) == HGIC_CMD_ENTER_SLEEP) {
                return get_unaligned_le16(data + sizeof(struct hgic_ctrl_hdr));
            }
        }
    }
    return 0;
}

struct sk_buff *hgic_skb_expand(struct sk_buff *skb, u32 head_size, u32 align)
{
	u32 headerlen     = max(skb_headroom(skb), head_size);
	unsigned int size = headerlen + skb_tailroom(skb) + skb->len + align;
	struct sk_buff *n = dev_alloc_skb(size);
    if(n){
    	skb_reserve(n, headerlen);
        headerlen = PTR_ALIGN(n->data, align) - n->data;
        skb_reserve(n, headerlen);
    	skb_put(n, skb->len);
        memcpy(n->data, skb->data, skb->len);
        n->dev        = skb->dev;
        n->pkt_type   = skb->pkt_type;
        n->priority   = skb->priority;
        n->protocol   = skb->protocol;
        n->vlan_proto = skb->vlan_proto;
        n->vlan_tci   = skb->vlan_tci;
        memcpy(n->cb, skb->cb, sizeof(skb->cb));
        return n;
    }
    return NULL;
}


#if defined(__RTOS__) && defined(HGIC_SMAC)
int umac_config_read(const char *name, char *buff, int size)
{
    int ret = 0;
    struct hgics_config *cfg = sys_get_umaccfg();
    struct net_device *ndev = net_device_get_by_name(name);

    if (ndev == NULL) {
        PRINTF("dev:%s is not exist!\r\n", name);
        return -1;
    }
    if (ndev->ifindex == 0) {
        strcpy(buff, (const char *)cfg->hg0);
        buff[strlen(cfg->hg0)] = 0;
    } else if (ndev->ifindex == 1) {
        strcpy(buff, (const char *)cfg->hg1);
        buff[strlen(cfg->hg1)] = 0;
    } else {
        ret = -1;
    }
    PRINTF("read %s:\r\n%s\r\n", name, buff);
    return ret;
}

int umac_config_write(const char *name, char *buff, int size)
{
    int ret = 0;
    struct hgics_config *cfg = sys_get_umaccfg();
    struct net_device *ndev = net_device_get_by_name(name);

    PRINTF("write %s:\r\n%s\r\n", name, buff);
    if (ndev == NULL) {
        PRINTF("dev:%s is not exist!\r\n", name);
        return -1;
    }
    if ((ndev->ifindex == 0) && size < sizeof(cfg->hg0)) {
        strcpy((char *)cfg->hg0, buff);
    } else if ((ndev->ifindex == 1) && size < sizeof(cfg->hg1)) {
        strcpy((char *)cfg->hg1, buff);
    } else {
        ret = -1;
    }
    if (!ret) {
        ret = sys_save_umaccfg(cfg);
    }
    return ret;
}
#endif
