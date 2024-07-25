
#ifdef __RTOS__
#include <linux/types.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/delay.h>
#include <linux/semaphore.h>
#include <linux/skbuff.h>
#include "porting/sdio.h"
#else
#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/semaphore.h>
#include <linux/mmc/card.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/host.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/sdio_ids.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/sd.h>
#include <linux/netdevice.h>

#define sdio_func_t   sdio_func
#define mmc_command_t mmc_command
#define sdio_device_id_t sdio_device_id
#define sdio_driver_t sdio_driver
#define vendor_id     vendor
#define device_id     device
#define f_num         num
#endif

#include "../hgic_def.h"
#include "utils.h"

#define SDIO_BLOCK_SIZE  64
#define SDIO_DATA_ADDR   0x0
#define SDIO_TRANS_COUNT_ADDR 0x1C
#define SDIO_INIT_STATUS_ADDR 0x04
#define SDIO_INIT_STATUS_ADDR2 0x48
#define SDIO_TRANS_COUNT_ADDR2 0x49
#define SDIO_BUSY_ADDR2        0x4c
#define HGIC_PKT_MAX_LEN       (8*1024)

#define SDIO_INIT_STATUS_DATA_READY  BIT(0)
#define SDIO_INIT_STATUS_BUSY        BIT(3)

#define SDIO_STATUS_STOP   BIT(0)
#define SDIO_STATUS_ERROR  BIT(1)
#define SDIO_TX_HEADROM (4)

static hgic_probe probe_hdl = NULL;
static u32 max_pkt_len = HGIC_PKT_MAX_LEN;

struct hgic_sdio {
    struct sdio_func_t  *func;
    u32 status;
    u32 data_addr;         /*sdio data register address*/
    u32 trans_cnt_addr;    /*sdio data length register address*/
    u32 int_status_addr;   /*interrupt status register address*/
    struct hgic_bus bus;
    u8 rx_retry;
    u8 busypd;
    struct completion busy;
    u8 *rxbuf;
};

const struct sdio_device_id_t hgic_sdio_wdev_ids[] = {
    {SDIO_DEVICE(HGIC_VENDOR_ID, HGIC_WLAN_4002)},
    {SDIO_DEVICE(HGIC_VENDOR_ID, HGIC_WLAN_4104)},
    {SDIO_DEVICE(HGIC_VENDOR_ID, HGIC_WLAN_8400)},
    { /* end: all zeroes */             },
};

#ifndef __RTOS__
#ifndef SDIO_BUS_WIDTH_MASK
#define SDIO_BUS_WIDTH_MASK 3
#endif
#ifndef mmc_card_highspeed
#define mmc_card_highspeed mmc_card_hs
#endif
#ifndef mmc_card_set_highspeed
#define mmc_card_set_highspeed(func)
#endif

#define FUNC_DEV(f)    (&((f)->dev))

#define SDIO_CAP_IRQ(func)      ((func)->card->host->caps & MMC_CAP_SDIO_IRQ)
#define SDIO_CAP_POLL(func)     ((func)->card->host->caps & MMC_CAP_NEEDS_POLL)
#define HOST_SPI_CRC(func, crc) (func)->card->host->use_spi_crc=crc

//#define mmc_card_disable_cd(c)  (1)
#define hgic_card_disable_cd(func)     mmc_card_disable_cd((func)->card)
#define hgic_card_set_highspeed(func)  mmc_card_set_highspeed((func)->card)
#define hgic_host_is_spi(func)         mmc_host_is_spi((func)->card->host)
#define hgic_card_cccr_widebus(func)   ((func)->card->cccr.low_speed && !(func)->card->cccr.wide_bus)
#define hgic_card_cccr_highspeed(func) ((func)->card->cccr.high_speed)
#define hgic_host_highspeed(func)      ((func)->card->host->caps & MMC_CAP_SD_HIGHSPEED)
#define hgic_host_supp_4bit(func)      ((func)->card->host->caps & MMC_CAP_4_BIT_DATA)
#define hgic_card_highspeed(func)      mmc_card_highspeed((func)->card)
#define hgic_func_rca(func)            ((func)->card->rca)
#define hgic_card_max_clock(func)      ((func)->card->cis.max_dtr)

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,10,14)
#define hgic_card_ocr(func)            ((func)->card->host->ocr)
#else
#define hgic_card_ocr(func)            ((func)->card->ocr)
#endif

static inline void hgic_mmc_set_timing(struct sdio_func_t *func, unsigned int timing)
{
    func->card->host->ios.timing = timing;
    func->card->host->ops->set_ios(func->card->host, &func->card->host->ios);
}
static inline void hgic_mmc_set_bus_width(struct sdio_func_t *func, unsigned int width)
{
    func->card->host->ios.bus_width = width;
    func->card->host->ops->set_ios(func->card->host, &func->card->host->ios);
}
static inline void hgic_mmc_set_clock(struct sdio_func_t *func, unsigned int hz)
{
    if (func->card->host->f_max && hz > func->card->host->f_max) {
        hz = func->card->host->f_max;
    }
    func->card->host->ios.clock = hz;
    func->card->host->ops->set_ios(func->card->host, &func->card->host->ios);
}
static inline int hgic_mmc_send_cmd(struct sdio_func_t *func, struct mmc_command_t *cmd, int retries)
{
    return mmc_wait_for_cmd(func->card->host, cmd, retries);
}
static inline void hgic_mmc_set_blk_size(struct sdio_func_t *func, unsigned int blk_size)
{
    func->card->host->max_blk_size = blk_size;
    func->card->host->ops->set_ios(func->card->host, &func->card->host->ios);
}
#endif

static int hgic_mmc_io_rw_direct(struct sdio_func_t *func, int write, unsigned fn,
                                 unsigned addr, u8 in, u8 *out)
{
    struct mmc_command_t cmd = {0};
    int err;

    /* sanity check */
    if (addr & ~0x1FFFF) {
        return -EINVAL;
    }

    cmd.opcode = SD_IO_RW_DIRECT;
    cmd.arg = write ? 0x80000000 : 0x00000000;
    cmd.arg |= fn << 28;
    cmd.arg |= (write && out) ? 0x08000000 : 0x00000000;
    cmd.arg |= addr << 9;
    cmd.arg |= in;
    cmd.flags = MMC_RSP_SPI_R5 | MMC_RSP_R5 | MMC_CMD_AC;

    err = hgic_mmc_send_cmd(func, &cmd, 0);
    if (err) {
        return err;
    }

    if (hgic_host_is_spi(func)) {
        /* host driver already reported errors */
    } else {
        if (cmd.resp[0] & R5_ERROR) {
            return -EIO;
        }
        if (cmd.resp[0] & R5_FUNCTION_NUMBER) {
            return -EINVAL;
        }
        if (cmd.resp[0] & R5_OUT_OF_RANGE) {
            return -ERANGE;
        }
    }

    if (out) {
        if (hgic_host_is_spi(func)) {
            *out = (cmd.resp[0] >> 8) & 0xFF;
        } else {
            *out = cmd.resp[0] & 0xFF;
        }
    }
    return 0;
}

static int hgic_sdio_reset(struct sdio_func_t *func)
{
    int ret;
    u8 abort;

    /* SDIO Simplified Specification V2.0, 4.4 Reset for SDIO */

    ret = hgic_mmc_io_rw_direct(func, 0, 0, SDIO_CCCR_ABORT, 0, &abort);
    if (ret) {
        abort = 0x08;
    } else {
        abort |= 0x08;
    }

    ret = hgic_mmc_io_rw_direct(func, 1, 0, SDIO_CCCR_ABORT, abort, NULL);
    return ret;
}

static int hgic_sdio_go_idle(struct sdio_func_t *func)
{
    int err;
    struct mmc_command_t cmd = {0};
    cmd.opcode = MMC_GO_IDLE_STATE;
    cmd.arg = 0;
    cmd.flags = MMC_RSP_SPI_R1 | MMC_RSP_NONE | MMC_CMD_BC;
    err = hgic_mmc_send_cmd(func, &cmd, 0);
    msleep(1);
    HOST_SPI_CRC(func, 0);
    return err;
}

static int hgic_mmc_send_if_cond(struct sdio_func_t *func, u32 ocr)
{
    struct mmc_command_t cmd = {0};
    int err;
    static const u8 test_pattern = 0xAA;
    u8 result_pattern;

    /*
     * To support SD 2.0 cards, we must always invoke SD_SEND_IF_COND
     * before SD_APP_OP_COND. This command will harmlessly fail for
     * SD 1.0 cards.
     */
    cmd.opcode = SD_SEND_IF_COND;
    cmd.arg = ((ocr & 0xFF8000) != 0) << 8 | test_pattern;
    cmd.flags = MMC_RSP_SPI_R7 | MMC_RSP_R7 | MMC_CMD_BCR;

    err = hgic_mmc_send_cmd(func, &cmd, 0);
    if (err) {
        return err;
    }

    if (hgic_host_is_spi(func)) {
        result_pattern = cmd.resp[1] & 0xFF;
    } else {
        result_pattern = cmd.resp[0] & 0xFF;
    }

    if (result_pattern != test_pattern) {
        return -EIO;
    }

    return 0;
}

static int hgic_send_io_op_cond(struct sdio_func_t *func, u32 ocr, u32 *rocr)
{
    struct mmc_command_t cmd = {0};
    int i, err = 0;

    BUG_ON(!func);

    cmd.opcode = SD_IO_SEND_OP_COND;
    cmd.arg = ocr;
    cmd.flags = MMC_RSP_SPI_R4 | MMC_RSP_R4 | MMC_CMD_BCR;

    for (i = 10; i; i--) {
        err = hgic_mmc_send_cmd(func, &cmd, 3);
        if (err) {
            break;
        }

        /* if we're just probing, do a single pass */
        if (ocr == 0) {
            break;
        }

        /* otherwise wait until reset completes */
        if (hgic_host_is_spi(func)) {
            /*
             * Both R1_SPI_IDLE and MMC_CARD_BUSY indicate
             * an initialized card under SPI, but some cards
             * (Marvell's) only behave when looking at this
             * one.
             */
            if (cmd.resp[1] & MMC_CARD_BUSY) {
                break;
            }
        } else {
            if (cmd.resp[0] & MMC_CARD_BUSY) {
                break;
            }
        }

        err = -ETIMEDOUT;

        mdelay(10);
    }

    if (rocr) {
        *rocr = cmd.resp[hgic_host_is_spi(func) ? 1 : 0];
    }

    return err;
}


static int hgic_sdio_get_card_addr(struct sdio_func_t *func, u32 *rca)
{
    int err;
    struct mmc_command_t cmd = {0};
    cmd.opcode = SD_SEND_RELATIVE_ADDR;
    cmd.arg    = 0;
    cmd.flags  = MMC_RSP_R6 | MMC_CMD_BCR;
    err = hgic_mmc_send_cmd(func, &cmd, 3);
    if (err) {
        return err;
    }
    *rca = cmd.resp[0] >> 16;
    return 0;
}

static u32 hgic_sdio_set_highspeed(struct sdio_func_t *func, int enable)
{
    int ret;
    u8 speed;

    if (!hgic_host_highspeed(func)) {
        return 0;
    }

    if (!hgic_card_cccr_highspeed(func)) {
        return 0;
    }

    ret = hgic_mmc_io_rw_direct(func, 0, 0, SDIO_CCCR_SPEED, 0, &speed);
    if (ret) {
        return ret;
    }

    if (enable) {
        speed |= SDIO_SPEED_EHS;
    } else {
        speed &= ~SDIO_SPEED_EHS;
    }

    ret = hgic_mmc_io_rw_direct(func, 1, 0, SDIO_CCCR_SPEED, speed, NULL);
    if (ret) {
        return ret;
    }

    hgic_card_set_highspeed(func);
    return 1;
}

static int hgic_sdio_disable_cd(struct sdio_func_t *func)
{
    int ret;
    u8 ctrl;

    if (!hgic_card_disable_cd(func)) {
        return 0;
    }

    ret = hgic_mmc_io_rw_direct(func, 0, 0, SDIO_CCCR_IF, 0, &ctrl);
    if (ret) {
        return ret;
    }
    ctrl |= SDIO_BUS_CD_DISABLE;
    return hgic_mmc_io_rw_direct(func, 1, 0, SDIO_CCCR_IF, ctrl, NULL);
}

static int hgic_sdio_set_wire_width(struct sdio_func_t *func)
{
    int ret;
    u8 ctrl;

    if (!hgic_host_supp_4bit(func)) {
        return 0;
    }

    if (hgic_card_cccr_widebus(func)) {
        return 0;
    }

    ret = hgic_mmc_io_rw_direct(func, 0, 0, SDIO_CCCR_IF, 0, &ctrl);
    if (ret) {
        return ret;
    }

    /* set as 4-bit bus width */
    ctrl &= ~ SDIO_BUS_WIDTH_MASK;
    ctrl |= SDIO_BUS_WIDTH_4BIT;
    ret = hgic_mmc_io_rw_direct(func, 1, 0, SDIO_CCCR_IF, ctrl, NULL);
    if (ret) {
        return ret;
    }

    hgic_mmc_set_bus_width(func, MMC_BUS_WIDTH_4);
    return 1;
}

static u32 hgic_sdio_select_card(struct sdio_func_t *func, u32 rca)
{
    int err;
    struct mmc_command_t cmd = {0};

    cmd.opcode = MMC_SELECT_CARD;
    if (func) {
        cmd.arg   = rca << 16;
        cmd.flags = MMC_RSP_R1 | MMC_CMD_AC;
    } else {
        cmd.arg   = 0;
        cmd.flags = MMC_RSP_NONE | MMC_CMD_AC;
    }

    err = hgic_mmc_send_cmd(func, &cmd, 3);
    if (err) {
        return err;
    }

    return 0;
}

static int hgic_sdio_int_enable(struct sdio_func_t *func, u8 enable)
{
    u8 temp;
    u8 dat;

    if (enable) {
        dat = (1 << func->f_num) | 0x1;
    } else {
        dat = 0x1;
    }
    return hgic_mmc_io_rw_direct(func, 1, 0, SDIO_CCCR_IENx, dat, &temp);
}

static int hgic_mmc_spi_set_crc(struct sdio_func_t *func, int use_crc)
{
    struct mmc_command_t cmd = {0};
    int err;

    cmd.opcode = MMC_SPI_CRC_ON_OFF;
    cmd.flags = MMC_RSP_SPI_R1;
    cmd.arg = use_crc;

    err = hgic_mmc_send_cmd(func, &cmd, 0);
    if (!err) {
        HOST_SPI_CRC(func, use_crc);
    }
    return err;
}


static int hgic_sdio_reinit_card(struct sdio_func_t *func)
{
#ifdef CONFIG_SDIO_REINIT
    int i   = 3;
    u32 ocr = 0;
    u32 rca = 0;
    int retry = 0;
    struct hgic_sdio *sdiodev = sdio_get_drvdata(func);

    hgic_enter();
__RETRY:
    if (!sdiodev ||
        test_bit(HGIC_BUS_FLAGS_DISABLE_REINIT, &sdiodev->bus.flags) ||
        test_bit(HGIC_BUS_FLAGS_SLEEP, &sdiodev->bus.flags)) {
        hgic_err("leave, can not reinit\r\n");
        return -1;
    }
    if (retry++ > 2) {
        hgic_err("leave, reinit fail\r\n");
        return -1;
    }

    i   = 5;
    ocr = 0;
    rca = 0;
    hgic_mmc_set_clock(func, 400000);
    hgic_mmc_set_timing(func, MMC_TIMING_LEGACY);
    hgic_mmc_set_bus_width(func, MMC_BUS_WIDTH_1);

    if (!hgic_sdio_get_card_addr(func, (u32 *)&rca)) {
        hgic_sdio_select_card(func, rca);
    }

    hgic_sdio_reset(func);
    hgic_sdio_go_idle(func);
    hgic_mmc_send_if_cond(func, ocr);

    if (hgic_send_io_op_cond(func, 0, (u32 *)&ocr)) {
        goto __RETRY;
    }

    if (hgic_send_io_op_cond(func, ocr, (u32 *)&ocr)) {
        goto __RETRY;
    }

    if (hgic_host_is_spi(func)) {
        if (hgic_mmc_spi_set_crc(func, 1)) {
            goto __RETRY;
        }
    } else {
        if (hgic_sdio_get_card_addr(func, (u32 *)&rca)) {
            goto __RETRY;
        }
        if (hgic_sdio_select_card(func, rca)) {
            goto __RETRY;
        }
        if (hgic_sdio_disable_cd(func) < 0) {
            goto __RETRY;
        }
    }

    if (hgic_sdio_set_highspeed(func, 1) < 0) {
        goto __RETRY;
    }

    hgic_mmc_set_clock(func, hgic_card_highspeed(func) ? 50000000 : hgic_card_max_clock(func));
    hgic_mmc_set_timing(func, MMC_TIMING_SD_HS);
    hgic_mmc_set_blk_size(func, SDIO_BLOCK_SIZE);

    if (hgic_sdio_set_wire_width(func) < 0) {
        goto __RETRY;
    }
    if (sdio_set_block_size(func, SDIO_BLOCK_SIZE)) {
        goto __RETRY;
    }
    if (hgic_sdio_int_enable(func, 1)) {
        goto __RETRY;
    }
    if (sdio_enable_func(func)) {
        goto __RETRY;
    }

#ifndef __RTOS__
    if (func->card->host->sdio_irq_thread) {
        wake_up_process(func->card->host->sdio_irq_thread);
    }
#endif
    hgic_leave();
#endif
    return 0;
}

static int hgic_sdio_reinit(void *bus)
{
    int ret = 0;
    struct hgic_sdio *sdiodev = container_of(bus, struct hgic_sdio, bus);
    sdio_claim_host(sdiodev->func);
    ret = hgic_sdio_reinit_card(sdiodev->func);
    sdio_release_host(sdiodev->func);
    return ret;
}

static int hgic_sdio_readb(struct sdio_func_t *func, u32 addr, int *err)
{
    u8  val   = 0;
    int retry = 2;

    val = sdio_readb(func, addr, err);
    //if (val == 0) {
    //    *err = -1;
    //}

    while (*err && retry-- > 0) {
        val = sdio_readb(func, addr, err);
    }
    return val;
}

static void hgic_sdio_writeb(struct sdio_func_t *func, u8 b, u32 addr, int *err)
{
    int retry = 4;
    do {
        sdio_writeb(func, b, addr, err);
    } while (*err && retry-- > 0);
}

static int hgic_sdio_copy_fromio(struct sdio_func_t *func, u8 *dest, u32 addr, int count)
{
    int  err = 0;
    err = sdio_memcpy_fromio(func, dest, addr, count);
    if (err) {
        hgic_err("err=%d\r\n", err);
        hgic_sdio_reinit_card(func);
    }
    return err;
}

static int hgic_sdio_copy_toio(struct sdio_func_t *func, u32 addr, u8 *src, int count)
{
    int  err = 0;

    err = sdio_memcpy_toio(func, addr, src, count);
    if (err) {
        hgic_err("err=%d\r\n", err);
        if (!hgic_sdio_reinit_card(func)) {
            err = sdio_memcpy_toio(func, addr, src, count);
        }
    }
    return err;
}

static int hgic_sdio_abort(struct sdio_func_t *func)
{
    int err_ret = 0;
    struct sdio_func_t func0;
    memcpy(&func0, func, sizeof(func0));
    func0.f_num = 0;
    hgic_sdio_writeb(&func0, 1, 6, &err_ret);
    return err_ret;
}

static int hgic_sdio_read_cccr(struct sdio_func_t *func, u8 *pending)
{
    int ret = 0;
    struct sdio_func_t func0;
    memcpy(&func0, func, sizeof(func0));
    func0.f_num = 0;
    *pending = hgic_sdio_readb(&func0, 0x5, &ret);
    return ret;
}

static u32 hgic_sdio_get_datalen(struct hgic_sdio *sdiodev, u8 addr)
{
    int err = 0;
    u32 len = 0;
    u8  ret = 0;

    ret = hgic_sdio_readb(sdiodev->func, addr, &err);
    if (err) {
        return 0xffffffff;
    }

    len = ret;
    ret = hgic_sdio_readb(sdiodev->func, addr + 1, &err);
    if (err) {
        return 0xffffffff;
    }

    len |= ret << 8;
    return len;
}

static u32 hgic_sdio_data_len(struct hgic_sdio *sdiodev)
{
    int ret = 0;
    u32 len = 0;

    if (!test_bit(HGIC_BUS_FLAGS_INBOOT, &sdiodev->bus.flags)) {
        if(sdiodev->bus.dev_id == HGIC_WLAN_4002){
            len = hgic_sdio_get_datalen(sdiodev, SDIO_TRANS_COUNT_ADDR2);
        }else{
            len = sdio_readb(sdiodev->func, SDIO_TRANS_COUNT_ADDR2, &ret);
            len = len * SDIO_BLOCK_SIZE;
        }
    }

    if (len == 0 || len == 0xffffffff) {
        len = hgic_sdio_get_datalen(sdiodev, sdiodev->trans_cnt_addr);
    }

    if (len == 0) {
        if (test_bit(HGIC_BUS_FLAGS_INBOOT, &sdiodev->bus.flags)) {
            len = 16;
        } else {
            len = 0xFFFFFFFF;
            hgic_err("get len error\r\n");
        }
    }
    return len;
}

static u32 hgic_sdio_int_status(struct hgic_sdio *sdiodev, struct sdio_func_t *func)
{
    int ret = 0;
    u8 pending = 0;
    u8 int_status1 = 0;
    u8 int_status2 = 0;

    ret = hgic_sdio_read_cccr(func, &pending);
    if (!ret && (pending & 02)) {
        int_status1 = hgic_sdio_readb(func, sdiodev->int_status_addr, &ret);
        if (!ret && !int_status1 && !test_bit(HGIC_BUS_FLAGS_INBOOT, &sdiodev->bus.flags)) {
            int_status2 = hgic_sdio_readb(func, SDIO_INIT_STATUS_ADDR2, &ret);
            if (int_status1 != int_status2) {
                hgic_err("INTID(%x:%x)\r\n", int_status1, int_status2);
                int_status1 = int_status2;
            }
        }
        if (!int_status1) {
            hgic_sdio_abort(func);
        }
    }
    return int_status1;
}

static void hgic_sdio_interrupt(struct sdio_func_t *func)
{
    int ret = 0;
    u32 len = 0;
    int read_more = 0;
    u32 int_status;
    struct hgic_sdio *sdiodev = sdio_get_drvdata(func);

    if (sdiodev == NULL || (sdiodev->status & SDIO_STATUS_STOP)) {
        return;
    }
    read_more = sdiodev->rx_retry;
    do {
        int_status = hgic_sdio_int_status(sdiodev, func);
        if (int_status & SDIO_INIT_STATUS_DATA_READY) {
            read_more = sdiodev->rx_retry;
            len = hgic_sdio_data_len(sdiodev);
            if (len == 0xFFFFFFFF) {
                hgic_err("data len error\r\n");
                hgic_sdio_abort(func);
                hgic_sdio_reinit_card(func);
                return;
            } else if (len > 0) {
                if (len > max_pkt_len){
                    hgic_err("len error: %d, max:%d\r\n", len, max_pkt_len);
                    hgic_sdio_abort(func);
                    return;
                }

                ret = hgic_sdio_copy_fromio(sdiodev->func, sdiodev->rxbuf, sdiodev->data_addr, len);
                if (ret) {
                    hgic_err("sdio_copy_fromio err!, ret:%d\r\n", ret);
                    return;
                }
                ret = sdiodev->bus.rx_packet(sdiodev->bus.bus_priv, sdiodev->rxbuf, len);
                if (ret) {
                    hgic_sdio_abort(func);
                }
            } else {
                hgic_sdio_abort(func);
            }
        }

        if ((int_status & SDIO_INIT_STATUS_BUSY) && sdiodev->busypd) {
            //printk("*\r\n");
            complete(&sdiodev->busy);
        }

        if (int_status == 0 && read_more > 0) {
            udelay(20);
        }
    } while (!ret && read_more-- > 0);
}

static int hgic_sdio_is_busy(struct hgic_sdio *sdiodev)
{
    int err = 0;
    u8  val = 0;
    val = hgic_sdio_readb(sdiodev->func, SDIO_BUSY_ADDR2, &err);
    if(err) hgic_sdio_reinit_card(sdiodev->func);
    return (err || (val & 0x01)) ? 1 : 0;
}

static int hgic_sdio_tx_packet(void *bus, struct sk_buff *skb)
{
    int ret  = 0;
    int busy = 1;
    struct list_head *head;
    struct hgic_sdio *sdiodev = container_of(bus, struct hgic_sdio, bus);
    int len = skb->len > SDIO_BLOCK_SIZE ? ALIGN(skb->len, SDIO_BLOCK_SIZE) : ALIGN(skb->len, 4);

#ifndef __RTOS__
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    head = &sdiodev->func->card->host->wq.head;
    #else
    head = &sdiodev->func->card->host->wq.task_list;
    #endif
    if (!list_empty(head) /*|| (!SDIO_CAP_IRQ(sdiodev->func) && time_after(jiffies, sdiodev->last_rxtick + msecs_to_jiffies(100)))*/) {
        schedule();
    }
#endif

    sdio_claim_host(sdiodev->func);
    if ((sdiodev->status & SDIO_STATUS_STOP) || test_bit(HGIC_BUS_FLAGS_SLEEP, &sdiodev->bus.flags)) {
        sdiodev->bus.tx_complete(sdiodev->bus.bus_priv, skb, 0);
        sdio_release_host(sdiodev->func);
        return -1;
    }

    while (busy && !test_bit(HGIC_BUS_FLAGS_SOFTFC, &sdiodev->bus.flags)) {
        busy = hgic_sdio_is_busy(sdiodev);
        if (busy) {
            sdiodev->busypd = 1;
            sdio_release_host(sdiodev->func);
            wait_for_completion_timeout(&sdiodev->busy, msecs_to_jiffies(10));
            sdio_claim_host(sdiodev->func);
            sdiodev->busypd = 0;
            if ((sdiodev->status & SDIO_STATUS_STOP) || test_bit(HGIC_BUS_FLAGS_SLEEP, &sdiodev->bus.flags)) {
                sdiodev->bus.tx_complete(sdiodev->bus.bus_priv, skb, 0);
                sdio_release_host(sdiodev->func);
                return -1;
            }
        }
    }

    ret = hgic_sdio_copy_toio(sdiodev->func, sdiodev->data_addr, skb->data, len);
    sdio_release_host(sdiodev->func);
    sdiodev->bus.tx_complete(sdiodev->bus.bus_priv, skb, !ret);
    return ret;
}

static int hgic_sdio_enable(struct sdio_func_t *func)
{
    int ret;

    hgic_dbg("Enter\n");
    sdio_claim_host(func);
    hgic_mmc_set_blk_size(func, SDIO_BLOCK_SIZE);
    ret = sdio_set_block_size(func, SDIO_BLOCK_SIZE);
    if (ret) {
        hgic_err("Set sdio block size %d failed: %d)\n", SDIO_BLOCK_SIZE, ret);
        goto out;
    }
    ret = sdio_claim_irq(func, hgic_sdio_interrupt);
    if (ret) {
        hgic_err("Set sdio interrupte handle failed: %d\n", ret);
        goto out;
    }
    ret = sdio_enable_func(func);
    if (ret) {
        sdio_release_irq(func);
        hgic_err("enable sdio function failed: %d)\n", ret);
        goto out;
    }
    hgic_dbg("ok\n");

out:
    sdio_release_host(func);
    return ret;
}

static int hgic_sdio_probe(struct sdio_func_t *func, const struct sdio_device_id_t *id)
{
    int ret = 0;
    struct hgic_sdio *sdiodev = NULL;

    hgic_dbg("Enter, func->num:%d, devid:%x\r\n", func->f_num, func->device_id);
    if (func->f_num != 1) {
        return -ENODEV;
    }

    sdiodev = kzalloc(sizeof(struct hgic_sdio), GFP_KERNEL);
    if (!sdiodev) {
        return -ENOMEM;
    }

    sdiodev->rxbuf = kmalloc(max_pkt_len, GFP_KERNEL);
    if (sdiodev->rxbuf == NULL) {
        hgic_err("alloc rxbuf fail, size:%d\r\n", max_pkt_len);
        goto __failed;
    }

    hgic_dbg("new sdio card: vendor:%x, id:%x\n", id->vendor_id, id->device_id);
    sdiodev->func = func;
    sdiodev->data_addr  = SDIO_DATA_ADDR;
    sdiodev->trans_cnt_addr = SDIO_TRANS_COUNT_ADDR;
    sdiodev->int_status_addr = SDIO_INIT_STATUS_ADDR;
    //sdiodev->status = SDIO_STATUS_STOP;
    sdiodev->bus.type = HGIC_BUS_SDIO;
    sdiodev->bus.drv_tx_headroom = SDIO_TX_HEADROM;
    sdiodev->bus.tx_packet = hgic_sdio_tx_packet;
#ifdef CONFIG_SDIO_REINIT
    sdiodev->bus.reinit = hgic_sdio_reinit;
#endif
    sdiodev->bus.bootdl_pktlen = 32704;
    sdiodev->bus.bootdl_cksum = HGIC_BUS_BOOTDL_CHECK_0XFD;
    sdiodev->bus.probe = probe_hdl;
    sdiodev->bus.dev_id = id->device_id;
    sdiodev->bus.blk_size = SDIO_BLOCK_SIZE;
    sdiodev->rx_retry = SDIO_CAP_IRQ(func) ? 0 : 5;
    init_completion(&sdiodev->busy);

    if (!SDIO_CAP_POLL(func)) {
        set_bit(HGIC_BUS_FLAGS_NOPOLL, &sdiodev->bus.flags);
    }

    if (hgic_host_is_spi(func)) {
        sdiodev->bus.bootdl_pktlen = 4096;
    }

    sdiodev->bus.probe(FUNC_DEV(func), &sdiodev->bus);
    if (sdiodev->bus.bus_priv == NULL) {
        hgic_err("err\r\n");
        goto __failed;
    }

    sdio_set_drvdata(func, sdiodev);
    ret = hgic_sdio_enable(func);
    if (ret) {
        goto __failed;
    }

    //sdiodev->status &= ~SDIO_STATUS_STOP;
    if (sdiodev->bus.probe_post) {
        sdiodev->bus.probe_post(sdiodev->bus.bus_priv);
    }
    hgic_dbg("ok\n");
    return ret;

__failed:
    hgic_dbg("failed\n");
    sdio_set_drvdata(func, NULL);
    if (sdiodev->bus.remove) {
        sdiodev->bus.remove(sdiodev->bus.bus_priv);
    }
    if (sdiodev->rxbuf) {
        kfree(sdiodev->rxbuf);
    }
    kfree(sdiodev);
    hgic_dbg("failed 2\n");
    return ret;
}

static void hgic_sdio_remove(struct sdio_func_t *func)
{
    struct hgic_sdio *sdiodev = NULL;

    hgic_dbg("Enter\n");
    sdiodev = (struct hgic_sdio *)sdio_get_drvdata(func);
    if (sdiodev) {
        set_bit(HGIC_BUS_FLAGS_DISABLE_REINIT, &sdiodev->bus.flags);
        sdiodev->status |= SDIO_STATUS_STOP;
        hgic_dbg("remove ... 1\n");
        sdio_claim_host(func);
        sdio_release_irq(func);
        sdio_release_host(func);
        hgic_dbg("remove ... 2\n");
        if (sdiodev->bus.remove) {
            sdiodev->bus.remove(sdiodev->bus.bus_priv);
        }
        hgic_dbg("remove ... 3\n");
        sdio_claim_host(func);
#ifdef __RTOS__
        deinit_completion(&sdiodev->busy);
#endif
        if (sdiodev->rxbuf) {
            kfree(sdiodev->rxbuf);
        }
        sdio_set_drvdata(func, NULL);
        kfree(sdiodev);
        sdio_release_host(func);
        hgic_dbg("remove ... 4\n");
    }
    hgic_dbg("Leave\n");
}

#ifdef CONFIG_PM
static int hgic_sdio_suspend(struct device *dev)
{
    int ret = 0;
    struct sdio_func_t *func = dev_to_sdio_func(dev);
    struct hgic_sdio *sdiodev = (struct hgic_sdio *)sdio_get_drvdata(func);
    if (sdiodev->bus.suspend) {
        ret = sdiodev->bus.suspend(sdiodev->bus.bus_priv);
    }
    return ret;
}
static int hgic_sdio_resume(struct device *dev)
{
    int ret = 0;
    struct sdio_func_t *func = dev_to_sdio_func(dev);
    struct hgic_sdio *sdiodev = (struct hgic_sdio *)sdio_get_drvdata(func);
    if (sdiodev->bus.resume) {
        ret = sdiodev->bus.resume(sdiodev->bus.bus_priv);
    }
    return ret;
}
static const struct dev_pm_ops hgic_sdio_pm_ops = {
    .suspend = hgic_sdio_suspend,
    .resume  = hgic_sdio_resume,
};
#endif

#ifdef SDIO_DRIVER_EXT
extern struct sdio_driver_t hgic_sdio_driver;
#else
static struct sdio_driver_t hgic_sdio_driver = {
    .name     = "hgic_sdio_wlan",
    .id_table = hgic_sdio_wdev_ids,
    .probe    = hgic_sdio_probe,
    .remove   = hgic_sdio_remove,
#ifdef CONFIG_PM
    .drv = {
        .pm = &hgic_sdio_pm_ops,
    },
#endif
};
#endif

int __init hgic_sdio_init(hgic_probe probe, u32 max_pkt)
{
    int ret;

    hgic_dbg("Enter, max_pkt_len = %d\n", max_pkt_len);
    probe_hdl = probe;
    if(max_pkt > HGIC_PKT_MAX_LEN){
        max_pkt_len = max_pkt;
    }
    ret = sdio_register_driver(&hgic_sdio_driver);
    hgic_dbg("Leave\n");
    return ret;
}

void __exit hgic_sdio_exit(void)
{
    hgic_dbg("Enter\n");
    sdio_unregister_driver(&hgic_sdio_driver);
    hgic_dbg("Leave\n");
}

