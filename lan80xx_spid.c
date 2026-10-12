// Copyright (c) 2026 Vincent Jardin, Vincent Cruz, Free Mobile
// SPDX-License-Identifier: BSD-4-Clause
//
// lan80xx-spid: userland SPI proxy daemon for one LAN80xx PHY package.
// Owns the spidev node exclusively and serializes/multiplexes register
// access for several client applications (sw-mepa, PTP agent, debug
// tools) with sequence-level atomicity.
//
// Standalone: no MEPA/MESA/MEBA dependency, links libc only.
//
// Single-threaded epoll loop, one SPI operation in flight at a time,
// three priority queues (PTP > normal > debug), whole-device claims
// with client-supplied cleanup ops, in-daemon pipelined reads, op-log
// ring, egress timestamp FIFO drain with push to a subscriber.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>
#include <linux/gpio.h>

#include "spiproxy.h"
#include "lan80xx_regs.h"
#include "log.h"
#include "parse.h"
#include "lan80xx_spid.h"
#include "ts_fifo.h"
#include "irq.h"

#define MAX_CLIENTS    16
#define MAX_QITEMS     256
#define TRACE_RING     1024
#define RD_RING_COUNT  16       /* rmw-race read-tracking ring depth      */
#define TRACE_TAIL_MAX 64       /* trace entries returned by SPIPROXY_TRACE */
#define TRACE_LINE_MAX 64       /* max bytes one trace line emits         */
#define SIDE_COUNT     2        /* PHY sides: HOST / LINE                 */
#define USEC_PER_SEC   1000000u
#define SPI_BYTES      7        /* 3 address + 4 data                    */
#define SPI_PAD_MAX    15
#define SPI_BUF_MAX    (SPI_BYTES + SPI_PAD_MAX) /* tx/rx buffer size     */
#define SPI_WRITE_FLAG   0x80u  /* byte0 bit7: 1 = write                  */
#define SPI_ADDR_HI_MASK 0x7fu  /* valid bits of the top address byte     */
#define SPI_SLICE_SHIFT  21     /* 23-bit addr = slice<<21 | mmd<<16 | reg */
#define SPI_MMD_SHIFT    16
#define SPI_CS_DELAY_SCK 2      /* thd;ssn: CS-high >= 2 SCK periods       */
#define RST_ASSERT_US    10000  /* default HW-reset assert  (10 ms)      */
#define RST_DEASSERT_US  100000 /* default HW-reset settle  (100 ms)     */

/* MCU mailbox (MMD 0x1e) */
#define MB_CMD_ADDR    0xd800
#define MB_RESP_ADDR   0xd900
#define MB_FLAG        0xda00
#define MB_MCU_MASK    0xda01
#define MB_GUARD_LO    0xd800   /* foreign access denied while in flight */
#define MB_GUARD_HI    0xdaff
#define MB_F_BUSY      0x00000001u   /* bit0: request pending            */
#define MB_F_RESP      0x00000002u   /* bit1: response ready             */
#define MB_SET_REQ     0x00010000u   /* doorbell                         */
#define MB_CLR_REQ     0x01000000u
#define MB_CLR_RESP    0x02000000u
#define MB_HDR_LEN     4
#define MB_CRC_LEN     2
#define MB_TIMEOUT_MS  500
#ifdef SPIPROXY_FUZZ
#define MB_POLL_DELAY_US  0u      /* fuzzer: no real backoff (one spin, no HW) */
#else
#define MB_POLL_DELAY_US  1000u   /* backoff between response-flag polls       */
#endif

#define REG_NAME_BUF   32       /* reg_name() output buffer size          */

typedef struct qitem {
    struct qitem *next;
    client_t     *c;
    struct spiproxy_hdr hdr;
    uint8_t       body[SPIPROXY_MSG_MAX];
} qitem_t;

typedef struct {
    uint64_t ts;
    uint32_t cid;
    uint8_t  slice, write, mmd;
    uint16_t reg;
    uint32_t val;
} trace_ent_t;

static struct {
    const char *dev, *sock;
    int spi_fd, srv_fd, ep_fd;
    int pad, freq;
    const char *rst_line;   /* reset GPIO line name (-r), NULL = disabled */
    int         rst_fd;     /* GPIO_V2 line-request fd, -1 = unavailable  */
    client_t cl[MAX_CLIENTS];
    uint32_t next_cid;
    /* queues: 0 = high (PTP), 1 = normal, 2 = low (debug) */
    qitem_t *qh[3], *qt[3];
    qitem_t pool[MAX_QITEMS], *freel;
    int n_queued;
    /* claim */
    client_t *claim_owner;
    uint64_t  claim_deadline;
    struct spiproxy_op claim_cleanup[SPIPROXY_BATCH_MAX];
    int       claim_ncleanup;
    /* mailbox in flight (guards MB_GUARD range) */
    int       mb_inflight;
    /* op log */
    trace_ent_t ring[TRACE_RING];
    unsigned  ring_w;
    uint64_t  n_reads, n_writes, n_io_err;
    /* full event log (-L): every message, register op (including the
     * internals of multi-op operations: batches, claim cleanups, the
     * mailbox protocol traffic), claim lifecycle, client lifecycle.
     * Lines are tagged with the owning client + request seq so a
     * multi-op operation groups by seq. */
    FILE     *log;
    struct {
        uint32_t cid;       /* client owning the current execution */
        const char *comm;   /* its process name                      */
        uint32_t seq;       /* its request sequence */
        const char *tag;    /* "", "mb", "cleanup", ...              */
    } lctx;
    /* lint state: cross-client hazard detectors (see lint_op()) */
    struct { uint32_t cid; char comm[COMM_PATH_MAX]; } page_owner[SLICE_COUNT][SIDE_COUNT];
    struct { uint32_t cid; char comm[COMM_PATH_MAX]; uint64_t ts; } cor_last[SIDE_COUNT];
    struct {
        uint8_t  slice, mmd;
        uint16_t reg;
        uint32_t cid;
        char     comm[COMM_PATH_MAX];
        uint64_t ts;
    } rd_ring[RD_RING_COUNT];
    unsigned rd_w;
    uint64_t n_warns;
    volatile sig_atomic_t stop;
} g;

uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * USEC_PER_SEC + ts.tv_nsec / 1000;
}

void warn_line(const char *fmt, ...)
{
    va_list ap;
    char buf[256];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    g.n_warns++;
    log_warn("%s", buf);
}

static const char *type_name(uint8_t t)
{
    static const char *n[] = {
        "?", "READ", "WRITE", "BATCH", "CLAIM", "RELEASE", "MAILBOX",
        "STATS", "TRACE", "TSFIFO_SUB", "BER_WINDOW", "DFU", "RESET",
        "TSFIFO_UNSUB",
    };
    return t < sizeof(n) / sizeof(n[0]) ? n[t] : "?";
}

static const char *status_name(int st)
{
    static const char *n[] = {
        "OK", "EINVAL", "EIO", "EBUSY", "ETIMEDOUT", "ENOSYS", "ECRC",
    };
    return st >= 0 && st < (int)(sizeof(n) / sizeof(n[0])) ? n[st] : "?";
}

/* Symbolic name for well-known registers: appended to OP log lines so
 * the event log greps by meaning, not only by address. Returns "" when
 * unknown.
 */
static const char *reg_name(uint8_t mmd, uint16_t reg, uint32_t val,
                            int write, char buf[REG_NAME_BUF])
{
    if (mmd == LAN80XX_MMD_GLOBAL) {
        switch (reg) {
        case LAN80XX_MCU_IO_MNGT_MISC_DEVICE_ID_REG:               return " DEVICE_ID";
        case LAN80XX_MCU_IO_MNGT_MISC_DEVICE_SILICON_REVISION_REG: return " SILICON_REV";
        case LAN80XX_MCU_IO_MNGT_MISC_DEVICE_FEATURE_DISABLE_REG:  return " FEATURE_FUSES";
        case MB_MCU_MASK: return " MB_MCU_INT_MASK";
        case MB_MCU_MASK + 1: return " MB_HOST_INT_MASK";
        case MB_FLAG:
            if (write && val == MB_SET_REQ)  return " MB_FLAG doorbell";
            if (write && val == MB_CLR_REQ)  return " MB_FLAG clr-req";
            if (write && val == MB_CLR_RESP) return " MB_FLAG clr-resp";
            return " MB_FLAG";
        default:
            if (reg >= MB_CMD_ADDR && reg <= MB_CMD_ADDR + 0xff) {
                snprintf(buf, REG_NAME_BUF, " MB_REQ[%u]", reg - MB_CMD_ADDR);
                return buf;
            }
            if (reg >= MB_RESP_ADDR && reg <= MB_RESP_ADDR + 0xff) {
                snprintf(buf, REG_NAME_BUF, " MB_RESP[%u]", reg - MB_RESP_ADDR);
                return buf;
            }
        }
        return " GLOBAL";
    }
    if (mmd == LAN80XX_MMD_HOST_PMA || mmd == LAN80XX_MMD_LINE_PMA) {
        const char *side = mmd == LAN80XX_MMD_HOST_PMA ? "HOST" : "LINE";
        if (reg == 0xf0ff) {
            snprintf(buf, REG_NAME_BUF, " %s_PMA8_CMU_FF(page)", side);
        } else if ((reg & 0xff00) == 0xf000) {
            snprintf(buf, REG_NAME_BUF, " %s_PMA8_CMU_%02X", side, reg & 0xff);
        } else if ((reg & 0xff00) == 0xf100) {
            snprintf(buf, REG_NAME_BUF, " %s_PMA8_LANE_%02X", side, reg & 0xff);
        } else if (reg == 0x0001) {
            snprintf(buf, REG_NAME_BUF, " %s_PMA_STATUS1", side);
        } else {
            snprintf(buf, REG_NAME_BUF, " %s_PMA", side);
        }
        return buf;
    }
    if (mmd == LAN80XX_MMD_HOST_PCS) {
        switch (reg) {
        case LAN80XX_HOST_PCS25G_STATUS1:       return " HOST_PCS_STATUS1";
        case LAN80XX_HOST_PCS25G_BASER_STATUS1: return " HOST_BASER_STATUS1";
        case LAN80XX_HOST_PCS25G_BASER_STATUS2: return " HOST_BASER_STATUS2(CoR)";
        }
        return " HOST_PCS25G";
    }
    if (mmd == LAN80XX_MMD_MAC_LINE_PCS) {
        return reg == LAN80XX_LINE_PCS25G_STATUS1 ? " LINE_PCS_STATUS1" : " LINE_PCS";
    }
    if (mmd == LAN80XX_MMD_LINE_KR) {
        return " AN";
    }
    buf[0] = 0;
    return buf;
}

static void on_sig(int sig)
{
    (void)sig;
    g.stop = 1;
}

/*
 * SPI core. 23-bit address: slice<<21 | mmd<<16 | reg, write = 0x80 in
 * byte 0. Reads are pipelined: the response to request N is clocked
 * out during request N+1, so a logical read is one 2-transfer ioctl
 * (request, then a dummy DEVICE_ID request that collects the data).
 */
#ifndef SPIPROXY_FUZZ
static void spi_fill(uint8_t *tx, int write, uint32_t addr, uint32_t val)
{
    memset(tx, 0xff, SPI_BUF_MAX);
    tx[0] = (uint8_t)((write ? SPI_WRITE_FLAG : 0u) |
                      ((addr >> 16) & SPI_ADDR_HI_MASK));
    tx[1] = (uint8_t)(addr >> 8);
    tx[2] = (uint8_t)addr;
    if (write) {
        tx[3] = (uint8_t)(val >> 24);
        tx[4] = (uint8_t)(val >> 16);
        tx[5] = (uint8_t)(val >> 8);
        tx[6] = (uint8_t)val;
    }
}

/* Compose the 23-bit SPI address: slice<<21 | mmd<<16 | reg. */
static uint32_t spi_addr(uint8_t slice, uint8_t mmd, uint16_t reg)
{
    return (uint32_t)slice << SPI_SLICE_SHIFT |
           (uint32_t)mmd   << SPI_MMD_SHIFT   | reg;
}

int spi_write_reg(uint8_t slice, uint8_t mmd, uint16_t reg, uint32_t val)
{
    uint8_t tx[SPI_BUF_MAX], rx[SPI_BUF_MAX];
    struct spi_ioc_transfer tr = {
        .tx_buf = (unsigned long)tx, .rx_buf = (unsigned long)rx,
        .len = SPI_BYTES, .speed_hz = g.freq, .bits_per_word = 8,
    };
    spi_fill(tx, 1, spi_addr(slice, mmd, reg), val);
    if (ioctl(g.spi_fd, SPI_IOC_MESSAGE(1), &tr) < 1) {
        g.n_io_err++;
        return -1;
    }
    g.n_writes++;
    return 0;
}

int spi_read_reg(uint8_t slice, uint8_t mmd, uint16_t reg, uint32_t *val)
{
    uint8_t tx0[SPI_BUF_MAX], rx0[SPI_BUF_MAX];
    uint8_t tx1[SPI_BUF_MAX], rx1[SPI_BUF_MAX];
    /* LAN80xx reads are one-transaction-delayed: the response to
     * request N is clocked out during request N+1's data window.
     * Issue the prime and capture as two separate SPI_IOC_MESSAGE(1)
     * ioctls so the kernel spidev layer deasserts CS on the ioctl
     * boundary. The earlier batched SPI_IOC_MESSAGE(2) + cs_change=1
     * + delay_usecs form assumed the SPI controller would honour the
     * chip's thd;ssn timing (DS00006161 Table 4-23) between chained
     * transfers; some controllers do not, and reads then return
     * varying garbage across restarts. Two separate ioctls match the
     * mepa_spidev reference in Microchip's mepa_toolkit. */
    struct spi_ioc_transfer tr_prime = {
        .tx_buf = (unsigned long)tx0, .rx_buf = (unsigned long)rx0,
        .len = SPI_BYTES + g.pad, .speed_hz = g.freq,
        .bits_per_word = 8,
    };
    struct spi_ioc_transfer tr_capture = {
        .tx_buf = (unsigned long)tx1, .rx_buf = (unsigned long)rx1,
        .len = SPI_BYTES + g.pad, .speed_hz = g.freq,
        .bits_per_word = 8,
    };
    spi_fill(tx0, 0, spi_addr(slice, mmd, reg), 0);
    spi_fill(tx1, 0, spi_addr(slice, LAN80XX_MMD_GLOBAL,
                              LAN80XX_MCU_IO_MNGT_MISC_DEVICE_ID_REG), 0);
    if (ioctl(g.spi_fd, SPI_IOC_MESSAGE(1), &tr_prime) < 0) {
        g.n_io_err++;
        return -1;
    }
    if (ioctl(g.spi_fd, SPI_IOC_MESSAGE(1), &tr_capture) < 0) {
        g.n_io_err++;
        return -1;
    }
    *val = (uint32_t)rx1[3] << 24 | (uint32_t)rx1[4] << 16 |
           (uint32_t)rx1[5] << 8 | rx1[6];
    g.n_reads++;
    return 0;
}
#else   /* SPIPROXY_FUZZ: hardware-free SPI backend, responses fed by fuzzer */
/* spi_read_reg pulls its result from this fuzzer-supplied feed (set by the
 * harness before draining), so device replies -- mailbox response words,
 * register reads -- are part of the fuzz input. MB_FLAG is the exception: it
 * models the MCU handshake (see spi_read_reg) so exec_mailbox terminates after
 * a single poll pass instead of spinning to its wall-clock timeout. */
static const uint8_t *g_fuzz_spi;
static size_t g_fuzz_spi_len;
static size_t g_fuzz_spi_pos;
static unsigned g_fuzz_mb_reads;   /* MB_FLAG reads since a tx went in flight */

/* A rare feed word that makes a (non-MB_FLAG) SPI read fail, so the fuzzer can
 * drive the I/O-error and mailbox-abort cleanup paths. Chosen unlikely so it
 * never collides with real corpus feed data (keeps the input format stable). */
#define SPI_FAIL_MAGIC 0xE770FA11u

static uint32_t fuzz_spi_next(void)
{
    uint32_t v = 0;
    unsigned i;

    for (i = 0; i < 4 && g_fuzz_spi_pos < g_fuzz_spi_len; i++) {
        v |= (uint32_t)g_fuzz_spi[g_fuzz_spi_pos++] << (i * 8);
    }
    return v;   /* exhausted feed reads as 0 */
}

int spi_write_reg(uint8_t slice, uint8_t mmd, uint16_t reg, uint32_t val)
{
    (void)slice;
    (void)mmd;
    (void)reg;
    (void)val;
    g.n_writes++;
    return 0;
}

int spi_read_reg(uint8_t slice, uint8_t mmd, uint16_t reg, uint32_t *val)
{
    (void)slice;
    if (mmd == LAN80XX_MMD_GLOBAL && reg == MB_FLAG) {
        /* Model the MCU flag so exec_mailbox terminates deterministically while
         * still running one drain_queues() pass with mb_inflight set -- that
         * pass is what exercises the in-flight guard and foreign-op
         * interleaving. Before the tx (mb_inflight clear) read not-busy so it
         * starts; once in flight, read BUSY on the first poll (so it spins once
         * and drains) then RESP. A nested mailbox arriving during that drain
         * reads BUSY at its pre-check and is rejected, so the handler stays
         * non-reentrant, as on hardware. */
        if (!g.mb_inflight) {
            g_fuzz_mb_reads = 0;
            *val = 0;
        } else {
            g_fuzz_mb_reads++;
            *val = MB_F_BUSY | (g_fuzz_mb_reads >= 2 ? MB_F_RESP : 0);
        }
    } else {
        uint32_t w = fuzz_spi_next();
        if (w == SPI_FAIL_MAGIC) {
            g.n_io_err++;
            return -1;   /* fuzzer-injected read failure (mirrors a bus error) */
        }
        *val = w;
    }
    g.n_reads++;
    return 0;
}
#endif  /* SPIPROXY_FUZZ */

void trace_add(client_t *c, const struct spiproxy_op *op)
{
    trace_ent_t *e = &g.ring[g.ring_w++ % TRACE_RING];
    e->ts = now_us();
    e->cid = c ? c->id : 0;
    e->slice = op->slice;
    e->write = op->write;
    e->mmd = op->mmd;
    e->reg = op->reg;
    e->val = op->val;
}

/*
 * Lint: detect cross-client violations of the multi-op conventions
 * Only CROSS-client patterns is warned: a single client doing loose
 * L1 sequences is its own business and would be pure noise. It claims
 * self-quiet these detectors (foreign ops are queued, not executed).
 *
 *  - page-ride:  client B accesses the paged PMA8 CMU/LANE space on a
 *    page (CMU_FF) last written by client A.
 *  - cor-poach:  clear-on-read counter (BASER status2) read by B
 *    within 120 s of A's read -- B consumed A's measurement window.
 *  - rmw-race:   B writes a register that A read < 10 ms ago and has
 *    not written back yet -- A's read-modify-write is likely torn.
 */
#define LINT_COR_WINDOW_US (120ULL * USEC_PER_SEC)
#define LINT_RMW_WINDOW_US (10ULL * 1000)

static void lint_op(const struct spiproxy_op *op)
{
    uint64_t now = now_us();
    int side = op->mmd == LAN80XX_MMD_HOST_PMA ? 0 :
               op->mmd == LAN80XX_MMD_LINE_PMA ? 1 : -1;

    /* page-ride + page-owner tracking (HOST=0x09 / LINE=0x01 PMA8) */
    if (side >= 0 && (op->reg & 0xfe00) == 0xf000) {
        if (op->reg == 0xf0ff && op->write) {
            g.page_owner[op->slice][side].cid = g.lctx.cid;
            snprintf(g.page_owner[op->slice][side].comm,
                     sizeof(g.page_owner[op->slice][side].comm), "%s",
                     g.lctx.comm);
        } else if (g.page_owner[op->slice][side].cid != 0 &&
                   g.page_owner[op->slice][side].cid != g.lctx.cid) {
            warn_line("page-ride: C%u(%s) %c s%u %02x %04x on page set by C%u(%s)",
                      g.lctx.cid, g.lctx.comm, op->write ? 'W' : 'R',
                      op->slice, op->mmd, op->reg,
                      g.page_owner[op->slice][side].cid,
                      g.page_owner[op->slice][side].comm);
        }
    }
    /* cor-poach (0x0b:0x21 host / 0x03:0x21 line BASER status2) */
    if (!op->write && op->reg == LAN80XX_HOST_PCS25G_BASER_STATUS2 &&
        (op->mmd == LAN80XX_MMD_HOST_PCS || op->mmd == LAN80XX_MMD_MAC_LINE_PCS)) {
        int k = op->mmd == LAN80XX_MMD_HOST_PCS ? 0 : 1;
        if (g.cor_last[k].cid != 0 && g.cor_last[k].cid != g.lctx.cid &&
            now - g.cor_last[k].ts < LINT_COR_WINDOW_US) {
            warn_line("cor-poach: C%u(%s) R s%u %02x 0021 %llus after C%u(%s) (counters consumed)",
                      g.lctx.cid, g.lctx.comm, op->slice, op->mmd,
                      (unsigned long long)((now - g.cor_last[k].ts) / USEC_PER_SEC),
                      g.cor_last[k].cid, g.cor_last[k].comm);
        }
        g.cor_last[k].cid = g.lctx.cid;
        g.cor_last[k].ts = now;
        snprintf(g.cor_last[k].comm, sizeof(g.cor_last[k].comm), "%s",
                 g.lctx.comm);
    }
    /* rmw-race: write to a register recently read by someone else */
    if (op->write) {
        for (unsigned int i = 0; i < RD_RING_COUNT; i++) {
            if (g.rd_ring[i].cid != 0 && g.rd_ring[i].cid != g.lctx.cid &&
                g.rd_ring[i].slice == op->slice &&
                g.rd_ring[i].mmd == op->mmd && g.rd_ring[i].reg == op->reg &&
                now - g.rd_ring[i].ts < LINT_RMW_WINDOW_US) {
                warn_line("rmw-race: C%u(%s) W s%u %02x %04x %llums after R by C%u(%s)",
                          g.lctx.cid, g.lctx.comm, op->slice, op->mmd,
                          op->reg,
                          (unsigned long long)((now - g.rd_ring[i].ts) / 1000),
                          g.rd_ring[i].cid, g.rd_ring[i].comm);
                g.rd_ring[i].cid = 0;
                break;
            }
        }
    } else {
        unsigned w = g.rd_w++ % RD_RING_COUNT;
        g.rd_ring[w].slice = op->slice;
        g.rd_ring[w].mmd = op->mmd;
        g.rd_ring[w].reg = op->reg;
        g.rd_ring[w].cid = g.lctx.cid;
        g.rd_ring[w].ts = now;
        snprintf(g.rd_ring[w].comm, sizeof(g.rd_ring[w].comm), "%s",
                 g.lctx.comm);
    }
}

/* Execute one register op; returns a spiproxy_status. */
static int exec_op(client_t *c, struct spiproxy_op *op)
{
    if (op->slice >= SLICE_COUNT) {
        return SPIPROXY_EINVAL;
    }
    if (g.mb_inflight && op->mmd == LAN80XX_MMD_GLOBAL &&
        op->reg >= MB_GUARD_LO && op->reg <= MB_GUARD_HI &&
        c != NULL) {
        return SPIPROXY_EBUSY; /* mailbox region while a MB tx is in flight */
    }
    if (tsf_fenced(op)) {
        return SPIPROXY_EBUSY; /* subscribed TS FIFO: only the drainer pops */
    }
    int rc = op->write ? spi_write_reg(op->slice, op->mmd, op->reg, op->val)
                       : spi_read_reg(op->slice, op->mmd, op->reg, &op->val);
    trace_add(c, op);
    if (rc == 0) {
        lint_op(op);
        if (op->write) {
            irq_after_client_write(op);     /* the interrupt pin's registers: verified after a write */
        }
    }
    if (g.log != NULL) {
        char nb[REG_NAME_BUF];
        log_debug("C%u(%s) seq=%u OP%s%s %c s%u %02x %04x = %08x%s%s",
                 g.lctx.cid, g.lctx.comm, g.lctx.seq,
                 g.lctx.tag[0] ? " " : "", g.lctx.tag,
                 op->write ? 'W' : 'R', op->slice, op->mmd, op->reg,
                 op->val, reg_name(op->mmd, op->reg, op->val, op->write, nb),
                 rc ? " IO-ERR" : "");
    }
    return rc ? SPIPROXY_EIO : SPIPROXY_OK;
}

/* Mailbox-internal register access: logged with the "mb" tag so the
 * protocol's own traffic appears in the event log too.
 */
static int mb_rd(uint8_t slice, uint16_t reg, uint32_t *val)
{
    int rc = spi_read_reg(slice, LAN80XX_MMD_GLOBAL, reg, val);
    if (g.log != NULL) {
        char nb[REG_NAME_BUF];
        log_debug("C%u(%s) seq=%u OP mb R s%u %02x %04x = %08x%s%s",
                 g.lctx.cid, g.lctx.comm, g.lctx.seq, slice, LAN80XX_MMD_GLOBAL,
                 reg, *val, reg_name(LAN80XX_MMD_GLOBAL, reg, *val, 0, nb),
                 rc ? " IO-ERR" : "");
    }
    return rc;
}

static int mb_wr(uint8_t slice, uint16_t reg, uint32_t val)
{
    int rc = spi_write_reg(slice, LAN80XX_MMD_GLOBAL, reg, val);
    if (g.log != NULL) {
        char nb[REG_NAME_BUF];
        log_debug("C%u(%s) seq=%u OP mb W s%u %02x %04x = %08x%s%s",
                 g.lctx.cid, g.lctx.comm, g.lctx.seq, slice, LAN80XX_MMD_GLOBAL,
                 reg, val, reg_name(LAN80XX_MMD_GLOBAL, reg, val, 1, nb),
                 rc ? " IO-ERR" : "");
    }
    return rc;
}

/*
 * Mailbox transaction: CRC16-CCITT packet into 0xd800+, doorbell,
 * poll FLAG bit1 (1 ms period, the wait yields to the main loop via
 * the caller's drain hook), read response from 0xd900+, CRC check,
 * clear. The MB_GUARD range is protected from foreign ops meanwhile.
 */
static uint16_t crc16_ccitt(const uint8_t *p, size_t n)
{
    uint16_t crc = 0xffff;
    while (n--) {
        crc ^= (uint16_t)(*p++) << 8;
        for (int i = 0; i < 8; i++) {
            crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : crc << 1;
        }
    }
    return crc;
}

static void drain_queues(int budget); /* fwd: interleave during MB wait */

static int exec_mailbox(client_t *c, struct spiproxy_mb *mb,
                        const uint8_t *payload, uint8_t *resp,
                        uint16_t *resp_len)
{
    uint8_t pkt[MB_HDR_LEN + SPIPROXY_MB_MAX + MB_CRC_LEN + 3];
    uint32_t v, timeout = mb->timeout_ms ? mb->timeout_ms : MB_TIMEOUT_MS;
    uint16_t len = MB_HDR_LEN + mb->payload_len + MB_CRC_LEN, crc, wlen;
    uint64_t t_end;
    
    if (mb->payload_len > SPIPROXY_MB_MAX || mb->slice >= SLICE_COUNT) {
        return SPIPROXY_EINVAL;
    }
    /* build packet: {id, 0xff, len_le} + payload + crc16 */
    pkt[0] = mb->cmd;
    pkt[1] = 0xff;
    pkt[2] = (uint8_t)len;
    pkt[3] = (uint8_t)(len >> 8);
    memcpy(pkt + MB_HDR_LEN, payload, mb->payload_len);
    crc = crc16_ccitt(pkt, MB_HDR_LEN + mb->payload_len);
    pkt[MB_HDR_LEN + mb->payload_len] = (uint8_t)crc;
    pkt[MB_HDR_LEN + mb->payload_len + 1] = (uint8_t)(crc >> 8);

    /* MCU busy with a previous command? */
    if (mb_rd(mb->slice, MB_FLAG, &v)) {
        return SPIPROXY_EIO;
    }
    if (v & MB_F_BUSY) {
        return SPIPROXY_EBUSY;
    }
    g.mb_inflight = 1;
    /* request words (LE), length rounded to 4 */
    wlen = (len + 3) & ~3;
    for (int i = 0; i < wlen; i += 4) {
        v = (uint32_t)pkt[i] | (uint32_t)pkt[i + 1] << 8 |
            (uint32_t)pkt[i + 2] << 16 | (uint32_t)pkt[i + 3] << 24;
        if (mb_wr(mb->slice, MB_CMD_ADDR + i / 4, v)) {
            goto io_err;
        }
    }
    /* enable MCU interrupt, ring the doorbell */
    if (mb_rd(mb->slice, MB_MCU_MASK, &v) ||
        mb_wr(mb->slice, MB_MCU_MASK, v | 1) ||
        mb_wr(mb->slice, MB_FLAG, MB_SET_REQ)) {
        goto io_err;
    }
    /* wait for the response flag, interleaving other clients' ops */
    t_end = now_us() + (uint64_t)timeout * 1000;
    for (;;) {
        if (mb_rd(mb->slice, MB_FLAG, &v)) {
            goto io_err;
        }
        if (v & MB_F_RESP) {
            break;
        }
        if (now_us() > t_end) {
            mb_wr(mb->slice, MB_FLAG, MB_CLR_REQ);
            g.mb_inflight = 0;
            return SPIPROXY_ETIMEDOUT;
        }
        drain_queues(4);     /* let foreign non-MB ops through */
        usleep(MB_POLL_DELAY_US);
    }
    /* response: word0 = header */
    if (mb_rd(mb->slice, MB_RESP_ADDR, &v)) {
        goto io_err;
    }
    len = (uint16_t)(v >> 16);
    if (len < MB_HDR_LEN + MB_CRC_LEN || len > MB_HDR_LEN + SPIPROXY_MB_MAX + MB_CRC_LEN) {
        mb_wr(mb->slice, MB_FLAG, MB_CLR_RESP);
        g.mb_inflight = 0;
        return SPIPROXY_EINVAL;
    }
    pkt[0] = (uint8_t)v;
    pkt[1] = (uint8_t)(v >> 8);
    pkt[2] = (uint8_t)(v >> 16);
    pkt[3] = (uint8_t)(v >> 24);
    wlen = (len + 3) & ~3;
    for (int i = 4; i < wlen; i += 4) {
        if (mb_rd(mb->slice, MB_RESP_ADDR + i / 4, &v)) {
            goto io_err;
        }
        pkt[i] = (uint8_t)v;
        pkt[i + 1] = (uint8_t)(v >> 8);
        pkt[i + 2] = (uint8_t)(v >> 16);
        pkt[i + 3] = (uint8_t)(v >> 24);
    }
    mb_wr(mb->slice, MB_FLAG, MB_CLR_RESP);
    g.mb_inflight = 0;
    crc = (uint16_t)pkt[len - 2] | (uint16_t)pkt[len - 1] << 8;
    if (crc16_ccitt(pkt, len - MB_CRC_LEN) != crc) {
        return SPIPROXY_ECRC;
    }
    mb->cmd = pkt[0];
    *resp_len = len - MB_HDR_LEN - MB_CRC_LEN;
    memcpy(resp, pkt + MB_HDR_LEN, *resp_len);
    (void)c;
    return SPIPROXY_OK;

io_err:
    g.mb_inflight = 0;
    return SPIPROXY_EIO;
}

/*
 * Messaging
 */
static void send_resp(client_t *c, const struct spiproxy_hdr *req,
                      int status, const void *body, uint32_t blen)
{
    uint8_t msg[sizeof(struct spiproxy_hdr) + SPIPROXY_MSG_MAX];
    struct spiproxy_hdr *h = (struct spiproxy_hdr *)msg;

    h->ver = SPIPROXY_VER;
    h->type = req->type | SPIPROXY_RESP;
    h->flags = (uint16_t)status;
    h->seq = req->seq;
    h->len = blen;
    if (blen) {
        memcpy(msg + sizeof(*h), body, blen);
    }
    if (send(c->fd, msg, sizeof(*h) + blen, MSG_DONTWAIT | MSG_NOSIGNAL) < 0) {
        c->n_err++;
    }
    log_debug("C%u(%s) seq=%u RSP %s st=%s len=%u", c->id, c->comm, req->seq,
             type_name(req->type), status_name(status), blen);
}

/* Unsolicited message (seq = 0) to a subscriber.
 * Returns -1 when it could not be queued on the socket (client gone or not reading).
 */
int send_push(client_t *c, uint8_t type, const void *body, uint32_t blen)
{
    uint8_t msg[sizeof(struct spiproxy_hdr) + SPIPROXY_MSG_MAX];
    struct spiproxy_hdr *h = (struct spiproxy_hdr *)msg;

    h->ver = SPIPROXY_VER;
    h->type = type | SPIPROXY_RESP;
    h->flags = SPIPROXY_OK;
    h->seq = 0;
    h->len = blen;
    if (blen) {
        memcpy(msg + sizeof(*h), body, blen);
    }
    if (send(c->fd, msg, sizeof(*h) + blen, MSG_DONTWAIT | MSG_NOSIGNAL) < 0) {
        c->n_err++;
        return -1;
    }
    log_debug("C%u(%s) seq=0 PUSH %s len=%u", c->id, c->comm, type_name(type),
              blen);
    return 0;
}

static void claim_end(int abnormal)
{
    uint32_t id;
    const char *comm;

    if (g.claim_owner) {
        id = g.claim_owner->id;
        comm = g.claim_owner->comm;
    } else {
        id = 0;
        comm = "?";
    }

    log_debug("C%u(%s) CLAIM end %s%s", id, comm,
             abnormal ? "ABNORMAL" : "normal",
             (abnormal && g.claim_ncleanup) ? " (running cleanup ops)" : "");
    if (abnormal && g.claim_ncleanup) {
        log_warn("claim by client %u ended abnormally: running %d cleanup ops",
                 id, g.claim_ncleanup);
        g.lctx.cid = id;
        g.lctx.comm = comm;
        g.lctx.seq = 0;
        g.lctx.tag = "cleanup";
        for (int i = 0; i < g.claim_ncleanup; i++) {
            exec_op(NULL, &g.claim_cleanup[i]);
        }
        g.lctx.tag = "";
    }
    g.claim_owner = NULL;
    g.claim_ncleanup = 0;
    g.claim_deadline = 0;
}

#ifndef SPIPROXY_FUZZ
int gpio_open_line_by_name(const char *name, uint64_t flags, const char *what)
{
    char path[sizeof("/dev/gpiochip") + 11];   /* + up to 11 digits of an int */
    int fd = -1;

    for (int n = 0; n < 64 && fd < 0; n++) {
        snprintf(path, sizeof(path), "/dev/gpiochip%d", n);
        int chip = open(path, O_RDONLY | O_CLOEXEC);
        if (chip < 0)
            continue;

        struct gpiochip_info ci = {0};
        if (ioctl(chip, GPIO_GET_CHIPINFO_IOCTL, &ci) == 0) {
            for (uint32_t off = 0; off < ci.lines; off++) {
                struct gpio_v2_line_info li = {
                    .offset = off,
                };
                if (ioctl(chip, GPIO_V2_GET_LINEINFO_IOCTL, &li) ||
                    strcmp(li.name, name)) {
                    continue;
                }

                struct gpio_v2_line_request req = {
                    .offsets = { [0] = off },
                    .num_lines = 1,
                    .config.flags = flags,
                };
                strncpy(req.consumer, "lan80xx-spid",
                        sizeof(req.consumer) - 1);
                if (ioctl(chip, GPIO_V2_GET_LINE_IOCTL, &req) == 0 &&
                    req.fd >= 0) {
                    fd = req.fd;
                    log_always("%s GPIO '%s' = %s line %u",
                               what, name, ci.name, off);
                } else {
                    log_error("%s GPIO '%s' = %s line %u: request failed: %s",
                              what, name, ci.name, off, strerror(errno));
                }
                break;
            }
        }
        close(chip);
    }
    if (fd < 0)
        log_error("%s GPIO '%s' not available on any gpiochip", what, name);
    return fd;
}

static int gpio_set(int fd, int value)
{
    struct gpio_v2_line_values v = { .bits = value ? 1 : 0, .mask = 1 };

    return ioctl(fd, GPIO_V2_LINE_SET_VALUES_IOCTL, &v);
}

/* Pulse the reset line: assert (ACTIVE_HIGH -> high), hold, release
 * (low -> PHY runs), settle. Caller has ensured g.rst_fd >= 0. */
static void gpio_pulse_reset(uint32_t assert_us, uint32_t deassert_us)
{
    gpio_set(g.rst_fd, 1);
    usleep(assert_us);
    gpio_set(g.rst_fd, 0);
    usleep(deassert_us);
}
#else   /* SPIPROXY_FUZZ: hardware-free build, no GPIO reset line / v2 uapi */
static void gpio_pulse_reset(uint32_t assert_us, uint32_t deassert_us)
{
    (void)assert_us;
    (void)deassert_us;   /* unreachable: RESET is gated on g.rst_fd < 0 */
}
#endif  /* SPIPROXY_FUZZ */

static void exec_item(qitem_t *it)
{
    client_t *c = it->c;
    struct spiproxy_hdr *h = &it->hdr;

    g.lctx.cid = c->id;
    g.lctx.comm = c->comm;
    g.lctx.seq = h->seq;
    g.lctx.tag = "";
    struct spiproxy_op *ops = (struct spiproxy_op *)it->body;
    char txt[SPIPROXY_MSG_MAX];
    int st, i, n, len;

    switch (h->type) {
    case SPIPROXY_READ:
    case SPIPROXY_WRITE:
        if (h->len != sizeof(*ops)) {
            send_resp(c, h, SPIPROXY_EINVAL, NULL, 0);
            return;
        }
        ops->write = (h->type == SPIPROXY_WRITE);
        st = exec_op(c, ops);
        c->n_ops++;
        send_resp(c, h, st, ops, sizeof(*ops));
        return;
    case SPIPROXY_BATCH:
        n = (int)(h->len / sizeof(*ops));
        if (n < 1 || n > SPIPROXY_BATCH_MAX || h->len % sizeof(*ops)) {
            send_resp(c, h, SPIPROXY_EINVAL, NULL, 0);
            return;
        }
        st = SPIPROXY_OK;
        for (i = 0; i < n && st == SPIPROXY_OK; i++) {
            st = exec_op(c, &ops[i]); /* atomic: nothing interleaves */
        }
        c->n_ops += i;
        send_resp(c, h, st, ops, h->len);
        return;
    case SPIPROXY_CLAIM: {
        struct spiproxy_claim *cl = (struct spiproxy_claim *)it->body;
        if (h->len < sizeof(*cl) ||
            cl->ncleanup > SPIPROXY_BATCH_MAX ||
            h->len != sizeof(*cl) + cl->ncleanup * sizeof(*ops)) {
            send_resp(c, h, SPIPROXY_EINVAL, NULL, 0);
            return;
        }
        if (g.claim_owner && g.claim_owner != c) {
            send_resp(c, h, SPIPROXY_EBUSY, NULL, 0);
            return;
        }
        g.claim_owner = c;
        log_debug("C%u(%s) seq=%u CLAIM grant max_ms=%u ncleanup=%u", c->id,
                 c->comm, h->seq, cl->max_ms, cl->ncleanup);
        g.claim_deadline = now_us() + (uint64_t)cl->max_ms * 1000;
        g.claim_ncleanup = cl->ncleanup;
        memcpy(g.claim_cleanup, it->body + sizeof(*cl),
               cl->ncleanup * sizeof(*ops));
        send_resp(c, h, SPIPROXY_OK, NULL, 0);
        return;
    }
    case SPIPROXY_RELEASE:
        if (g.claim_owner == c) {
            claim_end(0);
        }
        send_resp(c, h, SPIPROXY_OK, NULL, 0);
        return;
    case SPIPROXY_MAILBOX: {
        struct spiproxy_mb *mb = (struct spiproxy_mb *)it->body;
        uint8_t resp[sizeof(*mb) + SPIPROXY_MB_MAX];
        uint16_t rlen = 0;
        if (h->len != sizeof(*mb) + mb->payload_len) {
            send_resp(c, h, SPIPROXY_EINVAL, NULL, 0);
            return;
        }
        st = exec_mailbox(c, mb, it->body + sizeof(*mb),
                          resp + sizeof(*mb), &rlen);
        irq_verify_pin("a mailbox transaction", 0);
        mb->payload_len = rlen;
        memcpy(resp, mb, sizeof(*mb));
        send_resp(c, h, st, resp, sizeof(*mb) + (st == SPIPROXY_OK ? rlen : 0));
        return;
    }
    case SPIPROXY_STATS: {
        len = snprintf(txt, sizeof(txt),
                       "dev=%s freq=%d pad=%d rst=%s reads=%llu writes=%llu io_err=%llu warns=%llu queued=%d claim=%u mb_inflight=%d\n",
                       g.dev, g.freq, g.pad,
                       g.rst_fd >= 0 ? (g.rst_line ? g.rst_line : "on") : "off",
                       (unsigned long long)g.n_reads,
                       (unsigned long long)g.n_writes,
                       (unsigned long long)g.n_io_err,
                       (unsigned long long)g.n_warns, g.n_queued,
                       g.claim_owner ? g.claim_owner->id : 0, g.mb_inflight);
        len += irq_stats(txt + len, sizeof(txt) - len);
        for (i = 0; i < MAX_CLIENTS; i++) {
            if (g.cl[i].used) {
                len += snprintf(txt + len, sizeof(txt) - len,
                                "client %u(%s) pid %d msgs=%llu ops=%llu err=%llu\n",
                                g.cl[i].id, g.cl[i].comm, (int)g.cl[i].pid,
                                (unsigned long long)g.cl[i].n_msgs,
                                (unsigned long long)g.cl[i].n_ops,
                                (unsigned long long)g.cl[i].n_err);
            }
        }
        len += tsf_stats(txt + len, sizeof(txt) - len);
        send_resp(c, h, SPIPROXY_OK, txt, (uint32_t)len);
        return;
    }
    case SPIPROXY_TRACE: {
        unsigned start = g.ring_w > TRACE_TAIL_MAX ? g.ring_w - TRACE_TAIL_MAX : 0, w;
        len = 0;
        for (w = start; w < g.ring_w && len < (int)sizeof(txt) - TRACE_LINE_MAX; w++) {
            trace_ent_t *e = &g.ring[w % TRACE_RING];
            len += snprintf(txt + len, sizeof(txt) - len,
                            "%llu c%u %c %u %02x %04x %08x\n",
                            (unsigned long long)e->ts, e->cid,
                            e->write ? 'W' : 'R', e->slice, e->mmd,
                            e->reg, e->val);
        }
        send_resp(c, h, SPIPROXY_OK, txt, (uint32_t)len);
        return;
    }
    case SPIPROXY_RESET: {
        struct spiproxy_reset *rq = (struct spiproxy_reset *)it->body;
        uint32_t a, d;

        if (h->len != sizeof(*rq)) {
            send_resp(c, h, SPIPROXY_EINVAL, NULL, 0);
            return;
        }
        if (g.rst_fd < 0) {     /* no reset line configured (-r) / found */
            send_resp(c, h, SPIPROXY_ENOSYS, NULL, 0);
            return;
        }
        a = rq->assert_us ? rq->assert_us : RST_ASSERT_US;
        d = rq->deassert_us ? rq->deassert_us : RST_DEASSERT_US;
        /*
         * Single-threaded loop + sole spidev owner: no SPI op is in
         * flight here, so the HW reset is atomic vs all client traffic.
         * After this the chip is fresh, so any in-flight mailbox guard
         * is moot -- clear it.
         */
        g.mb_inflight = 0;
        gpio_pulse_reset(a, d);
        log_debug("C%u(%s) seq=%u RESET hw assert=%uus deassert=%uus", c->id,
                 c->comm, h->seq, a, d);
        send_resp(c, h, SPIPROXY_OK, NULL, 0);
        /* the chip is at its defaults: the interrupt pin set up again */
        irq_verify_pin("the PHY reset", 1);
        /* the TSU configuration is gone: tell each subscriber once */
        for (i = 0; i < MAX_CLIENTS; i++) {
            for (n = 0; n < SLICE_COUNT; n++) {
                if (g.cl[i].used && tsf_subscriber((uint8_t)n) == &g.cl[i]) {
                    send_push(&g.cl[i], SPIPROXY_RESET, NULL, 0);
                    break;
                }
            }
        }
        return;
    }
    case SPIPROXY_TSFIFO_SUB:
    case SPIPROXY_TSFIFO_UNSUB: {
        struct spiproxy_tsfifo_sub *rq = (struct spiproxy_tsfifo_sub *)it->body;

        if (h->len != sizeof(*rq) || rq->slice >= SLICE_COUNT) {
            send_resp(c, h, SPIPROXY_EINVAL, NULL, 0);
            return;
        }
        if (h->type == SPIPROXY_TSFIFO_SUB) {
            st = tsf_subscribe(c, rq);
        } else if (tsf_subscriber(rq->slice) == c) {
            tsf_unsubscribe(rq->slice);
            st = SPIPROXY_OK;
        } else {
            st = SPIPROXY_EINVAL;   /* not this client's subscription */
        }
        send_resp(c, h, st, NULL, 0);
        return;
    }
    default:
        send_resp(c, h, SPIPROXY_ENOSYS, NULL, 0);
        return;
    }
}

/*
 * Queues. An item is eligible unless a foreign claim holds the device
 * (control messages from anyone stay eligible so claims can be
 * queried/released and stats keep working).
 */
static int item_eligible(qitem_t *it)
{
    if (g.claim_owner == NULL || it->c == g.claim_owner) {
        return 1;
    }
    return it->hdr.type >= SPIPROXY_CLAIM && it->hdr.type != SPIPROXY_MAILBOX;
}

static void drain_queues(int budget)
{
    int q;

    while (budget--) {
        qitem_t *it = NULL, **pp = NULL;

        tsf_tick();   /* PTP first: drain the due TS FIFOs between ops */
        for (q = 0; q < 3 && it == NULL; q++) {
            for (pp = &g.qh[q]; *pp; pp = &(*pp)->next) {
                if (item_eligible(*pp)) {
                    it = *pp;
                    *pp = it->next;
                    if (g.qt[q] == it) {
                        /* recompute tail */
                        qitem_t *t = g.qh[q];
                        while (t && t->next) {
                            t = t->next;
                        }
                        g.qt[q] = t;
                    }
                    break;
                }
            }
        }
        if (it == NULL) {
            return;
        }
        g.n_queued--;
        exec_item(it);
        it->next = g.freel;
        g.freel = it;
    }
}

static void enqueue(client_t *c, struct spiproxy_hdr *h, uint8_t *body)
{
    int q = (h->flags & 3) == SPIPROXY_PRIO_HIGH ? 0 :
            (h->flags & 3) == SPIPROXY_PRIO_LOW  ? 2 : 1;
    qitem_t *it = g.freel;

    if (it == NULL) {
        send_resp(c, h, SPIPROXY_EBUSY, NULL, 0); /* queue full */
        return;
    }
    g.freel = it->next;
    it->next = NULL;
    it->c = c;
    it->hdr = *h;
    log_debug("C%u(%s) seq=%u REQ %s prio=%u len=%u", c->id, c->comm, h->seq,
             type_name(h->type), h->flags & 3, h->len);
    memcpy(it->body, body, h->len);
    if (g.qt[q]) {
        g.qt[q]->next = it;
    } else {
        g.qh[q] = it;
    }
    g.qt[q] = it;
    g.n_queued++;
}

static void client_drop(client_t *c)
{
    int q;
    qitem_t **pp;

    if (g.claim_owner == c) {
        claim_end(1); /* abnormal: run the cleanup ops */
    }
    for (q = 0; q < SLICE_COUNT; q++) {
        if (tsf_subscriber((uint8_t)q) == c) {
            tsf_unsubscribe((uint8_t)q);
        }
    }
    for (q = 0; q < 3; q++) {
        for (pp = &g.qh[q]; *pp;) {
            if ((*pp)->c == c) {
                qitem_t *it = *pp;
                *pp = it->next;
                it->next = g.freel;
                g.freel = it;
                g.n_queued--;
            } else {
                pp = &(*pp)->next;
            }
        }
        g.qt[q] = g.qh[q];
        while (g.qt[q] && g.qt[q]->next) {
            g.qt[q] = g.qt[q]->next;
        }
    }
    epoll_ctl(g.ep_fd, EPOLL_CTL_DEL, c->fd, NULL);
    close(c->fd);
    c->used = 0;
    log_debug("C%u(%s) EVT disconnect", c->id, c->comm);
}

/*
 * Validate one received datagram and enqueue it: header version, the length
 * field vs the byte count actually received, and the payload bound. Split out
 * of client_msg() so the transport parse can be exercised without a socket
 * (see the fuzz harness). msg holds n bytes.
 */
static void client_frame(client_t *c, uint8_t *msg, size_t n)
{
    struct spiproxy_hdr *h = (struct spiproxy_hdr *)msg;

    if (n < sizeof(*h) || h->ver != SPIPROXY_VER ||
        h->len != (uint32_t)n - sizeof(*h) || h->len > SPIPROXY_MSG_MAX) {
        struct spiproxy_hdr bad = { .type = 0, .seq = 0 };
        send_resp(c, n >= sizeof(*h) ? h : &bad, SPIPROXY_EINVAL, NULL, 0);
        return;
    }
    c->n_msgs++;
    enqueue(c, h, msg + sizeof(*h));
}

static void client_msg(client_t *c)
{
    uint8_t msg[sizeof(struct spiproxy_hdr) + SPIPROXY_MSG_MAX];
    ssize_t n = recv(c->fd, msg, sizeof(msg), 0);

    if (n <= 0) {
        client_drop(c);
        return;
    }
    client_frame(c, msg, (size_t)n);
}

static void accept_client(void)
{
    struct ucred uc = { 0 };
    socklen_t ul = sizeof(uc);
    struct epoll_event ev = { .events = EPOLLIN };
    int fd = accept(g.srv_fd, NULL, NULL), i;

    if (fd < 0) {
        return;
    }
    for (i = 0; i < MAX_CLIENTS && g.cl[i].used; i++) {
        ;
    }
    if (i == MAX_CLIENTS) {
        close(fd);
        return;
    }
    getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &ul);
    g.cl[i] = (client_t){ .fd = fd, .used = 1, .id = ++g.next_cid, .pid = uc.pid };
    {
        char path[40];
        FILE *fp;
        snprintf(path, sizeof(path), "/proc/%d/comm", (int)uc.pid);
        if ((fp = fopen(path, "r")) != NULL) {
            if (fgets(g.cl[i].comm, sizeof(g.cl[i].comm), fp) != NULL) {
                g.cl[i].comm[strcspn(g.cl[i].comm, "\n")] = 0;
            }
            fclose(fp);
        }
        if (g.cl[i].comm[0] == 0) {
            snprintf(g.cl[i].comm, sizeof(g.cl[i].comm), "?");
        }
    }
    ev.data.ptr = &g.cl[i];
    epoll_ctl(g.ep_fd, EPOLL_CTL_ADD, fd, &ev);
    log_always("client %u connected (pid %d)", g.cl[i].id, (int)uc.pid);
    log_debug("C%u(%s) EVT connect pid=%d", g.cl[i].id, g.cl[i].comm, (int)uc.pid);
}

static void usage(const char *p)
{
    fprintf(stderr,
            "Usage: %s -d /dev/spidevX.Y [-s sock] [-p pad] [-f hz]\n"
            "  -d  spidev of the LAN80xx package (required)\n"
            "  -s  listening socket (default %s)\n"
            "  -p  SPI padding bytes for reads (default 1)\n"
            "  -f  SPI clock in Hz (default 5000000)\n"
            "  -r  reset GPIO line NAME (e.g. lan8023-rst) -- enables the\n"
            "      SPIPROXY_RESET op (HW reset pulse); off if absent\n"
            "  -L  full event log to <file> ('-' = stderr): every message,\n"
            "      register op (incl. batch/claim-cleanup/mailbox internals),\n"
            "      claim + client lifecycle\n"
            "  -i  TS FIFO drain by interrupt: none, auto, only\n"
            "  -g  CPU GPIO NAME with the LAN80xx pin interrupt (default %s:a = INTR_A)\n"
            "  -w  auto mode's polling tail in ms (default %u)\n",
            p, SPIPROXY_SOCK, IRQ_LINE_DEFAULT, IRQ_IDLE_DEFAULT_MS);
}

#ifndef SPIPROXY_FUZZ
int main(int argc, char **argv)
{
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    struct epoll_event ev = { .events = EPOLLIN }, evs[8];
    uint32_t id = 0;
    int o, i, mode = 0;
    unsigned long v;
    static int irq_tag;     /* epoll tag of the interrupt line */

    g.sock = SPIPROXY_SOCK;
    g.pad = 1;
    g.freq = 5000000;
    g.rst_fd = -1;
    while ((o = getopt(argc, argv, "d:s:p:f:r:L:i:g:w:h")) != -1) {
        switch (o) {
        case 'd': g.dev = optarg; break;
        case 'i':
            if (irq_set_mode(optarg)) {
                fprintf(stderr, "-i: none, auto or only\n");
                return EXIT_FAILURE;
            }
            break;
        case 'g':
            irq_set_line(optarg);
            break;
        case 'w':
            if (!parse_uint(optarg, 10, 1, 60000, &v)) {
                return EXIT_FAILURE;
            }
            irq_set_idle_ms((uint32_t)v);
            break;
        case 's': g.sock = optarg; break;
        case 'p':
            if (!parse_uint(optarg, 10, 0, SPI_PAD_MAX, &v)) {
                return EXIT_FAILURE;
            }
            g.pad = (int)v;
            break;
        case 'f':
            if (!parse_uint(optarg, 10, 1, INT_MAX, &v)) {
                return EXIT_FAILURE;
            }
            g.freq = (int)v;
            break;
        case 'r': g.rst_line = optarg; break;
        case 'L':
            g.log = strcmp(optarg, "-") ? fopen(optarg, "w") : stderr;
            if (g.log == NULL) {
                perror(optarg);
                return EXIT_FAILURE;
            }
            break;
        default: usage(argv[0]); return EXIT_FAILURE;
        }
    }
    g.lctx.tag = "";
    if (g.dev == NULL) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    log_open("lan80xx-spid", g.log);
    if ((g.spi_fd = open(g.dev, O_RDWR)) < 0) {
        log_error("%s: %s", g.dev, strerror(errno));
        return EXIT_FAILURE;
    }
    if (flock(g.spi_fd, LOCK_EX | LOCK_NB)) {
        log_error("%s: already locked (another owner?)", g.dev);
        return EXIT_FAILURE;
    }
    ioctl(g.spi_fd, SPI_IOC_WR_MODE, &mode);
    /* startup sanity: DEVICE_ID must answer on slice 0 */
    if (spi_read_reg(0, LAN80XX_MMD_GLOBAL, LAN80XX_MCU_IO_MNGT_MISC_DEVICE_ID_REG, &id) || (id & 0xff00) != 0x8000) {
        log_warn("DEVICE_ID read %#x -- PHY not answering?", id);
    } else {
        log_always("%s: LAN80xx DEVICE_ID %#06x", g.dev, id);
    }

    /* Optional HW reset line (-r <line-name>): enables SPIPROXY_RESET. */
    if (g.rst_line)
        g.rst_fd = gpio_open_line_by_name(g.rst_line, GPIO_V2_LINE_FLAG_OUTPUT, "reset");

    /* The TS FIFO interrupt line (-i auto|only, -g): without it, polling. */
    irq_open();

    strncpy(sa.sun_path, g.sock, sizeof(sa.sun_path) - 1);
    unlink(g.sock);
    g.srv_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (bind(g.srv_fd, (struct sockaddr *)&sa, sizeof(sa)) ||
        listen(g.srv_fd, 8)) {
        log_error("%s: %s", g.sock, strerror(errno));
        return EXIT_FAILURE;
    }
    g.ep_fd = epoll_create1(EPOLL_CLOEXEC);
    ev.data.ptr = NULL; /* NULL = listening socket */
    epoll_ctl(g.ep_fd, EPOLL_CTL_ADD, g.srv_fd, &ev);
    if (irq_fd() >= 0) {
        struct epoll_event iev = { .events = EPOLLIN, .data.ptr = &irq_tag };   /* &irq_tag = the interrupt line */
        epoll_ctl(g.ep_fd, EPOLL_CTL_ADD, irq_fd(), &iev);
    }
    for (i = 0; i < MAX_QITEMS - 1; i++) {
        g.pool[i].next = &g.pool[i + 1];
    }
    g.freel = &g.pool[0];
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    signal(SIGPIPE, SIG_IGN);
    log_always("lan80xx-spid: %s @%d Hz pad %d, socket %s",
               g.dev, g.freq, g.pad, g.sock);

    while (!g.stop) {
        int timeout = g.n_queued ? 0 : (g.claim_owner ? 100 : -1);
        int tsf = tsf_timeout_ms();
        if (tsf >= 0 && (timeout < 0 || tsf < timeout)) {
            timeout = tsf;
        }
        int n = epoll_wait(g.ep_fd, evs, 8, timeout);
        for (i = 0; i < n; i++) {
            if (evs[i].data.ptr == NULL) {
                accept_client();
            } else if (evs[i].data.ptr == &irq_tag) {
                irq_service();
            } else {
                client_msg(evs[i].data.ptr);
            }
        }
        if (g.claim_owner && now_us() > g.claim_deadline) {
            log_warn("claim by client %u expired", g.claim_owner->id);
            log_debug("C%u CLAIM expired", g.claim_owner->id);
            claim_end(1);
        }
        drain_queues(64);
    }
    irq_exit();
    unlink(g.sock);
    log_always("lan80xx-spid: exit");
    log_close();
    return EXIT_SUCCESS;
}
#endif  /* SPIPROXY_FUZZ */
