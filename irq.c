// Copyright (c) 2026 Vincent Jardin, Vincent Cruz, Free Mobile
// SPDX-License-Identifier: BSD-4-Clause
//
// lan80xx-spid: the LAN80xx pin interrupt (INTR_A or INTR_B) and the SoC GPIO
// line wired to it, for the TS FIFO drain (-i -g -w).

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/gpio.h>

#include "irq.h"
#include "lan80xx_regs.h"
#include "lan80xx_spid.h"
#include "log.h"
#include "ts_fifo.h"

#define IRQ_MMD_LINE           0x01u        /* LINE_INTR_CTRL (and PMA), per slice */
#define IRQ_MMD_GLOBAL         0x1eu        /* GPIO_CTRL + GLOBAL: chip-wide, addressed on slice 0 */
#define IRQ_REG_EGR_INT_STATUS 0x9058u      /* 1588 block (LAN80XX_MMD_PTP), per slice; write 1 to clear */
#define IRQ_REG_EGR_INT_MASK   0x9059u
#define IRQ_REG_LINE_INTR_EN   0xc010u      /* + pin */
#define IRQ_REG_LINE_INTR_STAT 0xc012u      /* + pin */
#define IRQ_LINE_PTP_TSU_EGR   0x00000004u  /* bit 2 */
#define IRQ_REG_GPIO_CFG1      0xf200u      /* GPIO 32..39: bit (n - 32); output enable */
#define IRQ_REG_GPIO_OUT_INV1  0xf202u      /* 1 = inverted: the aggregate interrupt is active high by default */
#define IRQ_REG_GPIO_FUN_SEL1  0xf20au      /* 0 = alternate function, 1 = plain GPIO */
#define IRQ_REG_INTR_SRC_EN    0xf20eu      /* + pin */
#define IRQ_REG_INTR_STAT      0xf210u      /* + pin */
#define IRQ_SRC_CHIP_WIDE      0x00ff0000u  /* INTR_SRC_EN bits 16-23: MCU mailbox/ECC/WDT, GPIO, cross-connect, PTP LTC/STI */
#define IRQ_REG_IO_PAD_CTRL    0x0280u      /* + GPIO number */
#define IRQ_PAD_PUPD_OVR       0x00000004u  /* pad pull override (the driver clears it for an alt function) */
#define IRQ_PAD_PUPD_EN        0x00000003u
#define IRQ_GPIO_INTR_A        34u          /* INTR_A; INTR_B = 35 */

#define IRQ_SERVICE_ROUNDS     8            /* passes over the slices while the line stays asserted */
#define IRQ_OTHER_LOG_US       60000000u    /* "asserted by another source" logged once a minute */

/* Interrupt-driven drain: the daemon's settings and counters (-i -g -w) */
static struct irq_state {
    enum irq_mode mode;
    const char   *line;         /* SoC GPIO line name */
    unsigned      pin;          /* 0 = INTR_A (GPIO34), 1 = INTR_B (GPIO35) */
    int           fd;           /* GPIO v2 line request, falling-edge events; -1 = polling */
    uint32_t      idle_us;      /* auto: the polling tail */
    uint64_t      n_events;     /* edge events read */
    uint64_t      n_other_src;  /* the line stayed asserted with no TS FIFO status */
    uint64_t      n_missed;     /* entries found by the safety check, not by an interrupt */
    uint64_t      n_held;       /* safety reads that found the line held with no edge since the last one:
                                 * another source on the pin, the chip-wide bits cleared again */
    uint64_t      n_reapply;    /* the pin's configuration found moved (reset, mailbox, a client write) and set up again */
    uint64_t      other_log_us;
    int           armed[SLICE_COUNT];   /* the chip routes the slice's TS level to the pin */
} g_irq = { .line = IRQ_LINE_DEFAULT, .fd = -1, .idle_us = IRQ_IDLE_DEFAULT_MS * 1000u };

const char *irq_mode_name(enum irq_mode m)
{
    return m == IRQ_AUTO ? "auto" : m == IRQ_ONLY ? "only" : "none";
}

/* -i none|auto|only; -1 for another name */
int irq_set_mode(const char *name)
{
    static const char *const names[] = { [IRQ_NONE] = "none", [IRQ_AUTO] = "auto", [IRQ_ONLY] = "only" };

    for (unsigned m = 0; m < sizeof(names) / sizeof(names[0]); m++) {
        if (!strcmp(name, names[m])) {
            g_irq.mode = (enum irq_mode)m;
            return 0;
        }
    }
    return -1;
}

/* -g <line>[:a|:b] */
void irq_set_line(char *arg)
{
    char *sep = strrchr(arg, ':');

    if (sep != NULL && (sep[1] == 'a' || sep[1] == 'b') && sep[2] == '\0') {
        g_irq.pin = (sep[1] == 'b') ? 1u : 0u;
        *sep = '\0';
    }
    if (arg[0] != '\0') g_irq.line = arg;
}

/* -w <ms> */
void irq_set_idle_ms(uint32_t ms)
{
    g_irq.idle_us = ms * 1000u;
}

int irq_fd(void)
{
    return g_irq.fd;
}

enum irq_mode irq_mode(void)
{
    return g_irq.mode;
}

/* An interrupt mode with its line open */
int irq_active(void)
{
    return g_irq.mode != IRQ_NONE && g_irq.fd >= 0;
}

uint32_t irq_idle_us(void)
{
    return g_irq.idle_us;
}

uint64_t irq_events(void)
{
    return g_irq.n_events;
}

static int gpio_get(int fd);    /* the interrupt line's level, below */

/* Interrupt-path register access, logged with the "tsfifo-irq" tag */
static int irq_rd(uint8_t slice, uint8_t mmd, uint16_t reg, uint32_t *val)
{
    struct spiproxy_op op = { .slice = slice, .mmd = mmd, .reg = reg };
    int rc = spi_read_reg(slice, mmd, reg, &op.val);

    trace_add(NULL, &op);
    log_debug("C0 seq=0 OP tsfifo-irq R s%u %02x %04x = %08x%s", slice, mmd, reg, op.val,
              rc ? " IO-ERR" : "");
    if (rc) {
        io_err_warn("tsfifo-irq", &op);
        return rc;
    }
    *val = op.val;
    return 0;
}

static int irq_wr(uint8_t slice, uint8_t mmd, uint16_t reg, uint32_t val)
{
    struct spiproxy_op op = { .slice = slice, .write = 1, .mmd = mmd, .reg = reg, .val = val };
    int rc = spi_write_reg(slice, mmd, reg, val);

    trace_add(NULL, &op);
    log_debug("C0 seq=0 OP tsfifo-irq W s%u %02x %04x = %08x%s", slice, mmd, reg, val,
              rc ? " IO-ERR" : "");
    if (rc) {
        io_err_warn("tsfifo-irq", &op);
    }
    return rc;
}

/* Write-Read-Modify of one register: bits set, bits cleared */
static int irq_wrm(uint8_t slice, uint8_t mmd, uint16_t reg, uint32_t set, uint32_t clr)
{
    uint32_t v;

    if (irq_rd(slice, mmd, reg, &v)) {
        return -1;
    }
    return irq_wr(slice, mmd, reg, (v & ~clr) | set);
}

/* Clear a slice's TS level and overflow status. A failed write leaves the
 * level set, so no edge comes: the next safety read drains and clears it. */
void irq_ts_ack(uint8_t s)
{
    (void)irq_wr(s, LAN80XX_MMD_PTP, IRQ_REG_EGR_INT_STATUS, IRQ_EGR_TS_LEVEL | IRQ_EGR_TS_OVERFLOW);
}

/* -1 when an access failed */
static int irq_chip_wide_off(const char *when)
{
    uint32_t en = 0, st = 0;
    int err;

    if (irq_rd(0, IRQ_MMD_GLOBAL, (uint16_t)(IRQ_REG_INTR_SRC_EN + g_irq.pin), &en)) {
        return -1;
    }
    if (!(en & IRQ_SRC_CHIP_WIDE)) {
        return 0;
    }
    (void)irq_rd(0, IRQ_MMD_GLOBAL, (uint16_t)(IRQ_REG_INTR_STAT + g_irq.pin), &st);
    err = irq_wrm(0, IRQ_MMD_GLOBAL, (uint16_t)(IRQ_REG_INTR_SRC_EN + g_irq.pin), 0, IRQ_SRC_CHIP_WIDE);
    log_warn("INTR_%c: chip-wide sources %#x back on the pin (INTR_STAT %#x) at %s: %s",
             'A' + (char)g_irq.pin, en & IRQ_SRC_CHIP_WIDE, st, when,
             err ? "still on (SPI error)" : "off again");
    return err;
}

/* Route a subscribed slice's TS level interrupt to the pin (or undo it);
 * -1 when an access failed. */
int irq_slice_arm(uint8_t s, int on)
{
    const uint32_t src_bit = 1u << (8u + 2u * s + g_irq.pin);
    uint32_t st = 0;
    int err = 0;

    if (g_irq.mode == IRQ_NONE || g_irq.fd < 0 || (!on && !g_irq.armed[s])) {
        return 0;
    }
    if (on) {
        err |= irq_wrm(s, LAN80XX_MMD_PTP, IRQ_REG_EGR_INT_MASK, IRQ_EGR_TS_LEVEL, 0);
        err |= irq_wrm(s, IRQ_MMD_LINE, (uint16_t)(IRQ_REG_LINE_INTR_EN + g_irq.pin), IRQ_LINE_PTP_TSU_EGR, 0);
        err |= irq_wrm(0, IRQ_MMD_GLOBAL, (uint16_t)(IRQ_REG_INTR_SRC_EN + g_irq.pin), src_bit, 0);
        err |= irq_chip_wide_off("the subscription");
        irq_ts_ack(s);
        (void)irq_rd(s, LAN80XX_MMD_PTP, IRQ_REG_EGR_INT_MASK, &st);
        log_msg(err ? LOG_WARNING : LOG_NOTICE,
                "TS FIFO s%u: level interrupt routed to INTR_%c (EGR_INT_MASK %#x, LINE_INTR_EN bit 2, INTR_SRC_EN bit %u)%s",
                s, 'A' + (char)g_irq.pin, st, 8u + 2u * s + g_irq.pin, err ? ": incomplete (SPI error)" : "");
    } else {
        err |= irq_wrm(0, IRQ_MMD_GLOBAL, (uint16_t)(IRQ_REG_INTR_SRC_EN + g_irq.pin), 0, src_bit);
        err |= irq_wrm(s, IRQ_MMD_LINE, (uint16_t)(IRQ_REG_LINE_INTR_EN + g_irq.pin), 0, IRQ_LINE_PTP_TSU_EGR);
        /* the 1588 mask bit stays: the PTP daemon's MEPA instance set it too */
    }
    g_irq.armed[s] = on;
    return err;
}

/* 1 when the slice is routed and its TS level or overflow status is set */
int irq_ts_status(uint8_t s, uint32_t *st)
{
    if (!g_irq.armed[s] || irq_rd(s, LAN80XX_MMD_PTP, IRQ_REG_EGR_INT_STATUS, st)) {
        return 0;
    }
    return (*st & (IRQ_EGR_TS_LEVEL | IRQ_EGR_TS_OVERFLOW)) != 0;
}

/* The line's level: 0 asserted, 1 released (no line: released) */
int irq_line_level(void)
{
    return (g_irq.fd >= 0) ? gpio_get(g_irq.fd) : 1;
}

/* A safety read found the line held with no edge since the previous one */
void irq_line_held(void)
{
    g_irq.n_held++;
    (void)irq_chip_wide_off("a safety read with the line held");
}

/* Entries found by a safety read, not by an interrupt */
void irq_missed(uint64_t rows)
{
    g_irq.n_missed += rows;
}

/* At exit: the routed slices un-routed */
void irq_exit(void)
{
    for (uint8_t s = 0; s < SLICE_COUNT; s++) {
        if (g_irq.armed[s]) {
            const int err = irq_slice_arm(s, 0);

            irq_ts_ack(s);
            log_msg(err ? LOG_WARNING : LOG_NOTICE, "TS FIFO s%u: %s INTR_%c at exit%s", s,
                    err ? "still routed to" : "un-routed from", 'A' + (char)g_irq.pin,
                    err ? " (SPI error)" : "");
        }
    }
}

/* The STATS line of the interrupt drain */
int irq_stats(char *buf, size_t len)
{
    return snprintf(buf, len,
                    "tsfifo irq=%s line=%s pin=INTR_%c fd=%d events=%llu other_src=%llu missed=%llu held=%llu reapplied=%llu idle_ms=%u\n",
                    irq_mode_name(g_irq.mode), g_irq.line ? g_irq.line : "-", 'A' + (char)g_irq.pin,
                    g_irq.fd, (unsigned long long)g_irq.n_events,
                    (unsigned long long)g_irq.n_other_src, (unsigned long long)g_irq.n_missed, (unsigned long long)g_irq.n_held,
                    (unsigned long long)g_irq.n_reapply, g_irq.idle_us / 1000u);
}

#ifndef SPIPROXY_FUZZ
static void irq_pin_setup(void)
{
    const unsigned gpio = IRQ_GPIO_INTR_A + g_irq.pin;
    const uint32_t bit = 1u << (gpio - 32u);
    uint32_t fun = 0, cfg = 0, inv = 0;
    int err = 0;

    err |= irq_wrm(0, IRQ_MMD_GLOBAL, (uint16_t)(IRQ_REG_IO_PAD_CTRL + gpio), 0, IRQ_PAD_PUPD_OVR | IRQ_PAD_PUPD_EN);
    err |= irq_wrm(0, IRQ_MMD_GLOBAL, IRQ_REG_GPIO_CFG1, bit, 0);
    err |= irq_wrm(0, IRQ_MMD_GLOBAL, IRQ_REG_GPIO_OUT_INV1, bit, bit);
    err |= irq_wrm(0, IRQ_MMD_GLOBAL, IRQ_REG_GPIO_FUN_SEL1, 0, bit);
    err |= irq_wrm(0, IRQ_MMD_GLOBAL, (uint16_t)(IRQ_REG_INTR_SRC_EN + g_irq.pin), 0, IRQ_SRC_CHIP_WIDE);
    for (unsigned p = 0; p < 2; p++) {
        for (uint8_t s = 0; s < SLICE_COUNT; s++) {
            err |= irq_wrm(0, IRQ_MMD_GLOBAL, (uint16_t)(IRQ_REG_INTR_SRC_EN + p), 0, 1u << (8u + 2u * s + p));
            err |= irq_wrm(s, IRQ_MMD_LINE, (uint16_t)(IRQ_REG_LINE_INTR_EN + p), 0, IRQ_LINE_PTP_TSU_EGR);
        }
    }
    (void)irq_rd(0, IRQ_MMD_GLOBAL, IRQ_REG_GPIO_FUN_SEL1, &fun);
    (void)irq_rd(0, IRQ_MMD_GLOBAL, IRQ_REG_GPIO_CFG1, &cfg);
    (void)irq_rd(0, IRQ_MMD_GLOBAL, IRQ_REG_GPIO_OUT_INV1, &inv);
    log_msg(err ? LOG_WARNING : LOG_NOTICE,
            "TS FIFO interrupt: GPIO%u = INTR_%c as the aggregate interrupt output, inverted = active low (FUN_SEL %#x, CFG %#x, OUT_INV %#x)%s",
            gpio, 'A' + (char)g_irq.pin, fun, cfg, inv, err ? ": incomplete (SPI error)" : "");
}

void irq_verify_pin(const char *why, int full)
{
    const unsigned gpio = IRQ_GPIO_INTR_A + g_irq.pin;
    const uint32_t bit = 1u << (gpio - 32u);
    uint32_t src = 0, v = 0, want = 0;
    char moved[200];
    int n = 0;

#define MOVED(...) do { if (n >= 0 && n < (int)sizeof(moved)) { \
        n += snprintf(moved + n, sizeof(moved) - (size_t)n, __VA_ARGS__); } } while (0)

    if (g_irq.mode == IRQ_NONE || g_irq.fd < 0) {
        return;
    }
    for (uint8_t s = 0; s < SLICE_COUNT; s++) {
        if (tsf_subscriber(s) != NULL) {
            want |= 1u << (8u + 2u * s + g_irq.pin);
        }
    }
    if (irq_rd(0, IRQ_MMD_GLOBAL, (uint16_t)(IRQ_REG_INTR_SRC_EN + g_irq.pin), &src)) {
        return;
    }
    if ((src & IRQ_SRC_CHIP_WIDE) || (src & want) != want) {
        MOVED(" INTR_SRC_EN %#x", src);
    }
    if (full) {
        if (irq_rd(0, IRQ_MMD_GLOBAL, IRQ_REG_GPIO_FUN_SEL1, &v) == 0 && (v & bit)) {
            MOVED(" FUN_SEL1 %#x", v);
        }
        if (irq_rd(0, IRQ_MMD_GLOBAL, IRQ_REG_GPIO_CFG1, &v) == 0 && !(v & bit)) {
            MOVED(" CFG1 %#x", v);
        }
        if (irq_rd(0, IRQ_MMD_GLOBAL, IRQ_REG_GPIO_OUT_INV1, &v) == 0 && !(v & bit)) {
            MOVED(" OUT_INV1 %#x", v);
        }
        for (uint8_t s = 0; s < SLICE_COUNT; s++) {
            if (tsf_subscriber(s) == NULL) {
                continue;
            }
            if (irq_rd(s, IRQ_MMD_LINE, (uint16_t)(IRQ_REG_LINE_INTR_EN + g_irq.pin), &v) == 0 && !(v & IRQ_LINE_PTP_TSU_EGR)) {
                MOVED(" s%u LINE_INTR_EN %#x", s, v);
            }
            if (irq_rd(s, LAN80XX_MMD_PTP, IRQ_REG_EGR_INT_MASK, &v) == 0 && !(v & IRQ_EGR_TS_LEVEL)) {
                MOVED(" s%u EGR_INT_MASK %#x", s, v);
            }
        }
    }
#undef MOVED
    if (n <= 0) {
        return;
    }
    g_irq.n_reapply++;
    log_warn("INTR_%c: the pin's configuration moved after %s:%s -- set up again (%llu times)",
             'A' + (char)g_irq.pin, why, moved, (unsigned long long)g_irq.n_reapply);
    irq_pin_setup();
    tsf_irq_rearm();
}

void irq_after_client_write(const struct spiproxy_op *op)
{
    const unsigned gpio = IRQ_GPIO_INTR_A + g_irq.pin;
    char why[48];
    int owned = 0;

    if (g_irq.mode == IRQ_NONE || g_irq.fd < 0) {
        return;
    }
    if (op->mmd == IRQ_MMD_GLOBAL && op->slice == 0) {
        owned = op->reg == IRQ_REG_GPIO_CFG1 || op->reg == IRQ_REG_GPIO_OUT_INV1 ||
                op->reg == IRQ_REG_GPIO_FUN_SEL1 ||
                op->reg == (uint16_t)(IRQ_REG_INTR_SRC_EN + g_irq.pin) ||
                op->reg == (uint16_t)(IRQ_REG_IO_PAD_CTRL + gpio);
    } else if (op->mmd == IRQ_MMD_LINE) {
        owned = op->reg == (uint16_t)(IRQ_REG_LINE_INTR_EN + g_irq.pin);
    } else if (op->mmd == LAN80XX_MMD_PTP) {
        owned = op->reg == IRQ_REG_EGR_INT_MASK;
    }
    if (!owned) {
        return;
    }
    (void)snprintf(why, sizeof(why), "a client write to %02x:%04x", op->mmd, op->reg);
    irq_verify_pin(why, 1);
}

static int gpio_get(int fd)
{
    struct gpio_v2_line_values v = { .mask = 1 };

    if (ioctl(fd, GPIO_V2_LINE_GET_VALUES_IOCTL, &v)) {
        return -1;
    }
    return (int)(v.bits & 1);
}

void irq_service(void)
{
    struct gpio_v2_line_event ev;
    uint64_t now;
    int worked, level;

    while (read(g_irq.fd, &ev, sizeof(ev)) == (ssize_t)sizeof(ev)) {
        g_irq.n_events++;
    }
    for (int round = 0; round < IRQ_SERVICE_ROUNDS; round++) {
        now = now_us();
        worked = tsf_irq_drain(now);
        level = gpio_get(g_irq.fd);
        if (level != 0) {           /* released (1), or unreadable (-1) */
            return;
        }
        if (!worked) {
            uint32_t pin_st = 0, l0 = 0, l1 = 0;

            (void)irq_chip_wide_off("an asserted line with no TS FIFO status");
            g_irq.n_other_src++;
            if (now - g_irq.other_log_us >= IRQ_OTHER_LOG_US) {
                (void)irq_rd(0, IRQ_MMD_GLOBAL, (uint16_t)(IRQ_REG_INTR_STAT + g_irq.pin), &pin_st);
                (void)irq_rd(0, IRQ_MMD_LINE, (uint16_t)(IRQ_REG_LINE_INTR_STAT + g_irq.pin), &l0);
                (void)irq_rd(1, IRQ_MMD_LINE, (uint16_t)(IRQ_REG_LINE_INTR_STAT + g_irq.pin), &l1);
                warn_line("INTR_%c stays asserted with no TS FIFO status: another source (INTR_STAT %#x, LINE_INTR_STAT s0 %#x s1 %#x; %llu times)",
                          'A' + (char)g_irq.pin, pin_st, l0, l1, (unsigned long long)g_irq.n_other_src);
                g_irq.other_log_us = now;
            }
            return;
        }
    }
}

/* The TS FIFO interrupt line (-i auto|only, -g): without it, polling. */
void irq_open(void)
{
    if (g_irq.mode == IRQ_NONE) {
        return;
    }
    g_irq.fd = gpio_open_line_by_name(g_irq.line, GPIO_V2_LINE_FLAG_INPUT | GPIO_V2_LINE_FLAG_EDGE_FALLING,
                                      "TS FIFO interrupt");
    if (g_irq.fd < 0) {
        log_warn("TS FIFO drain mode %s without an interrupt line: polling at the subscription's period",
                 irq_mode_name(g_irq.mode));
        return;
    }
    (void)fcntl(g_irq.fd, F_SETFL, fcntl(g_irq.fd, F_GETFL) | O_NONBLOCK);
    irq_pin_setup();
    log_always("TS FIFO drain: interrupt mode %s on '%s' (INTR_%c), auto tail %u ms, safety check every %u ms",
               irq_mode_name(g_irq.mode), g_irq.line, 'A' + (char)g_irq.pin,
               g_irq.idle_us / 1000u, IRQ_SAFETY_POLL_US / 1000u);
}
#else
void irq_service(void)
{
}

static int gpio_get(int fd)
{
    (void)fd;
    return 1;    /* no line: released */
}

void irq_verify_pin(const char *why, int full)
{
    (void)why;
    (void)full;
}

void irq_after_client_write(const struct spiproxy_op *op)
{
    (void)op;
}
#endif  /* SPIPROXY_FUZZ */
