// Copyright (c) 2026 Vincent Jardin, Vincent Cruz, Free Mobile
// SPDX-License-Identifier: BSD-4-Clause
//
// lan80xx-spid: egress timestamp FIFO service. The daemon drains the FIFO of
// each subscribed slice and pushes the entries to the subscriber.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "irq.h"
#include "lan80xx_regs.h"
#include "lan80xx_spid.h"
#include "log.h"
#include "ts_fifo.h"

/* Egress timestamp FIFO (MMD 0x0A, PTP processor block at 0x9000) */
#define TSF_REG_ROW0      0x9070      /* EGR_TSFIFO_0: [31] empty, [30:27] flags,
                                         [23:0] bytes 0..2 of the row       */
#define TSF_REG_ROW9      0x9079      /* EGR_TSFIFO_9: read last, pops the row */
#define TSF_REG_DROP      0x907a      /* EGR_TSFIFO_DROP_CNT, cumulative      */
#define TSF_ROW_REGS      10
#define TSF_EMPTY         0x80000000u
#define TSF_FLAGS(v)      (((v) >> 27) & 0xfu)
#define TSF_FLAGS_FULL    15u         /* complete row                        */
#define TSF_PERIOD_MIN_US 1000u
#define TSF_PERIOD_MAX_US 1000000u
#define TSF_DROP_POLL_US  1000000u    /* EGR_TSFIFO_DROP_CNT refresh period   */

#define IRQ_DEAD_FINDS         4            /* safety reads in a row that found entries and no edge: the line is dead, poll */

/* One slice's subscription and drain state */
static struct tsf_slice {
    client_t *sub;
    uint32_t  period_us;
    uint64_t  next_us;
    uint64_t  drop_next_us;
    uint32_t  drop_cnt;         /* the chip's EGR_TSFIFO_DROP_CNT, last read */
    uint32_t  drop_at_sub;      /* ... as found at the subscription */
    uint64_t  n_entries, n_flushed, n_push_err;
    /* the interrupt modes */
    int      polling;           /* auto: in the polling tail (none: always) */
    uint64_t last_rows_us;      /* the last drain that found entries */
    uint64_t safety_next_us;
    uint64_t n_irq_rows, n_poll_rows, n_safety_hits;
    uint64_t n_safety_asserted; /* found by the safety check with the line asserted: the interrupt's, its edge queued */
    uint64_t events_seen;       /* irq_events() at the previous safety read: no change = no edge since */
    uint64_t n_ovf;             /* overflow status seen with an interrupt */
    int      first;             /* the subscription's first drain is due (interrupt modes) */
    uint64_t n_sub_rows;        /* rows of that first drain */
    unsigned no_edge_finds;     /* safety reads in a row that found entries with no edge since the previous one */
    int      irq_dead;          /* the line never edges for this slice: polling at the period until it does */
} g_tsf[SLICE_COUNT];

client_t *tsf_subscriber(uint8_t slice)
{
    return g_tsf[slice].sub;
}

/* A row register of a subscribed FIFO: only the drainer pops it */
int tsf_fenced(const struct spiproxy_op *op)
{
    return g_tsf[op->slice].sub != NULL && op->mmd == LAN80XX_MMD_PTP &&
           op->reg >= TSF_REG_ROW0 && op->reg <= TSF_REG_ROW9;
}

/* Does the periodic drain run for this slice now? */
static int tsf_polls(uint8_t s)
{
    return !irq_active() || g_tsf[s].irq_dead ||
           (irq_mode() == IRQ_AUTO && g_tsf[s].polling);
}

#ifdef SPIPROXY_FUZZ
/* deterministic: every deadline is due, whatever the wall clock */
static int tsf_due(uint64_t now, uint64_t deadline)
{
    (void)now;
    (void)deadline;
    return 1;
}
#else
static int tsf_due(uint64_t now, uint64_t deadline)
{
    return now >= deadline;
}
#endif

/* Drainer register read, logged with the "tsfifo" tag. */
static int tsf_rd(uint8_t slice, uint16_t reg, uint32_t *val)
{
    struct spiproxy_op op = { .slice = slice, .mmd = LAN80XX_MMD_PTP,
                              .reg = reg };
    int rc = spi_read_reg(slice, LAN80XX_MMD_PTP, reg, val);

    op.val = *val;
    trace_add(NULL, &op);
    log_debug("C%u seq=0 OP tsfifo R s%u %02x %04x = %08x%s",
              g_tsf[slice].sub ? g_tsf[slice].sub->id : 0, slice,
              LAN80XX_MMD_PTP, reg, *val, rc ? " IO-ERR" : "");
    return rc;
}

int tsf_subscribe(client_t *c, const struct spiproxy_tsfifo_sub *rq)
{
    uint32_t p = rq->period_us ? rq->period_us : SPIPROXY_TSFIFO_PERIOD_US;
    uint32_t d = 0;
    uint64_t now = now_us();

    if (g_tsf[rq->slice].sub != NULL && g_tsf[rq->slice].sub != c) {
        return SPIPROXY_EBUSY;
    }
    if (p < TSF_PERIOD_MIN_US) {
        p = TSF_PERIOD_MIN_US;
    } else if (p > TSF_PERIOD_MAX_US) {
        p = TSF_PERIOD_MAX_US;
    }
    memset(&g_tsf[rq->slice], 0, sizeof(g_tsf[rq->slice]));
    g_tsf[rq->slice].sub = c;
    if (tsf_rd(rq->slice, TSF_REG_DROP, &d)) {
        d = 0;
    }
    g_tsf[rq->slice].drop_cnt = d;
    g_tsf[rq->slice].drop_at_sub = d;
    g_tsf[rq->slice].period_us = p;
    g_tsf[rq->slice].next_us = now;     /* first drain right after the reply */
    g_tsf[rq->slice].drop_next_us = now + TSF_DROP_POLL_US;
    g_tsf[rq->slice].polling = 1;    /* auto: a tail after the first drain */
    g_tsf[rq->slice].first = 1;      /* only: a first drain too, see tsf_tick() */
    g_tsf[rq->slice].last_rows_us = now;
    g_tsf[rq->slice].safety_next_us = now + IRQ_SAFETY_POLL_US;
    irq_slice_arm(rq->slice, 1);
    log_always("client %u subscribed to the TS FIFO of slice %u, every %u us (drain: %s%s), EGR_TSFIFO_DROP_CNT %u as found",
               c->id, rq->slice, p, irq_mode_name(irq_mode()),
               (irq_mode() != IRQ_NONE && !irq_active()) ? ", no interrupt line: polling" : "", d);
    return SPIPROXY_OK;
}

void tsf_unsubscribe(uint8_t slice)
{
    irq_slice_arm(slice, 0);
    if (g_tsf[slice].sub != NULL) {
        log_always("client %u unsubscribed from the TS FIFO of slice %u "
                   "(entries %llu, flushed %llu, push errors %llu)",
                   g_tsf[slice].sub->id, slice,
                   (unsigned long long)g_tsf[slice].n_entries,
                   (unsigned long long)g_tsf[slice].n_flushed,
                   (unsigned long long)g_tsf[slice].n_push_err);
    }
    memset(&g_tsf[slice], 0, sizeof(g_tsf[slice]));
}

/*
 * Pop the complete rows of one slice's FIFO and push them to the
 * subscriber:
 * - the FIFO holds data when two successive reads of TSFIFO_0 say so,
 * - a row is TSFIFO_0 (bytes 0..2, flags) then TSFIFO_1..9 (bytes 3..38),
 *   TSFIFO_9 last,
 * - a row whose flags are not 15 is incomplete: it is popped and dropped,
 *   and the drain stops there.
 * At most SPIPROXY_TSFIFO_ROWS rows (the FIFO depth) per call; returns
 * how many were popped (a full count means the FIFO may hold more).
 */
static int tsf_drain(uint8_t s)
{
    uint8_t msg[sizeof(struct spiproxy_tsfifo_evt) +
                SPIPROXY_TSFIFO_ROWS * SPIPROXY_TSFIFO_ENTRY_LEN];
    struct spiproxy_tsfifo_evt ev;
    uint8_t *e = msg + sizeof(ev);
    uint32_t v, w;
    int n = 0, r, b;

    if (tsf_rd(s, TSF_REG_ROW0, &v) || (v & TSF_EMPTY) ||
        tsf_rd(s, TSF_REG_ROW0, &v) || (v & TSF_EMPTY)) {
        return 0;
    }
    while (n < SPIPROXY_TSFIFO_ROWS) {
        if (tsf_rd(s, TSF_REG_ROW0, &v) || (v & TSF_EMPTY)) {
            break;
        }
        if (TSF_FLAGS(v) != TSF_FLAGS_FULL) {
            for (r = 1; r < TSF_ROW_REGS; r++) {
                tsf_rd(s, (uint16_t)(TSF_REG_ROW0 + r), &w);
            }
            g_tsf[s].n_flushed++;
            break;
        }
        e[0] = (uint8_t)v;
        e[1] = (uint8_t)(v >> 8);
        e[2] = (uint8_t)(v >> 16);
        for (r = 1; r < TSF_ROW_REGS; r++) {
            if (tsf_rd(s, (uint16_t)(TSF_REG_ROW0 + r), &w)) {
                goto out;   /* row not popped yet: read again next time */
            }
            for (b = 0; b < 4; b++) {
                e[3 + (r - 1) * 4 + b] = (uint8_t)(w >> (8 * b));
            }
        }
        e += SPIPROXY_TSFIFO_ENTRY_LEN;
        n++;
    }
out:
    if (n == 0) {
        return 0;
    }
    ev.slice = s;
    ev.nentries = (uint8_t)n;
    ev.rsvd = 0;
    ev.drop_cnt = g_tsf[s].drop_cnt;
    ev.mono_us = (uint32_t)now_us();
    memcpy(msg, &ev, sizeof(ev));
    g_tsf[s].n_entries += (uint64_t)n;
    if (send_push(g_tsf[s].sub, SPIPROXY_TSFIFO_SUB, msg,
                  (uint32_t)(sizeof(ev) + (size_t)n * SPIPROXY_TSFIFO_ENTRY_LEN))) {
        g_tsf[s].n_push_err++;
        warn_line("TS FIFO s%u: %d entries not delivered to client %u",
                  s, n, g_tsf[s].sub->id);
    }
    return n;
}

/* Drain until the FIFO is empty */
static int tsf_drain_all(uint8_t s)
{
    int total = 0, n;

    for (int round = 0; round < 4; round++) {
        n = tsf_drain(s);
        total += n;
        if (n < SPIPROXY_TSFIFO_ROWS) {
            break;
        }
    }
    return total;
}

/* After a drain: the auto mode's polling tail bookkeeping */
static void tsf_after_drain(uint8_t s, int rows, uint64_t now)
{
    if (rows > 0) {
        g_tsf[s].last_rows_us = now;
        if (irq_mode() == IRQ_AUTO && !g_tsf[s].polling) {
            g_tsf[s].polling = 1;
            g_tsf[s].next_us = now + g_tsf[s].period_us;
        }
    } else if (irq_mode() == IRQ_AUTO && g_tsf[s].polling && !g_tsf[s].irq_dead &&
               now - g_tsf[s].last_rows_us >= irq_idle_us()) {
        g_tsf[s].polling = 0;    /* empty for the tail: back to the interrupt */
    }
}

/* The subscription's first drain in an interrupt mode: a FIFO that filled
 * before the subscription has its level asserted already and gives no edge. */
static void tsf_tick_first_drain(uint8_t s, uint64_t now)
{
    int rows;

    g_tsf[s].first = 0;
    rows = tsf_drain_all(s);
    irq_ts_ack(s);
    g_tsf[s].n_sub_rows += (uint64_t)rows;
    if (rows > 0) {
        log_always("TS FIFO s%u: %d entries drained at the subscription (the gap before it)", s, rows);
    }
    tsf_after_drain(s, rows, now);
}

/* The periodic drain, when due: mode none, auto's polling tail, a dead line. */
static void tsf_tick_poll(uint8_t s, uint64_t now)
{
    int rows;

    if (!tsf_due(now, g_tsf[s].next_us)) {
        return;
    }
    g_tsf[s].first = 0;
    rows = tsf_drain(s);
    g_tsf[s].n_poll_rows += (uint64_t)rows;
    g_tsf[s].next_us = now + g_tsf[s].period_us;
    tsf_after_drain(s, rows, now);
}

/* Who the entries of a safety read belong to: a line held by a source this
 * daemon does not own, the interrupt itself (line asserted, its edge queued
 * behind this pass), or a lost interrupt (line released). */
static void tsf_safety_account(uint8_t s, int rows, int level, int edged)
{
    if (level == 0 && rows > 1 && !edged) {
        irq_line_held();
        return;
    }
    if (level == 0) {
        g_tsf[s].n_safety_asserted++;
        return;
    }
    g_tsf[s].n_safety_hits++;
    irq_missed((uint64_t)rows);
    if (g_tsf[s].n_safety_hits == 1 || g_tsf[s].n_safety_hits % 100 == 0) {
        warn_line("TS FIFO s%u: %d entries found by the safety check, not by an interrupt (%llu times)",
                  s, rows, (unsigned long long)g_tsf[s].n_safety_hits);
    }
}

/* IRQ_DEAD_FINDS safety reads in a row with entries and no edge in between:
 * the line never edges, the slice polls at its period until an edge comes. */
static void tsf_safety_dead_line(uint8_t s, int level, int edged)
{
    if (edged) {
        g_tsf[s].no_edge_finds = 0;
        return;
    }
    if (++g_tsf[s].no_edge_finds < IRQ_DEAD_FINDS || g_tsf[s].irq_dead) {
        return;
    }
    g_tsf[s].irq_dead = 1;
    g_tsf[s].polling = 1;
    warn_line("TS FIFO s%u: the interrupt line never edges (%u safety reads found entries, %s, no edge): polling at the period until an edge comes",
              s, g_tsf[s].no_edge_finds, level == 0 ? "the line held" : "the line released");
}

/* Waiting for an interrupt: one read of TSFIFO_0 every IRQ_SAFETY_POLL_US
 * catches a lost one. */
static void tsf_tick_safety(uint8_t s, uint64_t now)
{
    const int edged = (irq_events() != g_tsf[s].events_seen);
    uint32_t v;
    int rows, level;

    if (!tsf_due(now, g_tsf[s].safety_next_us)) {
        return;
    }
    g_tsf[s].safety_next_us = now + IRQ_SAFETY_POLL_US;
    if (tsf_rd(s, TSF_REG_ROW0, &v) == 0 && !(v & TSF_EMPTY)) {
        level = irq_line_level();
        rows = tsf_drain_all(s);
        irq_ts_ack(s);
        tsf_safety_account(s, rows, level, edged);
        tsf_safety_dead_line(s, level, edged);
        tsf_after_drain(s, rows, now);
    }
    g_tsf[s].events_seen = irq_events();
}

/* The chip's drop counter, once a second: a change since the last read is a
 * loss of this subscription. */
static void tsf_tick_drops(uint8_t s, uint64_t now)
{
    uint32_t d;

    if (!tsf_due(now, g_tsf[s].drop_next_us)) {
        return;
    }
    g_tsf[s].drop_next_us = now + TSF_DROP_POLL_US;
    if (tsf_rd(s, TSF_REG_DROP, &d) != 0) {
        return;
    }
    if (d != g_tsf[s].drop_cnt) {
        warn_line("TS FIFO s%u: EGR_TSFIFO_DROP_CNT %u -> %u "
                  "(FIFO full, timestamps lost)",
                  s, g_tsf[s].drop_cnt, d);
    }
    g_tsf[s].drop_cnt = d;
}

/* One slice, one tick: the periodic drain while polling; otherwise the
 * subscription's first drain, then the safety read while waiting for an edge. */
static void tsf_tick_slice(uint8_t s, uint64_t now)
{
    if (tsf_polls(s)) {
        tsf_tick_poll(s, now);
        return;
    }
    if (g_tsf[s].first) {
        tsf_tick_first_drain(s, now);
        return;
    }
    tsf_tick_safety(s, now);
}

/*
 * Drain the subscribed FIFOs that are due, refresh their drop counters.
 * Called from the main loop and between queued operations.
 */
void tsf_tick(void)
{
    const uint64_t now = now_us();

    for (uint8_t s = 0; s < SLICE_COUNT; s++) {
        if (g_tsf[s].sub == NULL) {
            continue;
        }
        tsf_tick_slice(s, now);
        tsf_tick_drops(s, now);
    }
}

/* Milliseconds until the next TS FIFO deadline, -1 if none. */
int tsf_timeout_ms(void)
{
    uint64_t now = now_us(), next = UINT64_MAX;

    for (uint8_t s = 0; s < SLICE_COUNT; s++) {
        if (g_tsf[s].sub == NULL) {
            continue;
        }
        if (tsf_polls(s)) {
            if (g_tsf[s].next_us < next) {
                next = g_tsf[s].next_us;
            }
        } else if (g_tsf[s].safety_next_us < next) {
            next = g_tsf[s].safety_next_us;
        }
        if (g_tsf[s].drop_next_us < next) {
            next = g_tsf[s].drop_next_us;
        }
    }
    if (next == UINT64_MAX) {
        return -1;
    }
    return next <= now ? 0 : (int)((next - now + 999) / 1000);
}

/* An edge: drain the slices whose TS level or overflow status is set */
int tsf_irq_drain(uint64_t now)
{
    uint32_t st;
    int worked = 0, rows;

    for (uint8_t s = 0; s < SLICE_COUNT; s++) {
        if (g_tsf[s].sub == NULL || !irq_ts_status(s, &st)) {
            continue;
        }
        rows = tsf_drain_all(s);
        if (st & IRQ_EGR_TS_OVERFLOW) {
            g_tsf[s].n_ovf++;
        }
        irq_ts_ack(s);
        g_tsf[s].n_irq_rows += (uint64_t)rows;
        g_tsf[s].no_edge_finds = 0;
        if (g_tsf[s].irq_dead) {
            g_tsf[s].irq_dead = 0;       /* an edge after all: back to the mode's drain */
            g_tsf[s].polling = (irq_mode() == IRQ_AUTO);
            log_always("TS FIFO s%u: the interrupt line edges again: drain by interrupt (%s)", s, irq_mode_name(irq_mode()));
        }
        tsf_after_drain(s, rows, now);
        worked = 1;
    }
    return worked;
}

/* The pin set up again: route the subscribed slices again */
void tsf_irq_rearm(void)
{
    for (uint8_t s = 0; s < SLICE_COUNT; s++) {
        if (g_tsf[s].sub != NULL) {
            irq_slice_arm(s, 1);
            g_tsf[s].first = 1;      /* entries may wait in the FIFO */
        }
    }
}

/* The STATS lines of the subscribed slices */
int tsf_stats(char *buf, size_t len)
{
    int n = 0;

    for (int i = 0; i < SLICE_COUNT; i++) {
        if (g_tsf[i].sub != NULL) {
            n += snprintf(buf + n, len - n,
                          "tsfifo s%d client %u(%s) period=%uus entries=%llu flushed=%llu push_err=%llu drop_cnt=%u drop_since_sub=%u irq_rows=%llu poll_rows=%llu sub_rows=%llu safety_hits=%llu safety_asserted=%llu irq_ovf=%llu irq_dead=%d polling=%d\n",
                          i, g_tsf[i].sub->id, g_tsf[i].sub->comm,
                          g_tsf[i].period_us,
                          (unsigned long long)g_tsf[i].n_entries,
                          (unsigned long long)g_tsf[i].n_flushed,
                          (unsigned long long)g_tsf[i].n_push_err,
                          g_tsf[i].drop_cnt, g_tsf[i].drop_cnt - g_tsf[i].drop_at_sub,
                          (unsigned long long)g_tsf[i].n_irq_rows,
                          (unsigned long long)g_tsf[i].n_poll_rows,
                          (unsigned long long)g_tsf[i].n_sub_rows,
                          (unsigned long long)g_tsf[i].n_safety_hits,
                          (unsigned long long)g_tsf[i].n_safety_asserted,
                          (unsigned long long)g_tsf[i].n_ovf,
                          g_tsf[i].irq_dead,
                          tsf_polls((uint8_t)i));
        }
    }
    return n;
}
