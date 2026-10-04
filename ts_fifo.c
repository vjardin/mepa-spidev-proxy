// Copyright (c) 2026 Vincent Jardin, Vincent Cruz, Free Mobile
// SPDX-License-Identifier: BSD-4-Clause
//
// lan80xx-spid: egress timestamp FIFO service. The daemon drains the FIFO of
// each subscribed slice and pushes the entries to the subscriber.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

/* One slice's subscription and drain state */
static struct tsf_slice {
    client_t *sub;
    uint32_t  period_us;
    uint64_t  next_us;
    uint64_t  drop_next_us;
    uint32_t  drop_cnt;
    uint64_t  n_entries, n_flushed, n_push_err;
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
    g_tsf[rq->slice].period_us = p;
    g_tsf[rq->slice].next_us = now;     /* first drain right after the reply */
    g_tsf[rq->slice].drop_next_us = now + TSF_DROP_POLL_US;
    log_always("client %u subscribed to the TS FIFO of slice %u, every %u us",
               c->id, rq->slice, p);
    return SPIPROXY_OK;
}

void tsf_unsubscribe(uint8_t slice)
{
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
 * At most SPIPROXY_TSFIFO_ROWS rows (the FIFO depth) per call.
 */
static void tsf_drain(uint8_t s)
{
    uint8_t msg[sizeof(struct spiproxy_tsfifo_evt) +
                SPIPROXY_TSFIFO_ROWS * SPIPROXY_TSFIFO_ENTRY_LEN];
    struct spiproxy_tsfifo_evt ev;
    uint8_t *e = msg + sizeof(ev);
    uint32_t v, w;
    int n = 0, r, b;

    if (tsf_rd(s, TSF_REG_ROW0, &v) || (v & TSF_EMPTY) ||
        tsf_rd(s, TSF_REG_ROW0, &v) || (v & TSF_EMPTY)) {
        return;
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
        return;
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
}

/*
 * Drain the subscribed FIFOs that are due, refresh their drop counters.
 * Called from the main loop and between queued operations.
 */
void tsf_tick(void)
{
    uint64_t now = now_us();
    uint32_t d;

    for (uint8_t s = 0; s < SLICE_COUNT; s++) {
        if (g_tsf[s].sub == NULL) {
            continue;
        }
        if (tsf_due(now, g_tsf[s].next_us)) {
            tsf_drain(s);
            g_tsf[s].next_us = now + g_tsf[s].period_us;
        }
        if (tsf_due(now, g_tsf[s].drop_next_us)) {
            if (tsf_rd(s, TSF_REG_DROP, &d) == 0) {
                if (d != g_tsf[s].drop_cnt) {
                    warn_line("TS FIFO s%u: EGR_TSFIFO_DROP_CNT %u -> %u "
                              "(FIFO full, timestamps lost)",
                              s, g_tsf[s].drop_cnt, d);
                }
                g_tsf[s].drop_cnt = d;
            }
            g_tsf[s].drop_next_us = now + TSF_DROP_POLL_US;
        }
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
        if (g_tsf[s].next_us < next) {
            next = g_tsf[s].next_us;
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

/* The STATS lines of the subscribed slices */
int tsf_stats(char *buf, size_t len)
{
    int n = 0;

    for (int i = 0; i < SLICE_COUNT; i++) {
        if (g_tsf[i].sub != NULL) {
            n += snprintf(buf + n, len - n,
                          "tsfifo s%d client %u(%s) period=%uus entries=%llu flushed=%llu push_err=%llu drop_cnt=%u\n",
                          i, g_tsf[i].sub->id, g_tsf[i].sub->comm,
                          g_tsf[i].period_us,
                          (unsigned long long)g_tsf[i].n_entries,
                          (unsigned long long)g_tsf[i].n_flushed,
                          (unsigned long long)g_tsf[i].n_push_err,
                          g_tsf[i].drop_cnt);
        }
    }
    return n;
}
