// Copyright (c) 2026 Vincent Jardin, Vincent Cruz, Free Mobile
// SPDX-License-Identifier: BSD-4-Clause
//
// lan80xx-spid: the LAN80xx pin interrupt for the TS FIFO drain.

#ifndef IRQ_H
#define IRQ_H

#include <stddef.h>
#include <stdint.h>

#include "spiproxy.h"

#define IRQ_EGR_TS_LEVEL       0x00000008u  /* bit 3 */
#define IRQ_EGR_TS_OVERFLOW    0x00000001u  /* bit 0: entries dropped (EGR_TSFIFO_DROP_CNT counts them); cleared with the level after a drain */
#define IRQ_LINE_DEFAULT       "lan8023-mdint"
#define IRQ_IDLE_DEFAULT_MS    50u          /* -w: auto mode's polling tail after the last non-empty drain */
#define IRQ_SAFETY_POLL_US     500000u      /* the FIFO is checked anyway while waiting for an interrupt */

enum irq_mode { IRQ_NONE = 0, IRQ_AUTO, IRQ_ONLY };

/* the daemon */
int  irq_set_mode(const char *name);
void irq_set_line(char *arg);
void irq_set_idle_ms(uint32_t ms);
void irq_open(void);
int  irq_fd(void);
void irq_service(void);
void irq_verify_pin(const char *why, int full);
void irq_after_client_write(const struct spiproxy_op *op);
void irq_exit(void);
int  irq_stats(char *buf, size_t len);

/* the TS FIFO service */
enum irq_mode irq_mode(void);
const char *irq_mode_name(enum irq_mode m);
int  irq_active(void);
uint32_t irq_idle_us(void);
uint64_t irq_events(void);
int  irq_line_level(void);
void irq_slice_arm(uint8_t s, int on);
int  irq_ts_status(uint8_t s, uint32_t *st);
void irq_ts_ack(uint8_t s);
void irq_line_held(void);
void irq_missed(uint64_t rows);

#endif /* IRQ_H */
