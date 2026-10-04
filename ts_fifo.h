// Copyright (c) 2026 Vincent Jardin, Vincent Cruz, Free Mobile
// SPDX-License-Identifier: BSD-4-Clause
//
// lan80xx-spid: egress timestamp FIFO service.

#ifndef TS_FIFO_H
#define TS_FIFO_H

#include <stddef.h>
#include <stdint.h>

#include "lan80xx_spid.h"

/* the daemon */
client_t *tsf_subscriber(uint8_t slice);
int  tsf_fenced(const struct spiproxy_op *op);
int  tsf_subscribe(client_t *c, const struct spiproxy_tsfifo_sub *rq);
void tsf_unsubscribe(uint8_t slice);
void tsf_tick(void);
int  tsf_timeout_ms(void);
int  tsf_stats(char *buf, size_t len);

#endif /* TS_FIFO_H */
