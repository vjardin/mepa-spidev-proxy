// Copyright (c) 2026 Vincent Jardin, Vincent Cruz, Free Mobile
// SPDX-License-Identifier: BSD-4-Clause
//
// lan80xx-spid: what the daemon core shares with its other source files.

#ifndef LAN80XX_SPID_H
#define LAN80XX_SPID_H

#include <stdint.h>
#include <sys/types.h>

#include "spiproxy.h"

#define SLICE_COUNT    4        /* SPI slices per package (0..3)          */
#define COMM_PATH_MAX (20U)

typedef struct client {
    int      fd;
    int      used;
    uint32_t id;
    pid_t    pid;
    char     comm[COMM_PATH_MAX];   /* /proc/<pid>/comm of the client process */
    uint64_t n_ops, n_msgs, n_err;
} client_t;

uint64_t now_us(void);
void warn_line(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int  spi_read_reg(uint8_t slice, uint8_t mmd, uint16_t reg, uint32_t *val);
int  spi_write_reg(uint8_t slice, uint8_t mmd, uint16_t reg, uint32_t val);
void trace_add(client_t *c, const struct spiproxy_op *op);
void io_err_warn(const char *tag, const struct spiproxy_op *op);
int  send_push(client_t *c, uint8_t type, const void *body, uint32_t blen);
int  gpio_open_line_by_name(const char *name, uint64_t flags, const char *what);

#endif /* LAN80XX_SPID_H */
