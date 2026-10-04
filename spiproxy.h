// Copyright (c) 2026 Vincent Jardin, Vincent Cruz, Free Mobile
// SPDX-License-Identifier: BSD-4-Clause
//
// lan80xx-spid API/protocol: shared between the SPI proxy daemon and
// its clients.
// Transport: SOCK_SEQPACKET unix socket, one datagram = one message =
// header + body.
// Responses echo `seq` with type | SPIPROXY_RESP and the status code in
// hdr.flags.
// Unsolicited messages (TS FIFO subscription pushes, the reset notice
// to subscribers) have seq = 0.

#ifndef SPIPROXY_H
#define SPIPROXY_H

#include <stdint.h>

#define SPIPROXY_VER       1
#define SPIPROXY_SOCK      "/run/lan80xx-spid.sock"
#define SPIPROXY_BATCH_MAX 64
#define SPIPROXY_MB_MAX    1018   /* mailbox payload, chip limit */
#define SPIPROXY_MSG_MAX   4096

enum spiproxy_type {
    SPIPROXY_READ = 1,   /* body: 1 x spiproxy_op (val ignored)          */
    SPIPROXY_WRITE,      /* body: 1 x spiproxy_op                        */
    SPIPROXY_BATCH,      /* body: N x spiproxy_op, atomic, N <= 64       */
    SPIPROXY_CLAIM,      /* body: spiproxy_claim [+ cleanup ops]         */
    SPIPROXY_RELEASE,    /* body: empty                                  */
    SPIPROXY_MAILBOX,    /* body: spiproxy_mb [+ payload]                */
    SPIPROXY_STATS,      /* body: empty; response body: text             */
    SPIPROXY_TRACE,      /* body: empty; response body: text (op ring)   */
    SPIPROXY_TSFIFO_SUB, /* body: spiproxy_tsfifo_sub; pushes, see below */
    SPIPROXY_BER_WINDOW, /* reserved, ENOSYS in this version             */
    SPIPROXY_DFU,        /* reserved,  ENOSYS in this version            */
    SPIPROXY_RESET,      /* body: spiproxy_reset; pulse the HW reset GPIO */
    SPIPROXY_TSFIFO_UNSUB, /* body: spiproxy_tsfifo_sub (period ignored)  */
};
#define SPIPROXY_RESP 0x80

enum spiproxy_status {
    SPIPROXY_OK = 0,
    SPIPROXY_EINVAL,     /* malformed request                            */
    SPIPROXY_EIO,        /* spidev transfer failed                       */
    SPIPROXY_EBUSY,      /* device claimed by another client / MB region */
    SPIPROXY_ETIMEDOUT,  /* mailbox response timeout                     */
    SPIPROXY_ENOSYS,     /* reserved request type                       */
    SPIPROXY_ECRC,       /* mailbox response CRC mismatch                */
};

/* hdr.flags, requests: bits[1:0] = priority class */
#define SPIPROXY_PRIO_NORMAL 0   /* config / MEPA                        */
#define SPIPROXY_PRIO_HIGH   1   /* PTP-class                            */
#define SPIPROXY_PRIO_LOW    2   /* debug tools                          */

struct spiproxy_hdr {
    uint8_t  ver;
    uint8_t  type;
    uint16_t flags;      /* request: priority; response: status          */
    uint32_t seq;        /* echoed in the response                       */
    uint32_t len;        /* body bytes following this header             */
};

/* One register access. Reads return val in the response; the daemon
 * performs the pipelined dummy DEVICE_ID collect internally. */
struct spiproxy_op {
    uint8_t  slice;      /* 0..3 (channel bits of the SPI instruction)   */
    uint8_t  write;      /* 0 = read, 1 = write                          */
    uint8_t  mmd;
    uint8_t  rsvd;
    uint16_t reg;
    uint16_t rsvd2;
    uint32_t val;
};

/* Whole-device claim. cleanup ops (immediately following this struct,
 * ncleanup <= SPIPROXY_BATCH_MAX) are executed by the daemon if the
 * claim ends abnormally (client death or max_ms expiry): e.g. the
 * DFE-restore writes of an interrupted eye scan. */
struct spiproxy_claim {
    uint32_t max_ms;
    uint16_t ncleanup;
    uint16_t rsvd;
};

/* MCU mailbox transaction (one full request/response protocol run,
 * P3 in the design doc). Response body: same struct (cmd = response
 * packet id, payload_len = response payload size) + payload. */
struct spiproxy_mb {
    uint8_t  slice;      /* base slice of the package                    */
    uint8_t  cmd;        /* enDEVICE_COMMANDS_T id                       */
    uint16_t payload_len;
    uint32_t timeout_ms; /* 0 = default 500 ms                           */
};

/* Hardware reset: the daemon pulses the LAN80xx reset line (the GPIO
 * named by `lan80xx-spid -r <line-name>`, e.g. "lan8023-rst", ACTIVE_HIGH).
 * The clean full reset that a soft GLOBAL_FAST_RESET
 * over SPI cannot do from a running OS.
 * 0 fields use the daemon defaults (10 ms assert / 100 ms deassert).
 * Status SPIPROXY_ENOSYS if no reset line was configured/found. */
struct spiproxy_reset {
    uint32_t assert_us;
    uint32_t deassert_us;
};

/*
 * Egress (H2L) timestamp FIFO of one slice, drained by the daemon.
 *
 * TSFIFO_SUB subscribes the client to the FIFO of slice:
 * the daemon polls it every period_us, then it pops every complete row
 * and it pushes the entries to the client.
 */
#define SPIPROXY_TSFIFO_ENTRY_LEN 39   /* bytes of one FIFO row / entry      */
#define SPIPROXY_TSFIFO_ROWS      16   /* FIFO depth: max entries per push   */
#define SPIPROXY_TSFIFO_PERIOD_US 5000 /* default drain period               */

struct spiproxy_tsfifo_sub {
    uint8_t  slice;      /* 0..3                                         */
    uint8_t  rsvd[3];
    uint32_t period_us;  /* 0 = default; clamped to 1000..1000000        */
};

/*
 * Push: type = SPIPROXY_TSFIFO_SUB | SPIPROXY_RESP, seq = 0, status OK,
 * body = this header + nentries x SPIPROXY_TSFIFO_ENTRY_LEN bytes.
 * Entry bytes, in the order of MEPA's lan80xx_phy_ts_fifo_empty_priv():
 *   [0]      sub-nanoseconds
 *   [1..4]   nanoseconds, little endian
 *   [5..8]   seconds[31:0], little endian
 *   [9..10]  seconds[47:32], little endian
 *   [11..38] signature, as selected by the egress signature builder
 *            (MEPA default: [11..12] sequenceId, [13..22] sourcePortIdentity
 *            byte-reversed, [23] domainNumber, [24] messageType in bits 3:0)
 */
struct spiproxy_tsfifo_evt {
    uint8_t  slice;
    uint8_t  nentries;
    uint16_t rsvd;
    uint32_t drop_cnt;   /* EGR_TS_FIFO_DROP_CNT, refreshed every second  */
    uint32_t mono_us;    /* CLOCK_MONOTONIC in us when the rows were read,
                            modulo 2^32 (wraps every ~71 min)           */
};

#endif /* SPIPROXY_H */
