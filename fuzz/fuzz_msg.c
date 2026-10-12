// Copyright (c) 2026 Vincent Jardin, Vincent Cruz, Free Mobile
// SPDX-License-Identifier: BSD-4-Clause
//
// libFuzzer harness for the lan80xx-spid request path.
//
// It #includes the daemon's sources with -DSPIPROXY_FUZZ, which drops main()
// and swaps the SPI backend for a fuzzer-driven stub, giving this TU direct
// access to the (static) daemon internals.
//
// Each input is:
//     [u16 spi_feed_len][spi_feed bytes][ message sequence ]
// The spi_feed drives the stub SPI backend (spi_read_reg returns successive
// 4-byte little-endian words from it), so device replies -- mailbox response
// words in particular -- are fuzzed. The message sequence is a run of
// length-prefixed requests; each is a 16-bit frame (top bit = which of two
// clients, low 15 bits = message length) followed by the spiproxy_hdr + body.
//
// Rather than call exec_item() directly, the harness enqueue()s the messages
// and runs the real drain_queues() scheduler, so the queue, priority classes,
// item_eligible() and the whole-device claim gating are exercised, along with
// the cross-client lint hazards (page-ride / cor-poach / rmw-race). No
// sockets, epoll, or hardware.
//
// After draining, both clients are dropped, exercising the queue purge and --
// for a claim still held -- the abnormal claim_end() cleanup-op path.
//
// Not covered: client_msg()'s transport framing (bypassed here; messages are
// handed to enqueue() directly).

#include "lan80xx_spid.c"
#include "ts_fifo.c"
#include "irq.c"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    client_t cl[FUZZ_NCLIENTS];
    size_t off, feed_len;
    int i;

    if (size < 2) {
        return 0;
    }
    /* [u16 spi_feed_len][spi_feed][message sequence] */
    feed_len = (size_t)(data[0] | ((size_t)data[1] << 8));
    off = 2;
    if (feed_len > size - off) {
        feed_len = size - off;
    }
    g_fuzz_spi = data + off;
    g_fuzz_spi_len = feed_len;
    g_fuzz_spi_pos = 0;
    off += feed_len;

    fuzz_reset();
    fuzz_clients(cl);

    /* Enqueue a sequence of length-prefixed messages. */
    while (off + 2 <= size) {
        uint16_t framing = (uint16_t)(data[off] | ((uint16_t)data[off + 1] << 8));
        unsigned who = framing >> 15;          /* client selector (0/1) */
        size_t mlen = framing & 0x7FFFU;       /* message length (hdr + body) */
        struct spiproxy_hdr h;
        size_t avail;

        off += 2;
        avail = size - off;
        if (mlen > avail) {
            mlen = avail;
        }
        if (mlen < sizeof(h)) {
            break;   /* not a whole message left */
        }
        if (mlen > sizeof(h) + SPIPROXY_MSG_MAX) {
            mlen = sizeof(h) + SPIPROXY_MSG_MAX;
        }
        memcpy(&h, data + off, sizeof(h));
        h.len = (uint32_t)(mlen - sizeof(h));   /* self-consistent framing */
        /* enqueue() only reads the body, so casting away const is safe. */
        enqueue(&cl[who % FUZZ_NCLIENTS], &h,
                (uint8_t *)(uintptr_t)(data + off + sizeof(h)));
        off += mlen;
    }

    /* Run the real scheduler: eligibility, priority, claim gating. */
    drain_queues(2 * MAX_QITEMS);

    /* Drop both clients: exercises the queue purge and, when a claim is still
     * held, the abnormal claim_end() cleanup-op path. */
    for (i = 0; i < FUZZ_NCLIENTS; i++) {
        client_drop(&cl[i]);
    }
    fuzz_check_invariants();
    return 0;
}
