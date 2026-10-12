// Copyright (c) 2026 Vincent Jardin, Vincent Cruz, Free Mobile
// SPDX-License-Identifier: BSD-4-Clause
//
// libFuzzer harness for the lan80xx-spid transport parse: client_frame(),
// the ver / len-vs-bytecount / SPIPROXY_MSG_MAX validation that untrusted
// client datagrams hit first (before the request handlers fuzz_msg covers).
//
// It #includes the daemon's sources with -DSPIPROXY_FUZZ (same hardware-free
// SPI stub and shared setup as fuzz_msg). Each input is a run of raw
// datagrams, each a u16 length prefix followed by that many bytes handed
// verbatim to client_frame() -- so the header (ver/type/flags/seq/len) is
// fuzzed directly rather than made self-consistent. Datagrams alternate
// between two clients; afterwards the scheduler is drained and both clients
// dropped, matching fuzz_msg's teardown.

#include "lan80xx_spid.c"
#include "ts_fifo.c"
#include "irq.c"
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Mirror client_msg()'s receive buffer: recv() fills this suitably aligned
     * stack array, so the daemon parses the header at natural alignment.
     * Copying each datagram in (rather than pointing client_frame at the raw,
     * arbitrarily aligned fuzz buffer) matches that -- and avoids spurious
     * unaligned-access reports the real code path never triggers. */
    _Alignas(struct spiproxy_hdr)
    uint8_t msg[sizeof(struct spiproxy_hdr) + SPIPROXY_MSG_MAX];
    client_t cl[FUZZ_NCLIENTS];
    size_t off = 0;
    unsigned k = 0;
    int i;

    /* No device replies needed here; the stub feed reads as zero. */
    g_fuzz_spi = NULL;
    g_fuzz_spi_len = 0;
    g_fuzz_spi_pos = 0;

    fuzz_reset();
    fuzz_clients(cl);

    /* [u16 datagram_len][datagram] ... -> client_frame(), as recv() would. */
    while (off + 2 <= size) {
        size_t dlen = (size_t)(data[off] | ((size_t)data[off + 1] << 8));
        size_t n;

        off += 2;
        if (dlen > size - off) {
            dlen = size - off;
        }
        n = dlen > sizeof(msg) ? sizeof(msg) : dlen; /* recv caps at the buffer */
        memcpy(msg, data + off, n);
        client_frame(&cl[k++ % FUZZ_NCLIENTS], msg, n);
        off += dlen;
    }

    drain_queues(2 * MAX_QITEMS);
    for (i = 0; i < FUZZ_NCLIENTS; i++) {
        client_drop(&cl[i]);
    }
    fuzz_check_invariants();
    return 0;
}
