// Copyright (c) 2026 Vincent Jardin, Vincent Cruz, Free Mobile
// SPDX-License-Identifier: BSD-4-Clause
//
// Shared setup for the lan80xx-spid fuzz harnesses. Include AFTER the
// daemon's sources (it uses their static globals/types).
// Each harness is its own binary, so the non-static LLVMFuzzerInitialize
// defined here is linked exactly once.

#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#define FUZZ_NCLIENTS 2

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    g.freq = 5000000;   /* nonzero; unused by the stub backend, kept sane */
    g.rst_fd = -1;      /* RESET returns ENOSYS -> no usleep on fuzz input */
    g.ep_fd = -1;       /* client_drop()'s epoll_ctl() fails harmlessly */
    g.log = NULL;       /* no event-log side output */
    g.lctx.tag = "";
    setlogmask(0);      /* drop syslog output (perf; keeps the system log clean) */
    return 0;
}

/* Fresh per-input daemon state: dispatch/lint flags, the trace + rmw rings,
 * and the qitem freelist/queues (rebuilt, not the ~1 MB of bodies). */
static void fuzz_reset(void)
{
    int i;

    g.claim_owner = NULL;
    g.claim_ncleanup = 0;
    g.claim_deadline = 0;
    g.mb_inflight = 0;
    g.ring_w = 0;
    g.rd_w = 0;
    g.n_queued = 0;
    memset(g.page_owner, 0, sizeof(g.page_owner));
    memset(g.cor_last, 0, sizeof(g.cor_last));
    memset(g.rd_ring, 0, sizeof(g.rd_ring));
    memset(g_tsf, 0, sizeof(g_tsf));
    for (i = 0; i < MAX_QITEMS - 1; i++) {
        g.pool[i].next = &g.pool[i + 1];
    }
    g.pool[MAX_QITEMS - 1].next = NULL;
    g.freel = &g.pool[0];
    for (i = 0; i < 3; i++) {
        g.qh[i] = NULL;
        g.qt[i] = NULL;
    }
}

/* FUZZ_NCLIENTS fresh clients (ids 1..N, no socket: fd -1). */
static void fuzz_clients(client_t *cl)
{
    int i;

    for (i = 0; i < FUZZ_NCLIENTS; i++) {
        memset(&cl[i], 0, sizeof(cl[i]));
        cl[i].used = 1;
        cl[i].id = (uint32_t)(i + 1);
        cl[i].fd = -1;   /* send_resp()'s send() fails harmlessly */
    }
}

/* End-of-input consistency oracle: after both clients are dropped, every qitem
 * must be back on the freelist, the queues empty, and no mailbox tx dangling.
 * A leaked/double-freed item or a stuck in-flight guard on any path (including
 * the injected-error cleanup) trips this, and libFuzzer saves the reproducer.
 * The count is capped so a cyclic freelist (double-free) can't spin forever. */
static void fuzz_check_invariants(void)
{
    int n = 0, q;
    qitem_t *it;

    for (it = g.freel; it != NULL && n <= MAX_QITEMS; it = it->next) {
        n++;
    }
    for (q = 0; q < 3; q++) {
        for (it = g.qh[q]; it != NULL && n <= MAX_QITEMS; it = it->next) {
            n++;
        }
    }
    if (n != MAX_QITEMS || g.n_queued != 0 || g.mb_inflight != 0) {
        fprintf(stderr, "INVARIANT: qitems=%d/%d n_queued=%d mb_inflight=%d\n",
                n, MAX_QITEMS, g.n_queued, g.mb_inflight);
        abort();
    }
}

#endif /* FUZZ_COMMON_H */
