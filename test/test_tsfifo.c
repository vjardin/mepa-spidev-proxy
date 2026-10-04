// Copyright (c) 2026 Vincent Jardin, Vincent Cruz, Free Mobile
// SPDX-License-Identifier: BSD-4-Clause
//
// Unit test of the egress TS FIFO service of lan80xx-spid.
//
// Like the fuzz harnesses, it #includes the daemon's sources built with
// -DSPIPROXY_FUZZ: no main(), no hardware, and spi_read_reg() returns the
// successive 32-bit words of a feed set by the test. The test scripts the
// FIFO registers word by word, runs the drain, and checks the pushes the
// clients receive on real socketpairs, the register fence, the counters
// and the subscription lifecycle.

#include "lan80xx_spid.c"
#include "ts_fifo.c"

#include <syslog.h>

static int n_fail;

#define CHECK(cond) do {                                                  \
        if (!(cond)) {                                                    \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,        \
                    __LINE__, #cond);                                     \
            n_fail++;                                                     \
        }                                                                 \
    } while (0)

#define NCLIENTS 2

static int peer[NCLIENTS];          /* the client side of each socketpair */
static uint8_t feed[4 * 512];
static uint32_t seqno;

/* SPI feed: the stub returns these words, little endian, in order. */
static void feed_set(const uint32_t *w, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        feed[4 * i]     = (uint8_t)w[i];
        feed[4 * i + 1] = (uint8_t)(w[i] >> 8);
        feed[4 * i + 2] = (uint8_t)(w[i] >> 16);
        feed[4 * i + 3] = (uint8_t)(w[i] >> 24);
    }
    g_fuzz_spi = feed;
    g_fuzz_spi_len = 4 * n;
    g_fuzz_spi_pos = 0;
}

static size_t feed_used(void)
{
    return g_fuzz_spi_pos / 4;
}

/* Run one request through exec_item() and return the status of the
 * response the client receives. */
static int req(int who, uint8_t type, const void *body, uint32_t len)
{
    static qitem_t it;
    uint8_t msg[sizeof(struct spiproxy_hdr) + SPIPROXY_MSG_MAX];
    struct spiproxy_hdr h;
    ssize_t n;

    memset(&it, 0, sizeof(it));
    it.c = &g.cl[who];
    it.hdr.ver = SPIPROXY_VER;
    it.hdr.type = type;
    it.hdr.seq = ++seqno;
    it.hdr.len = len;
    if (len) {
        memcpy(it.body, body, len);
    }
    exec_item(&it);
    n = recv(peer[who], msg, sizeof(msg), MSG_DONTWAIT);
    if (n < (ssize_t)sizeof(h)) {
        return -1;
    }
    memcpy(&h, msg, sizeof(h));
    if (h.seq != seqno || h.type != (type | SPIPROXY_RESP)) {
        return -1;
    }
    return h.flags;
}

static int sub(int who, uint8_t type, uint8_t slice, uint32_t period_us)
{
    struct spiproxy_tsfifo_sub rq = { .slice = slice, .period_us = period_us };

    return req(who, type, &rq, sizeof(rq));
}

/* Next pending push for a client: its header type, -1 if none. */
static int push(int who, struct spiproxy_tsfifo_evt *ev, uint8_t *entries)
{
    uint8_t msg[sizeof(struct spiproxy_hdr) + SPIPROXY_MSG_MAX];
    struct spiproxy_hdr h;
    ssize_t n = recv(peer[who], msg, sizeof(msg), MSG_DONTWAIT);

    if (n < (ssize_t)sizeof(h)) {
        return -1;
    }
    memcpy(&h, msg, sizeof(h));
    CHECK(h.seq == 0);
    CHECK(h.flags == SPIPROXY_OK);
    CHECK(h.len == (uint32_t)n - sizeof(h));
    if (ev != NULL && h.len >= sizeof(*ev)) {
        memcpy(ev, msg + sizeof(h), sizeof(*ev));
        if (entries != NULL) {
            memcpy(entries, msg + sizeof(h) + sizeof(*ev), h.len - sizeof(*ev));
        }
    }
    return h.type;
}

/* The 10 register words of a row holding `e` (39 bytes), with flags. */
static void row_words(const uint8_t *e, uint32_t flags, uint32_t *w)
{
    w[0] = flags << 27 | (uint32_t)e[0] | (uint32_t)e[1] << 8 |
           (uint32_t)e[2] << 16;
    for (int r = 1; r < 10; r++) {
        const uint8_t *p = e + 3 + (r - 1) * 4;
        w[r] = (uint32_t)p[0] | (uint32_t)p[1] << 8 |
               (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
    }
}

static void entry_pattern(uint8_t *e, uint8_t seed)
{
    for (int i = 0; i < SPIPROXY_TSFIFO_ENTRY_LEN; i++) {
        e[i] = (uint8_t)(seed + i);
    }
}

static void setup(void)
{
    int sv[2];

    g.freq = 5000000;
    g.rst_fd = -1;
    g.ep_fd = -1;
    g.log = NULL;
    g.lctx.tag = "";
    setlogmask(0);
    for (int i = 0; i < NCLIENTS; i++) {
        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv)) {
            perror("socketpair");
            exit(2);
        }
        memset(&g.cl[i], 0, sizeof(g.cl[i]));
        g.cl[i].used = 1;
        g.cl[i].id = (uint32_t)(i + 1);
        g.cl[i].fd = sv[0];
        snprintf(g.cl[i].comm, sizeof(g.cl[i].comm), "test%d", i + 1);
        peer[i] = sv[1];
    }
}

static void test_subscribe(void)
{
    CHECK(sub(0, SPIPROXY_TSFIFO_SUB, 1, 0) == SPIPROXY_OK);
    CHECK(g_tsf[1].sub == &g.cl[0]);
    CHECK(g_tsf[1].period_us == SPIPROXY_TSFIFO_PERIOD_US);
    CHECK(sub(1, SPIPROXY_TSFIFO_SUB, 1, 0) == SPIPROXY_EBUSY);
    CHECK(sub(1, SPIPROXY_TSFIFO_SUB, 2, 10) == SPIPROXY_OK);
    CHECK(g_tsf[2].period_us == TSF_PERIOD_MIN_US);       /* clamped */
    CHECK(sub(1, SPIPROXY_TSFIFO_SUB, 2, 5000000) == SPIPROXY_OK);
    CHECK(g_tsf[2].period_us == TSF_PERIOD_MAX_US);       /* clamped */
    CHECK(sub(1, SPIPROXY_TSFIFO_UNSUB, 1, 0) == SPIPROXY_EINVAL); /* not its */
    CHECK(sub(1, SPIPROXY_TSFIFO_SUB, 4, 0) == SPIPROXY_EINVAL);   /* slice */
    CHECK(req(1, SPIPROXY_TSFIFO_SUB, "x", 1) == SPIPROXY_EINVAL); /* length */
    CHECK(sub(1, SPIPROXY_TSFIFO_UNSUB, 2, 0) == SPIPROXY_OK);
    CHECK(g_tsf[2].sub == NULL);
    CHECK(push(0, NULL, NULL) == -1 && push(1, NULL, NULL) == -1);
}

static void test_drain(void)
{
    uint8_t e1[SPIPROXY_TSFIFO_ENTRY_LEN], e2[SPIPROXY_TSFIFO_ENTRY_LEN];
    uint8_t got[SPIPROXY_TSFIFO_ROWS * SPIPROXY_TSFIFO_ENTRY_LEN];
    struct spiproxy_tsfifo_evt ev;
    uint32_t w[2 + SPIPROXY_TSFIFO_ROWS * 10 + 1], r1[10], r2[10];
    size_t k;

    /* empty: one read of TSFIFO_0, no push */
    w[0] = TSF_EMPTY;
    feed_set(w, 1);
    tsf_drain(1);
    CHECK(feed_used() == 1);
    CHECK(push(0, NULL, NULL) == -1);

    /* the second read (2R confirm) says empty: no push */
    w[0] = 0;
    w[1] = TSF_EMPTY;
    feed_set(w, 2);
    tsf_drain(1);
    CHECK(feed_used() == 2);
    CHECK(push(0, NULL, NULL) == -1);

    /* two complete rows, then empty */
    entry_pattern(e1, 0x10);
    entry_pattern(e2, 0x80);
    row_words(e1, TSF_FLAGS_FULL, r1);
    row_words(e2, TSF_FLAGS_FULL, r2);
    k = 0;
    w[k++] = r1[0];
    w[k++] = r1[0];
    memcpy(&w[k], r1, sizeof(r1));
    k += 10;
    memcpy(&w[k], r2, sizeof(r2));
    k += 10;
    w[k++] = TSF_EMPTY;
    feed_set(w, k);
    g_tsf[1].drop_cnt = 7;
    tsf_drain(1);
    CHECK(feed_used() == k);
    CHECK(push(0, &ev, got) == (SPIPROXY_TSFIFO_SUB | SPIPROXY_RESP));
    CHECK(ev.slice == 1 && ev.nentries == 2 && ev.drop_cnt == 7);
    CHECK(memcmp(got, e1, sizeof(e1)) == 0);
    CHECK(memcmp(got + SPIPROXY_TSFIFO_ENTRY_LEN, e2, sizeof(e2)) == 0);
    CHECK(g_tsf[1].n_entries == 2);

    /* incomplete row: popped (TSFIFO_1..9 read), dropped, drain stops */
    row_words(e1, 3, r1);
    k = 0;
    w[k++] = r1[0];
    w[k++] = r1[0];
    memcpy(&w[k], r1, sizeof(r1));
    k += 10;
    feed_set(w, k);
    tsf_drain(1);
    CHECK(feed_used() == k);
    CHECK(push(0, NULL, NULL) == -1);
    CHECK(g_tsf[1].n_flushed == 1);

    /* a full FIFO: at most SPIPROXY_TSFIFO_ROWS rows per drain */
    row_words(e1, TSF_FLAGS_FULL, r1);
    k = 0;
    w[k++] = r1[0];
    w[k++] = r1[0];
    for (int i = 0; i < SPIPROXY_TSFIFO_ROWS; i++) {
        memcpy(&w[k], r1, sizeof(r1));
        k += 10;
    }
    w[k] = r1[0];                    /* a 17th row, left for the next drain */
    feed_set(w, k + 1);
    tsf_drain(1);
    CHECK(feed_used() == k);
    CHECK(push(0, &ev, got) == (SPIPROXY_TSFIFO_SUB | SPIPROXY_RESP));
    CHECK(ev.nentries == SPIPROXY_TSFIFO_ROWS);
    CHECK(memcmp(got + (SPIPROXY_TSFIFO_ROWS - 1) * SPIPROXY_TSFIFO_ENTRY_LEN,
                 e1, sizeof(e1)) == 0);

    /* I/O error in the middle of a row: no push, row read again next time */
    k = 0;
    w[k++] = r1[0];
    w[k++] = r1[0];
    w[k++] = r1[0];
    w[k++] = r1[1];
    w[k++] = SPI_FAIL_MAGIC;
    feed_set(w, k);
    tsf_drain(1);
    CHECK(feed_used() == k);
    CHECK(push(0, NULL, NULL) == -1);
}

static void test_fence(void)
{
    struct spiproxy_op op = { .slice = 1, .mmd = LAN80XX_MMD_PTP, .reg = 0x9075 };
    struct spiproxy_op batch[2] = {
        { .slice = 3, .mmd = LAN80XX_MMD_PTP, .reg = 0x9070 },
        { .slice = 1, .mmd = LAN80XX_MMD_PTP, .reg = 0x9079 },
    };
    uint32_t w[2] = { 0x1234, 0x5678 };

    feed_set(w, 2);
    CHECK(req(1, SPIPROXY_READ, &op, sizeof(op)) == SPIPROXY_EBUSY);
    CHECK(req(0, SPIPROXY_READ, &op, sizeof(op)) == SPIPROXY_EBUSY); /* subscriber too */
    op.reg = 0x906f;                                  /* CSR: not a row */
    CHECK(req(1, SPIPROXY_READ, &op, sizeof(op)) == SPIPROXY_OK);
    op.slice = 3;                                     /* slice not subscribed */
    op.reg = 0x9079;
    CHECK(req(1, SPIPROXY_READ, &op, sizeof(op)) == SPIPROXY_OK);
    CHECK(feed_used() == 2);
    feed_set(w, 2);
    CHECK(req(1, SPIPROXY_BATCH, batch, sizeof(batch)) == SPIPROXY_EBUSY);
    CHECK(feed_used() == 1);                          /* stopped at the fence */
}

static void test_tick_reset_drop(void)
{
    uint32_t w[4];
    int n_warns = (int)g.n_warns;

    /* client 1 on slice 1 (from the tests above), client 2 on slice 3 */
    CHECK(sub(1, SPIPROXY_TSFIFO_SUB, 3, 0) == SPIPROXY_OK);
    /* in this build every deadline is due: per slice, one empty drain
     * then one drop counter read */
    w[0] = TSF_EMPTY;
    w[1] = 7;                        /* slice 1: drop count unchanged */
    w[2] = TSF_EMPTY;
    w[3] = 2;                        /* slice 3: 0 -> 2, warned */
    feed_set(w, 4);
    tsf_tick();
    CHECK(feed_used() == 4);
    CHECK(g_tsf[1].drop_cnt == 7 && g_tsf[3].drop_cnt == 2);
    CHECK((int)g.n_warns == n_warns + 1);
    int t = tsf_timeout_ms();        /* next deadline: the drain period */
    CHECK(t > 0 && t <= (int)(SPIPROXY_TSFIFO_PERIOD_US / 1000));

    /* RESET: OK to the requester, one notice to each subscriber */
    struct spiproxy_reset rr = { 0 };
    g.rst_fd = 1;                    /* pretend a reset line exists */
    CHECK(sub(0, SPIPROXY_TSFIFO_SUB, 2, 0) == SPIPROXY_OK);  /* 2nd slice */
    CHECK(req(1, SPIPROXY_RESET, &rr, sizeof(rr)) == SPIPROXY_OK);
    CHECK(push(0, NULL, NULL) == (SPIPROXY_RESET | SPIPROXY_RESP));
    CHECK(push(0, NULL, NULL) == -1);                /* once, not per slice */
    CHECK(push(1, NULL, NULL) == (SPIPROXY_RESET | SPIPROXY_RESP));
    g.rst_fd = -1;

    /* a push that cannot be delivered is counted */
    int fd = g_tsf[3].sub->fd;
    uint8_t e[SPIPROXY_TSFIFO_ENTRY_LEN];
    uint32_t r[10], v[13];
    entry_pattern(e, 1);
    row_words(e, TSF_FLAGS_FULL, r);
    v[0] = r[0];
    v[1] = r[0];
    memcpy(&v[2], r, sizeof(r));
    v[12] = TSF_EMPTY;
    feed_set(v, 13);
    g_tsf[3].sub->fd = -1;
    tsf_drain(3);
    CHECK(g_tsf[3].n_push_err == 1);
    g_tsf[3].sub->fd = fd;

    CHECK(strcmp(type_name(SPIPROXY_RESET), "RESET") == 0);
    CHECK(strcmp(type_name(SPIPROXY_TSFIFO_UNSUB), "TSFIFO_UNSUB") == 0);
}

static void test_drop(void)
{
    /* a disconnecting client loses all its subscriptions */
    CHECK(g_tsf[1].sub == &g.cl[0] && g_tsf[2].sub == &g.cl[0]);
    client_drop(&g.cl[0]);
    CHECK(g_tsf[1].sub == NULL && g_tsf[2].sub == NULL);
    CHECK(g_tsf[3].sub == &g.cl[1]);
    client_drop(&g.cl[1]);
    CHECK(g_tsf[3].sub == NULL);
}

int main(void)
{
    setup();
    test_subscribe();
    test_drain();
    test_fence();
    test_tick_reset_drop();
    test_drop();
    if (n_fail) {
        fprintf(stderr, "test_tsfifo: %d check(s) failed\n", n_fail);
        return EXIT_FAILURE;
    }
    printf("test_tsfifo: all checks passed\n");
    return EXIT_SUCCESS;
}
