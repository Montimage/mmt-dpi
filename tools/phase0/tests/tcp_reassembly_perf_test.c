/*
 * tcp_reassembly_perf_test.c — issue #245 harness for the bounded, linear
 * TCP reassembly rework (F-PERF-003/004/005/006, F-BUG-038).
 *
 * Drives synthetic Ethernet/IPv4/TCP packets through the real
 * process_packet_with_reassembly() pipeline and asserts:
 *
 *   A. in-order stream (2048 x 512 B): zero segment-list node visits
 *      (tail-pointer append — F-PERF-004), zero steady-state packet
 *      allocations (pooled slot — F-PERF-003), bytes moved == stream bytes
 *      (each byte flattened once — F-PERF-005), content verified.
 *   B. reordered streams: reversed arrivals (O(1) head-prepend, still zero
 *      visits) and interleaved arrivals (bounded interior-insert walk);
 *      the flattened image is the seq-sorted concatenation either way.
 *   C. retransmission duplicates are dropped and counted.
 *   D. overlapping segment ranges: concatenation semantics preserved,
 *      memory stays bounded (pre-#245 tcp_seg_reassembly() behaviour).
 *   E. 32-bit sequence wraparound: a stream crossing 2^32 keeps order.
 *   F. set_tcp_reassembly_limit(): a 64 KiB ceiling bounds the flattened
 *      image and pending store; surplus bytes are dropped and counted.
 *   G. teardown: expiring the sessions drops the resident-bytes gauge to
 *      zero; the ipacket pool drains at mmt_close_handler().
 *
 * Built against a plain (non-sanitized) SDK by
 * run_tcp_reassembly_perf_test.sh — the timing/assertion output is the
 * before/after comparison for the issue; ASan/UBSan coverage comes from
 * running the same source under the sanitizer variant runners.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>     /* struct pkthdr (DLT_EN10MB comes from mmt_core.h) */
#include <time.h>
#include <inttypes.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "packet_processing.h"   /* stat accessors + internals (private hdr) */

/* ------------------------------------------------------------------ */
/* plumbing                                                            */
/* ------------------------------------------------------------------ */
static int g_failures = 0;

#define CHECK(cond, ...) do {                                        \
        if (!(cond)) {                                               \
            g_failures++;                                            \
            printf("  FAIL %s:%d: ", __func__, __LINE__);            \
            printf(__VA_ARGS__);                                     \
            printf("\n");                                            \
        }                                                            \
    } while (0)

/*
 * Packet fixture — Ethernet + IPv4 + TCP (PSH|ACK) like the other phase0
 * harnesses; the pipeline does not verify checksums. Fields patched per
 * packet: ip.tot_len, tcp.source (per-phase flow), tcp.seq, payload.
 */
#define HDR_LEN   54                 /* eth(14) + ip(20) + tcp(20)     */
#define TOTLEN_OFF (14 + 2)          /* iphdr.tot_len                  */
#define SPORT_OFF  (14 + 20)         /* tcphdr.source                  */
#define SEQ_OFF    (14 + 20 + 4)     /* tcphdr.seq                     */

static uint8_t pkt_template[HDR_LEN] = {
    0x02,0,0,0,0,2, 0x02,0,0,0,0,1, 0x08,0x00,                 /* eth */
    0x45,0x00,0x00,0x40, 0,1, 0x40,0x00, 64, 6, 0,0,           /* ip  */
    10,0,0,1, 10,0,0,2,                                        /* src,dst */
    0x9c,0x40, 0x00,0x50, 0,0,3,0xe8, 0,0,0,0,                 /* tcp */
    0x50,0x18, 0xff,0xff, 0,0, 0,0
};

static uint8_t pkt_buf[HDR_LEN + 2048];
static uint8_t seg_buf[2048];

/* Deterministic payload pattern for segment index i (seq-order index). */
static void fill_seg(uint32_t seg_index, uint8_t *buf, uint32_t len) {
    for (uint32_t j = 0; j < len; j++)
        buf[j] = (uint8_t) (seg_index * 33u + j * 7u);
}

static uint8_t expected_seg_byte(uint32_t seg_index, uint32_t j) {
    return (uint8_t) (seg_index * 33u + j * 7u);
}

static void feed_pkt(mmt_handler_t *h, uint16_t sport, uint32_t seq,
                 const uint8_t *payload, uint32_t plen, long ts_sec) {
    memcpy(pkt_buf, pkt_template, HDR_LEN);
    uint32_t tot = 20 + 20 + plen;
    pkt_buf[TOTLEN_OFF]     = (uint8_t) (tot >> 8);
    pkt_buf[TOTLEN_OFF + 1] = (uint8_t) tot;
    pkt_buf[SPORT_OFF]     = (uint8_t) (sport >> 8);
    pkt_buf[SPORT_OFF + 1] = (uint8_t) sport;
    pkt_buf[SEQ_OFF]     = (uint8_t) (seq >> 24);
    pkt_buf[SEQ_OFF + 1] = (uint8_t) (seq >> 16);
    pkt_buf[SEQ_OFF + 2] = (uint8_t) (seq >> 8);
    pkt_buf[SEQ_OFF + 3] = (uint8_t) seq;
    if (plen > 0) memcpy(pkt_buf + HDR_LEN, payload, plen);
    struct pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.caplen = hdr.len = HDR_LEN + plen;
    hdr.ts.tv_sec = ts_sec;
    packet_process(h, &hdr, pkt_buf);
}

/* ------------------------------------------------------------------ */
/* extraction — the packet handler asks for the session payload so the  */
/* incremental drain runs inside the pipeline, like a real consumer.    */
/* ------------------------------------------------------------------ */
static uint32_t g_last_len = 0;
static const uint8_t *g_last_img = NULL;   /* image pointer (session-owned) */
static uint64_t g_cb_count = 0;
static int g_extract_all = 1;   /* 0: extract only on the plen==0 flush ACK */

static int pkt_handler(const ipacket_t *ip, mmt_opaque_t args) {
    (void) args;
    g_cb_count++;
    /* A payload-less TCP packet (caplen == header-only) is the per-phase
     * flush: with g_extract_all == 0 the intermediate packets keep their
     * segments pending and only the flush drains the store — this is how
     * reordered/duplicate arrivals are verified as a full image. */
    if (!g_extract_all && ip->p_hdr->caplen > HDR_LEN)
        return 0;
    void *l = get_attribute_extracted_data(ip, PROTO_TCP, TCP_SESSION_PAYLOAD_UP_LEN);
    g_last_len = (l != NULL) ? *((uint32_t *) l) : 0;
    g_last_img = (const uint8_t *) get_attribute_extracted_data(ip, PROTO_TCP, TCP_SESSION_PAYLOAD_UP);
    return 0;
}

/* Verify the last extracted image equals the seq-sorted concatenation of
 * seg_count segments of plen bytes with the fill_seg pattern. */
static void check_image(uint32_t seg_count, uint32_t plen) {
    CHECK(g_last_img != NULL, "no flattened image returned");
    CHECK(g_last_len == seg_count * plen,
          "image_len %u != expected %u", g_last_len, seg_count * plen);
    if (g_last_img == NULL || g_last_len != seg_count * plen) return;
    uint32_t bad = 0;
    for (uint32_t i = 0; i < seg_count && bad < 5; i++) {
        for (uint32_t j = 0; j < plen && bad < 5; j++) {
            if (g_last_img[i * plen + j] != expected_seg_byte(i, j)) {
                CHECK(0, "image[%u] = %02x, expected %02x (seg %u)",
                      i * plen + j, g_last_img[i * plen + j],
                      expected_seg_byte(i, j), i);
                bad++;
            }
        }
    }
}

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec * 1e9 + (double) ts.tv_nsec;
}

#define T0 1000
#define TIMEOUT_DELAY 60
static int g_expired = 0;
static void on_session_expired(const mmt_session_t *s, mmt_opaque_t args) {
    (void) s; (void) args;
    g_expired++;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char errbuf[1024];

    if (!init_extraction()) {
        printf("tcp-reassembly-perf: init_extraction() failed\n");
        return 2;
    }
    /* TCP_ENABLE_REASSEMBLE is a protocol-global toggle: arm it before the
     * handler starts processing so the reassembly pre-classifier is live. */
    update_protocol(PROTO_TCP, TCP_ENABLE_REASSEMBLE);

    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        printf("tcp-reassembly-perf: mmt_init_handler failed: %s\n", errbuf);
        return 2;
    }
    CHECK(enable_mmt_reassembly(h) == 1, "enable_mmt_reassembly");
    set_default_session_timed_out(h, TIMEOUT_DELAY);
    register_session_timeout_handler(h, on_session_expired, NULL);
    CHECK(register_packet_handler(h, 1, pkt_handler, NULL) == 1,
          "register_packet_handler");
    CHECK(register_extraction_attribute_by_name(h, "TCP", "TCP_SESSION_PAYLOAD_UP") == 1,
          "register tcp_session_payload_up");
    CHECK(register_extraction_attribute_by_name(h, "TCP", "TCP_SESSION_PAYLOAD_UP_LEN") == 1,
          "register tcp_session_payload_up_len");

    /* ------------------------------------------------------------ */
    /* Phase A — in-order stream, extraction on every packet          */
    /* ------------------------------------------------------------ */
    {
        const uint32_t N = 2048, PLEN = 512;
        uint64_t v0 = mmt_tcp_reasm_insert_visits();
        uint64_t m0 = mmt_tcp_reasm_bytes_moved();
        uint64_t a0 = mmt_reassembly_packet_alloc_count();
        double t0 = now_ns();
        for (uint32_t i = 0; i < N; i++) {
            fill_seg(i, seg_buf, PLEN);
            feed_pkt(h, 0x9c40, 1000 + i * PLEN, seg_buf, PLEN, T0);
        }
        double ns = now_ns() - t0;
        check_image(N, PLEN);
        uint64_t visits = mmt_tcp_reasm_insert_visits() - v0;
        uint64_t moved = mmt_tcp_reasm_bytes_moved() - m0;
        uint64_t allocs = mmt_reassembly_packet_alloc_count() - a0;
        CHECK(visits == 0,
              "in-order stream walked the segment list %llu times (F-PERF-004)",
              (unsigned long long) visits);
        CHECK(moved == (uint64_t) N * PLEN,
              "flatten moved %llu bytes for a %u-byte stream (F-PERF-005)",
              (unsigned long long) moved, N * PLEN);
        CHECK(allocs <= 4,
              "reassembly path allocated %llu times over %u packets (F-PERF-003)",
              (unsigned long long) allocs, N);
        CHECK(mmt_tcp_reasm_resident_bytes() == (uint64_t) N * PLEN,
              "resident bytes %llu != image bytes %u",
              (unsigned long long) mmt_tcp_reasm_resident_bytes(), N * PLEN);
        printf("  in-order: %u pkts, %.0f ns/pkt, moved=%llu B, visits=%llu, allocs=%llu\n",
               N, ns / N, (unsigned long long) moved,
               (unsigned long long) visits, (unsigned long long) allocs);
    }

    /* ------------------------------------------------------------ */
    /* Phase B1 — strictly reversed arrivals (head-prepend, O(1))     */
    /* ------------------------------------------------------------ */
    {
        const uint32_t N = 512, PLEN = 256;
        const uint32_t base = 70000;
        g_extract_all = 0;                 /* accumulate; flush at the end */
        g_last_img = NULL; g_last_len = 0;
        uint64_t v0 = mmt_tcp_reasm_insert_visits();
        for (int32_t i = N - 1; i >= 0; i--) {
            fill_seg((uint32_t) i, seg_buf, PLEN);
            feed_pkt(h, 0x9c41, base + (uint32_t) i * PLEN, seg_buf, PLEN, T0);
        }
        feed_pkt(h, 0x9c41, base + N * PLEN, NULL, 0, T0);   /* flush ACK */
        check_image(N, PLEN);
        uint64_t visits = mmt_tcp_reasm_insert_visits() - v0;
        CHECK(visits == 0,
              "reversed stream walked the list %llu times", (unsigned long long) visits);
        printf("  reversed: %u pkts, visits=%llu\n", N, (unsigned long long) visits);
    }

    /* ------------------------------------------------------------ */
    /* Phase B2 — interleaved arrivals (interior inserts, bounded)    */
    /* ------------------------------------------------------------ */
    {
        const uint32_t N = 256, PLEN = 256;
        const uint32_t base = 200000;
        g_last_img = NULL; g_last_len = 0;
        uint64_t v0 = mmt_tcp_reasm_insert_visits();
        for (uint32_t i = 0; i < N; i += 2) {            /* evens first  */
            fill_seg(i, seg_buf, PLEN);
            feed_pkt(h, 0x9c42, base + i * PLEN, seg_buf, PLEN, T0);
        }
        for (uint32_t i = 1; i < N; i += 2) {            /* then odds    */
            fill_seg(i, seg_buf, PLEN);
            feed_pkt(h, 0x9c42, base + i * PLEN, seg_buf, PLEN, T0);
        }
        feed_pkt(h, 0x9c42, base + N * PLEN, NULL, 0, T0);   /* flush ACK */
        check_image(N, PLEN);
        uint64_t visits = mmt_tcp_reasm_insert_visits() - v0;
        CHECK(visits > 0, "interleaved inserts took no interior walk");
        CHECK(visits < (uint64_t) N * N,
              "interleaved visits %llu exceed the N^2 sanity bound",
              (unsigned long long) visits);
        printf("  interleaved: %u pkts, visits=%llu\n", N, (unsigned long long) visits);
    }

    /* ------------------------------------------------------------ */
    /* Phase C — retransmission duplicates                            */
    /* ------------------------------------------------------------ */
    {
        const uint32_t N = 256, PLEN = 256;
        const uint32_t base = 400000;
        g_last_img = NULL; g_last_len = 0;
        uint64_t d0 = mmt_tcp_reasm_bytes_dropped();
        for (uint32_t i = 0; i < N; i++) {
            fill_seg(i, seg_buf, PLEN);
            feed_pkt(h, 0x9c43, base + i * PLEN, seg_buf, PLEN, T0);
            feed_pkt(h, 0x9c43, base + i * PLEN, seg_buf, PLEN, T0);  /* dup */
        }
        feed_pkt(h, 0x9c43, base + N * PLEN, NULL, 0, T0);   /* flush ACK */
        check_image(N, PLEN);
        uint64_t dropped = mmt_tcp_reasm_bytes_dropped() - d0;
        CHECK(dropped == (uint64_t) N * PLEN,
              "duplicate drop counted %llu B, expected %u B",
              (unsigned long long) dropped, N * PLEN);
        printf("  duplicates: %u pkts (x2), dropped=%llu B\n",
               N, (unsigned long long) dropped);
    }

    /* ------------------------------------------------------------ */
    /* Phase D — overlapping ranges: sorted-concat semantics + bound  */
    /* ------------------------------------------------------------ */
    {
        /* Two segments [seq0,+200] and [seq0+100,+200] overlap 100 bytes;
         * the list keeps both (distinct seqs) and the image concatenates
         * them — same observable result as pre-#245 tcp_seg_reassembly(). */
        const uint32_t base = 600000;
        g_last_img = NULL; g_last_len = 0;
        memset(seg_buf, 'A', 200);
        feed_pkt(h, 0x9c44, base, seg_buf, 200, T0);
        memset(seg_buf, 'B', 200);
        feed_pkt(h, 0x9c44, base + 100, seg_buf, 200, T0);
        feed_pkt(h, 0x9c44, base + 300, NULL, 0, T0);        /* flush ACK */
        CHECK(g_last_len == 400, "overlap image_len %u != 400", g_last_len);
        if (g_last_img != NULL && g_last_len == 400) {
            CHECK(g_last_img[0] == 'A' && g_last_img[199] == 'A',
                  "overlap: first segment bytes mangled");
            CHECK(g_last_img[200] == 'B' && g_last_img[399] == 'B',
                  "overlap: second segment bytes mangled");
        }
        printf("  overlap: image_len=%u (concatenated, bounded)\n", g_last_len);
    }

    /* ------------------------------------------------------------ */
    /* Phase E — 32-bit sequence wraparound                           */
    /* ------------------------------------------------------------ */
    {
        g_last_img = NULL; g_last_len = 0;
        uint64_t v0 = mmt_tcp_reasm_insert_visits();
        memset(seg_buf, 0x10, 16);
        feed_pkt(h, 0x9c45, 0xfffffff0u, seg_buf, 16, T0);   /* straddles 2^32 */
        memset(seg_buf, 0x20, 16);
        feed_pkt(h, 0x9c45, 0x00000000u, seg_buf, 16, T0);   /* post-wrap      */
        memset(seg_buf, 0x30, 16);
        feed_pkt(h, 0x9c45, 0x00000010u, seg_buf, 16, T0);
        feed_pkt(h, 0x9c45, 0x00000020u, NULL, 0, T0);       /* flush ACK */
        CHECK(mmt_tcp_reasm_insert_visits() - v0 == 0,
              "wraparound stream took a list walk");
        CHECK(g_last_len == 48, "wrap image_len %u != 48", g_last_len);
        if (g_last_img != NULL && g_last_len == 48) {
            CHECK(g_last_img[0] == 0x10 && g_last_img[16] == 0x20 && g_last_img[32] == 0x30,
                  "wrap image order broken across 2^32");
        }
        printf("  wrap: image_len=%u\n", g_last_len);
    }

    /* ------------------------------------------------------------ */
    /* Phase F — ceiling: 64 KiB limit on a 256 KiB stream            */
    /* ------------------------------------------------------------ */
    {
        const uint32_t N = 256, PLEN = 1024, LIMIT = 64 * 1024;
        g_extract_all = 1;
        g_last_img = NULL; g_last_len = 0;
        CHECK(set_tcp_reassembly_limit(h, LIMIT) == 1, "set limit 64KiB");
        uint64_t d0 = mmt_tcp_reasm_bytes_dropped();
        /* resident is a GLOBAL gauge — the earlier phases' images still count.
         * The per-flow ceiling means this phase's session adds at most LIMIT. */
        uint64_t r0 = mmt_tcp_reasm_resident_bytes();
        for (uint32_t i = 0; i < N; i++) {
            fill_seg(i, seg_buf, PLEN);
            feed_pkt(h, 0x9c46, 800000 + i * PLEN, seg_buf, PLEN, T0);
        }
        uint64_t dropped = mmt_tcp_reasm_bytes_dropped() - d0;
        uint64_t r1 = mmt_tcp_reasm_resident_bytes();
        CHECK(g_last_len <= LIMIT,
              "image_len %u exceeds the %u-byte ceiling", g_last_len, LIMIT);
        CHECK(r1 - r0 <= LIMIT,
              "phase-F flow added %llu resident B beyond the %u ceiling (F-BUG-038)",
              (unsigned long long) (r1 - r0), LIMIT);
        CHECK(dropped > 100 * 1024,
              "ceiling dropped only %llu B of a %u-B stream",
              (unsigned long long) dropped, N * PLEN);
        CHECK(set_tcp_reassembly_limit(h, 0) == 1 &&
              h->tcp_reassembly_limit == MMT_TCP_REASSEMBLY_LIMIT_DEFAULT,
              "limit 0 did not restore the default");
        printf("  ceiling: image_len=%u, dropped=%llu B, resident=%llu B\n",
               g_last_len, (unsigned long long) dropped,
               (unsigned long long) mmt_tcp_reasm_resident_bytes());
    }

    /* ------------------------------------------------------------ */
    /* Phase G — teardown: expire sessions, drain the pool            */
    /* ------------------------------------------------------------ */
    {
        /* One packet 2*timeout later: the expiry sweep frees every earlier
         * session's reassembly state through clean_session_payload(). */
        feed_pkt(h, 0x9c47, 0, NULL, 0, T0 + 2 * TIMEOUT_DELAY);
        CHECK(g_expired >= 6,
              "only %d sessions expired (expected the 6 phase flows)", g_expired);
        CHECK(mmt_tcp_reasm_resident_bytes() == 0,
              "%llu reassembly bytes still resident after teardown",
              (unsigned long long) mmt_tcp_reasm_resident_bytes());
        printf("  teardown: %d sessions expired, resident=%llu B\n",
               g_expired, (unsigned long long) mmt_tcp_reasm_resident_bytes());
    }

    mmt_close_handler(h);
    /* init_extraction() dlopen()s every plugin .so — without
     * close_extraction() the plugin copy of libmmt_tcpip is never dlclosed,
     * so LeakSanitizer reports its constructor-time avltrees as leaked. */
    close_extraction();

    if (g_failures == 0) {
        printf("tcp-reassembly-perf: PASS (%llu handler callbacks)\n",
               (unsigned long long) g_cb_count);
        return 0;
    }
    printf("tcp-reassembly-perf: FAIL (%d failures)\n", g_failures);
    return 1;
}
