/*
 * session_scale_test.c — issue #254 (F-PERF-011/012/013) scale harness.
 *
 * Exercises the reworked timeout/session stores at a 100k-session scale:
 *
 *   1. Burst: 100,000 distinct TCP flows through packet_process() — grows the
 *      per-protocol session table, the interned-IP registry and the timeout
 *      index through the real pipeline.
 *   2. Zero-allocation timeout index: with an interposed allocation counter
 *      armed, drive a >400k-op milestone churn — milestone insert, advance
 *      (update), list lookup, per-session unlink and milestone delete — and
 *      assert the counter stayed at zero.
 *   3. Idle: advance the packet clock past the session timeout so the whole
 *      burst expires through the real per-second sweep; assert every burst
 *      session expired and the process RSS returned within 20% of its
 *      pre-burst value (the session and interned-IP tables shrink instead of
 *      pinning peak memory — F-PERF-011).
 *
 * Built against a plain (non-sanitized) SDK by run_session_scale_test.sh:
 * ASan would own malloc and keep freed blocks quarantined, which would
 * defeat both the allocation counter and the RSS check.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>   /* __libc_malloc/__libc_calloc/..., malloc_trim */
#include <pcap.h>     /* struct pkthdr (DLT_EN10MB itself comes from mmt_core.h) */

#include "mmt_core.h"
#include "packet_processing.h"   /* mmt_handler_t / mmt_session_t internals */
#include "hash_utils.h"          /* insert_session_timeout_milestone & co.  */

/* ------------------------------------------------------------------ */
/* allocation counter — interposed libc entry points. A definition in  */
/* the main executable wins the dynamic linker's lookup, so the calls  */
/* made inside libmmt_core/libmmt_tcpip are counted here too.           */
/* ------------------------------------------------------------------ */
static long g_alloc_count;
static volatile int g_counting;

/* glibc internal entry points — <malloc.h> does not declare them. */
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void  __libc_free(void *);

void *malloc(size_t n) {
    if (g_counting) g_alloc_count++;
    return __libc_malloc(n);
}
void *calloc(size_t nm, size_t sz) {
    if (g_counting) g_alloc_count++;
    return __libc_calloc(nm, sz);
}
void *realloc(void *p, size_t n) {
    if (g_counting) g_alloc_count++;
    return __libc_realloc(p, n);
}
void free(void *p) {
    __libc_free(p);
}

/* ------------------------------------------------------------------ */
/* test plumbing                                                       */
/* ------------------------------------------------------------------ */
static int g_failures = 0;
static int g_expired = 0;

#define CHECK(cond, ...) do {                                        \
        if (!(cond)) {                                               \
            g_failures++;                                            \
            printf("  FAIL %s:%d: ", __func__, __LINE__);            \
            printf(__VA_ARGS__);                                     \
            printf("\n");                                            \
        }                                                            \
    } while (0)

static void on_session_expired(const mmt_session_t *s, mmt_opaque_t args) {
    (void) s; (void) args;
    g_expired++;
}

static long read_rss_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (f == NULL) return -1;
    char line[256];
    long rss = -1;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (sscanf(line, "VmRSS: %ld kB", &rss) == 1) break;
    }
    fclose(f);
    return rss;
}

/* ------------------------------------------------------------------ */
/* packet fixture — Ethernet + IPv4 + TCP, like the fi_engine packet.  */
/* The pipeline does not verify checksums; only the 5-tuple matters.   */
/* ------------------------------------------------------------------ */
static uint8_t pkt_template[] = {
    0x02,0,0,0,0,2, 0x02,0,0,0,0,1, 0x08,0x00,                 /* eth */
    0x45,0x00,0x00,0x40, 0,1, 0x40,0x00, 64, 6, 0,0,           /* ip  */
    10,0,0,1, 10,0,0,2,                                        /* src,dst */
    0x9c,0x40, 0x00,0x50, 0,0,3,0xe8, 0,0,0,0,                 /* tcp */
    0x50,0x18, 0xff,0xff, 0,0, 0,0,
    'G','E','T',' ','/',' ','\r','\n','\r','\n'                /* payload */
};
#define SADDR_OFF (14 + 12)  /* eth(14) + iphdr.saddr offset(12) */
#define SPORT_OFF (14 + 20)  /* eth + iphdr(20) + tcphdr.source(0) */

#define N_SESSIONS 100000
#define TIMEOUT_DELAY 60
#define T0 1000            /* burst timestamp (seconds) */
#define M0 4352            /* fabricated-churn base milestone: slots 256..383,
                              clear of the real milestone slot (1060 % 1024 = 36) */

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char errbuf[1024];
    uint8_t pkt[sizeof(pkt_template)];
    struct pkthdr hdr;
    long i;

    if (!init_extraction()) {
        printf("session-scale: init_extraction() failed\n");
        return 2;
    }
    mmt_handler_t *h = mmt_init_handler(DLT_EN10MB, 0, errbuf);
    if (h == NULL) {
        printf("session-scale: mmt_init_handler failed: %s\n", errbuf);
        return 2;
    }
    set_default_session_timed_out(h, TIMEOUT_DELAY);
    register_session_timeout_handler(h, on_session_expired, NULL);

    memset(&hdr, 0, sizeof(hdr));
    hdr.caplen = hdr.len = sizeof(pkt_template);

    long rss_pre = read_rss_kb();

    /* ---- Phase 1: 100k-session burst through the real pipeline ---------- */
    for (i = 0; i < N_SESSIONS; i++) {
        memcpy(pkt, pkt_template, sizeof(pkt));
        /* distinct flow per iteration: 10.i.j.k source + varying port */
        pkt[SADDR_OFF + 1] = (uint8_t) (i >> 16);
        pkt[SADDR_OFF + 2] = (uint8_t) (i >> 8);
        pkt[SADDR_OFF + 3] = (uint8_t) i;
        pkt[SPORT_OFF]     = (uint8_t) (0x40 + ((i * 7) & 0x3f));
        hdr.ts.tv_sec  = T0;
        hdr.ts.tv_usec = 0;
        packet_process(h, &hdr, pkt);
    }
    uint64_t burst_sessions = h->sessions_count;
    CHECK(burst_sessions >= N_SESSIONS,
          "burst created only %llu sessions (expected >= %d)",
          (unsigned long long) burst_sessions, N_SESSIONS);
    long rss_peak = read_rss_kb();
    printf("  burst: %llu sessions, RSS %ld -> %ld KiB\n",
           (unsigned long long) burst_sessions, rss_pre, rss_peak);

    /* ---- Phase 2: armed zero-allocation timeout-index churn ------------- */
    mmt_session_t *fake = (mmt_session_t *) calloc(N_SESSIONS, sizeof(*fake));
    CHECK(fake != NULL, "fabricated session array");
    if (fake == NULL) { mmt_close_handler(h); return 2; }

    g_alloc_count = 0;
    g_counting = 1;

    /* (a) 100k inserts on one fresh milestone — prepend, zero allocations */
    for (i = 0; i < N_SESSIONS; i++) {
        fake[i].session_timeout_milestone = M0;
        if (insert_session_timeout_milestone(h, M0, &fake[i]) != 1) {
            CHECK(0, "insert milestone %d failed at i=%ld", M0, i);
            break;
        }
    }
    CHECK(get_timed_out_session_list(h, M0) == &fake[N_SESSIONS - 1],
          "milestone %d list head is the last prepended session", M0);

    /* (b) 100k timeout advances M0 -> M0+1 — the hot-path update */
    for (i = 0; i < N_SESSIONS; i++) {
        if (update_session_timeout_milestone(h, M0 + 1, M0, &fake[i]) != 1) {
            CHECK(0, "advance milestone failed at i=%ld", i);
            break;
        }
        fake[i].session_timeout_milestone = M0 + 1; /* caller keeps the field in
                                                     step — same contract the
                                                     engine follows */
    }
    CHECK(get_timed_out_session_list(h, M0) == NULL,
          "source milestone %d drained after the advances", M0);

    /* (c) 100k per-session unlinks via force_session_timeout */
    for (i = 0; i < N_SESSIONS; i++) {
        if (force_session_timeout(h, &fake[i]) != 1) {
            CHECK(0, "force_session_timeout failed at i=%ld", i);
            break;
        }
    }
    CHECK(get_timed_out_session_list(h, M0 + 1) == NULL,
          "milestone %d drained after force-unlinks", M0 + 1);
    CHECK(delete_timeout_milestone(h, M0 + 1) == 1, "delete empty milestone");

    /* (d) 100k inserts spread over 64 distinct milestones + per-second sweep */
    for (i = 0; i < N_SESSIONS; i++) {
        uint32_t m = (uint32_t) (M0 + 16 + (i & 63));
        fake[i].session_timeout_milestone = m;
        if (insert_session_timeout_milestone(h, m, &fake[i]) != 1) {
            CHECK(0, "spread insert failed at i=%ld", i);
            break;
        }
    }
    for (i = 0; i < 64; i++) {
        uint32_t m = (uint32_t) (M0 + 16 + i);
        mmt_session_t *list = get_timed_out_session_list(h, m);
        CHECK(list != NULL, "milestone %u list missing", m);
        while (list != NULL) {
            mmt_session_t *nxt = list->next;
            if (force_session_timeout(h, list) != 1) {
                CHECK(0, "spread force unlink failed");
                break;
            }
            list = nxt;
        }
        CHECK(get_timed_out_session_list(h, m) == NULL,
              "milestone %u still live after unlink", m);
        CHECK(delete_timeout_milestone(h, m) == 1, "delete milestone %u", m);
    }

    g_counting = 0;
    CHECK(g_alloc_count == 0,
          "timeout index performed %ld allocation(s) across >%d ops "
          "(insert+advance+lookup+unlink+delete at 100k sessions)",
          g_alloc_count, 4 * N_SESSIONS);
    printf("  timeout index: %d+ ops, %ld allocations\n",
           4 * N_SESSIONS, g_alloc_count);
    free(fake);

    /* ---- Phase 3: idle — expire the whole burst through the real sweep --- */
    memset(&hdr, 0, sizeof(hdr));
    hdr.caplen = hdr.len = sizeof(pkt_template);
    memcpy(pkt, pkt_template, sizeof(pkt));
    pkt[SADDR_OFF + 3] = 0xfe; /* one extra flow — survives the sweep */
    hdr.ts.tv_sec  = T0 + TIMEOUT_DELAY + 2;
    hdr.ts.tv_usec = 0;
    packet_process(h, &hdr, pkt);

    CHECK(g_expired >= (int) burst_sessions,
          "sweep expired %d of %llu burst sessions",
          g_expired, (unsigned long long) burst_sessions);
    CHECK(h->active_sessions_count <= 1,
          "%llu sessions still active after the idle sweep",
          (unsigned long long) h->active_sessions_count);

    malloc_trim(0);
    long rss_post = read_rss_kb();
    printf("  idle:  expired=%d, RSS %ld KiB (pre-burst %ld, peak %ld)\n",
           g_expired, rss_post, rss_pre, rss_peak);
    /* F-PERF-011 acceptance: resident memory back within 20% of pre-burst. */
    if (rss_pre > 0 && rss_post > 0) {
        CHECK(rss_post * 5 <= rss_pre * 6,
              "RSS did not return within 20%% of pre-burst "
              "(pre=%ld KiB, post=%ld KiB, peak=%ld KiB)",
              rss_pre, rss_post, rss_peak);
    }

    mmt_close_handler(h);
    close_extraction();

    if (g_failures == 0) {
        printf("session-scale: PASS (burst=%llu sessions, expired=%d, "
               "index ops alloc-free, RSS %ld->%ld->%ld KiB)\n",
               (unsigned long long) burst_sessions,
               g_expired, rss_pre, rss_peak, rss_post);
        return 0;
    }
    printf("session-scale: %d check(s) FAILED\n", g_failures);
    return 1;
}
