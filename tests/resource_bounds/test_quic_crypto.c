/*
 * test_quic_crypto.c — the "quic-crypto" resource_bounds fixture (issue
 * #571): collecting the ClientHello of QUIC client Initials keeps at most
 * one buffer of the hello's declared length (2^14 bytes at most) and one
 * facts block per flow, allocates nothing for CRYPTO frames outside the
 * message window or for a header it never completes, decrypts at most
 * QUIC_CRYPTO_MAX_ATTEMPTS Initials per flow, and leaves nothing allocated
 * once every flow is released — the call the QUIC session cleanup makes
 * when a session times out (_quic_ietf_session_data_cleanup).
 *
 * quic_ietf_crypto.c, tls_client_hello.c, quic_ietf_initial.c, mmt_crypto.c,
 * mmt_sha256.c and memory.c are compiled beside this TU with the counted
 * allocator of tcp-memory.
 *
 * Workload (fixed seed): 1,000 flows, all alive until teardown, in turn
 *
 *   complete   the RFC 9001 A.2 ClientHello as 1 .. 6 seeded CRYPTO frames
 *              per packet, shuffled, over 1 .. 3 packets: facts kept
 *   header     1 .. 3 bytes of the handshake header only: never started
 *   in-flight  the header and part of the hello, a hole left (every tenth
 *              declares a 2^14-byte hello): live at teardown
 *   hostile    CRYPTO frames at offset 2^62-1, 16380 + 10, 2^32 + 0..4095,
 *              a length 2^62-1 and one past the plaintext: no allocation
 *   forged     20 RFC 9001 A.2 Initials with one seeded byte flipped:
 *              at most 8 decryptions, nothing allocated
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../src/mmt_tcpip/lib/protocols/quic_ietf_crypto.h"
#include "../parser_boundaries/quic_initial_vectors.h"

#include "tcp_alloc_count.h"
#include "rb_result.h"

#define RB "quic-crypto" /* results.json fixture id */

static int checks;
static int failures;
#define CHECK(cond, ...)                                                                                     \
    do {                                                                                                     \
        checks++;                                                                                            \
        if (!(cond)) {                                                                                       \
            failures++;                                                                                      \
            fprintf(stderr, "FAIL %d: ", __LINE__);                                                          \
            fprintf(stderr, __VA_ARGS__);                                                                    \
            fprintf(stderr, "\n");                                                                           \
        }                                                                                                    \
    } while (0)

#define FLOWS 1000u
#define FORGED_DATAGRAMS 20u
#define SEED 0x5eed0571c4f70e11ULL

static uint64_t g_rng = SEED;

static uint64_t rnd(void) { /* splitmix64 */
    uint64_t z = (g_rng += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static size_t unhex(const char *s, uint8_t *out, size_t cap) {
    size_t n = 0;
    for (; s[0] != '\0' && s[1] != '\0' && n < cap; n++, s += 2) {
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) {
            exit(2);
        }
        out[n] = (uint8_t) v;
    }
    return n;
}

/* ---- frame builder ------------------------------------------------------- */

typedef struct {
    uint8_t b[20000];
    size_t n;
} buf_t;

static void put(buf_t *b, const void *p, size_t n) {
    memcpy(b->b + b->n, p, n);
    b->n += n;
}

static void put_varint(buf_t *b, uint64_t v) {
    uint8_t e[8];
    size_t n = v < 0x40 ? 1 : v < 0x4000 ? 2 : v < 0x40000000 ? 4 : 8;
    for (size_t i = 0; i < n; i++) {
        e[n - 1 - i] = (uint8_t) (v >> (8 * i));
    }
    e[0] |= (uint8_t) ((n == 1 ? 0 : n == 2 ? 1 : n == 4 ? 2 : 3) << 6);
    put(b, e, n);
}

static void put_crypto(buf_t *b, uint64_t off, const uint8_t *data, size_t len) {
    static const uint8_t type = 0x06;
    put(b, &type, 1);
    put_varint(b, off);
    put_varint(b, len);
    put(b, data, len);
}

/* Walks `b` from an exact-size heap copy. */
static quic_crypto_result_t walk(quic_crypto_t *st, const buf_t *b) {
    uint8_t *p = malloc(b->n ? b->n : 1);
    if (p == NULL) {
        exit(2);
    }
    memcpy(p, b->b, b->n);
    quic_crypto_result_t r = quic_crypto_walk_frames(st, p, b->n);
    free(p);
    return r;
}

static uint8_t g_hello[512];
static size_t g_hello_len;
static uint8_t g_big[TLS_HELLO_MAX_MESSAGE];

enum kind { COMPLETE, HEADER, IN_FLIGHT, HOSTILE, FORGED, KINDS };

static struct {
    uint64_t by_kind[KINDS];
    uint64_t completed, facts_live, hostile_allocs, header_allocs, forged_allocs, in_flight;
    uint64_t max_reasm_bytes, max_attempts, decrypt_attempts;
} m;

/* The hello in shuffled 1 .. 6-frame packets over 1 .. 3 packets. */
static void run_complete(quic_crypto_t *st) {
    size_t packets = 1 + (size_t) (rnd() % 3), per = 1 + (size_t) (rnd() % 6), total = packets * per;
    quic_crypto_result_t r = QUIC_CRYPTO_NONE;
    for (size_t p = 0; p < packets; p++) {
        size_t order[6];
        for (size_t k = 0; k < per; k++) {
            order[k] = p * per + k;
        }
        for (size_t k = per; k > 1; k--) {
            size_t j = (size_t) (rnd() % k), t = order[k - 1];
            order[k - 1] = order[j];
            order[j] = t;
        }
        buf_t b;
        b.n = 0;
        for (size_t k = 0; k < per; k++) {
            size_t lo = order[k] * g_hello_len / total, hi = (order[k] + 1) * g_hello_len / total;
            put_crypto(&b, lo, g_hello + lo, hi - lo);
        }
        r = walk(st, &b);
    }
    if (r == QUIC_CRYPTO_HELLO && st->hello != NULL && strcmp(st->hello->sni, "example.com") == 0) {
        m.completed++;
    }
}

static void run_header(quic_crypto_t *st) {
    buf_t b;
    b.n = 0;
    uint64_t before = tcm_calls;
    put_crypto(&b, 0, g_hello, 1 + (size_t) (rnd() % 3));
    walk(st, &b);
    m.header_allocs += tcm_calls - before;
}

static void run_in_flight(quic_crypto_t *st, int big) {
    buf_t b;
    b.n = 0;
    if (big) {
        put_crypto(&b, 0, g_big, 1000 + (size_t) (rnd() % 8000));
    } else {
        size_t hole = 8 + (size_t) (rnd() % (g_hello_len - 16));
        put_crypto(&b, 0, g_hello, hole);
        put_crypto(&b, hole + 1, g_hello + hole + 1, g_hello_len - hole - 1);
    }
    walk(st, &b);
    size_t bytes = tls_hello_reasm_footprint(st->reasm);
    if (bytes > m.max_reasm_bytes) {
        m.max_reasm_bytes = bytes;
    }
    if (st->reasm != NULL) {
        m.in_flight++;
    }
}

static void run_hostile(quic_crypto_t *st) {
    static const uint8_t junk[16] = {0};
    buf_t b;
    b.n = 0;
    uint64_t before = tcm_calls;
    put_crypto(&b, (UINT64_C(1) << 62) - 1, junk, 10);
    put_crypto(&b, 16380, junk, 10);
    put_crypto(&b, (UINT64_C(1) << 32) + (rnd() % 4096), junk, 16);
    walk(st, &b);
    b.n = 0;
    static const uint8_t crypto = 0x06;
    put(&b, &crypto, 1);
    put_varint(&b, 0);
    put_varint(&b, (rnd() & 1) ? (UINT64_C(1) << 62) - 1 : 200);
    put(&b, junk, 10);
    walk(st, &b);
    m.hostile_allocs += tcm_calls - before;
    CHECK(st->reasm == NULL && st->hdr_have == 0, "hostile frames left state behind");
}

static void run_forged(quic_crypto_t *st, const uint8_t *initial) {
    static const int endpoint;
    uint8_t *pkt = malloc(1200);
    if (pkt == NULL) {
        exit(2);
    }
    uint64_t before = tcm_calls;
    for (unsigned d = 0; d < FORGED_DATAGRAMS; d++) {
        memcpy(pkt, initial, 1200);
        pkt[30 + rnd() % 1170] ^= (uint8_t) (1 + rnd() % 255);
        quic_crypto_consume(st, &endpoint, pkt, 1200, 1200);
    }
    m.forged_allocs += tcm_calls - before;
    free(pkt);
    m.decrypt_attempts += st->attempts;
    if (st->attempts > m.max_attempts) {
        m.max_attempts = st->attempts;
    }
}

int main(void) {
    static quic_crypto_t flows[FLOWS];
    static uint8_t initial[1200];
    uint8_t frame[512];
    size_t n = unhex(RFC_V1_CRYPTO_FRAME, frame, sizeof frame);
    g_hello_len = n - 4;
    memcpy(g_hello, frame + 4, g_hello_len);
    unhex(RFC_V1_PROTECTED, initial, sizeof initial);
    /* a ClientHello header declaring 2^14 - 4 body bytes */
    memset(g_big, 0x42, sizeof g_big);
    g_big[0] = 1;
    g_big[1] = 0x00;
    g_big[2] = 0x3f;
    g_big[3] = 0xfc;
    rb_seed(RB, "workload", SEED);
    CHECK(g_hello_len == 241, "RFC 9001 A.2 hello is 241 bytes");

    int64_t live_before = tcm_outstanding;
    for (unsigned i = 0; i < FLOWS; i++) {
        enum kind kind = (enum kind) (i % KINDS);
        quic_crypto_t *st = &flows[i];
        m.by_kind[kind]++;
        switch (kind) {
        case COMPLETE: run_complete(st); break;
        case HEADER: run_header(st); break;
        case IN_FLIGHT: run_in_flight(st, (i / KINDS) % 10 == 0); break;
        case HOSTILE: run_hostile(st); break;
        default: run_forged(st, initial); break;
        }
    }
    for (unsigned i = 0; i < FLOWS; i++) {
        m.facts_live += flows[i].hello != NULL;
    }
    int64_t live_at_teardown = tcm_outstanding - live_before;
    for (unsigned i = 0; i < FLOWS; i++) {
        quic_crypto_release(&flows[i]); /* _quic_ietf_session_data_cleanup */
    }
    int64_t leaked = tcm_outstanding - live_before;
    CHECK(m.completed == m.by_kind[COMPLETE], "%llu of %llu complete flows completed",
          (unsigned long long) m.completed, (unsigned long long) m.by_kind[COMPLETE]);
    CHECK((uint64_t) live_at_teardown == m.facts_live + m.in_flight, "live blocks at teardown %lld != facts + buffers",
          (long long) live_at_teardown);

    rb_metric(RB, "flows", FLOWS);
    rb_metric(RB, "complete", m.by_kind[COMPLETE]);
    rb_metric(RB, "header_only", m.by_kind[HEADER]);
    rb_metric(RB, "in_flight", m.by_kind[IN_FLIGHT]);
    rb_metric(RB, "hostile", m.by_kind[HOSTILE]);
    rb_metric(RB, "forged", m.by_kind[FORGED]);
    rb_metric(RB, "completed", m.completed);
    rb_metric(RB, "facts_at_teardown", m.facts_live);
    rb_metric(RB, "buffers_at_teardown", m.in_flight);
    rb_metric(RB, "header_only_allocs", m.header_allocs);
    rb_metric(RB, "hostile_allocs", m.hostile_allocs);
    rb_metric(RB, "forged_allocs", m.forged_allocs);
    rb_metric(RB, "max_reasm_bytes", m.max_reasm_bytes);
    rb_metric(RB, "facts_bytes", sizeof (quic_hello_facts_t));
    rb_metric(RB, "max_attempts", m.max_attempts);
    rb_metric(RB, "decrypt_attempts", m.decrypt_attempts);
    rb_metric(RB, "leaked_allocations", (uint64_t) (leaked < 0 ? -leaked : leaked));
    rb_metric(RB, "checks.failed", (uint64_t) failures);
    printf("quic-crypto: %u flows, %llu hellos, %llu buffers and %llu facts live at teardown, %llu left after "
           "release, at most %llu decryptions per flow, %d checks, %d failure(s)\n",
           FLOWS, (unsigned long long) m.completed, (unsigned long long) m.in_flight,
           (unsigned long long) m.facts_live, (unsigned long long) (leaked < 0 ? -leaked : leaked),
           (unsigned long long) m.max_attempts, checks, failures);
    return failures == 0 ? 0 : 1;
}
