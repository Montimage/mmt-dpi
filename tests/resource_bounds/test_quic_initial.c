/*
 * test_quic_initial.c — the "quic-initial" resource_bounds fixture (issue
 * #570, F-BUG-307): decrypting a QUIC client Initial allocates nothing,
 * never writes past the caller's output buffer, writes at most the packet's
 * header + plaintext into it, and refuses every hostile datagram with a
 * reason.
 *
 * quic_ietf_initial.c, mmt_crypto.c and mmt_sha256.c are compiled beside
 * this TU with the counted allocator of tcp-memory (-Dmalloc=tcm_malloc ...),
 * so any allocation on the decrypt path would be counted.
 *
 * Workload (fixed seed): 1,000 datagrams, in turn
 *
 *   valid      the RFC 9001 A.2 or RFC 9369 A.2 client Initial, unchanged:
 *              must decrypt
 *   flipped    the same packet with one random byte xor-ed with a random
 *              non-zero value: must be refused
 *   truncated  the same packet cut to a random 0 .. 1,199 bytes inside a
 *              1,200-byte datagram: must be refused
 *   random     1,200 .. 1,500 random bytes behind a v1 Initial first byte
 *              and version, with a random 0 .. 40-byte DCID length: must be
 *              refused (a random tag never verifies)
 *
 * Each datagram sits in a heap buffer of exactly its length; the output
 * buffer is QUIC_INITIAL_OUT_BUFFER bytes followed by a 64-byte canary.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../src/mmt_tcpip/lib/protocols/quic_ietf_initial.h"
#include "../parser_boundaries/quic_initial_vectors.h"

#include "tcp_alloc_count.h"
#include "rb_result.h"

#define RB "quic-initial" /* results.json fixture id */

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

#define DATAGRAMS 1000u
#define PACKET_LEN 1200u
#define CANARY 64u
#define SEED 0x5eed0570c11e1a17ULL

static uint64_t g_rng = SEED;

static uint64_t rnd(void) { /* splitmix64 */
    uint64_t z = (g_rng += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void unhex(const char *s, uint8_t *out, size_t cap) {
    for (size_t n = 0; s[0] != '\0' && s[1] != '\0' && n < cap; n++, s += 2) {
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) {
            exit(2);
        }
        out[n] = (uint8_t) v;
    }
}

enum kind { VALID, FLIPPED, TRUNCATED, RANDOM };

static struct {
    uint64_t by_status[QUIC_INITIAL_ERR_RESERVED_BITS + 1];
    uint64_t valid_failed, hostile_accepted, max_written, canary_overwrites, allocs;
} m;

int main(void) {
    static uint8_t rfc[2][PACKET_LEN];
    static uint8_t src[1500];
    static uint8_t out[QUIC_INITIAL_OUT_BUFFER + CANARY];
    unhex(RFC_V1_PROTECTED, rfc[0], PACKET_LEN);
    unhex(RFC_V2_PROTECTED, rfc[1], PACKET_LEN);
    rb_seed(RB, "workload", SEED);

    uint64_t calls_before = tcm_calls;
    for (unsigned i = 0; i < DATAGRAMS; i++) {
        enum kind kind = (enum kind) (i % 4);
        size_t len = PACKET_LEN, datagram = PACKET_LEN;
        memcpy(src, rfc[(i / 4) & 1], PACKET_LEN);
        if (kind == FLIPPED) {
            src[rnd() % PACKET_LEN] ^= (uint8_t) (1 + rnd() % 255);
        } else if (kind == TRUNCATED) {
            len = (size_t) (rnd() % PACKET_LEN);
        } else if (kind == RANDOM) {
            len = datagram = 1200 + (size_t) (rnd() % 301);
            for (size_t k = 0; k < len; k++) {
                src[k] = (uint8_t) rnd();
            }
            src[0] = (uint8_t) (0xc0 | (src[0] & 0x0f));
            src[1] = src[2] = src[3] = 0;
            src[4] = 1;
            src[5] = (uint8_t) (rnd() % 41);
        }
        uint8_t *pkt = malloc(len ? len : 1);
        if (pkt == NULL) {
            perror("malloc");
            return 2;
        }
        memcpy(pkt, src, len);
        memset(out, 0xa5, sizeof out);
        quic_initial_info_t info;
        quic_initial_status_t st = quic_ietf_initial_decrypt(pkt, len, datagram, out, QUIC_INITIAL_OUT_BUFFER, &info);
        free(pkt);
        m.by_status[st]++;
        if (kind == VALID && st != QUIC_INITIAL_OK) {
            m.valid_failed++;
        }
        if (kind != VALID && st == QUIC_INITIAL_OK) {
            m.hostile_accepted++;
        }
        size_t written = 0; /* the highest byte of `out` that changed */
        for (size_t k = sizeof out; k > 0; k--) {
            if (out[k - 1] != 0xa5) {
                written = k;
                break;
            }
        }
        if (written > m.max_written) {
            m.max_written = written;
        }
        if (written > QUIC_INITIAL_OUT_BUFFER) {
            m.canary_overwrites++;
        }
        if (st == QUIC_INITIAL_OK) {
            CHECK(written <= info.header_len + info.payload_len, "datagram %u wrote %zu bytes", i, written);
        }
    }
    m.allocs = tcm_calls - calls_before;
    CHECK(m.valid_failed == 0, "%llu valid Initials not decrypted", (unsigned long long) m.valid_failed);
    CHECK(m.hostile_accepted == 0, "%llu hostile Initials accepted", (unsigned long long) m.hostile_accepted);

    static const char *names[] = {"ok", "refused_arg", "refused_short_datagram", "refused_not_initial",
                                  "refused_cid_length", "refused_truncated", "refused_buffer", "refused_auth",
                                  "refused_reserved_bits"};
    rb_metric(RB, "datagrams", DATAGRAMS);
    for (unsigned s = 0; s <= QUIC_INITIAL_ERR_RESERVED_BITS; s++) {
        rb_metric(RB, names[s], m.by_status[s]);
    }
    rb_metric(RB, "decrypt_allocs", m.allocs);
    rb_metric(RB, "max_written_bytes", m.max_written);
    rb_metric(RB, "canary_overwrites", m.canary_overwrites);
    rb_metric(RB, "leaked_allocations", (uint64_t) (tcm_outstanding < 0 ? -tcm_outstanding : tcm_outstanding));
    rb_metric(RB, "checks.failed", (uint64_t) failures);
    printf("quic-initial: %u datagrams, %llu decrypted, %llu allocations, at most %llu B written, %d checks, "
           "%d failure(s)\n",
           DATAGRAMS, (unsigned long long) m.by_status[QUIC_INITIAL_OK], (unsigned long long) m.allocs,
           (unsigned long long) m.max_written, checks, failures);
    return failures == 0 ? 0 : 1;
}
