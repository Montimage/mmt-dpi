/*
 * test_quic_crypto_unit.c — the ClientHello of a QUIC client's Initial
 * CRYPTO frames (issue #571, quic_ietf_crypto.c).
 *
 * quic_ietf_crypto.c is included directly, behind the decryption
 * (quic_ietf_initial.c, mmt_crypto.c, mmt_sha256.c) and the shared
 * ClientHello parser and reassembly buffer (tls_client_hello.c), with
 * mmt_malloc()/mmt_free() defined here over malloc()/free() so live blocks
 * are counted, and quic_ietf_initial_decrypt(), tls_hello_reasm_begin() and
 * tls_hello_reasm_feed() wrapped so their calls are counted. Every input
 * sits in a heap buffer of exactly its length, so a read past it aborts
 * under SANITIZE=asan.
 *
 *   initials  the RFC 9001 / RFC 9369 Appendix A.2 client Initials yield
 *             SNI example.com, ALPN "alpn" and a 'q' JA4; a datagram below
 *             1,200 bytes or a short header is not decrypted at all;
 *   frames    one frame, reversed frames with a 2-byte first frame (header
 *             held), the header split over two packets, frames before the
 *             header lost, duplicates and overlaps, six shuffled frames
 *             (sorted, so four ranges suffice), PADDING / PING / ACK /
 *             ACK_ECN skipped, a CONNECTION_CLOSE, an unknown type or a
 *             malformed varint ending the walk;
 *   refusals  (T1) a CRYPTO length past the plaintext left, length 2^62-1,
 *             offset 16380 + length 10, offset 2^62-1 and offset 2^32 + 4
 *             (which a 32-bit narrowing would wrap into the message) feed
 *             nothing and allocate nothing; a handshake type other than
 *             ClientHello, a declared length over 2^14 and 17 CRYPTO
 *             frames in one packet end the flow without allocating;
 *   cap       (B3) forged Initials cost at most QUIC_CRYPTO_MAX_ATTEMPTS
 *             decryptions per flow, failed ones included;
 *   client    (B2) a failed datagram from another endpoint latches
 *             nothing; once a client Initial decrypted, other endpoints'
 *             datagrams are not decrypted;
 *   release   (T2) a flow mid-collection and one with facts free everything.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mmt_core.h"

static long g_live_blocks;
static unsigned long g_alloc_calls;

void *mmt_malloc(size_t size) {
    g_alloc_calls++;
    void *p = malloc(size);
    if (p != NULL) {
        g_live_blocks++;
    }
    return p;
}

void mmt_free(mmt_opaque_t x) {
    if (x != NULL) {
        g_live_blocks--;
        free(x);
    }
}

#include "mmt_sha256.c"
#include "mmt_crypto.c"
#include "protocols/quic_ietf_initial.c"
#include "protocols/tls_client_hello.c"

static unsigned g_decrypts, g_begins, g_feeds;

static quic_initial_status_t counted_decrypt(const uint8_t *pkt, size_t pkt_len, size_t datagram_len,
        uint8_t *out, size_t out_cap, quic_initial_info_t *info) {
    g_decrypts++;
    return quic_ietf_initial_decrypt(pkt, pkt_len, datagram_len, out, out_cap, info);
}

static tls_hello_reasm_status_t counted_begin(tls_hello_reasm_t **slot, uint32_t need, uint32_t base,
        uint8_t tag) {
    g_begins++;
    return tls_hello_reasm_begin(slot, need, base, tag);
}

static tls_hello_reasm_status_t counted_feed(tls_hello_reasm_t **slot, uint32_t pos, const uint8_t *data,
        size_t len) {
    g_feeds++;
    return tls_hello_reasm_feed(slot, pos, data, len);
}

#define quic_ietf_initial_decrypt counted_decrypt
#define tls_hello_reasm_begin counted_begin
#define tls_hello_reasm_feed counted_feed
#include "protocols/quic_ietf_crypto.c"
#undef quic_ietf_initial_decrypt
#undef tls_hello_reasm_begin
#undef tls_hello_reasm_feed

#include "quic_initial_vectors.h"

static int g_failures;
static int g_checks;

#define CHECK(cond, msg)                                                                                     \
    do {                                                                                                     \
        g_checks++;                                                                                          \
        if (cond) {                                                                                          \
            printf("  PASS: %s\n", (msg));                                                                   \
        } else {                                                                                             \
            printf("  FAIL: %s (line %d)\n", (msg), __LINE__);                                               \
            g_failures++;                                                                                    \
        }                                                                                                    \
    } while (0)

static size_t unhex(const char *s, uint8_t *out, size_t cap) {
    size_t n = 0;
    while (s[0] != '\0') {
        unsigned v;
        if (s[1] == '\0' || n >= cap || sscanf(s, "%2x", &v) != 1) {
            fprintf(stderr, "bad test vector\n");
            exit(2);
        }
        out[n++] = (uint8_t) v;
        s += 2;
    }
    return n;
}

/* ---- builders ------------------------------------------------------------ */

/* The RFC 9001 A.2 ClientHello: the CRYPTO frame's data (241 bytes). */
static uint8_t g_hello[512];
static size_t g_hello_len;

typedef struct {
    uint8_t b[20000];
    size_t n;
} buf_t;

static void put(buf_t *b, const void *p, size_t n) {
    if (b->n + n > sizeof b->b) {
        fprintf(stderr, "builder overflow\n");
        exit(2);
    }
    memcpy(b->b + b->n, p, n);
    b->n += n;
}

static void put_u8(buf_t *b, uint8_t v) {
    put(b, &v, 1);
}

/* RFC 9000 §16 varint in its 8-byte form when `wide`, else the shortest. */
static void put_varint(buf_t *b, uint64_t v, int wide) {
    uint8_t e[8];
    size_t n = wide ? 8 : v < 0x40 ? 1 : v < 0x4000 ? 2 : v < 0x40000000 ? 4 : 8;
    for (size_t i = 0; i < n; i++) {
        e[n - 1 - i] = (uint8_t) (v >> (8 * i));
    }
    e[0] |= (uint8_t) ((n == 1 ? 0 : n == 2 ? 1 : n == 4 ? 2 : 3) << 6);
    put(b, e, n);
}

static void put_crypto(buf_t *b, uint64_t off, const uint8_t *data, size_t len) {
    put_u8(b, 0x06);
    put_varint(b, off, 0);
    put_varint(b, len, 0);
    put(b, data, len);
}

/* CRYPTO frame of g_hello[from, to). */
static void put_part(buf_t *b, size_t from, size_t to) {
    put_crypto(b, from, g_hello + from, to - from);
}

/* Walks b in an exact-size heap copy. */
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

static quic_crypto_result_t consume(quic_crypto_t *st, const void *src, const uint8_t *pkt, size_t len,
        size_t datagram_len) {
    uint8_t *p = malloc(len ? len : 1);
    if (p == NULL) {
        exit(2);
    }
    memcpy(p, pkt, len);
    quic_crypto_result_t r = quic_crypto_consume(st, src, p, len, datagram_len);
    free(p);
    return r;
}

static void reset_counters(void) {
    g_decrypts = g_begins = g_feeds = 0;
    g_alloc_calls = 0;
}

static int hello_is_rfc(const quic_crypto_t *st) {
    return st->hello != NULL && strcmp(st->hello->sni, "example.com") == 0 && st->hello->sni_len == 11
        && strcmp(st->hello->alpn, "alpn") == 0 && st->hello->has_ja4
        && strncmp(st->hello->ja4, "q13d0211an_", 11) == 0;
}

/* ---- initials ------------------------------------------------------------ */

static uint8_t g_v1[1200], g_v2[1200];

static void test_initials(void) {
    printf("initials\n");
    static const int one, two;
    quic_crypto_t st;
    memset(&st, 0, sizeof st);
    reset_counters();
    CHECK(consume(&st, &one, g_v1, sizeof g_v1, sizeof g_v1) == QUIC_CRYPTO_HELLO,
          "RFC 9001 A.2 client Initial: the ClientHello completes");
    CHECK(hello_is_rfc(&st), "SNI example.com, ALPN alpn, JA4 q13d0211an_ (transport 'q')");
    CHECK(st.client == &one && st.attempts == 1 && st.state == QUIC_CRYPTO_DONE && st.reasm == NULL,
          "one decryption, the client latched, the buffer freed, the flow done");
    CHECK(consume(&st, &one, g_v1, sizeof g_v1, sizeof g_v1) == QUIC_CRYPTO_NONE && g_decrypts == 1,
          "a done flow decrypts nothing more");
    quic_crypto_release(&st);
    CHECK(g_live_blocks == 0, "release frees the facts");

    memset(&st, 0, sizeof st);
    CHECK(consume(&st, &two, g_v2, sizeof g_v2, sizeof g_v2) == QUIC_CRYPTO_HELLO && hello_is_rfc(&st),
          "RFC 9369 A.2 (QUIC v2) client Initial: same facts");
    quic_crypto_release(&st);

    memset(&st, 0, sizeof st);
    reset_counters();
    CHECK(consume(&st, &one, g_v1, sizeof g_v1, 1199) == QUIC_CRYPTO_NONE && g_decrypts == 0 && st.attempts == 0,
          "datagram of 1,199 bytes (RFC 9000 §14.1): not decrypted, no attempt counted");
    uint8_t shorthdr[1200];
    memcpy(shorthdr, g_v1, sizeof shorthdr);
    shorthdr[0] = 0x43;
    CHECK(consume(&st, &one, shorthdr, sizeof shorthdr, sizeof shorthdr) == QUIC_CRYPTO_NONE && g_decrypts == 0,
          "short header: not decrypted, no attempt counted");
    uint8_t handshake[1200];
    memcpy(handshake, g_v1, sizeof handshake);
    handshake[0] = 0xe0; /* v1 long type 0b10: Handshake */
    CHECK(consume(&st, &one, handshake, sizeof handshake, sizeof handshake) == QUIC_CRYPTO_NONE && g_decrypts == 0,
          "v1 Handshake packet: not decrypted");
    CHECK(consume(&st, &one, g_v1, 4, sizeof g_v1) == QUIC_CRYPTO_NONE && g_decrypts == 0,
          "4 readable bytes (no version): not decrypted");
    quic_crypto_release(&st);
    CHECK(g_live_blocks == 0, "no block left");
}

/* ---- frames -------------------------------------------------------------- */

static void test_frames(void) {
    printf("frames\n");
    quic_crypto_t st;
    buf_t b;
    size_t L = g_hello_len;

    memset(&st, 0, sizeof st);
    memset(&b, 0, sizeof b);
    put_part(&b, 0, L);
    CHECK(walk(&st, &b) == QUIC_CRYPTO_HELLO && hello_is_rfc(&st), "one CRYPTO frame with the whole hello");
    quic_crypto_release(&st);

    memset(&st, 0, sizeof st);
    memset(&b, 0, sizeof b);
    put_part(&b, 100, L);
    put_part(&b, 2, 100);
    put_part(&b, 0, 2);
    reset_counters();
    CHECK(walk(&st, &b) == QUIC_CRYPTO_HELLO && hello_is_rfc(&st),
          "reverse offset order, the frame at offset 0 only 2 bytes: header held, then fed in order");
    CHECK(g_begins == 1, "one buffer started");
    quic_crypto_release(&st);

    memset(&st, 0, sizeof st);
    memset(&b, 0, sizeof b);
    put_part(&b, 0, 3);
    reset_counters();
    CHECK(walk(&st, &b) == QUIC_CRYPTO_NONE && g_begins == 0 && g_alloc_calls == 0 && st.hdr_have == 0x07,
          "3 header bytes: held, no buffer allocated");
    memset(&b, 0, sizeof b);
    put_part(&b, 3, L);
    CHECK(walk(&st, &b) == QUIC_CRYPTO_HELLO && hello_is_rfc(&st),
          "the 4th header byte in the next packet: the held 3 are fed with it");
    quic_crypto_release(&st);

    memset(&st, 0, sizeof st);
    memset(&b, 0, sizeof b);
    put_part(&b, 0, 2);
    put_part(&b, 50, L);
    CHECK(walk(&st, &b) == QUIC_CRYPTO_NONE && st.reasm == NULL, "header incomplete: [50, end) cannot be kept");
    memset(&b, 0, sizeof b);
    put_part(&b, 2, 50);
    CHECK(walk(&st, &b) == QUIC_CRYPTO_NONE && st.reasm != NULL && st.state == QUIC_CRYPTO_ACTIVE,
          "header completes: the buffer holds [0, 50), [50, end) of the earlier packet is lost (documented limit)");
    memset(&b, 0, sizeof b);
    put_part(&b, 50, L);
    CHECK(walk(&st, &b) == QUIC_CRYPTO_HELLO && hello_is_rfc(&st), "a retransmission of [50, end) completes it");
    quic_crypto_release(&st);

    memset(&st, 0, sizeof st);
    memset(&b, 0, sizeof b);
    put_part(&b, 0, 120);
    put_part(&b, 60, 200);
    put_part(&b, 0, 120);
    put_part(&b, 200, L);
    CHECK(walk(&st, &b) == QUIC_CRYPTO_HELLO && hello_is_rfc(&st), "duplicate and overlapping frames");
    quic_crypto_release(&st);

    /* eight frames in shuffled order: fed as they come they would open more
     * than TLS_HELLO_MAX_RANGES (4) disjoint ranges and drop the buffer */
    static const int order[] = {7, 5, 3, 1, 0, 2, 4, 6};
    memset(&st, 0, sizeof st);
    memset(&b, 0, sizeof b);
    for (size_t i = 0; i < 8; i++) {
        size_t k = (size_t) order[i];
        put_part(&b, k * 30, k == 7 ? L : k * 30 + 30);
    }
    CHECK(walk(&st, &b) == QUIC_CRYPTO_HELLO && hello_is_rfc(&st),
          "eight shuffled frames: sorted by offset, the hello completes");
    quic_crypto_release(&st);

    memset(&st, 0, sizeof st);
    memset(&b, 0, sizeof b);
    put_u8(&b, 0x00); /* PADDING */
    put_u8(&b, 0x01); /* PING */
    put_u8(&b, 0x02); /* ACK: largest 9, delay 0, 1 range, first 2, gap 1, len 3 */
    put_varint(&b, 9, 0);
    put_varint(&b, 0, 0);
    put_varint(&b, 1, 0);
    put_varint(&b, 2, 0);
    put_varint(&b, 1, 0);
    put_varint(&b, 3, 0);
    put_u8(&b, 0x03); /* ACK_ECN: no range, three counts */
    put_varint(&b, 5, 0);
    put_varint(&b, 300, 0);
    put_varint(&b, 0, 0);
    put_varint(&b, 0, 0);
    put_varint(&b, 7, 0);
    put_varint(&b, 8, 0);
    put_varint(&b, 70000, 0);
    put_part(&b, 0, L);
    put_u8(&b, 0x00);
    CHECK(walk(&st, &b) == QUIC_CRYPTO_HELLO && hello_is_rfc(&st), "PADDING, PING, ACK and ACK_ECN skipped");
    quic_crypto_release(&st);

    static const struct {
        uint8_t prefix[12];
        size_t len;
        const char *what;
    } stops[] = {
        {{0x1c, 0x00, 0x00, 0x00}, 4, "CONNECTION_CLOSE ends the walk"},
        {{0x08, 0x00, 0x00}, 3, "a STREAM frame (not allowed in an Initial) ends the walk"},
        {{0x02, 0x09, 0x00, 0x7f, 0xff}, 5, "ACK with a range count past the plaintext ends the walk"},
    };
    for (size_t i = 0; i < sizeof stops / sizeof stops[0]; i++) {
        memset(&st, 0, sizeof st);
        memset(&b, 0, sizeof b);
        put(&b, stops[i].prefix, stops[i].len);
        put_part(&b, 0, L);
        reset_counters();
        CHECK(walk(&st, &b) == QUIC_CRYPTO_NONE && st.hello == NULL && g_feeds == 0 && g_alloc_calls == 0,
              stops[i].what);
        quic_crypto_release(&st);
    }

    memset(&st, 0, sizeof st);
    memset(&b, 0, sizeof b);
    put_u8(&b, 0x06);
    put_u8(&b, 0x00);
    put_u8(&b, 0x80); /* 4-byte varint length, 1 byte present */
    reset_counters();
    CHECK(walk(&st, &b) == QUIC_CRYPTO_NONE && g_feeds == 0 && g_alloc_calls == 0 && st.hdr_have == 0,
          "malformed varint ends the walk");
    CHECK(g_live_blocks == 0, "no block left");
}

/* ---- refusals (T1) ------------------------------------------------------- */

static void test_refusals(void) {
    printf("refusals\n");
    quic_crypto_t st;
    buf_t b;
    size_t L = g_hello_len;

    memset(&st, 0, sizeof st);
    memset(&b, 0, sizeof b);
    put_u8(&b, 0x06);
    put_varint(&b, 0, 0);
    put_varint(&b, 500, 0);
    put(&b, g_hello, 10);
    reset_counters();
    CHECK(walk(&st, &b) == QUIC_CRYPTO_NONE && g_feeds == 0 && g_alloc_calls == 0 && st.hdr_have == 0,
          "CRYPTO length 500 with 10 bytes of plaintext left: no feed, no allocation, no header byte");

    memset(&st, 0, sizeof st);
    memset(&b, 0, sizeof b);
    put_u8(&b, 0x06);
    put_varint(&b, 0, 0);
    put_varint(&b, (UINT64_C(1) << 62) - 1, 0);
    put(&b, g_hello, L);
    reset_counters();
    CHECK(walk(&st, &b) == QUIC_CRYPTO_NONE && g_feeds == 0 && g_alloc_calls == 0 && st.hdr_have == 0,
          "CRYPTO length 2^62-1 at offset 0: no feed, no allocation");

    /* out-of-window frames are skipped over their (validated) length and the
     * walk goes on; on a started buffer they feed nothing (a narrowed
     * 2^32 + 4 would land on byte 4), and the hello still completes */
    static const struct {
        uint64_t off;
        const char *what;
    } far[] = {
        {16380, "offset 16380 + length 10 > 2^14"},
        {(UINT64_C(1) << 62) - 1, "offset 2^62-1"},
        {(UINT64_C(1) << 32) + 4, "offset 2^32 + 4 (would wrap to 4 if narrowed first)"},
    };
    for (size_t i = 0; i < sizeof far / sizeof far[0]; i++) {
        static const uint8_t junk[10] = {0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee};
        char msg[160];
        memset(&st, 0, sizeof st);
        memset(&b, 0, sizeof b);
        put_crypto(&b, far[i].off, junk, sizeof junk);
        reset_counters();
        snprintf(msg, sizeof msg, "%s alone: no feed, no allocation", far[i].what);
        CHECK(walk(&st, &b) == QUIC_CRYPTO_NONE && g_feeds == 0 && g_alloc_calls == 0 && st.hdr_have == 0, msg);
        memset(&b, 0, sizeof b);
        put_part(&b, 0, 4);
        put_crypto(&b, far[i].off, junk, sizeof junk);
        put_part(&b, 4, 100);
        reset_counters();
        snprintf(msg, sizeof msg, "%s beside the hello's start: skipped (3 feeds: held header, 2 frames)",
                 far[i].what);
        CHECK(walk(&st, &b) == QUIC_CRYPTO_NONE && st.reasm != NULL && g_feeds == 3, msg);
        memset(&b, 0, sizeof b);
        put_crypto(&b, far[i].off, junk, sizeof junk);
        reset_counters();
        snprintf(msg, sizeof msg, "%s on a started buffer: no feed, no allocation", far[i].what);
        CHECK(walk(&st, &b) == QUIC_CRYPTO_NONE && g_feeds == 0 && g_alloc_calls == 0, msg);
        memset(&b, 0, sizeof b);
        put_part(&b, 100, L);
        snprintf(msg, sizeof msg, "%s: the rest completes the hello, intact", far[i].what);
        CHECK(walk(&st, &b) == QUIC_CRYPTO_HELLO && hello_is_rfc(&st), msg);
        quic_crypto_release(&st);
    }

    static const struct {
        uint8_t hdr[4];
        const char *what;
    } bad[] = {
        {{0x02, 0x00, 0x00, 0x30}, "handshake type 2 (ServerHello): flow done, nothing allocated"},
        {{0x01, 0x00, 0x3f, 0xfd}, "declared length 16381 + 4 > 2^14: flow done, nothing allocated"},
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        memset(&st, 0, sizeof st);
        memset(&b, 0, sizeof b);
        put_crypto(&b, 0, bad[i].hdr, 4);
        reset_counters();
        CHECK(walk(&st, &b) == QUIC_CRYPTO_NONE && st.state == QUIC_CRYPTO_DONE && g_begins == 0
              && g_alloc_calls == 0, bad[i].what);
        quic_crypto_release(&st);
    }

    memset(&st, 0, sizeof st);
    memset(&b, 0, sizeof b);
    for (size_t i = 0; i < QUIC_CRYPTO_MAX_FRAMES + 1; i++) {
        put_part(&b, i * 10, i * 10 + 10);
    }
    reset_counters();
    CHECK(walk(&st, &b) == QUIC_CRYPTO_NONE && st.state == QUIC_CRYPTO_DONE && g_feeds == 0
          && g_alloc_calls == 0, "17 CRYPTO frames in one packet: flow done, nothing fed or allocated");
    quic_crypto_release(&st);

    memset(&st, 0, sizeof st);
    memset(&b, 0, sizeof b);
    for (size_t i = 0; i < QUIC_CRYPTO_MAX_FRAMES; i++) {
        put_part(&b, i * 15, i == QUIC_CRYPTO_MAX_FRAMES - 1 ? L : i * 15 + 15);
    }
    CHECK(walk(&st, &b) == QUIC_CRYPTO_HELLO && hello_is_rfc(&st), "16 CRYPTO frames: accepted");
    quic_crypto_release(&st);
    CHECK(g_live_blocks == 0, "no block left");
}

/* ---- cap (B3) and client (B2) --------------------------------------------- */

static void test_cap_and_client(void) {
    printf("cap and client\n");
    static const int client, other;
    uint8_t forged[1200];
    memcpy(forged, g_v1, sizeof forged);
    forged[600] ^= 0x01; /* the AEAD tag no longer verifies */
    quic_crypto_t st;
    memset(&st, 0, sizeof st);
    reset_counters();
    for (int i = 0; i < 20; i++) {
        consume(&st, &client, forged, sizeof forged, sizeof forged);
    }
    CHECK(g_decrypts == QUIC_CRYPTO_MAX_ATTEMPTS, "20 forged Initials: QUIC_CRYPTO_MAX_ATTEMPTS (8) decryptions");
    CHECK(st.state == QUIC_CRYPTO_DONE && st.client == NULL, "the flow is done, no client latched");
    CHECK(consume(&st, &client, g_v1, sizeof g_v1, sizeof g_v1) == QUIC_CRYPTO_NONE
          && g_decrypts == QUIC_CRYPTO_MAX_ATTEMPTS, "a valid Initial after the cap is not decrypted");
    quic_crypto_release(&st);

    /* a failed Initial ends the walk of its datagram */
    uint8_t two[2400];
    memcpy(two, forged, 1200);
    memcpy(two + 1200, forged, 1200);
    memset(&st, 0, sizeof st);
    reset_counters();
    consume(&st, &client, two, sizeof two, sizeof two);
    CHECK(g_decrypts == 1 && st.attempts == 1, "a failed first Initial stops the datagram walk");

    memset(&st, 0, sizeof st);
    reset_counters();
    consume(&st, &other, forged, sizeof forged, sizeof forged);
    CHECK(st.client == NULL && st.attempts == 1, "a failed datagram from another endpoint latches nothing");
    CHECK(consume(&st, &client, g_v1, 600, sizeof g_v1) == QUIC_CRYPTO_NONE && st.client == NULL,
          "a truncated Initial does not latch either");
    /* a first Initial that only starts the hello */
    buf_t b;
    memset(&b, 0, sizeof b);
    put_part(&b, 0, 2);
    CHECK(walk(&st, &b) == QUIC_CRYPTO_NONE, "half a header so far");
    CHECK(consume(&st, &client, g_v1, sizeof g_v1, sizeof g_v1) == QUIC_CRYPTO_HELLO && st.client == &client,
          "the client's Initial decrypts: its endpoint latched, the hello completes");
    quic_crypto_release(&st);

    memset(&st, 0, sizeof st);
    st.client = &client;
    reset_counters();
    CHECK(consume(&st, &other, g_v1, sizeof g_v1, sizeof g_v1) == QUIC_CRYPTO_NONE && g_decrypts == 0,
          "once latched, another endpoint's Initial is not decrypted");
    quic_crypto_release(&st);
    CHECK(g_live_blocks == 0, "no block left");
}

/* ---- release (T2) -------------------------------------------------------- */

static void test_release(void) {
    printf("release\n");
    quic_crypto_t st;
    buf_t b;
    memset(&st, 0, sizeof st);
    memset(&b, 0, sizeof b);
    put_part(&b, 0, 100);
    walk(&st, &b);
    CHECK(st.reasm != NULL && g_live_blocks == 1, "mid-collection: one buffer live");
    quic_crypto_release(&st);
    CHECK(st.reasm == NULL && st.hello == NULL && g_live_blocks == 0, "release frees the buffer");
    quic_crypto_release(&st);
    quic_crypto_release(NULL);
    CHECK(g_live_blocks == 0, "a second release and a NULL state are harmless");
}

int main(void) {
    uint8_t frame[512];
    size_t n = unhex(RFC_V1_CRYPTO_FRAME, frame, sizeof frame);
    /* 06, offset 00, length 40f1, then the 241-byte ClientHello */
    g_hello_len = n - 4;
    memcpy(g_hello, frame + 4, g_hello_len);
    if (unhex(RFC_V1_PROTECTED, g_v1, sizeof g_v1) != sizeof g_v1
            || unhex(RFC_V2_PROTECTED, g_v2, sizeof g_v2) != sizeof g_v2 || g_hello_len != 241) {
        fprintf(stderr, "bad test vector\n");
        return 2;
    }
    test_initials();
    test_frames();
    test_refusals();
    test_cap_and_client();
    test_release();
    printf("\n%d/%d checks passed\n", g_checks - g_failures, g_checks);
    return g_failures == 0 ? 0 : 1;
}
