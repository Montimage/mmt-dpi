/*
 * test_tls_client_hello_unit.c — the shared ClientHello parser and its
 * bounded reassembly buffer (issue #568, F-BUG-302).
 *
 * src/mmt_tcpip/lib/protocols/tls_client_hello.c is included directly, with
 * mmt_malloc()/mmt_free() defined here over malloc()/free() so the live
 * blocks and bytes are counted. Every input buffer is heap-allocated to
 * exactly its length (and the parser cases also at an odd address), so a
 * read one byte past the end aborts under SANITIZE=asan.
 *
 *   parser  well-formed hello with SNI, extension walk and early stop,
 *           absent / non-host_name / overrunning SNI, declared extension
 *           block past the buffer (TRUNCATED), every truncation of a hello,
 *           bad handshake type, oversized session id, overrunning cipher
 *           suites, a hello without extensions;
 *   reasm   refusals (empty, oversize > 2^14, slot in use) allocate nothing;
 *           two in-order segments, three reordered ones, duplicates and
 *           partial overlaps add no byte twice, bytes past the declared
 *           length are ignored, too many holes and too many stalls drop and
 *           free, the sequence space wraps, the footprint never exceeds
 *           the header plus 2^14 bytes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mmt_core.h"

static long g_live_blocks;
static size_t g_live_bytes;
static size_t g_peak_bytes;
static unsigned long g_alloc_calls;

/* Each block carries its size in front, so mmt_free() can count bytes. */
void *mmt_malloc(size_t size) {
    size_t *p = malloc(sizeof (size_t) + size);
    if (p == NULL) {
        return NULL;
    }
    *p = size;
    g_alloc_calls++;
    g_live_blocks++;
    g_live_bytes += size;
    if (g_live_bytes > g_peak_bytes) {
        g_peak_bytes = g_live_bytes;
    }
    return p + 1;
}

void mmt_free(mmt_opaque_t x) {
    if (x == NULL) {
        return;
    }
    size_t *p = (size_t *) x - 1;
    g_live_blocks--;
    g_live_bytes -= *p;
    free(p);
}

#include "protocols/tls_client_hello.c"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, msg) do {                                         \
        g_checks++;                                                   \
        if (cond) {                                                   \
            printf("  PASS: %s\n", (msg));                            \
        } else {                                                      \
            printf("  FAIL: %s\n", (msg));                            \
            g_failures++;                                             \
        }                                                             \
    } while (0)

/* ---- ClientHello builder ------------------------------------------------ */

typedef struct {
    uint8_t b[20000];
    size_t n;
} buf_t;

static void put8(buf_t *w, uint8_t v) { w->b[w->n++] = v; }
static void put16(buf_t *w, uint16_t v) { put8(w, (uint8_t) (v >> 8)); put8(w, (uint8_t) v); }
static void putn(buf_t *w, const void *p, size_t n) { memcpy(w->b + w->n, p, n); w->n += n; }

static void put_ext(buf_t *w, uint16_t type, const uint8_t *body, uint16_t len) {
    put16(w, type);
    put16(w, len);
    putn(w, body, len);
}

static uint16_t sni_body(uint8_t *out, const char *host, uint8_t name_type) {
    uint16_t hl = (uint16_t) strlen(host);
    out[0] = (uint8_t) ((hl + 3) >> 8);
    out[1] = (uint8_t) (hl + 3);
    out[2] = name_type;
    out[3] = (uint8_t) (hl >> 8);
    out[4] = (uint8_t) hl;
    memcpy(out + 5, host, hl);
    return (uint16_t) (hl + 5);
}

/* A ClientHello handshake message: type 1, u24 length, body. `exts` holds
 * the extension block (exts_len bytes), declared as `declared_exts` bytes;
 * exts == NULL omits the block. */
static void build_hello(buf_t *w, const uint8_t *exts, uint16_t exts_len, uint16_t declared_exts) {
    buf_t body;
    body.n = 0;
    put16(&body, 0x0303);
    for (int i = 0; i < 32; i++) put8(&body, (uint8_t) i);
    put8(&body, 0);                               /* session id */
    put16(&body, 4); put16(&body, 0x002f); put16(&body, 0x0035);
    put8(&body, 1); put8(&body, 0);               /* null compression */
    if (exts != NULL) {
        put16(&body, declared_exts);
        putn(&body, exts, exts_len);
    }
    w->n = 0;
    put8(w, 1);
    put8(w, (uint8_t) (body.n >> 16)); put8(w, (uint8_t) (body.n >> 8)); put8(w, (uint8_t) body.n);
    putn(w, body.b, body.n);
}

/* Exact-size heap copy at an odd address; *raw is what to free. */
static uint8_t *exact_copy(const uint8_t *src, size_t n, uint8_t **raw) {
    uint8_t *base = malloc(n + 1);
    if (base == NULL) { perror("malloc"); exit(2); }
    uint8_t *p = base + 1;
    memcpy(p, src, n);
    *raw = base;
    return p;
}

static tls_client_hello_status_t parse_exact(const buf_t *w, size_t n, tls_client_hello_t *ch) {
    uint8_t *raw;
    uint8_t *p = exact_copy(w->b, n, &raw);
    tls_client_hello_status_t st = tls_client_hello_parse(p, n, ch);
    /* the result points into p: compare the SNI before freeing */
    if (ch->sni != NULL) {
        ch->sni = w->b + (ch->sni - p);
    }
    free(raw);
    return st;
}

/* ---- parser ---------------------------------------------------------- */

static int count_ext(uint16_t type, const uint8_t *data, uint16_t len, void *ctx) {
    (void) type; (void) data; (void) len;
    (*(unsigned *) ctx)++;
    return 0;
}

static int stop_at_sni(uint16_t type, const uint8_t *data, uint16_t len, void *ctx) {
    (void) data; (void) len;
    (*(unsigned *) ctx)++;
    return type == TLS_EXT_SERVER_NAME;
}

static void test_parse_well_formed(void) {
    printf("[#568] parser: well-formed ClientHello\n");
    uint8_t exts[512], sni[300];
    buf_t e = { .n = 0 };
    static const uint8_t alpn[] = { 0x00, 0x03, 0x02, 'h', '2' };
    put_ext(&e, 16 /* ALPN */, alpn, sizeof alpn);
    put_ext(&e, TLS_EXT_SERVER_NAME, sni, sni_body(sni, "www.example.com", 0));
    put_ext(&e, 43 /* supported_versions */, (const uint8_t *) "\x02\x03\x04", 3);
    memcpy(exts, e.b, e.n);
    buf_t w;
    build_hello(&w, exts, (uint16_t) e.n, (uint16_t) e.n);

    tls_client_hello_t ch;
    tls_client_hello_status_t st = parse_exact(&w, w.n, &ch);
    CHECK(st == TLS_CH_OK, "complete hello parses OK");
    CHECK(ch.legacy_version == 0x0303 && ch.cipher_suites_len == 4 && ch.compression_len == 1,
          "fixed fields read (version, 4 suite bytes, 1 compression method)");
    CHECK(ch.extension_count == 3, "three extensions walked");
    CHECK(ch.sni_status == TLS_SNI_OK && ch.sni_len == 15 && memcmp(ch.sni, "www.example.com", 15) == 0,
          "SNI host_name read after a leading extension");

    /* foreach on a live buffer */
    uint8_t *raw;
    uint8_t *p = exact_copy(w.b, w.n, &raw);
    tls_client_hello_parse(p, w.n, &ch);
    unsigned n = 0;
    CHECK(tls_client_hello_foreach_extension(&ch, count_ext, &n) == 3 && n == 3,
          "foreach visits every extension");
    n = 0;
    tls_client_hello_foreach_extension(&ch, stop_at_sni, &n);
    CHECK(n == 2, "a non-zero visitor return stops the walk");
    CHECK(tls_client_hello_foreach_extension(NULL, count_ext, &n) == 0, "foreach(NULL) visits nothing");
    free(raw);

    /* the body entry point, as the single-segment classifier calls it */
    p = exact_copy(w.b + 4, w.n - 4, &raw);
    CHECK(tls_client_hello_parse_body(p, w.n - 4, &ch) == TLS_CH_OK && ch.sni_status == TLS_SNI_OK,
          "parse_body reads the same hello without its handshake header");
    free(raw);
}

static void test_parse_sni_variants(void) {
    printf("[#568] parser: absent and malformed SNI\n");
    uint8_t sni[300];
    buf_t e, w;
    tls_client_hello_t ch;

    e.n = 0;
    put_ext(&e, 23, (const uint8_t *) "", 0);
    build_hello(&w, e.b, (uint16_t) e.n, (uint16_t) e.n);
    CHECK(parse_exact(&w, w.n, &ch) == TLS_CH_OK && ch.sni_status == TLS_SNI_ABSENT,
          "no server_name extension: SNI absent");

    e.n = 0;
    put_ext(&e, TLS_EXT_SERVER_NAME, sni, sni_body(sni, "host.example", 1));
    build_hello(&w, e.b, (uint16_t) e.n, (uint16_t) e.n);
    CHECK(parse_exact(&w, w.n, &ch) == TLS_CH_OK && ch.sni_status == TLS_SNI_MALFORMED && ch.sni == NULL,
          "name_type 1 (not host_name): SNI malformed");

    e.n = 0;
    uint16_t bl = sni_body(sni, "host.example", 0);
    sni[4] = 200; /* name_length past the extension */
    put_ext(&e, TLS_EXT_SERVER_NAME, sni, bl);
    build_hello(&w, e.b, (uint16_t) e.n, (uint16_t) e.n);
    CHECK(parse_exact(&w, w.n, &ch) == TLS_CH_OK && ch.sni_status == TLS_SNI_MALFORMED,
          "name_length overrunning the extension: SNI malformed");

    e.n = 0;
    put_ext(&e, TLS_EXT_SERVER_NAME, sni, 4);
    build_hello(&w, e.b, (uint16_t) e.n, (uint16_t) e.n);
    CHECK(parse_exact(&w, w.n, &ch) == TLS_CH_OK && ch.sni_status == TLS_SNI_MALFORMED,
          "4-byte server_name body (< 5-byte header): SNI malformed");

    /* a second server_name never replaces the first */
    e.n = 0;
    put_ext(&e, TLS_EXT_SERVER_NAME, sni, sni_body(sni, "first.example", 0));
    put_ext(&e, TLS_EXT_SERVER_NAME, sni + 100, sni_body(sni + 100, "second.example", 0));
    build_hello(&w, e.b, (uint16_t) e.n, (uint16_t) e.n);
    CHECK(parse_exact(&w, w.n, &ch) == TLS_CH_OK && ch.sni_len == 13
          && memcmp(ch.sni, "first.example", 13) == 0, "the first server_name wins");
}

static void test_parse_truncated(void) {
    printf("[#568] parser: truncated and declared-past-the-buffer hellos\n");
    uint8_t sni[300];
    buf_t e, w;
    tls_client_hello_t ch;

    e.n = 0;
    put_ext(&e, TLS_EXT_SERVER_NAME, sni, sni_body(sni, "www.example.com", 0));
    put_ext(&e, 21 /* padding */, (const uint8_t *) "\0\0\0\0\0\0\0\0", 8);
    /* extension block declared 100 bytes longer than present */
    build_hello(&w, e.b, (uint16_t) e.n, (uint16_t) (e.n + 100));
    CHECK(parse_exact(&w, w.n, &ch) == TLS_CH_TRUNCATED && ch.sni_status == TLS_SNI_OK
          && ch.extension_count == 2, "declared block past the buffer: TRUNCATED, extensions that fit walked");

    /* every prefix of a complete hello: never OK, never out of bounds */
    build_hello(&w, e.b, (uint16_t) e.n, (uint16_t) e.n);
    int bad = 0;
    for (size_t n = 0; n < w.n; n++) {
        tls_client_hello_status_t st = parse_exact(&w, n, &ch);
        if (st == TLS_CH_OK) bad++;
    }
    CHECK(bad == 0, "each of the hello's prefixes parses MALFORMED or TRUNCATED (ASan: in bounds)");

    /* an extension whose length does not fit stops the walk before SNI */
    e.n = 0;
    put16(&e, 23); put16(&e, 0xFFFC);
    put_ext(&e, TLS_EXT_SERVER_NAME, sni, sni_body(sni, "www.example.com", 0));
    build_hello(&w, e.b, (uint16_t) e.n, (uint16_t) e.n);
    CHECK(parse_exact(&w, w.n, &ch) == TLS_CH_OK && ch.sni_status == TLS_SNI_ABSENT
          && ch.extension_count == 0, "extension length 0xFFFC stops the walk (F-BUG-064)");
}

static void test_parse_malformed(void) {
    printf("[#568] parser: malformed fixed fields\n");
    buf_t w;
    tls_client_hello_t ch;

    build_hello(&w, NULL, 0, 0);
    CHECK(parse_exact(&w, w.n, &ch) == TLS_CH_OK && ch.extensions == NULL && ch.sni_status == TLS_SNI_ABSENT,
          "a hello without an extension block parses OK");

    w.b[0] = 2; /* ServerHello */
    CHECK(parse_exact(&w, w.n, &ch) == TLS_CH_MALFORMED, "handshake type 2 is not a ClientHello");

    build_hello(&w, NULL, 0, 0);
    w.b[4 + 34] = 33; /* session id length > 32 */
    CHECK(parse_exact(&w, w.n, &ch) == TLS_CH_MALFORMED, "session id length 33 rejected");

    build_hello(&w, NULL, 0, 0);
    w.b[4 + 35] = 0x7F; /* cipher suites length 0x7F04 */
    CHECK(parse_exact(&w, w.n, &ch) == TLS_CH_MALFORMED, "cipher suites overrunning the buffer rejected");

    build_hello(&w, NULL, 0, 0);
    w.b[4 + 41] = 200; /* compression methods length */
    CHECK(parse_exact(&w, w.n, &ch) == TLS_CH_MALFORMED, "compression methods overrunning the buffer rejected");

    CHECK(tls_client_hello_parse(NULL, 10, &ch) == TLS_CH_MALFORMED
          && tls_client_hello_parse_body(w.b, 10, NULL) == TLS_CH_MALFORMED,
          "NULL buffer / NULL result rejected");
}

/* ---- reassembly -------------------------------------------------------- */

static void fill(uint8_t *p, size_t n, uint32_t seed) {
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t) ((i * 31u + seed) & 0xFF);
}

/* Feeds msg[off, off+len) at stream position base+off, from an exact copy. */
static tls_hello_reasm_status_t feed(tls_hello_reasm_t **slot, uint32_t base, const uint8_t *msg,
                                     size_t off, size_t len) {
    uint8_t *raw;
    uint8_t *p = exact_copy(msg + off, len, &raw);
    tls_hello_reasm_status_t st = tls_hello_reasm_feed(slot, base + (uint32_t) off, p, len);
    free(raw);
    return st;
}

static int data_equals(const tls_hello_reasm_t *r, const uint8_t *msg, uint32_t len) {
    uint32_t n = 0;
    const uint8_t *d = tls_hello_reasm_data(r, &n);
    return d != NULL && n == len && memcmp(d, msg, len) == 0;
}

static void test_reasm_refusals(void) {
    printf("[#568] reassembly: refusals allocate nothing\n");
    tls_hello_reasm_t *r = NULL;
    unsigned long calls = g_alloc_calls;
    CHECK(tls_hello_reasm_begin(&r, 0, 1, 0) == TLS_REASM_DROPPED && r == NULL, "length 0 refused");
    CHECK(tls_hello_reasm_begin(&r, TLS_HELLO_MAX_MESSAGE + 1, 1, 0) == TLS_REASM_DROPPED && r == NULL,
          "length 2^14 + 1 (oversize record) refused");
    CHECK(tls_hello_reasm_begin(&r, 65535, 1, 0) == TLS_REASM_DROPPED && r == NULL, "length 65535 refused");
    CHECK(tls_hello_reasm_begin(NULL, 10, 1, 0) == TLS_REASM_DROPPED, "NULL slot refused");
    CHECK(g_alloc_calls == calls, "no allocation for a refused begin");
    CHECK(tls_hello_reasm_feed(&r, 1, (const uint8_t *) "x", 1) == TLS_REASM_DROPPED
          && tls_hello_reasm_feed(NULL, 1, (const uint8_t *) "x", 1) == TLS_REASM_DROPPED,
          "feed on an empty or NULL slot is DROPPED");
    CHECK(tls_hello_reasm_begin(&r, 10, 1, 7) == TLS_REASM_PENDING && r != NULL, "length 10 accepted");
    tls_hello_reasm_t *keep = r;
    CHECK(tls_hello_reasm_begin(&r, 10, 1, 0) == TLS_REASM_DROPPED && r == keep, "slot in use refused, kept");
    CHECK(tls_hello_reasm_tag(r) == 7 && tls_hello_reasm_tag(NULL) == 0, "tag returned");
    tls_hello_reasm_release(&r);
    tls_hello_reasm_release(&r);
    CHECK(r == NULL && g_live_blocks == 0, "release frees and clears the slot (twice is a no-op)");
    uint32_t n = 99;
    CHECK(tls_hello_reasm_data(NULL, &n) == NULL && n == 0 && tls_hello_reasm_footprint(NULL) == 0,
          "accessors on NULL");
}

static void test_reasm_in_order_and_reordered(void) {
    printf("[#568] reassembly: in-order, reordered, duplicated, overlapping\n");
    static uint8_t msg[1800];
    fill(msg, sizeof msg, 5);
    tls_hello_reasm_t *r = NULL;
    const uint32_t base = 1005;

    tls_hello_reasm_begin(&r, sizeof msg, base, 0);
    CHECK(feed(&r, base, msg, 0, 1455) == TLS_REASM_PENDING, "first segment: pending");
    CHECK(feed(&r, base, msg, 1455, 345) == TLS_REASM_COMPLETE && data_equals(r, msg, sizeof msg),
          "second segment completes the message, bytes intact");
    CHECK(feed(&r, base, msg, 0, 10) == TLS_REASM_COMPLETE, "a feed after completion stays COMPLETE");
    tls_hello_reasm_release(&r);

    tls_hello_reasm_begin(&r, sizeof msg, base, 0);
    feed(&r, base, msg, 0, 600);
    CHECK(feed(&r, base, msg, 1200, 600) == TLS_REASM_PENDING, "third segment before the second: pending");
    size_t before = g_live_bytes;
    CHECK(feed(&r, base, msg, 0, 600) == TLS_REASM_PENDING && g_live_bytes == before,
          "retransmitted first segment: no growth");
    CHECK(feed(&r, base, msg, 500, 800) == TLS_REASM_COMPLETE && data_equals(r, msg, sizeof msg),
          "an overlapping middle segment completes the message");
    tls_hello_reasm_release(&r);

    /* the record header before the body and the next record after it */
    tls_hello_reasm_begin(&r, 100, base, 0);
    CHECK(feed(&r, base - 5, msg, 0, 50) == TLS_REASM_PENDING, "bytes before the message start skipped");
    CHECK(feed(&r, base, msg, 45, 300) == TLS_REASM_COMPLETE
          && tls_hello_reasm_footprint(r) == sizeof (tls_hello_reasm_t) + 100,
          "bytes past the declared length ignored: footprint is header + 100");
    tls_hello_reasm_release(&r);

    /* sequence space wraps inside the message */
    const uint32_t wrap = 0xFFFFFF00u;
    tls_hello_reasm_begin(&r, sizeof msg, wrap, 0);
    feed(&r, wrap, msg, 1000, 800);
    CHECK(feed(&r, wrap, msg, 0, 1000) == TLS_REASM_COMPLETE && data_equals(r, msg, sizeof msg),
          "positions wrapping past 2^32 placed correctly");
    tls_hello_reasm_release(&r);
    CHECK(g_live_blocks == 0 && g_live_bytes == 0, "every reassembly freed");
}

static void test_reasm_drops(void) {
    printf("[#568] reassembly: drops are bounded and free the buffer\n");
    static uint8_t msg[TLS_HELLO_MAX_MESSAGE];
    fill(msg, sizeof msg, 9);
    tls_hello_reasm_t *r = NULL;
    const uint32_t base = 77;

    /* holes: ranges at 0, 100, 200, 300 then a fifth disjoint one */
    tls_hello_reasm_begin(&r, 1000, base, 0);
    for (size_t off = 0; off < 400; off += 100) feed(&r, base, msg, off, 10);
    CHECK(r != NULL, "four disjoint ranges kept");
    CHECK(feed(&r, base, msg, 500, 10) == TLS_REASM_DROPPED && r == NULL && g_live_blocks == 0,
          "a fifth disjoint range drops and frees the reassembly");

    /* a range that bridges holes merges them */
    tls_hello_reasm_begin(&r, 1000, base, 0);
    for (size_t off = 0; off < 400; off += 100) feed(&r, base, msg, off, 10);
    CHECK(feed(&r, base, msg, 5, 400) == TLS_REASM_PENDING && feed(&r, base, msg, 500, 10) == TLS_REASM_PENDING,
          "a bridging segment merges the ranges, leaving room for another");
    tls_hello_reasm_release(&r);

    /* stalls: duplicates and out-of-window segments */
    tls_hello_reasm_begin(&r, 1000, base, 0);
    feed(&r, base, msg, 0, 100);
    tls_hello_reasm_status_t st = TLS_REASM_PENDING;
    int feeds = 0;
    while (r != NULL && feeds < 100) {
        st = (feeds % 2 == 0) ? feed(&r, base, msg, 0, 100)           /* duplicate */
                              : tls_hello_reasm_feed(&r, base + 5000, msg, 10); /* past the end */
        feeds++;
    }
    CHECK(st == TLS_REASM_DROPPED && feeds == TLS_HELLO_MAX_STALLS && r == NULL && g_live_blocks == 0,
          "TLS_HELLO_MAX_STALLS segments without a new byte drop the reassembly");
    tls_hello_reasm_begin(&r, 1000, base, 0);
    feeds = 0;
    while (r != NULL && feeds < 100) {
        tls_hello_reasm_feed(&r, base, msg, 0);
        feeds++;
    }
    CHECK(feeds == TLS_HELLO_MAX_STALLS, "empty segments count as stalls");

    /* the largest message: bounded footprint, byte-exact */
    g_peak_bytes = g_live_bytes;
    tls_hello_reasm_begin(&r, TLS_HELLO_MAX_MESSAGE, base, 0);
    for (size_t off = 0; off < sizeof msg; off += 1460) {
        size_t n = sizeof msg - off < 1460 ? sizeof msg - off : 1460;
        st = feed(&r, base, msg, off, n);
    }
    CHECK(st == TLS_REASM_COMPLETE && data_equals(r, msg, sizeof msg), "a 2^14-byte message completes");
    char m[160];
    snprintf(m, sizeof m, "peak %zu B <= header %zu B + 16384 B", g_peak_bytes, sizeof (tls_hello_reasm_t));
    CHECK(g_peak_bytes <= sizeof (tls_hello_reasm_t) + TLS_HELLO_MAX_MESSAGE, m);
    tls_hello_reasm_release(&r);
    CHECK(g_live_blocks == 0 && g_live_bytes == 0, "nothing left allocated");
}

int main(void) {
    printf("=== TLS ClientHello parser and reassembly (issue #568) ===\n");
    test_parse_well_formed();
    test_parse_sni_variants();
    test_parse_truncated();
    test_parse_malformed();
    test_reasm_refusals();
    test_reasm_in_order_and_reordered();
    test_reasm_drops();
    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
