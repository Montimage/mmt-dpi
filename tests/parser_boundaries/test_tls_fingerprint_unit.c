/*
 * test_tls_fingerprint_unit.c — the in-tree SHA-256 and the TLS hello readers
 * built on the shared ClientHello parser: supported_versions, ALPN, ECH,
 * the ServerHello parser and the JA4 fingerprint (issue #569, F-BUG-309).
 *
 * src/mmt_tcpip/lib/mmt_sha256.c and protocols/tls_client_hello.c are
 * included directly (mmt_malloc()/mmt_free() over malloc()/free()). Every
 * parsed buffer is heap-allocated to exactly its length, so a read past the
 * end aborts under SANITIZE=asan.
 *
 *   sha256   the FIPS 180-2 Appendix B messages ("abc", the 448- and 896-bit
 *            ones, one million 'a') and the empty string, fed whole and in
 *            uneven pieces across the 64-byte block boundary;
 *   ja4      a ClientHello with the suites, extensions and signature
 *            algorithms of the FoxIO JA4 specification example, GREASE
 *            interleaved, gives the published
 *            t13d1516h2_8daaf6152771_e5627efa2ab1; then every rule of the
 *            specification: no SNI (i), no ALPN (00), a one-character and a
 *            non-alphanumeric ALPN, no signature algorithms (no "_"), no
 *            supported_versions (legacy version), the version table, no
 *            cipher suite or extension (zeros), counts capped at 99, and a
 *            hello past TLS_JA4_MAX_ITEMS (no JA4);
 *   hello    the advertised version (GREASE skipped, highest wins), the ALPN
 *            text (truncation, malformed names), the outer/inner ECH type,
 *            and ServerHello parsing (TLS 1.3 selected_version, TLS 1.2
 *            ALPN, truncated extensions, malformed headers).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mmt_core.h"

void *mmt_malloc(size_t size) {
    return malloc(size);
}

void mmt_free(mmt_opaque_t x) {
    free(x);
}

#include "mmt_sha256.c"
#include "protocols/tls_client_hello.c"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, ...) do {                                        \
        g_checks++;                                                  \
        if (cond) {                                                  \
            printf("  PASS: ");                                      \
        } else {                                                     \
            printf("  FAIL: ");                                      \
            g_failures++;                                            \
        }                                                            \
        printf(__VA_ARGS__);                                         \
        printf("\n");                                                \
    } while (0)

/* ---- SHA-256 ------------------------------------------------------------ */

static void hex(const uint8_t *d, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) {
        sprintf(out + 2 * i, "%02x", d[i]);
    }
}

/* Digest of `msg` fed in pieces of `step` bytes (0: in one call). */
static void sha_hex(const uint8_t *msg, size_t len, size_t step, char out[65]) {
    mmt_sha256_ctx_t c;
    uint8_t d[MMT_SHA256_DIGEST_LEN];
    mmt_sha256_init(&c);
    if (step == 0) {
        mmt_sha256_update(&c, msg, len);
    } else {
        for (size_t off = 0; off < len; off += step) {
            mmt_sha256_update(&c, msg + off, len - off < step ? len - off : step);
        }
    }
    mmt_sha256_final(&c, d);
    hex(d, sizeof d, out);
}

static void test_sha256(void) {
    static const struct { const char *msg; const char *digest; } v[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
    };
    static const size_t steps[] = {0, 1, 7, 63, 64, 65};
    char out[65];
    printf("case sha256: FIPS 180-2 Appendix B vectors\n");
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        size_t len = strlen(v[i].msg);
        uint8_t *m = malloc(len + 1);
        memcpy(m, v[i].msg, len);
        for (size_t s = 0; s < sizeof steps / sizeof steps[0]; s++) {
            sha_hex(m, len, steps[s], out);
            CHECK(strcmp(out, v[i].digest) == 0, "%zu-byte message, pieces of %zu: %s", len, steps[s], out);
        }
        free(m);
    }
    size_t mlen = 1000000;
    uint8_t *a = malloc(mlen);
    memset(a, 'a', mlen);
    sha_hex(a, mlen, 0, out);
    CHECK(strcmp(out, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0,
          "one million 'a', whole: %s", out);
    sha_hex(a, mlen, 1000, out);
    CHECK(strcmp(out, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0,
          "one million 'a', 1,000-byte pieces: %s", out);
    free(a);
    uint8_t seq[200];
    for (int i = 0; i < 200; i++) {
        seq[i] = (uint8_t) i;
    }
    sha_hex(seq, sizeof seq, 55, out);
    CHECK(strcmp(out, "1901da1c9f699b48f6b2636e65cbf73abf99d0441ef67f5c540a42f7051dec6f") == 0,
          "bytes 0..199, pieces of 55 (padding spills into a second block): %s", out);
    mmt_sha256_ctx_t c;
    uint8_t d[MMT_SHA256_DIGEST_LEN];
    mmt_sha256_init(&c);
    mmt_sha256_update(&c, NULL, 0);
    mmt_sha256_final(&c, d);
    hex(d, sizeof d, out);
    CHECK(strcmp(out, v[0].digest) == 0, "a NULL, zero-length update is the empty message");
}

/* ---- ClientHello builder ------------------------------------------------ */

typedef struct {
    uint8_t b[4096];
    size_t n;
} buf_t;

static void put8(buf_t *w, unsigned v) { w->b[w->n++] = (uint8_t) v; }
static void put16(buf_t *w, unsigned v) { put8(w, v >> 8); put8(w, v); }
static void putn(buf_t *w, const void *p, size_t n) { if (n) memcpy(w->b + w->n, p, n); w->n += n; }
static void ext(buf_t *w, unsigned type, const void *body, size_t n) {
    put16(w, type);
    put16(w, (unsigned) n);
    putn(w, body, n);
}

enum {
    H_NO_SNI = 1, H_NO_ALPN = 2, H_NO_SIGALGS = 4, H_NO_VERSIONS = 8,
    H_ECH_OUTER = 16, H_ECH_INNER = 32, H_ALPN_ONE = 64, H_ALPN_BINARY = 128,
    H_NO_SUITES = 256, H_NO_EXTENSIONS = 512,
};

static const uint16_t spec_suites[] = {
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
    0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
};
static const uint16_t spec_sigalgs[] = {
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
};

/* The extensions of the JA4 specification example, GREASE interleaved. */
static void spec_extensions(buf_t *e, unsigned flags) {
    uint8_t tmp[64];
    ext(e, 0x0a0a, NULL, 0);
    if (!(flags & H_NO_SNI)) {
        static const uint8_t sni[] = {0, 19, 0, 0, 16, 'a', 'c', 'c', 'u', 'r', 'a', 'c', 'y',
                                      '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'};
        ext(e, 0x0000, sni, sizeof sni);
    }
    ext(e, 0x0017, NULL, 0);
    ext(e, 0xff01, "\0", 1);
    ext(e, 0x000a, "\x00\x06\x2a\x2a\x00\x1d\x00\x17", 8);
    ext(e, 0x000b, "\x01\x00", 2);
    ext(e, 0x0023, NULL, 0);
    if (flags & H_ALPN_ONE) {
        ext(e, 0x0010, "\x00\x02\x01h", 4);
    } else if (flags & H_ALPN_BINARY) {
        ext(e, 0x0010, "\x00\x03\x02\xab\xcd", 5);
    } else if (!(flags & H_NO_ALPN)) {
        ext(e, 0x0010, "\x00\x0c\x02h2\x08http/1.1", 14);
    }
    ext(e, 0x0005, "\x01\x00\x00\x00\x00", 5);
    if (!(flags & H_NO_SIGALGS)) {
        size_t k = 0;
        tmp[k++] = 0;
        tmp[k++] = 16;
        for (size_t i = 0; i < 8; i++) {
            tmp[k++] = (uint8_t) (spec_sigalgs[i] >> 8);
            tmp[k++] = (uint8_t) spec_sigalgs[i];
        }
        ext(e, 0x000d, tmp, k);
    }
    ext(e, 0x0012, NULL, 0);
    ext(e, 0x0033, "\x00\x00", 2);
    ext(e, 0x002d, "\x01\x01", 2);
    if (!(flags & H_NO_VERSIONS)) {
        ext(e, 0x002b, "\x06\x3a\x3a\x03\x04\x03\x03", 7);
    }
    ext(e, 0x001b, "\x02\x00\x02", 3);
    ext(e, 0x4469, "\x00\x03\x02h2", 6);
    ext(e, 0x2a2a, "\0", 1);
    ext(e, 0x0015, "\0\0\0\0", 4);
    if (flags & (H_ECH_OUTER | H_ECH_INNER)) {
        static const uint8_t outer[] = {0, 0, 1, 0, 1, 0x2a, 0, 2, 9, 9, 0, 3, 1, 2, 3};
        static const uint8_t inner[] = {1};
        if (flags & H_ECH_OUTER) {
            ext(e, 0xfe0d, outer, sizeof outer);
        } else {
            ext(e, 0xfe0d, inner, sizeof inner);
        }
    }
}

/* A ClientHello handshake message (header first). `nsuites` > 0 replaces
 * the specification's suites with that many distinct non-GREASE ones. */
static size_t build_hello(buf_t *w, unsigned flags, unsigned nsuites) {
    buf_t e = {.n = 0};
    w->n = 0;
    put8(w, 1);
    put8(w, 0);
    put16(w, 0);                                  /* length, patched below */
    put16(w, 0x0303);
    for (int i = 0; i < 32; i++) put8(w, (unsigned) i);
    put8(w, 0);                                   /* session id */
    if (flags & H_NO_SUITES) {
        put16(w, 2);
        put16(w, 0x1a1a);                         /* a GREASE suite alone */
    } else if (nsuites > 0) {
        put16(w, 2 * nsuites);
        for (unsigned i = 0; i < nsuites; i++) put16(w, 0x1000 + i);
    } else {
        put16(w, 2 * (1 + 15));
        put16(w, 0x0a0a);
        for (int i = 0; i < 15; i++) put16(w, spec_suites[i]);
    }
    put8(w, 1);
    put8(w, 0);                                   /* null compression */
    if (!(flags & H_NO_EXTENSIONS)) {
        spec_extensions(&e, flags);
        put16(w, (unsigned) e.n);
        putn(w, e.b, e.n);
    }
    size_t body = w->n - 4;
    w->b[1] = (uint8_t) (body >> 16);
    w->b[2] = (uint8_t) (body >> 8);
    w->b[3] = (uint8_t) body;
    return w->n;
}

/* Parses an exact-size heap copy; returns the status. */
static tls_client_hello_status_t parse(const buf_t *w, tls_client_hello_t *ch, uint8_t **copy) {
    *copy = malloc(w->n);
    memcpy(*copy, w->b, w->n);
    return tls_client_hello_parse(*copy, w->n, ch);
}

static void ja4_of(unsigned flags, unsigned nsuites, char out[TLS_JA4_LEN + 1], int *rc) {
    buf_t w;
    tls_client_hello_t ch;
    uint8_t *copy;
    build_hello(&w, flags, nsuites);
    tls_client_hello_status_t st = parse(&w, &ch, &copy);
    *rc = st == TLS_CH_OK ? tls_client_hello_ja4(&ch, 't', out) : -1;
    free(copy);
}

static void expect_ja4(const char *label, unsigned flags, unsigned nsuites, const char *want) {
    char out[TLS_JA4_LEN + 1] = "unset";
    int rc;
    ja4_of(flags, nsuites, out, &rc);
    CHECK(rc == 1 && strcmp(out, want) == 0, "%s: %s (want %s)", label, out, want);
}

static void test_ja4(void) {
    printf("case ja4: the FoxIO JA4 specification example and rules\n");
    expect_ja4("specification example", 0, 0, "t13d1516h2_8daaf6152771_e5627efa2ab1");
    expect_ja4("no server_name: i", H_NO_SNI, 0, "t13i1515h2_8daaf6152771_e5627efa2ab1");
    expect_ja4("no ALPN: 00", H_NO_ALPN, 0, "t13d151500_8daaf6152771_e5627efa2ab1");
    expect_ja4("one-character ALPN", H_ALPN_ONE, 0, "t13d1516hh_8daaf6152771_e5627efa2ab1");
    expect_ja4("non-alphanumeric ALPN: hex digits", H_ALPN_BINARY, 0, "t13d1516ad_8daaf6152771_e5627efa2ab1");
    expect_ja4("no signature algorithms: no underscore", H_NO_SIGALGS, 0, "t13d1515h2_8daaf6152771_bebfbbe173b2");
    expect_ja4("no supported_versions: legacy version", H_NO_VERSIONS, 0, "t12d1515h2_8daaf6152771_8d4582d59f63");
    expect_ja4("outer ECH counts as an extension", H_ECH_OUTER, 0, "t13d1517h2_8daaf6152771_b1ff8ab2d16f");
    expect_ja4("only a GREASE suite: zeros", H_NO_SUITES, 0, "t13d0016h2_000000000000_e5627efa2ab1");
    expect_ja4("no extension block: zeros", H_NO_EXTENSIONS, 0, "t12i150000_8daaf6152771_000000000000");

    char out[TLS_JA4_LEN + 1];
    int rc;
    ja4_of(0, 120, out, &rc);
    CHECK(rc == 1 && memcmp(out, "t13d9916h2_", 11) == 0, "120 suites: count capped at 99 (%s)", out);
    ja4_of(0, TLS_JA4_MAX_ITEMS + 1, out, &rc);
    CHECK(rc == 0 && out[0] == '\0', "%u suites (past TLS_JA4_MAX_ITEMS): no JA4", TLS_JA4_MAX_ITEMS + 1);

    static const struct { uint16_t v; const char *tok; } versions[] = {
        {0x0304, "13"}, {0x0303, "12"}, {0x0302, "11"}, {0x0301, "10"}, {0x0300, "s3"},
        {0x0002, "s2"}, {0xfeff, "d1"}, {0xfefd, "d2"}, {0xfefc, "d3"}, {0x0305, "00"},
    };
    for (size_t i = 0; i < sizeof versions / sizeof versions[0]; i++) {
        const char *t = tls_ja4_version(versions[i].v);
        CHECK(strcmp(t, versions[i].tok) == 0, "version 0x%04x -> %s", versions[i].v, t);
    }

    /* QUIC hellos carry the protocol letter q */
    buf_t w;
    tls_client_hello_t ch;
    uint8_t *copy;
    build_hello(&w, 0, 0);
    parse(&w, &ch, &copy);
    CHECK(tls_client_hello_ja4(&ch, 'q', out) == 1 && out[0] == 'q', "transport letter q (%s)", out);
    /* an ALPN whose first name overruns its list gives 00 */
    ch.alpn = (const uint8_t *) "\x00\x01\x02h2";
    ch.alpn_len = 5;
    tls_client_hello_ja4(&ch, 't', out);
    CHECK(memcmp(out + 8, "00", 2) == 0, "ALPN name past its list length: 00 (%s)", out);
    ch.alpn = (const uint8_t *) "\x00\x01\x00";
    ch.alpn_len = 3;
    tls_client_hello_ja4(&ch, 't', out);
    CHECK(memcmp(out + 8, "00", 2) == 0, "empty first ALPN name: 00 (%s)", out);
    free(copy);
}

static void test_hello_readers(void) {
    printf("case hello: versions, ALPN text, ECH\n");
    buf_t w;
    tls_client_hello_t ch;
    uint8_t *copy;
    char text[64];

    build_hello(&w, 0, 0);
    CHECK(parse(&w, &ch, &copy) == TLS_CH_OK, "the specification hello parses");
    CHECK(tls_client_hello_version(&ch) == 0x0304, "advertised version 0x0304, GREASE skipped (0x%04x)",
          tls_client_hello_version(&ch));
    CHECK(ch.ech_outer == 0 && ch.has_sni_extension == 1, "no ECH, a server_name");
    CHECK(tls_alpn_text(ch.alpn, ch.alpn_len, text, sizeof text) == 11 && strcmp(text, "h2,http/1.1") == 0,
          "ALPN text h2,http/1.1 (got '%s')", text);
    CHECK(tls_alpn_text(ch.alpn, ch.alpn_len, text, 6) == 2 && strcmp(text, "h2") == 0,
          "a name that does not fit is left out whole (got '%s')", text);
    free(copy);

    build_hello(&w, H_NO_VERSIONS, 0);
    parse(&w, &ch, &copy);
    CHECK(tls_client_hello_version(&ch) == 0x0303, "no supported_versions: legacy_version");
    free(copy);

    build_hello(&w, H_ECH_OUTER, 0);
    parse(&w, &ch, &copy);
    CHECK(ch.ech_outer == 1, "an outer encrypted_client_hello is flagged");
    free(copy);
    build_hello(&w, H_ECH_INNER, 0);
    parse(&w, &ch, &copy);
    CHECK(ch.ech_outer == 0, "an inner ECH type is not");
    free(copy);

    memset(&ch, 0, sizeof ch);
    ch.legacy_version = 0x0301;
    ch.supported_versions = (const uint8_t *) "\x08\x0a\x0a";
    ch.supported_versions_len = 3;
    CHECK(tls_client_hello_version(&ch) == 0x0301, "a list longer than its extension, GREASE only: legacy");
    ch.supported_versions = (const uint8_t *) "\x04\x03\x02\x03\x03";
    ch.supported_versions_len = 5;
    CHECK(tls_client_hello_version(&ch) == 0x0303, "the highest entry wins (0x%04x)", tls_client_hello_version(&ch));

    CHECK(tls_alpn_text(NULL, 0, text, sizeof text) == 0 && text[0] == '\0', "no ALPN list: empty text");
    CHECK(tls_alpn_text((const uint8_t *) "\x00\x04\x00\x02h2", 6, text, sizeof text) == 0,
          "a zero-length first name stops the list");
    CHECK(tls_alpn_text((const uint8_t *) "\x00\x09\x02h2\x09http/1.1", 13, text, sizeof text) == 2
          && strcmp(text, "h2") == 0, "a name past the list end is left out (got '%s')", text);
}

/* A ServerHello handshake message. */
static size_t build_server_hello(buf_t *w, unsigned version_ext, const char *alpn, int sid_len) {
    buf_t e = {.n = 0};
    w->n = 0;
    put8(w, 2);
    put8(w, 0);
    put16(w, 0);
    put16(w, 0x0303);
    for (int i = 0; i < 32; i++) put8(w, 0x40u + (unsigned) i);
    put8(w, (unsigned) sid_len);
    for (int i = 0; i < sid_len && i < 32; i++) put8(w, (unsigned) i);
    put16(w, 0x1301);
    put8(w, 0);
    if (version_ext) {
        uint8_t v[2] = {(uint8_t) (version_ext >> 8), (uint8_t) version_ext};
        ext(&e, 0x002b, v, 2);
    }
    if (alpn != NULL) {
        uint8_t a[32];
        size_t n = strlen(alpn);
        a[0] = 0;
        a[1] = (uint8_t) (n + 1);
        a[2] = (uint8_t) n;
        memcpy(a + 3, alpn, n);
        ext(&e, 0x0010, a, n + 3);
    }
    put16(w, (unsigned) e.n);
    putn(w, e.b, e.n);
    size_t body = w->n - 4;
    w->b[1] = (uint8_t) (body >> 16);
    w->b[2] = (uint8_t) (body >> 8);
    w->b[3] = (uint8_t) body;
    return w->n;
}

static tls_client_hello_status_t parse_sh(const buf_t *w, size_t len, tls_server_hello_t *sh) {
    uint8_t *copy = malloc(len ? len : 1);
    memcpy(copy, w->b, len);
    tls_client_hello_status_t st = tls_server_hello_parse(copy, len, sh);
    free(copy);
    return st;
}

static void test_server_hello(void) {
    printf("case server hello: selected version and ALPN\n");
    buf_t w;
    tls_server_hello_t sh;
    char text[32];

    build_server_hello(&w, 0x0304, NULL, 32);
    CHECK(parse_sh(&w, w.n, &sh) == TLS_CH_OK && sh.selected_version == 0x0304
          && sh.legacy_version == 0x0303 && sh.cipher_suite == 0x1301,
          "TLS 1.3: selected_version 0x%04x, legacy 0x%04x", sh.selected_version, sh.legacy_version);
    build_server_hello(&w, 0, "h2", 0);
    CHECK(parse_sh(&w, w.n, &sh) == TLS_CH_OK && sh.selected_version == 0 && sh.alpn != NULL,
          "TLS 1.2 with ALPN: no selected_version");
    build_server_hello(&w, 0, "h2", 0);
    uint8_t *copy = malloc(w.n);
    memcpy(copy, w.b, w.n);
    tls_server_hello_parse(copy, w.n, &sh);
    CHECK(tls_alpn_text(sh.alpn, sh.alpn_len, text, sizeof text) == 2 && strcmp(text, "h2") == 0,
          "the selected protocol is h2 (got '%s')", text);
    free(copy);

    build_server_hello(&w, 0x0304, "h2", 0);
    CHECK(parse_sh(&w, w.n - 3, &sh) == TLS_CH_TRUNCATED && sh.selected_version == 0x0304 && sh.alpn == NULL,
          "extension block cut short: TRUNCATED, the extensions that fit are read");
    build_server_hello(&w, 0, NULL, 0);
    CHECK(parse_sh(&w, w.n - 2, &sh) == TLS_CH_TRUNCATED, "declared length past the buffer: TRUNCATED");
    CHECK(parse_sh(&w, 3, &sh) == TLS_CH_MALFORMED, "shorter than a handshake header: MALFORMED");
    w.b[0] = 1;
    CHECK(parse_sh(&w, w.n, &sh) == TLS_CH_MALFORMED, "a ClientHello type: MALFORMED");
    build_server_hello(&w, 0, NULL, 0);
    CHECK(parse_sh(&w, 4 + 30, &sh) == TLS_CH_MALFORMED, "body shorter than version + random: MALFORMED");
    build_server_hello(&w, 0, NULL, 0);
    w.b[4 + 34] = 33;
    CHECK(parse_sh(&w, w.n, &sh) == TLS_CH_MALFORMED && sh.legacy_version == 0,
          "a 33-byte session id: MALFORMED, nothing set");
    CHECK(tls_server_hello_parse(NULL, 10, &sh) == TLS_CH_MALFORMED
          && tls_server_hello_parse(w.b, w.n, NULL) == TLS_CH_MALFORMED, "NULL buffer or result: MALFORMED");
}

int main(void) {
    printf("=== SHA-256, TLS hello readers and JA4 (issue #569) ===\n");
    test_sha256();
    test_ja4();
    test_hello_readers();
    test_server_hello();
    printf("=== %d checks, %d failure(s) ===\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
