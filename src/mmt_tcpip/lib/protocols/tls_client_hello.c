/*
 * tls_client_hello.c — transport-independent TLS ClientHello parser and the
 * bounded buffer that collects a ClientHello spread over several segments
 * (issue #568, F-BUG-302); the ALPN, supported_versions, ECH and JA4 readers
 * and the ServerHello parser (issue #569). API and limits: tls_client_hello.h.
 *
 * Wire layout parsed (RFC 8446 §4.1.2, RFC 5246 §7.4.1.2):
 *
 *   uint16 legacy_version
 *   opaque random[32]
 *   opaque legacy_session_id<0..32>
 *   CipherSuite cipher_suites<2..2^16-2>
 *   opaque legacy_compression_methods<1..2^8-1>
 *   Extension extensions<8..2^16-1>      (absent in pre-TLS 1.2 hellos)
 *
 * Every multi-byte field is read byte by byte: the buffer may sit at any
 * alignment (issues #57/#59).
 */
#include <stdlib.h>
#include <string.h>

#include "mmt_core.h"
#include "tls_client_hello.h"
#include "../mmt_sha256.h"

/* legacy_version (2) + random (32) + legacy_session_id length (1) */
#define TLS_CH_FIXED_PREFIX 35u
/* RFC 8446 §4.1.2: legacy_session_id<0..32> */
#define TLS_CH_MAX_SESSION_ID 32u
/* server_name_list length (2) + name_type (1) + name length (2) */
#define TLS_SNI_HEADER 5u

struct tls_hello_range {
    uint16_t start;
    uint16_t end; /* exclusive */
};

struct tls_hello_reasm {
    uint32_t base;    /* stream position of data[0] */
    uint16_t need;    /* declared message length, 1..TLS_HELLO_MAX_MESSAGE */
    uint16_t have;    /* bytes of [0, need) present */
    uint8_t tag;      /* caller data */
    uint8_t stalls;   /* segments that added no byte */
    uint8_t nranges;  /* entries of ranges[] in use: sorted, disjoint, not adjacent */
    struct tls_hello_range ranges[TLS_HELLO_MAX_RANGES];
    uint8_t data[];
};

static inline uint16_t tls_rd16(const uint8_t *p) {
    return (uint16_t) (((uint16_t) p[0] << 8) | (uint16_t) p[1]);
}

static inline uint32_t tls_rd24(const uint8_t *p) {
    return ((uint32_t) p[0] << 16) | ((uint32_t) p[1] << 8) | (uint32_t) p[2];
}

/* RFC 6066 §3 server_name body: list length, name_type, name length, name.
 * Only the first entry is read; it must be a host_name that fits `len`. */
static void tls_read_sni(const uint8_t *ext, uint16_t len, tls_client_hello_t *out) {
    out->sni_status = TLS_SNI_MALFORMED;
    if (len < TLS_SNI_HEADER || ext[2] != 0 /* host_name */) {
        return;
    }
    uint16_t name_len = tls_rd16(ext + 3);
    if ((uint32_t) TLS_SNI_HEADER + name_len > len) {
        return;
    }
    out->sni = ext + TLS_SNI_HEADER;
    out->sni_len = name_len;
    out->sni_status = TLS_SNI_OK;
}

/* Walks the extension block; stops at the first extension that does not fit.
 * Returns the number visited. */
static unsigned tls_walk_extensions(const uint8_t *ext, uint16_t len,
        tls_client_hello_ext_fn fn, void *ctx) {
    uint32_t pos = 0;
    unsigned n = 0;
    while (pos + 4 <= len) {
        uint16_t type = tls_rd16(ext + pos);
        uint16_t elen = tls_rd16(ext + pos + 2);
        if (elen > len - pos - 4) {
            break;
        }
        n++;
        if (fn(type, ext + pos + 4, elen, ctx) != 0) {
            break;
        }
        pos += 4u + elen;
    }
    return n;
}

/* Keeps the first extension of a type: `*body` NULL until then. */
static void tls_keep_first(const uint8_t **body, uint16_t *body_len,
        const uint8_t *data, uint16_t len) {
    if (*body == NULL) {
        *body = data;
        *body_len = len;
    }
}

static int tls_note_extension(uint16_t type, const uint8_t *data, uint16_t len, void *ctx) {
    tls_client_hello_t *out = (tls_client_hello_t *) ctx;
    switch (type) {
    case TLS_EXT_SERVER_NAME:
        out->has_sni_extension = 1;
        if (out->sni_status == TLS_SNI_ABSENT) {
            tls_read_sni(data, len, out);
        }
        break;
    case TLS_EXT_ALPN:
        tls_keep_first(&out->alpn, &out->alpn_len, data, len);
        break;
    case TLS_EXT_SUPPORTED_VERSIONS:
        tls_keep_first(&out->supported_versions, &out->supported_versions_len, data, len);
        break;
    case TLS_EXT_SIGNATURE_ALGORITHMS:
        tls_keep_first(&out->signature_algorithms, &out->signature_algorithms_len, data, len);
        break;
    case TLS_EXT_ENCRYPTED_CLIENT_HELLO:
        /* RFC 9849 §5: ECHClientHello starts with its type; an outer one
         * carries the encrypted inner hello, whose server_name is hidden. */
        if (len >= 1 && data[0] == TLS_ECH_OUTER) {
            out->ech_outer = 1;
        }
        break;
    default:
        break;
    }
    return 0;
}

tls_client_hello_status_t tls_client_hello_parse_body(const uint8_t *body, size_t len,
        tls_client_hello_t *out) {
    tls_client_hello_t ch;
    memset(&ch, 0, sizeof ch);
    if (out != NULL) {
        memset(out, 0, sizeof *out);
    }
    if (body == NULL || out == NULL || len < TLS_CH_FIXED_PREFIX) {
        return TLS_CH_MALFORMED;
    }
    ch.legacy_version = tls_rd16(body);
    ch.random = body + 2;
    ch.session_id_len = body[34];
    size_t off = TLS_CH_FIXED_PREFIX;
    if (ch.session_id_len > TLS_CH_MAX_SESSION_ID || off + ch.session_id_len + 2 > len) {
        return TLS_CH_MALFORMED;
    }
    ch.session_id = body + off;
    off += ch.session_id_len;
    ch.cipher_suites_len = tls_rd16(body + off);
    off += 2;
    if (off + ch.cipher_suites_len + 1 > len) {
        return TLS_CH_MALFORMED;
    }
    ch.cipher_suites = body + off;
    off += ch.cipher_suites_len;
    ch.compression_len = body[off++];
    if (off + ch.compression_len > len) {
        return TLS_CH_MALFORMED;
    }
    ch.compression = body + off;
    off += ch.compression_len;

    tls_client_hello_status_t status = TLS_CH_OK;
    /* Fewer than 2 bytes left: no extension block (a pre-TLS 1.2 hello). */
    if (off + 2 <= len) {
        uint16_t declared = tls_rd16(body + off);
        size_t avail = len - off - 2;
        ch.extensions = body + off + 2;
        ch.extensions_len = (uint16_t) (declared <= avail ? declared : avail);
        if (declared > avail) {
            status = TLS_CH_TRUNCATED;
        }
        ch.extension_count = (uint16_t) tls_client_hello_foreach_extension(&ch,
                tls_note_extension, &ch);
    }
    *out = ch;
    return status;
}

tls_client_hello_status_t tls_client_hello_parse(const uint8_t *msg, size_t len,
        tls_client_hello_t *out) {
    if (out != NULL) {
        memset(out, 0, sizeof *out);
    }
    if (msg == NULL || len < 4 || msg[0] != TLS_HANDSHAKE_CLIENT_HELLO) {
        return TLS_CH_MALFORMED;
    }
    size_t declared = tls_rd24(msg + 1);
    size_t avail = len - 4;
    tls_client_hello_status_t status = tls_client_hello_parse_body(msg + 4,
            declared <= avail ? declared : avail, out);
    if (status == TLS_CH_OK && declared > avail) {
        status = TLS_CH_TRUNCATED;
    }
    return status;
}

unsigned tls_client_hello_foreach_extension(const tls_client_hello_t *ch,
        tls_client_hello_ext_fn fn, void *ctx) {
    if (ch == NULL || fn == NULL || ch->extensions == NULL) {
        return 0;
    }
    return tls_walk_extensions(ch->extensions, ch->extensions_len, fn, ctx);
}

/* ---- versions, ALPN, ServerHello (issue #569) --------------------------- */

uint16_t tls_client_hello_version(const tls_client_hello_t *ch) {
    uint16_t best = 0;
    const uint8_t *sv = ch->supported_versions;
    if (sv != NULL && ch->supported_versions_len >= 1) {
        /* RFC 8446 §4.2.1: ProtocolVersion versions<2..254>, 1-byte length */
        uint32_t n = sv[0];
        if (n > (uint32_t) ch->supported_versions_len - 1) {
            n = (uint32_t) ch->supported_versions_len - 1;
        }
        for (uint32_t i = 0; i + 2 <= n; i += 2) {
            uint16_t v = tls_rd16(sv + 1 + i);
            if (!TLS_IS_GREASE(v) && v > best) {
                best = v;
            }
        }
    }
    return best != 0 ? best : ch->legacy_version;
}

size_t tls_alpn_text(const uint8_t *list, uint16_t len, char *out, size_t cap) {
    size_t w = 0;
    out[0] = '\0';
    if (list == NULL || len < 2) {
        return 0;
    }
    /* RFC 7301 §3.1: ProtocolName protocol_name_list<2..2^16-1>, each name
     * a non-empty opaque<1..2^8-1> */
    uint32_t end = 2u + tls_rd16(list);
    if (end > len) {
        end = len;
    }
    uint32_t pos = 2;
    while (pos < end) {
        uint8_t n = list[pos];
        if (n == 0 || pos + 1u + n > end || w + (w > 0) + n + 1 > cap) {
            break;
        }
        if (w > 0) {
            out[w++] = ',';
        }
        memcpy(out + w, list + pos + 1, n);
        w += n;
        pos += 1u + n;
    }
    out[w] = '\0';
    return w;
}

/* ServerHello extensions: supported_versions holds the one selected_version
 * (RFC 8446 §4.2.1); ALPN the one selected protocol (RFC 7301 §3.1). */
static int tls_note_server_extension(uint16_t type, const uint8_t *data, uint16_t len, void *ctx) {
    tls_server_hello_t *out = (tls_server_hello_t *) ctx;
    if (type == TLS_EXT_SUPPORTED_VERSIONS && len == 2 && out->selected_version == 0) {
        out->selected_version = tls_rd16(data);
    } else if (type == TLS_EXT_ALPN) {
        tls_keep_first(&out->alpn, &out->alpn_len, data, len);
    }
    return 0;
}

tls_client_hello_status_t tls_server_hello_parse(const uint8_t *msg, size_t len,
        tls_server_hello_t *out) {
    if (out != NULL) {
        memset(out, 0, sizeof *out);
    }
    if (msg == NULL || out == NULL || len < TLS_HANDSHAKE_HEADER_LEN
            || msg[0] != TLS_HANDSHAKE_SERVER_HELLO) {
        return TLS_CH_MALFORMED;
    }
    /* RFC 8446 §4.1.3: legacy_version, random[32], legacy_session_id_echo,
     * cipher_suite, legacy_compression_method, extensions */
    size_t declared = tls_rd24(msg + 1);
    size_t avail = len - TLS_HANDSHAKE_HEADER_LEN;
    size_t blen = declared <= avail ? declared : avail;
    const uint8_t *body = msg + TLS_HANDSHAKE_HEADER_LEN;
    if (blen < TLS_CH_FIXED_PREFIX) {
        return TLS_CH_MALFORMED;
    }
    uint8_t sid_len = body[TLS_CH_FIXED_PREFIX - 1];
    size_t off = TLS_CH_FIXED_PREFIX + sid_len;
    if (sid_len > TLS_CH_MAX_SESSION_ID || off + 3 > blen) {
        return TLS_CH_MALFORMED;
    }
    tls_server_hello_t sh;
    memset(&sh, 0, sizeof sh);
    sh.legacy_version = tls_rd16(body);
    sh.cipher_suite = tls_rd16(body + off);
    off += 3; /* cipher_suite (2) + compression method (1) */
    tls_client_hello_status_t status = declared > avail ? TLS_CH_TRUNCATED : TLS_CH_OK;
    if (off + 2 <= blen) {
        size_t ext_avail = blen - off - 2;
        size_t ext_len = tls_rd16(body + off);
        if (ext_len > ext_avail) {
            ext_len = ext_avail;
            status = TLS_CH_TRUNCATED;
        }
        tls_walk_extensions(body + off + 2, (uint16_t) ext_len, tls_note_server_extension, &sh);
    }
    *out = sh;
    return status;
}

/* ---- JA4 (FoxIO JA4 specification, technical_details/JA4.md) ------------ */

static const char tls_hex_digits[] = "0123456789abcdef";

static int tls_cmp_u16(const void *a, const void *b) {
    uint16_t x = *(const uint16_t *) a, y = *(const uint16_t *) b;
    return (x > y) - (x < y);
}

static int tls_is_alnum(uint8_t c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/* The two-character version token; "00" for a value the table lacks. */
static const char *tls_ja4_version(uint16_t v) {
    switch (v) {
    case 0x0304: return "13";
    case 0x0303: return "12";
    case 0x0302: return "11";
    case 0x0301: return "10";
    case 0x0300: return "s3";
    case 0x0002: return "s2";
    case 0xfeff: return "d1";
    case 0xfefd: return "d2";
    case 0xfefc: return "d3";
    default: return "00";
    }
}

/* Two decimal digits, 99 for anything above. */
static void tls_ja4_count(char *p, unsigned n) {
    if (n > 99) {
        n = 99;
    }
    p[0] = (char) ('0' + n / 10);
    p[1] = (char) ('0' + n % 10);
}

/* First and last character of the first ALPN protocol name; the first and
 * last digit of its hex form when either is not alphanumeric; "00" when the
 * hello has no (non-empty) first name. */
static void tls_ja4_alpn(const tls_client_hello_t *ch, char out[2]) {
    out[0] = out[1] = '0';
    const uint8_t *l = ch->alpn;
    if (l == NULL || ch->alpn_len < 3) {
        return;
    }
    uint8_t n = l[2];
    if (n == 0 || 3u + n > ch->alpn_len || 1u + n > tls_rd16(l)) {
        return;
    }
    uint8_t first = l[3], last = l[2 + n];
    if (tls_is_alnum(first) && tls_is_alnum(last)) {
        out[0] = (char) first;
        out[1] = (char) last;
    } else {
        out[0] = tls_hex_digits[first >> 4];
        out[1] = tls_hex_digits[last & 0x0f];
    }
}

/* Absorbs `n` values as comma-separated 4-digit lowercase hex. */
static void tls_hash_u16_list(mmt_sha256_ctx_t *c, const uint16_t *v, unsigned n) {
    for (unsigned i = 0; i < n; i++) {
        char item[5];
        unsigned k = 0;
        if (i > 0) {
            item[k++] = ',';
        }
        for (int shift = 12; shift >= 0; shift -= 4) {
            item[k++] = tls_hex_digits[(v[i] >> shift) & 0x0f];
        }
        mmt_sha256_update(c, item, k);
    }
}

/* The first 12 hex digits of the digest in `c` (consumed). */
static void tls_hash12(mmt_sha256_ctx_t *c, char out[12]) {
    uint8_t d[MMT_SHA256_DIGEST_LEN];
    mmt_sha256_final(c, d);
    for (unsigned i = 0; i < 6; i++) {
        out[2 * i] = tls_hex_digits[d[i] >> 4];
        out[2 * i + 1] = tls_hex_digits[d[i] & 0x0f];
    }
}

/* Non-GREASE 16-bit values of a big-endian list of `bytes` bytes, in wire
 * order. Returns how many, or -1 past TLS_JA4_MAX_ITEMS. */
static int tls_collect_u16(const uint8_t *p, uint32_t bytes, uint16_t *dst) {
    unsigned n = 0;
    for (uint32_t i = 0; i + 2 <= bytes; i += 2) {
        uint16_t v = tls_rd16(p + i);
        if (TLS_IS_GREASE(v)) {
            continue;
        }
        if (n == TLS_JA4_MAX_ITEMS) {
            return -1;
        }
        dst[n++] = v;
    }
    return (int) n;
}

struct tls_ja4_extensions {
    uint16_t types[TLS_JA4_MAX_ITEMS]; /* sorted part: SNI and ALPN left out */
    unsigned n;
    unsigned count;                    /* every non-GREASE extension */
    int overflow;
};

static int tls_ja4_note_extension(uint16_t type, const uint8_t *data, uint16_t len, void *ctx) {
    struct tls_ja4_extensions *e = (struct tls_ja4_extensions *) ctx;
    (void) data;
    (void) len;
    if (TLS_IS_GREASE(type)) {
        return 0;
    }
    e->count++;
    if (type == TLS_EXT_SERVER_NAME || type == TLS_EXT_ALPN) {
        return 0;
    }
    if (e->n == TLS_JA4_MAX_ITEMS) {
        e->overflow = 1;
        return 1;
    }
    e->types[e->n++] = type;
    return 0;
}

/* JA4_c: the sorted extensions, then "_" and the signature algorithms in
 * wire order when there are any; 12 zeros without an extension. */
static int tls_ja4_extensions_hash(const tls_client_hello_t *ch, unsigned *count, char out[12]) {
    struct tls_ja4_extensions e;
    uint16_t sigalgs[TLS_JA4_MAX_ITEMS];
    int nsig = 0;
    memset(&e, 0, sizeof e);
    tls_client_hello_foreach_extension(ch, tls_ja4_note_extension, &e);
    const uint8_t *sa = ch->signature_algorithms;
    if (sa != NULL && ch->signature_algorithms_len >= 2) {
        uint32_t bytes = tls_rd16(sa); /* SignatureScheme list<2..2^16-2> */
        if (bytes > (uint32_t) ch->signature_algorithms_len - 2) {
            bytes = (uint32_t) ch->signature_algorithms_len - 2;
        }
        nsig = tls_collect_u16(sa + 2, bytes, sigalgs);
    }
    if (e.overflow || nsig < 0) {
        return 0;
    }
    *count = e.count;
    if (e.n == 0) {
        memset(out, '0', 12);
        return 1;
    }
    qsort(e.types, e.n, sizeof e.types[0], tls_cmp_u16);
    mmt_sha256_ctx_t c;
    mmt_sha256_init(&c);
    tls_hash_u16_list(&c, e.types, e.n);
    if (nsig > 0) {
        mmt_sha256_update(&c, "_", 1);
        tls_hash_u16_list(&c, sigalgs, (unsigned) nsig);
    }
    tls_hash12(&c, out);
    return 1;
}

/* JA4_b: the sorted cipher suites; 12 zeros without one. Returns how many
 * suites, or -1 past TLS_JA4_MAX_ITEMS. */
static int tls_ja4_ciphers_hash(const tls_client_hello_t *ch, char out[12]) {
    uint16_t suites[TLS_JA4_MAX_ITEMS];
    int n = tls_collect_u16(ch->cipher_suites, ch->cipher_suites_len, suites);
    if (n <= 0) {
        memset(out, '0', 12);
        return n;
    }
    qsort(suites, (size_t) n, sizeof suites[0], tls_cmp_u16);
    mmt_sha256_ctx_t c;
    mmt_sha256_init(&c);
    tls_hash_u16_list(&c, suites, (unsigned) n);
    tls_hash12(&c, out);
    return n;
}

int tls_client_hello_ja4(const tls_client_hello_t *ch, char transport,
        char out[TLS_JA4_LEN + 1]) {
    unsigned ext_count = 0;
    out[0] = '\0';
    /* JA4_a (10) "_" JA4_b (12) "_" JA4_c (12) */
    int suites = tls_ja4_ciphers_hash(ch, out + 11);
    if (suites < 0 || !tls_ja4_extensions_hash(ch, &ext_count, out + 24)) {
        out[0] = '\0';
        return 0;
    }
    const char *version = tls_ja4_version(tls_client_hello_version(ch));
    out[0] = transport;
    out[1] = version[0];
    out[2] = version[1];
    out[3] = ch->has_sni_extension ? 'd' : 'i';
    tls_ja4_count(out + 4, (unsigned) suites);
    tls_ja4_count(out + 6, ext_count);
    tls_ja4_alpn(ch, out + 8);
    out[10] = '_';
    out[23] = '_';
    out[TLS_JA4_LEN] = '\0';
    return 1;
}

/* ---- reassembly ------------------------------------------------------- */

tls_hello_reasm_status_t tls_hello_reasm_begin(tls_hello_reasm_t **slot, uint32_t need,
        uint32_t base, uint8_t tag) {
    if (slot == NULL || *slot != NULL || need == 0 || need > TLS_HELLO_MAX_MESSAGE) {
        return TLS_REASM_DROPPED;
    }
    tls_hello_reasm_t *r = (tls_hello_reasm_t *) mmt_malloc(sizeof (*r) + need);
    if (r == NULL) {
        return TLS_REASM_DROPPED;
    }
    memset(r, 0, sizeof (*r));
    r->base = base;
    r->need = (uint16_t) need;
    r->tag = tag;
    *slot = r;
    return TLS_REASM_PENDING;
}

/* Adds [start, end) to the range set. Returns the bytes it added, or -1 when
 * the merged set would exceed TLS_HELLO_MAX_RANGES (the set is unchanged). */
static int tls_reasm_add_range(tls_hello_reasm_t *r, uint16_t start, uint16_t end) {
    struct tls_hello_range merged[TLS_HELLO_MAX_RANGES + 1];
    unsigned n = 0, i = 0, covered = 0;
    uint16_t s = start, e = end;
    for (; i < r->nranges && r->ranges[i].end < s; i++) {
        merged[n++] = r->ranges[i];
    }
    for (; i < r->nranges && r->ranges[i].start <= e; i++) {
        covered += (unsigned) (r->ranges[i].end - r->ranges[i].start);
        s = r->ranges[i].start < s ? r->ranges[i].start : s;
        e = r->ranges[i].end > e ? r->ranges[i].end : e;
    }
    merged[n++] = (struct tls_hello_range) { s, e };
    for (; i < r->nranges; i++) {
        if (n == TLS_HELLO_MAX_RANGES) {
            return -1;
        }
        merged[n++] = r->ranges[i];
    }
    if (n > TLS_HELLO_MAX_RANGES) {
        return -1;
    }
    memcpy(r->ranges, merged, n * sizeof merged[0]);
    r->nranges = (uint8_t) n;
    return (int) ((unsigned) (e - s) - covered);
}

static tls_hello_reasm_status_t tls_reasm_stall(tls_hello_reasm_t **slot) {
    if (++(*slot)->stalls >= TLS_HELLO_MAX_STALLS) {
        tls_hello_reasm_release(slot);
        return TLS_REASM_DROPPED;
    }
    return TLS_REASM_PENDING;
}

tls_hello_reasm_status_t tls_hello_reasm_feed(tls_hello_reasm_t **slot, uint32_t pos,
        const uint8_t *data, size_t len) {
    if (slot == NULL || *slot == NULL) {
        return TLS_REASM_DROPPED;
    }
    tls_hello_reasm_t *r = *slot;
    if (r->have == r->need) {
        return TLS_REASM_COMPLETE;
    }
    /* Signed distance in sequence space (RFC 1982 style). */
    int64_t rel = (int32_t) (pos - r->base);
    size_t skip = 0;
    if (data == NULL || len == 0) {
        return tls_reasm_stall(slot);
    }
    if (rel < 0) {
        if ((uint64_t) (-rel) >= len) {
            return tls_reasm_stall(slot);
        }
        skip = (size_t) (-rel);
        rel = 0;
    }
    if (rel >= r->need) {
        return tls_reasm_stall(slot);
    }
    size_t n = len - skip;
    if (n > (size_t) (r->need - rel)) {
        n = (size_t) (r->need - rel);
    }
    int added = tls_reasm_add_range(r, (uint16_t) rel, (uint16_t) (rel + (int64_t) n));
    if (added < 0) {
        tls_hello_reasm_release(slot);
        return TLS_REASM_DROPPED;
    }
    memcpy(r->data + rel, data + skip, n);
    if (added == 0) {
        return tls_reasm_stall(slot);
    }
    r->have = (uint16_t) (r->have + added);
    return r->have == r->need ? TLS_REASM_COMPLETE : TLS_REASM_PENDING;
}

const uint8_t *tls_hello_reasm_data(const tls_hello_reasm_t *r, uint32_t *len) {
    if (r == NULL) {
        if (len != NULL) {
            *len = 0;
        }
        return NULL;
    }
    if (len != NULL) {
        *len = r->need;
    }
    return r->data;
}

uint8_t tls_hello_reasm_tag(const tls_hello_reasm_t *r) {
    return r != NULL ? r->tag : 0;
}

size_t tls_hello_reasm_footprint(const tls_hello_reasm_t *r) {
    return r != NULL ? sizeof (*r) + r->need : 0;
}

void tls_hello_reasm_release(tls_hello_reasm_t **slot) {
    if (slot != NULL && *slot != NULL) {
        mmt_free(*slot);
        *slot = NULL;
    }
}
