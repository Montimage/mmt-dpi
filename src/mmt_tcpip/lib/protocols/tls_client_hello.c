/*
 * tls_client_hello.c — transport-independent TLS ClientHello parser and the
 * bounded buffer that collects a ClientHello spread over several segments
 * (issue #568, F-BUG-302). API and limits: tls_client_hello.h.
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
#include <string.h>

#include "mmt_core.h"
#include "tls_client_hello.h"

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

static int tls_note_extension(uint16_t type, const uint8_t *data, uint16_t len, void *ctx) {
    tls_client_hello_t *out = (tls_client_hello_t *) ctx;
    if (type == TLS_EXT_SERVER_NAME && out->sni_status == TLS_SNI_ABSENT) {
        tls_read_sni(data, len, out);
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
