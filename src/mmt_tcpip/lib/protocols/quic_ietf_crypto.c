/*
 * quic_ietf_crypto.c — the ClientHello of a QUIC client's Initial CRYPTO
 * frames (issue #571). See quic_ietf_crypto.h for the bounds.
 */
#include <string.h>

#include "mmt_core.h"
#include "quic_ietf_initial.h"
#include "quic_ietf_crypto.h"

/* Frame types (RFC 9000 §19, §12.4: the ones an Initial may carry). */
#define QUIC_FRAME_PADDING 0x00
#define QUIC_FRAME_PING 0x01
#define QUIC_FRAME_ACK 0x02
#define QUIC_FRAME_ACK_ECN 0x03
#define QUIC_FRAME_CRYPTO 0x06
/* ACK frame (RFC 9000 §19.3): Largest Acknowledged, ACK Delay, ACK Range
 * Count and First ACK Range, then two varints per range, then the three
 * ECN counts of an ACK_ECN frame. */
#define QUIC_ACK_RANGE_VARINTS 2u
#define QUIC_ACK_ECN_COUNTS 3
/* Long header first byte (RFC 9000 §17.2) and Initial type codes. */
#define QUIC_HEADER_FORM_BIT 0x80
#define QUIC_FIXED_BIT 0x40
#define QUIC_LONG_TYPE_SHIFT 4
#define QUIC_LONG_TYPE_MASK 0x03
#define QUIC_V1_INITIAL_TYPE 0
#define QUIC_V2_INITIAL_TYPE 1 /* RFC 9369 §3.2 */
#define QUIC_VERSION_END 5     /* first byte + 32-bit version */
/* hdr_have once every byte of the 4-byte handshake header is known. */
#define QUIC_HDR_COMPLETE ((1u << TLS_HANDSHAKE_HEADER_LEN) - 1u)

typedef struct quic_crypto_frame {
    uint64_t offset;
    size_t len;
    const uint8_t *data;
} quic_crypto_frame_t;

/* RFC 9000 §16 variable-length integer at buf[*cur .. len). */
static int quic_crypto_varint(const uint8_t *buf, size_t len, size_t *cur, uint64_t *value) {
    if (*cur >= len) {
        return 0;
    }
    size_t n = (size_t) 1 << (buf[*cur] >> 6);
    if (n > len - *cur) {
        return 0;
    }
    uint64_t v = buf[*cur] & 0x3f;
    for (size_t i = 1; i < n; i++) {
        v = (v << 8) | buf[*cur + i];
    }
    *cur += n;
    *value = v;
    return 1;
}

/* Skips an ACK / ACK_ECN frame body (RFC 9000 §19.3); 0 when it overruns. */
static int quic_crypto_skip_ack(const uint8_t *f, size_t len, size_t *cur, int ecn) {
    uint64_t v, count;
    if (!quic_crypto_varint(f, len, cur, &v) || !quic_crypto_varint(f, len, cur, &v)
            || !quic_crypto_varint(f, len, cur, &count) || !quic_crypto_varint(f, len, cur, &v)) {
        return 0;
    }
    /* each range takes at least one byte per varint: a count past the
     * plaintext left cannot be met */
    if (count > (len - *cur) / QUIC_ACK_RANGE_VARINTS) {
        return 0;
    }
    for (uint64_t i = 0; i < count; i++) {
        if (!quic_crypto_varint(f, len, cur, &v) || !quic_crypto_varint(f, len, cur, &v)) {
            return 0;
        }
    }
    for (int i = 0; ecn && i < QUIC_ACK_ECN_COUNTS; i++) {
        if (!quic_crypto_varint(f, len, cur, &v)) {
            return 0;
        }
    }
    return 1;
}

/* Lists the CRYPTO frames of one packet's plaintext, in wire order. The walk
 * ends at the first frame it cannot step over: one an Initial does not
 * carry (CONNECTION_CLOSE ends the stream too), a malformed varint, or a
 * length past the plaintext left — checked in 64 bits before anything
 * else. A CRYPTO frame outside the message window [0, 2^14) is skipped
 * over its validated length: its offset is never narrowed. Returns -1 when
 * the packet carries more than QUIC_CRYPTO_MAX_FRAMES CRYPTO frames. */
static int quic_crypto_collect(const uint8_t *f, size_t len, quic_crypto_frame_t *list, size_t *n) {
    size_t cur = 0;
    while (cur < len) {
        uint8_t type = f[cur++];
        uint64_t off, flen;
        if (type == QUIC_FRAME_PADDING || type == QUIC_FRAME_PING) {
            continue;
        }
        if (type == QUIC_FRAME_ACK || type == QUIC_FRAME_ACK_ECN) {
            if (!quic_crypto_skip_ack(f, len, &cur, type == QUIC_FRAME_ACK_ECN)) {
                return 0;
            }
            continue;
        }
        if (type != QUIC_FRAME_CRYPTO || !quic_crypto_varint(f, len, &cur, &off)
                || !quic_crypto_varint(f, len, &cur, &flen) || flen > len - cur) {
            return 0;
        }
        const uint8_t *data = f + cur;
        cur += (size_t) flen;
        if (flen == 0 || off > TLS_HELLO_MAX_MESSAGE || flen > TLS_HELLO_MAX_MESSAGE - off) {
            continue;
        }
        if (*n == QUIC_CRYPTO_MAX_FRAMES) {
            return -1;
        }
        list[*n].offset = off;
        list[*n].len = (size_t) flen;
        list[*n].data = data;
        (*n)++;
    }
    return 0;
}

/* Keeps the bytes of the 4-byte handshake header a frame carries. */
static void quic_crypto_note_header(quic_crypto_t *st, const quic_crypto_frame_t *fr) {
    for (uint64_t i = fr->offset; i < TLS_HANDSHAKE_HEADER_LEN && i < fr->offset + fr->len; i++) {
        if (!(st->hdr_have & (1u << i))) {
            st->hdr[i] = fr->data[i - fr->offset];
            st->hdr_have |= (uint8_t) (1u << i);
        }
    }
}

/* Starts the buffer once the handshake header is known — held across
 * packets in st->hdr: a ClientHello of at most TLS_HELLO_MAX_MESSAGE bytes,
 * header included. Anything else ends the flow. Returns 1 when the buffer
 * exists. */
static int quic_crypto_begin(quic_crypto_t *st) {
    if (st->reasm != NULL) {
        return 1;
    }
    if (st->hdr_have != QUIC_HDR_COMPLETE) {
        return 0;
    }
    uint32_t need = TLS_HANDSHAKE_HEADER_LEN
        + (((uint32_t) st->hdr[1] << 16) | ((uint32_t) st->hdr[2] << 8) | st->hdr[3]);
    if (st->hdr[0] != TLS_HANDSHAKE_CLIENT_HELLO || need > TLS_HELLO_MAX_MESSAGE
            || tls_hello_reasm_begin(&st->reasm, need, 0, 0) != TLS_REASM_PENDING) {
        st->state = QUIC_CRYPTO_DONE;
        return 0;
    }
    /* the held header bytes are the message's first 4, whichever packets
     * carried them (a fresh buffer takes one range: never DROPPED) */
    (void) tls_hello_reasm_feed(&st->reasm, 0, st->hdr, TLS_HANDSHAKE_HEADER_LEN);
    return 1;
}

/* The collected ClientHello: its facts, then the buffer is freed. */
static quic_crypto_result_t quic_crypto_complete(quic_crypto_t *st) {
    uint32_t len = 0;
    const uint8_t *msg = tls_hello_reasm_data(st->reasm, &len);
    tls_client_hello_t ch;
    quic_crypto_result_t res = QUIC_CRYPTO_NONE;
    if (msg != NULL && tls_client_hello_parse(msg, len, &ch) == TLS_CH_OK) {
        quic_hello_facts_t *h = (quic_hello_facts_t *) mmt_malloc(sizeof (*h));
        if (h != NULL) {
            memset(h, 0, sizeof (*h));
            if (ch.sni_status == TLS_SNI_OK) {
                h->sni_len = ch.sni_len < QUIC_HELLO_SNI_CAP ? ch.sni_len : QUIC_HELLO_SNI_CAP - 1;
                memcpy(h->sni, ch.sni, h->sni_len);
            }
            h->alpn_len = (uint16_t) tls_alpn_text(ch.alpn, ch.alpn_len, h->alpn, sizeof (h->alpn));
            h->has_ja4 = (uint8_t) tls_client_hello_ja4(&ch, 'q', h->ja4);
            h->sni_hidden = ch.ech_outer;
            st->hello = h;
            res = QUIC_CRYPTO_HELLO;
        }
    }
    tls_hello_reasm_release(&st->reasm);
    st->state = QUIC_CRYPTO_DONE;
    return res;
}

quic_crypto_result_t quic_crypto_walk_frames(quic_crypto_t *st, const uint8_t *frames, size_t len) {
    quic_crypto_frame_t list[QUIC_CRYPTO_MAX_FRAMES];
    size_t n = 0;
    if (st == NULL || frames == NULL || st->state != QUIC_CRYPTO_ACTIVE) {
        return QUIC_CRYPTO_NONE;
    }
    if (quic_crypto_collect(frames, len, list, &n) != 0) {
        tls_hello_reasm_release(&st->reasm);
        st->state = QUIC_CRYPTO_DONE;
        return QUIC_CRYPTO_NONE;
    }
    for (size_t i = 0; i < n; i++) {
        quic_crypto_note_header(st, &list[i]);
    }
    if (!quic_crypto_begin(st)) {
        return QUIC_CRYPTO_NONE;
    }
    /* ascending offsets: a shuffled packet (Chrome reorders its CRYPTO
     * frames) then grows one range instead of opening several */
    for (size_t i = 1; i < n; i++) {
        quic_crypto_frame_t fr = list[i];
        size_t j = i;
        for (; j > 0 && list[j - 1].offset > fr.offset; j--) {
            list[j] = list[j - 1];
        }
        list[j] = fr;
    }
    for (size_t i = 0; i < n; i++) {
        /* offset + len <= 2^14 (quic_crypto_collect): fits 32 bits */
        tls_hello_reasm_status_t status = tls_hello_reasm_feed(&st->reasm, (uint32_t) list[i].offset,
                list[i].data, list[i].len);
        if (status == TLS_REASM_DROPPED) {
            st->state = QUIC_CRYPTO_DONE;
            return QUIC_CRYPTO_NONE;
        }
        if (status == TLS_REASM_COMPLETE) {
            return quic_crypto_complete(st);
        }
    }
    return QUIC_CRYPTO_NONE;
}

/* A v1/v2 client Initial long header (RFC 9000 §17.2.2, RFC 9369 §3.2). */
static int quic_crypto_is_initial(const uint8_t *p, size_t avail) {
    if (avail < QUIC_VERSION_END
            || (p[0] & (QUIC_HEADER_FORM_BIT | QUIC_FIXED_BIT)) != (QUIC_HEADER_FORM_BIT | QUIC_FIXED_BIT)) {
        return 0;
    }
    uint32_t version = ((uint32_t) p[1] << 24) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 8) | p[4];
    uint8_t type = (p[0] >> QUIC_LONG_TYPE_SHIFT) & QUIC_LONG_TYPE_MASK;
    return (version == QUIC_INITIAL_VERSION_1 && type == QUIC_V1_INITIAL_TYPE)
        || (version == QUIC_INITIAL_VERSION_2 && type == QUIC_V2_INITIAL_TYPE);
}

quic_crypto_result_t quic_crypto_consume(quic_crypto_t *st, const void *src,
        const uint8_t *pkt, size_t pkt_len, size_t datagram_len) {
    uint8_t out[QUIC_INITIAL_OUT_BUFFER];
    quic_crypto_result_t res = QUIC_CRYPTO_NONE;
    size_t off = 0;
    if (st == NULL || pkt == NULL || st->state != QUIC_CRYPTO_ACTIVE
            || (st->client != NULL && st->client != src) || datagram_len < QUIC_INITIAL_MIN_DATAGRAM) {
        return QUIC_CRYPTO_NONE;
    }
    /* coalesced packets (RFC 9000 §12.2): each Initial in turn */
    while (off < pkt_len && st->state == QUIC_CRYPTO_ACTIVE && st->attempts < QUIC_CRYPTO_MAX_ATTEMPTS
            && quic_crypto_is_initial(pkt + off, pkt_len - off)) {
        quic_initial_info_t info;
        st->attempts++;
        if (quic_ietf_initial_decrypt(pkt + off, pkt_len - off, datagram_len, out, sizeof (out), &info)
                != QUIC_INITIAL_OK) {
            break;
        }
        if (st->client == NULL) {
            st->client = src;
        }
        res = quic_crypto_walk_frames(st, out + info.header_len, info.payload_len);
        off += info.packet_len;
    }
    if (st->state == QUIC_CRYPTO_ACTIVE && st->attempts >= QUIC_CRYPTO_MAX_ATTEMPTS) {
        tls_hello_reasm_release(&st->reasm);
        st->state = QUIC_CRYPTO_DONE;
    }
    return res;
}

void quic_crypto_release(quic_crypto_t *st) {
    if (st == NULL) {
        return;
    }
    tls_hello_reasm_release(&st->reasm);
    mmt_free(st->hello);
    st->hello = NULL;
    st->state = QUIC_CRYPTO_DONE;
}
