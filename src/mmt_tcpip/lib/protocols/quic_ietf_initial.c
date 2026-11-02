/*
 * quic_ietf_initial.c — client Initial packet protection removal for QUIC
 * v1 (RFC 9000/9001) and v2 (RFC 9369), issue #570. API: quic_ietf_initial.h.
 *
 * Initial packet (RFC 9000 §17.2.2):
 *
 *   Header Form (1) = 1, Fixed Bit (1) = 1, Long Packet Type (2),
 *   Reserved Bits (2), Packet Number Length (2),     <- low 4 bits protected
 *   Version (32), DCID Length (8), DCID (0..160), SCID Length (8),
 *   SCID (0..160), Token Length (i), Token (..), Length (i),
 *   Packet Number (8..32),                            <- protected
 *   Packet Payload (8..)                              <- AEAD ciphertext + tag
 *
 * Every field is read byte by byte inside [pkt, pkt + pkt_len): the packet
 * may sit at any alignment and every declared span is checked before use.
 */
#include <string.h>

#include "../mmt_crypto.h"
#include "quic_ietf_initial.h"

/* RFC 9001 §5.4.2: the header-protection sample starts 4 bytes after the
 * start of the Packet Number field and is 16 bytes long. */
#define QUIC_INITIAL_SAMPLE_OFFSET 4u
#define QUIC_INITIAL_SAMPLE_LEN 16u
/* flags + version + DCID length */
#define QUIC_INITIAL_FIXED_PREFIX 6u
/* Long Packet Type of an Initial: 0b00 in v1, 0b01 in v2 (RFC 9369 §3.2). */
#define QUIC_INITIAL_TYPE_V1 0u
#define QUIC_INITIAL_TYPE_V2 1u
/* Reserved Bits once header protection is removed (RFC 9000 §17.2). */
#define QUIC_INITIAL_RESERVED_BITS 0x0cu

/* Per-version Initial salt and key-derivation labels. */
typedef struct quic_initial_version {
    uint8_t salt[20];
    const char *key_label;
    const char *iv_label;
    const char *hp_label;
} quic_initial_version_t;

/* RFC 9001 §5.2 */
static const quic_initial_version_t quic_initial_v1 = {
    {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
     0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
    "quic key", "quic iv", "quic hp"};

/* RFC 9369 §3.3.1 and §3.3.2 */
static const quic_initial_version_t quic_initial_v2 = {
    {0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
     0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9},
    "quicv2 key", "quicv2 iv", "quicv2 hp"};

/* The validated layout of an Initial packet. */
typedef struct quic_initial_layout {
    uint32_t version;
    uint8_t dcid_len;
    uint8_t scid_len;
    size_t pn_offset; /* start of the protected Packet Number */
    size_t end;       /* pn_offset + Length */
} quic_initial_layout_t;

/* RFC 9000 §16 variable-length integer at pkt[*cursor .. len). */
static int quic_initial_varint(const uint8_t *pkt, size_t len, size_t *cursor, uint64_t *value) {
    if (*cursor >= len) {
        return 0;
    }
    size_t n = (size_t) 1 << (pkt[*cursor] >> 6);
    if (n > len - *cursor) {
        return 0;
    }
    uint64_t v = pkt[*cursor] & 0x3fu;
    for (size_t i = 1; i < n; i++) {
        v = (v << 8) | pkt[*cursor + i];
    }
    *cursor += n;
    *value = v;
    return 1;
}

/* Long header, fixed bit, version 1 or 2, Initial packet type. */
static quic_initial_status_t quic_initial_check_type(const uint8_t *pkt, uint32_t *version) {
    if ((pkt[0] & 0xc0u) != 0xc0u) {
        return QUIC_INITIAL_ERR_NOT_INITIAL;
    }
    uint32_t v = ((uint32_t) pkt[1] << 24) | ((uint32_t) pkt[2] << 16) | ((uint32_t) pkt[3] << 8) | pkt[4];
    unsigned type = (pkt[0] >> 4) & 3u;
    if ((v == QUIC_INITIAL_VERSION_1 && type == QUIC_INITIAL_TYPE_V1) ||
        (v == QUIC_INITIAL_VERSION_2 && type == QUIC_INITIAL_TYPE_V2)) {
        *version = v;
        return QUIC_INITIAL_OK;
    }
    return QUIC_INITIAL_ERR_NOT_INITIAL;
}

/* A connection ID: its length byte at pkt[*cursor], at most 20, then the
 * bytes. Leaves the cursor after the ID. */
static quic_initial_status_t quic_initial_cid(const uint8_t *pkt, size_t len, size_t *cursor, uint8_t *cid_len) {
    if (*cursor >= len) {
        return QUIC_INITIAL_ERR_TRUNCATED;
    }
    uint8_t n = pkt[*cursor];
    if (n > QUIC_INITIAL_MAX_CID_LEN) {
        return QUIC_INITIAL_ERR_CID_LENGTH;
    }
    if ((size_t) n > len - *cursor - 1) {
        return QUIC_INITIAL_ERR_TRUNCATED;
    }
    *cid_len = n;
    *cursor += 1u + n;
    return QUIC_INITIAL_OK;
}

static quic_initial_status_t quic_initial_parse(const uint8_t *pkt, size_t len, quic_initial_layout_t *l) {
    if (len < QUIC_INITIAL_FIXED_PREFIX) {
        return QUIC_INITIAL_ERR_TRUNCATED;
    }
    quic_initial_status_t st = quic_initial_check_type(pkt, &l->version);
    size_t cursor = QUIC_INITIAL_FIXED_PREFIX - 1; /* the DCID length */
    if (st == QUIC_INITIAL_OK) {
        st = quic_initial_cid(pkt, len, &cursor, &l->dcid_len);
    }
    if (st == QUIC_INITIAL_OK) {
        st = quic_initial_cid(pkt, len, &cursor, &l->scid_len);
    }
    if (st != QUIC_INITIAL_OK) {
        return st;
    }
    uint64_t token_len, length;
    if (!quic_initial_varint(pkt, len, &cursor, &token_len) || token_len > len - cursor) {
        return QUIC_INITIAL_ERR_TRUNCATED;
    }
    cursor += (size_t) token_len;
    if (!quic_initial_varint(pkt, len, &cursor, &length) || length > len - cursor ||
        length < QUIC_INITIAL_SAMPLE_OFFSET + QUIC_INITIAL_SAMPLE_LEN) {
        return QUIC_INITIAL_ERR_TRUNCATED;
    }
    l->pn_offset = cursor;
    l->end = cursor + (size_t) length;
    return QUIC_INITIAL_OK;
}

/* RFC 9001 §5.1-5.2: the client Initial key, IV and header-protection key
 * from the client's Destination Connection ID. */
static void quic_initial_keys(const quic_initial_version_t *ver, const uint8_t *dcid, uint8_t dcid_len,
                              uint8_t key[MMT_AES128_KEY_LEN], uint8_t iv[MMT_GCM_IV_LEN],
                              uint8_t hp[MMT_AES128_KEY_LEN]) {
    uint8_t initial_secret[MMT_HMAC_SHA256_LEN];
    uint8_t client_secret[MMT_HMAC_SHA256_LEN];
    mmt_hkdf_extract(ver->salt, sizeof ver->salt, dcid, dcid_len, initial_secret);
    /* fixed labels and lengths far below the limits: these cannot fail */
    (void) mmt_hkdf_expand_label(initial_secret, "client in", client_secret, sizeof client_secret);
    (void) mmt_hkdf_expand_label(client_secret, ver->key_label, key, MMT_AES128_KEY_LEN);
    (void) mmt_hkdf_expand_label(client_secret, ver->iv_label, iv, MMT_GCM_IV_LEN);
    (void) mmt_hkdf_expand_label(client_secret, ver->hp_label, hp, MMT_AES128_KEY_LEN);
}

quic_initial_status_t quic_ietf_initial_decrypt(const uint8_t *pkt, size_t pkt_len, size_t datagram_len,
                                                uint8_t *out, size_t out_cap, quic_initial_info_t *info) {
    if (pkt == NULL || out == NULL || info == NULL) {
        return QUIC_INITIAL_ERR_ARG;
    }
    if (datagram_len < QUIC_INITIAL_MIN_DATAGRAM) {
        return QUIC_INITIAL_ERR_SHORT_DATAGRAM;
    }
    quic_initial_layout_t l;
    quic_initial_status_t st = quic_initial_parse(pkt, pkt_len, &l);
    if (st != QUIC_INITIAL_OK) {
        return st;
    }
    /* header + plaintext = the packet without its 16-byte tag; end is at
     * least pn_offset + 20, so this cannot wrap */
    if (l.end - MMT_GCM_TAG_LEN > out_cap) {
        return QUIC_INITIAL_ERR_BUFFER;
    }
    const quic_initial_version_t *ver = l.version == QUIC_INITIAL_VERSION_2 ? &quic_initial_v2 : &quic_initial_v1;
    uint8_t key[MMT_AES128_KEY_LEN], iv[MMT_GCM_IV_LEN], hp[MMT_AES128_KEY_LEN];
    quic_initial_keys(ver, pkt + QUIC_INITIAL_FIXED_PREFIX, l.dcid_len, key, iv, hp);

    /* RFC 9001 §5.4.1-5.4.3: mask = AES-ECB(hp, sample) */
    mmt_aes128_ctx_t aes;
    uint8_t mask[MMT_AES_BLOCK_LEN];
    mmt_aes128_init(&aes, hp);
    mmt_aes128_encrypt_block(&aes, pkt + l.pn_offset + QUIC_INITIAL_SAMPLE_OFFSET, mask);
    uint8_t flags = (uint8_t) (pkt[0] ^ (mask[0] & 0x0fu));
    uint8_t pn_len = (uint8_t) ((flags & 3u) + 1u);
    size_t header_len = l.pn_offset + pn_len;
    memcpy(out, pkt, header_len);
    out[0] = flags;
    uint32_t pn = 0;
    for (unsigned i = 0; i < pn_len; i++) {
        out[l.pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | out[l.pn_offset + i];
    }

    /* RFC 9001 §5.3: nonce = IV xor the packet number, left-padded */
    for (unsigned i = 0; i < 4; i++) {
        iv[MMT_GCM_IV_LEN - 1 - i] ^= (uint8_t) (pn >> (8 * i));
    }
    mmt_aes128_init(&aes, key);
    const mmt_aead_io_t io = {out, header_len, pkt + header_len, l.end - header_len, out + header_len};
    if (mmt_aes128_gcm_open(&aes, iv, &io) != 0) {
        return QUIC_INITIAL_ERR_AUTH;
    }
    if (flags & QUIC_INITIAL_RESERVED_BITS) {
        return QUIC_INITIAL_ERR_RESERVED_BITS;
    }
    info->version = l.version;
    info->packet_number = pn;
    info->pn_length = pn_len;
    info->dcid_len = l.dcid_len;
    info->scid_len = l.scid_len;
    info->header_len = header_len;
    info->payload_len = l.end - header_len - MMT_GCM_TAG_LEN;
    info->packet_len = l.end;
    return QUIC_INITIAL_OK;
}
