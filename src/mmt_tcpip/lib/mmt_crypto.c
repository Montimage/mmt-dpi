/*
 * mmt_crypto.c — HMAC-SHA256, HKDF, AES-128 and AES-128-GCM (issue #570).
 * API, scope and the constant-time note: mmt_crypto.h.
 *
 * Every multi-byte quantity is handled byte by byte, so inputs may sit at any
 * alignment and the result does not depend on the host byte order.
 */
#include <string.h>

#include "mmt_crypto.h"
#include "mmt_sha256.h"

/* ---- HMAC-SHA256 (RFC 2104) ------------------------------------------- */

typedef struct mmt_hmac_ctx {
    mmt_sha256_ctx_t inner;
    mmt_sha256_ctx_t outer;
} mmt_hmac_ctx_t;

static void hmac_init(mmt_hmac_ctx_t *ctx, const uint8_t *key, size_t key_len) {
    uint8_t block[MMT_SHA256_BLOCK_LEN] = {0};
    if (key_len > MMT_SHA256_BLOCK_LEN) {
        /* RFC 2104 §2: a key longer than the block is hashed first */
        mmt_sha256_init(&ctx->inner);
        mmt_sha256_update(&ctx->inner, key, key_len);
        mmt_sha256_final(&ctx->inner, block);
    } else if (key_len > 0) {
        memcpy(block, key, key_len);
    }
    for (unsigned i = 0; i < MMT_SHA256_BLOCK_LEN; i++) {
        block[i] ^= 0x36; /* ipad */
    }
    mmt_sha256_init(&ctx->inner);
    mmt_sha256_update(&ctx->inner, block, sizeof block);
    for (unsigned i = 0; i < MMT_SHA256_BLOCK_LEN; i++) {
        block[i] ^= 0x36 ^ 0x5c; /* ipad -> opad */
    }
    mmt_sha256_init(&ctx->outer);
    mmt_sha256_update(&ctx->outer, block, sizeof block);
}

static void hmac_final(mmt_hmac_ctx_t *ctx, uint8_t out[MMT_HMAC_SHA256_LEN]) {
    uint8_t inner[MMT_SHA256_DIGEST_LEN];
    mmt_sha256_final(&ctx->inner, inner);
    mmt_sha256_update(&ctx->outer, inner, sizeof inner);
    mmt_sha256_final(&ctx->outer, out);
}

void mmt_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                     uint8_t out[MMT_HMAC_SHA256_LEN]) {
    mmt_hmac_ctx_t ctx;
    hmac_init(&ctx, key, key_len);
    mmt_sha256_update(&ctx.inner, msg, msg_len);
    hmac_final(&ctx, out);
}

/* ---- HKDF (RFC 5869) and HKDF-Expand-Label (RFC 8446 §7.1) -------------- */

void mmt_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                      uint8_t prk[MMT_HMAC_SHA256_LEN]) {
    mmt_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int mmt_hkdf_expand(const uint8_t prk[MMT_HMAC_SHA256_LEN], const uint8_t *info, size_t info_len,
                    uint8_t *okm, size_t okm_len) {
    if (okm_len > MMT_HKDF_SHA256_MAX_OKM) {
        return -1;
    }
    uint8_t t[MMT_HMAC_SHA256_LEN] = {0};
    size_t t_len = 0; /* T(0) is the empty string */
    size_t done = 0;
    for (uint8_t counter = 1; done < okm_len; counter++) {
        mmt_hmac_ctx_t ctx;
        hmac_init(&ctx, prk, MMT_HMAC_SHA256_LEN);
        mmt_sha256_update(&ctx.inner, t, t_len);
        if (info_len > 0) { /* `info` may be NULL when empty */
            mmt_sha256_update(&ctx.inner, info, info_len);
        }
        mmt_sha256_update(&ctx.inner, &counter, 1);
        hmac_final(&ctx, t);
        t_len = sizeof t;
        size_t n = okm_len - done < t_len ? okm_len - done : t_len;
        memcpy(okm + done, t, n);
        done += n;
    }
    return 0;
}

int mmt_hkdf_expand_label(const uint8_t secret[MMT_HMAC_SHA256_LEN], const char *label, uint8_t *out,
                          size_t out_len) {
    static const char prefix[] = "tls13 ";
    const size_t prefix_len = sizeof prefix - 1;
    size_t label_len = strlen(label);
    if (label_len > MMT_HKDF_MAX_LABEL || out_len > 0xffffu) {
        return -1;
    }
    /* struct HkdfLabel { uint16 length; opaque label<7..255>;
     *                    opaque context<0..255>; } — context empty */
    uint8_t info[2 + 1 + 255 + 1];
    size_t n = 0;
    info[n++] = (uint8_t) (out_len >> 8);
    info[n++] = (uint8_t) out_len;
    info[n++] = (uint8_t) (prefix_len + label_len);
    memcpy(info + n, prefix, prefix_len);
    n += prefix_len;
    memcpy(info + n, label, label_len);
    n += label_len;
    info[n++] = 0;
    return mmt_hkdf_expand(secret, info, n, out, out_len);
}

/* ---- AES-128 (FIPS 197), encryption direction ---------------------------- */

/* FIPS 197 Figure 7: the S-box. */
static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

/* Multiplication by x in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (§4.2.1). */
static inline uint8_t aes_xtime(uint8_t b) {
    return (uint8_t) ((b << 1) ^ ((b >> 7) * 0x1b));
}

void mmt_aes128_init(mmt_aes128_ctx_t *ctx, const uint8_t key[MMT_AES128_KEY_LEN]) {
    uint8_t *w = ctx->round_keys;
    uint8_t rcon = 0x01;
    memcpy(w, key, MMT_AES128_KEY_LEN);
    for (unsigned i = MMT_AES128_KEY_LEN; i < sizeof ctx->round_keys; i += 4) {
        uint8_t t[4] = {w[i - 4], w[i - 3], w[i - 2], w[i - 1]};
        if (i % MMT_AES128_KEY_LEN == 0) {
            /* SubWord(RotWord(temp)) xor Rcon[i/Nk] */
            uint8_t first = t[0];
            t[0] = (uint8_t) (aes_sbox[t[1]] ^ rcon);
            t[1] = aes_sbox[t[2]];
            t[2] = aes_sbox[t[3]];
            t[3] = aes_sbox[first];
            rcon = aes_xtime(rcon);
        }
        for (unsigned j = 0; j < 4; j++) {
            w[i + j] = (uint8_t) (w[i + j - MMT_AES128_KEY_LEN] ^ t[j]);
        }
    }
}

/* SubBytes then ShiftRows (§5.1.1-5.1.2); the state is column-major,
 * s[4c + r]. */
static void aes_sub_shift(uint8_t s[MMT_AES_BLOCK_LEN]) {
    uint8_t t[MMT_AES_BLOCK_LEN];
    for (unsigned c = 0; c < 4; c++) {
        for (unsigned r = 0; r < 4; r++) {
            t[4 * c + r] = aes_sbox[s[4 * ((c + r) & 3) + r]];
        }
    }
    memcpy(s, t, sizeof t);
}

/* MixColumns (§5.1.3). */
static void aes_mix_columns(uint8_t s[MMT_AES_BLOCK_LEN]) {
    for (unsigned c = 0; c < 4; c++) {
        uint8_t *col = s + 4 * c;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        uint8_t all = (uint8_t) (a0 ^ a1 ^ a2 ^ a3);
        col[0] = (uint8_t) (a0 ^ all ^ aes_xtime((uint8_t) (a0 ^ a1)));
        col[1] = (uint8_t) (a1 ^ all ^ aes_xtime((uint8_t) (a1 ^ a2)));
        col[2] = (uint8_t) (a2 ^ all ^ aes_xtime((uint8_t) (a2 ^ a3)));
        col[3] = (uint8_t) (a3 ^ all ^ aes_xtime((uint8_t) (a3 ^ a0)));
    }
}

static void aes_add_round_key(uint8_t s[MMT_AES_BLOCK_LEN], const uint8_t *rk) {
    for (unsigned i = 0; i < MMT_AES_BLOCK_LEN; i++) {
        s[i] ^= rk[i];
    }
}

void mmt_aes128_encrypt_block(const mmt_aes128_ctx_t *ctx, const uint8_t in[MMT_AES_BLOCK_LEN],
                              uint8_t out[MMT_AES_BLOCK_LEN]) {
    uint8_t s[MMT_AES_BLOCK_LEN];
    memcpy(s, in, sizeof s);
    aes_add_round_key(s, ctx->round_keys);
    for (unsigned round = 1; round <= 10; round++) {
        aes_sub_shift(s);
        if (round < 10) {
            aes_mix_columns(s);
        }
        aes_add_round_key(s, ctx->round_keys + MMT_AES_BLOCK_LEN * round);
    }
    memcpy(out, s, sizeof s);
}

/* ---- AES-128-GCM (NIST SP 800-38D) --------------------------------------- */

/* X <- X * Y in GF(2^128) with the GCM bit order (SP 800-38D §6.3,
 * Algorithm 1). */
static void gcm_mul(uint8_t x[MMT_AES_BLOCK_LEN], const uint8_t y[MMT_AES_BLOCK_LEN]) {
    uint8_t z[MMT_AES_BLOCK_LEN] = {0};
    uint8_t v[MMT_AES_BLOCK_LEN];
    memcpy(v, y, sizeof v);
    for (unsigned i = 0; i < 128; i++) {
        if (x[i >> 3] & (0x80u >> (i & 7))) {
            for (unsigned j = 0; j < MMT_AES_BLOCK_LEN; j++) {
                z[j] ^= v[j];
            }
        }
        uint8_t lsb = v[MMT_AES_BLOCK_LEN - 1] & 1u;
        for (unsigned j = MMT_AES_BLOCK_LEN - 1; j > 0; j--) {
            v[j] = (uint8_t) ((v[j] >> 1) | (v[j - 1] << 7));
        }
        v[0] >>= 1;
        if (lsb) {
            v[0] ^= 0xe1; /* R = 11100001 || 0^120 */
        }
    }
    memcpy(x, z, sizeof z);
}

/* GHASH over `data`, zero-padded to a whole number of blocks (§6.4). */
static void gcm_ghash(uint8_t y[MMT_AES_BLOCK_LEN], const uint8_t h[MMT_AES_BLOCK_LEN], const uint8_t *data,
                      size_t len) {
    while (len > 0) {
        size_t n = len < MMT_AES_BLOCK_LEN ? len : MMT_AES_BLOCK_LEN;
        for (size_t i = 0; i < n; i++) {
            y[i] ^= data[i];
        }
        gcm_mul(y, h);
        data += n;
        len -= n;
    }
}

static void gcm_store_be64(uint8_t *p, uint64_t v) {
    for (unsigned i = 0; i < 8; i++) {
        p[i] = (uint8_t) (v >> (56 - 8 * i));
    }
}

/* inc32 (§6.2): the low 32 bits of the counter block, modulo 2^32. */
static void gcm_inc32(uint8_t cb[MMT_AES_BLOCK_LEN]) {
    for (unsigned i = MMT_AES_BLOCK_LEN; i > MMT_AES_BLOCK_LEN - 4; i--) {
        if (++cb[i - 1] != 0) {
            break;
        }
    }
}

int mmt_aes128_gcm_open(const mmt_aes128_ctx_t *ctx, const uint8_t iv[MMT_GCM_IV_LEN],
                        const mmt_aead_io_t *io) {
    if (io->in_len < MMT_GCM_TAG_LEN) {
        return -1;
    }
    const size_t ct_len = io->in_len - MMT_GCM_TAG_LEN;
    uint8_t h[MMT_AES_BLOCK_LEN] = {0};
    uint8_t j0[MMT_AES_BLOCK_LEN];
    uint8_t s[MMT_AES_BLOCK_LEN] = {0};
    uint8_t block[MMT_AES_BLOCK_LEN];

    mmt_aes128_encrypt_block(ctx, h, h); /* H = CIPH_K(0^128) */
    memcpy(j0, iv, MMT_GCM_IV_LEN);      /* J0 = IV || 0^31 || 1 */
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;

    /* S = GHASH_H(A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64) */
    gcm_ghash(s, h, io->aad, io->aad_len);
    gcm_ghash(s, h, io->in, ct_len);
    gcm_store_be64(block, (uint64_t) io->aad_len * 8u);
    gcm_store_be64(block + 8, (uint64_t) ct_len * 8u);
    gcm_ghash(s, h, block, sizeof block);

    /* T = MSB_t(GCTR_K(J0, S)); compared over every byte */
    mmt_aes128_encrypt_block(ctx, j0, block);
    uint8_t diff = 0;
    for (unsigned i = 0; i < MMT_GCM_TAG_LEN; i++) {
        diff |= (uint8_t) (block[i] ^ s[i] ^ io->in[ct_len + i]);
    }
    if (diff != 0) {
        return -1;
    }

    /* P = GCTR_K(inc32(J0), C) */
    uint8_t cb[MMT_AES_BLOCK_LEN];
    memcpy(cb, j0, sizeof cb);
    for (size_t off = 0; off < ct_len; off += MMT_AES_BLOCK_LEN) {
        gcm_inc32(cb);
        mmt_aes128_encrypt_block(ctx, cb, block);
        size_t n = ct_len - off < MMT_AES_BLOCK_LEN ? ct_len - off : MMT_AES_BLOCK_LEN;
        for (size_t i = 0; i < n; i++) {
            io->out[off + i] = (uint8_t) (io->in[off + i] ^ block[i]);
        }
    }
    return 0;
}
