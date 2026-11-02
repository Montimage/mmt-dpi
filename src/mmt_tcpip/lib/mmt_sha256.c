/*
 * mmt_sha256.c — SHA-256 per FIPS 180-4 §6.2 (issue #569). API: mmt_sha256.h.
 */
#include <string.h>

#include "mmt_sha256.h"

/* FIPS 180-4 §4.2.2: the first 32 bits of the fractional parts of the cube
 * roots of the first 64 primes. */
static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline uint32_t sha256_rotr(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

static inline uint32_t sha256_load_be32(const uint8_t *p) {
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

static inline void sha256_store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t) (v >> 24);
    p[1] = (uint8_t) (v >> 16);
    p[2] = (uint8_t) (v >> 8);
    p[3] = (uint8_t) v;
}

/* FIPS 180-4 §6.2.2: one 512-bit block into the hash state. */
static void sha256_compress(uint32_t state[8], const uint8_t *block) {
    uint32_t w[64];
    for (unsigned t = 0; t < 16; t++) {
        w[t] = sha256_load_be32(block + 4 * t);
    }
    for (unsigned t = 16; t < 64; t++) {
        uint32_t s0 = sha256_rotr(w[t - 15], 7) ^ sha256_rotr(w[t - 15], 18) ^ (w[t - 15] >> 3);
        uint32_t s1 = sha256_rotr(w[t - 2], 17) ^ sha256_rotr(w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (unsigned t = 0; t < 64; t++) {
        uint32_t s1 = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + ch + sha256_k[t] + w[t];
        uint32_t s0 = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void mmt_sha256_init(mmt_sha256_ctx_t *ctx) {
    /* FIPS 180-4 §5.3.3 */
    static const uint32_t h0[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    memcpy(ctx->state, h0, sizeof h0);
    ctx->total = 0;
    ctx->used = 0;
}

void mmt_sha256_update(mmt_sha256_ctx_t *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *) data;
    ctx->total += len;
    if (ctx->used > 0) {
        size_t take = MMT_SHA256_BLOCK_LEN - ctx->used;
        if (take > len) {
            take = len;
        }
        memcpy(ctx->block + ctx->used, p, take);
        ctx->used += (uint32_t) take;
        p += take;
        len -= take;
        if (ctx->used < MMT_SHA256_BLOCK_LEN) {
            return;
        }
        sha256_compress(ctx->state, ctx->block);
        ctx->used = 0;
    }
    for (; len >= MMT_SHA256_BLOCK_LEN; p += MMT_SHA256_BLOCK_LEN, len -= MMT_SHA256_BLOCK_LEN) {
        sha256_compress(ctx->state, p);
    }
    if (len > 0) {
        memcpy(ctx->block, p, len);
        ctx->used = (uint32_t) len;
    }
}

void mmt_sha256_final(mmt_sha256_ctx_t *ctx, uint8_t out[MMT_SHA256_DIGEST_LEN]) {
    /* FIPS 180-4 §5.1.1: a 1 bit, zeros to 448 mod 512, the bit length. */
    uint64_t bits = ctx->total * 8u;
    ctx->block[ctx->used++] = 0x80;
    if (ctx->used > MMT_SHA256_BLOCK_LEN - 8) {
        memset(ctx->block + ctx->used, 0, MMT_SHA256_BLOCK_LEN - ctx->used);
        sha256_compress(ctx->state, ctx->block);
        ctx->used = 0;
    }
    memset(ctx->block + ctx->used, 0, MMT_SHA256_BLOCK_LEN - 8 - ctx->used);
    sha256_store_be32(ctx->block + MMT_SHA256_BLOCK_LEN - 8, (uint32_t) (bits >> 32));
    sha256_store_be32(ctx->block + MMT_SHA256_BLOCK_LEN - 4, (uint32_t) bits);
    sha256_compress(ctx->state, ctx->block);
    for (unsigned i = 0; i < 8; i++) {
        sha256_store_be32(out + 4 * i, ctx->state[i]);
    }
    memset(ctx, 0, sizeof *ctx);
}
