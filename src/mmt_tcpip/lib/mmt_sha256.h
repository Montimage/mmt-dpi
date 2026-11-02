/*
 * mmt_sha256.h — in-tree SHA-256 (FIPS 180-4 §6.2) for the TCP/IP plugin
 * (issue #569).
 *
 * The SDK links no third-party library (issue #495, tools/ci/build-deps.txt),
 * so the digest the JA4 fingerprint truncates (tls_client_hello.c) is
 * computed here. The streaming interface is the building block a later
 * HMAC/HKDF (QUIC Initial keys, issue #570) needs as well. Internal to the
 * plugin: built with -fvisibility=hidden, never exported or installed.
 *
 * Inputs may sit at any alignment; the digest is written big-endian as FIPS
 * 180-4 specifies. Not constant-time with respect to the message length,
 * which is public in every use the plugin makes of it.
 */
#ifndef MMT_SHA256_H
#define MMT_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Bytes of a SHA-256 digest. */
#define MMT_SHA256_DIGEST_LEN 32u
/** Bytes of a SHA-256 message block. */
#define MMT_SHA256_BLOCK_LEN 64u

/** A digest being computed. */
typedef struct mmt_sha256_ctx {
    uint32_t state[8];
    uint64_t total;                      /**< message bytes absorbed */
    uint8_t block[MMT_SHA256_BLOCK_LEN]; /**< the pending partial block */
    uint32_t used;                       /**< bytes of `block` in use */
} mmt_sha256_ctx_t;

/** Starts a digest (FIPS 180-4 §5.3.3 initial hash value). */
void mmt_sha256_init(mmt_sha256_ctx_t *ctx);

/** Absorbs `len` bytes of `data` (NULL allowed when `len` is 0). */
void mmt_sha256_update(mmt_sha256_ctx_t *ctx, const void *data, size_t len);

/** Pads, writes the 32-byte digest to `out` and wipes the context. */
void mmt_sha256_final(mmt_sha256_ctx_t *ctx, uint8_t out[MMT_SHA256_DIGEST_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* MMT_SHA256_H */
