/*
 * mmt_crypto.h — in-tree HMAC-SHA256, HKDF, AES-128 and AES-128-GCM for the
 * TCP/IP plugin (issue #570).
 *
 * The SDK links no third-party library (issue #495, tools/ci/build-deps.txt),
 * so the primitives that remove the protection of a QUIC Initial packet
 * (RFC 9001 §5) are written here, on top of the SHA-256 of mmt_sha256.h:
 *
 *   HMAC-SHA256          RFC 2104 (test vectors: RFC 4231)
 *   HKDF-Extract/Expand  RFC 5869 (test vectors: RFC 5869 Appendix A)
 *   HKDF-Expand-Label    RFC 8446 §7.1, with an empty context
 *   AES-128              FIPS 197, the encryption direction only — the one
 *                        that CTR mode, GCM and QUIC header protection use
 *   AES-128-GCM          NIST SP 800-38D, authenticated decryption with a
 *                        96-bit IV and a 128-bit tag
 *
 * Internal to the plugin: built with -fvisibility=hidden, never exported or
 * installed. Not constant-time: every key the plugin derives with it comes
 * from public data (the QUIC Initial keys are a function of the client's
 * Destination Connection ID, RFC 9001 §5.2), so no secret is protected.
 * Inputs may sit at any alignment; nothing here allocates.
 */
#ifndef MMT_CRYPTO_H
#define MMT_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Bytes of an HMAC-SHA256 output and of an HKDF-SHA256 pseudorandom key. */
#define MMT_HMAC_SHA256_LEN 32u
/** Longest HKDF-Expand output: 255 blocks of the hash (RFC 5869 §2.3). */
#define MMT_HKDF_SHA256_MAX_OKM (255u * MMT_HMAC_SHA256_LEN)
/** Longest HKDF-Expand-Label label: 255 bytes minus the "tls13 " prefix. */
#define MMT_HKDF_MAX_LABEL 249u
/** Bytes of an AES block and of an AES-128 key. */
#define MMT_AES_BLOCK_LEN 16u
#define MMT_AES128_KEY_LEN 16u
/** Bytes of the GCM IV (96 bits, SP 800-38D §5.2.1.1) and tag. */
#define MMT_GCM_IV_LEN 12u
#define MMT_GCM_TAG_LEN 16u

/** An expanded AES-128 key: 11 round keys (FIPS 197 §5.2). */
typedef struct mmt_aes128_ctx {
    uint8_t round_keys[176];
} mmt_aes128_ctx_t;

/** The buffers of one authenticated decryption. `in` holds the ciphertext
 *  followed by the 16-byte tag; `out` receives `in_len - 16` plaintext
 *  bytes and must not overlap `in`. */
typedef struct mmt_aead_io {
    const uint8_t *aad;
    size_t aad_len;
    const uint8_t *in;
    size_t in_len;
    uint8_t *out;
} mmt_aead_io_t;

/** HMAC-SHA256 of `msg` under `key` (any length) into `out`. */
void mmt_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                     uint8_t out[MMT_HMAC_SHA256_LEN]);

/** HKDF-Extract (RFC 5869 §2.2): `prk` = HMAC-SHA256(salt, ikm). */
void mmt_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                      uint8_t prk[MMT_HMAC_SHA256_LEN]);

/** HKDF-Expand (RFC 5869 §2.3): `okm_len` bytes of output keying material.
 *  Returns 0, or -1 (nothing written) when `okm_len` exceeds
 *  MMT_HKDF_SHA256_MAX_OKM. */
int mmt_hkdf_expand(const uint8_t prk[MMT_HMAC_SHA256_LEN], const uint8_t *info, size_t info_len,
                    uint8_t *okm, size_t okm_len);

/** HKDF-Expand-Label (RFC 8446 §7.1) with an empty context: `out_len`
 *  bytes derived from `secret` under the NUL-terminated `label` (without
 *  its "tls13 " prefix). Returns 0, or -1 (nothing written) when the label
 *  is longer than MMT_HKDF_MAX_LABEL or `out_len` exceeds 65535 or
 *  MMT_HKDF_SHA256_MAX_OKM. */
int mmt_hkdf_expand_label(const uint8_t secret[MMT_HMAC_SHA256_LEN], const char *label, uint8_t *out,
                          size_t out_len);

/** Expands a 16-byte AES-128 key (FIPS 197 §5.2). */
void mmt_aes128_init(mmt_aes128_ctx_t *ctx, const uint8_t key[MMT_AES128_KEY_LEN]);

/** Encrypts one 16-byte block (FIPS 197 §5.1); `in` and `out` may alias. */
void mmt_aes128_encrypt_block(const mmt_aes128_ctx_t *ctx, const uint8_t in[MMT_AES_BLOCK_LEN],
                              uint8_t out[MMT_AES_BLOCK_LEN]);

/** AES-128-GCM authenticated decryption (SP 800-38D §7.2) of `io->in`
 *  under the 96-bit `iv`. Returns 0 and writes the plaintext when the tag
 *  verifies; -1 when it does not or `io->in_len` is shorter than the tag,
 *  and then writes nothing. */
int mmt_aes128_gcm_open(const mmt_aes128_ctx_t *ctx, const uint8_t iv[MMT_GCM_IV_LEN],
                        const mmt_aead_io_t *io);

#ifdef __cplusplus
}
#endif

#endif /* MMT_CRYPTO_H */
