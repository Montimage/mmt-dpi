/*
 * test_quic_initial_decrypt_unit.c — QUIC v1/v2 client Initial decryption
 * and the crypto under it (issue #570, F-BUG-307 part 1).
 *
 * mmt_sha256.c, mmt_crypto.c and protocols/quic_ietf_initial.c are included
 * directly, so their static helpers are reachable: the test seals packets
 * with the same GHASH/CTR internals the decryptor opens them with.
 *
 *   primitives  AES-128 (FIPS 197 Appendix B and C.1), HMAC-SHA256 (RFC 4231
 *               test cases 1-7), HKDF (RFC 5869 A.1-A.3, the 255-block
 *               limit), HKDF-Expand-Label limits, AES-128-GCM (the GCM
 *               specification's test cases 1-4, as published with NIST
 *               SP 800-38D) and every tag/length refusal;
 *   vectors     every A.1 row of RFC 9001 and RFC 9369 (initial secret,
 *               client and server secrets, key, iv, hp), the A.2 sample and
 *               mask, and the A.2 client Initial of both RFCs decrypted end
 *               to end (A.3 server Initial, A.4 Retry and A.5 ChaCha20 are
 *               not client Initials: out of scope, docs/DECISIONS.md);
 *   malformed   every prefix of both A.2 packets, each in a heap buffer of
 *               exactly its length (also at an odd address), datagrams
 *               below 1,200 bytes, connection IDs of 21 bytes, overrunning
 *               token and Length fields, a Length too short for the
 *               header-protection sample, an output buffer one byte short,
 *               flipped tag and ciphertext bytes, a 1,200-byte Initial of
 *               filler (as in the accuracy corpus), reserved bits set under
 *               a valid tag, short headers, other versions and packet types.
 *
 * Under SANITIZE=asan any read past a buffer aborts the run.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mmt_sha256.c"
#include "mmt_crypto.c"
#include "protocols/quic_ietf_initial.c"

static int g_failures;
static int g_checks;

#define CHECK(cond, msg)                                                                                     \
    do {                                                                                                     \
        g_checks++;                                                                                          \
        if (!(cond)) {                                                                                       \
            printf("  FAIL: %s (line %d)\n", (msg), __LINE__);                                               \
            g_failures++;                                                                                    \
        }                                                                                                    \
    } while (0)

/* Decodes the hex string `s` into `out` (at most `cap` bytes); returns the
 * byte count. Exits on a malformed vector. */
static size_t unhex(const char *s, uint8_t *out, size_t cap) {
    size_t n = 0;
    while (s[0] != '\0') {
        unsigned v;
        if (s[1] == '\0' || n >= cap || sscanf(s, "%2x", &v) != 1) {
            fprintf(stderr, "bad test vector\n");
            exit(2);
        }
        out[n++] = (uint8_t) v;
        s += 2;
    }
    return n;
}

/* `len` bytes of `src` in a heap buffer of exactly that size, at an odd
 * address when `odd` is set. *block receives the pointer to free(). */
static uint8_t *exact_copy(const uint8_t *src, size_t len, int odd, uint8_t **block) {
    *block = malloc(len + (odd ? 1 : 0) + (len == 0 && !odd ? 1 : 0));
    if (*block == NULL) {
        perror("malloc");
        exit(2);
    }
    uint8_t *p = *block + (odd ? 1 : 0);
    if (len) {
        memcpy(p, src, len);
    }
    return p;
}

static int hex_equal(const uint8_t *got, size_t len, const char *want_hex) {
    uint8_t want[256];
    size_t n = unhex(want_hex, want, sizeof want);
    return n == len && memcmp(got, want, len) == 0;
}

#include "quic_initial_vectors.h"

/* RFC 9001 A.1 / RFC 9369 A.1: the client's Destination Connection ID. */
static const uint8_t RFC_DCID[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
#define RFC_FRAMES_LEN 1162u
#define RFC_PACKET_LEN 1200u

/* ---- primitives ---------------------------------------------------------- */

static void test_aes(void) {
    static const struct {
        const char *key, *pt, *ct;
    } kat[] = {
        /* FIPS 197 Appendix B */
        {"2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734", "3925841d02dc09fbdc118597196a0b32"},
        /* FIPS 197 Appendix C.1 */
        {"000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"},
    };
    for (size_t i = 0; i < sizeof kat / sizeof kat[0]; i++) {
        uint8_t key[16], blk[16];
        mmt_aes128_ctx_t ctx;
        unhex(kat[i].key, key, sizeof key);
        unhex(kat[i].pt, blk, sizeof blk);
        mmt_aes128_init(&ctx, key);
        mmt_aes128_encrypt_block(&ctx, blk, blk); /* in and out alias */
        CHECK(hex_equal(blk, sizeof blk, kat[i].ct), "AES-128 known answer (FIPS 197)");
    }
}

static void test_hmac(void) {
    /* RFC 4231 §4.2-4.8: key, data, HMAC-SHA-256 (case 5 truncated to 128 bits) */
    static const struct {
        const char *key, *data, *mac;
    } tc[] = {
        {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
        {"4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
        {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
         "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"},
        {"0102030405060708090a0b0c0d0e0f10111213141516171819",
         "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
         "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"},
        {"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "546573742057697468205472756e636174696f6e",
         "a3b6167473100ee06e0c796c2955552b"},
        {NULL, "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d20"
               "48617368204b6579204669727374",
         "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"},
        {NULL, "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d"
               "73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174"
               "612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e"
               "6720757365642062792074686520484d414320616c676f726974686d2e",
         "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"},
    };
    for (size_t i = 0; i < sizeof tc / sizeof tc[0]; i++) {
        uint8_t key[131], data[160], mac[32];
        size_t key_len;
        if (tc[i].key != NULL) {
            key_len = unhex(tc[i].key, key, sizeof key);
        } else {
            /* cases 6 and 7: a 131-byte key, longer than the block */
            key_len = sizeof key;
            memset(key, 0xaa, key_len);
        }
        size_t data_len = unhex(tc[i].data, data, sizeof data);
        mmt_hmac_sha256(key, key_len, data, data_len, mac);
        size_t want = strlen(tc[i].mac) / 2;
        CHECK(hex_equal(mac, want, tc[i].mac), "HMAC-SHA256 (RFC 4231)");
    }
}

static void test_hkdf(void) {
    /* RFC 5869 A.1-A.3 */
    static const struct {
        const char *ikm, *salt, *info, *prk, *okm;
    } tc[] = {
        {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9",
         "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"},
        {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
         "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
         "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
         "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
         "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
         "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
         "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
         "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09"
         "da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"},
        {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "",
         "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
         "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"},
    };
    for (size_t i = 0; i < sizeof tc / sizeof tc[0]; i++) {
        uint8_t ikm[80], salt[80], info[80], prk[32], okm[82];
        size_t ikm_len = unhex(tc[i].ikm, ikm, sizeof ikm);
        size_t salt_len = unhex(tc[i].salt, salt, sizeof salt);
        size_t info_len = unhex(tc[i].info, info, sizeof info);
        size_t okm_len = strlen(tc[i].okm) / 2;
        mmt_hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
        CHECK(hex_equal(prk, sizeof prk, tc[i].prk), "HKDF-Extract (RFC 5869)");
        CHECK(mmt_hkdf_expand(prk, info, info_len, okm, okm_len) == 0 && hex_equal(okm, okm_len, tc[i].okm),
              "HKDF-Expand (RFC 5869)");
    }

    /* the 255-block limit of RFC 5869 §2.3 */
    static uint8_t big[MMT_HKDF_SHA256_MAX_OKM + 1];
    uint8_t prk[32];
    memset(prk, 0x11, sizeof prk);
    memset(big, 0xee, sizeof big);
    CHECK(mmt_hkdf_expand(prk, NULL, 0, big, sizeof big) == -1 && big[0] == 0xee,
          "HKDF-Expand refuses 255 * 32 + 1 bytes and writes nothing");
    CHECK(mmt_hkdf_expand(prk, NULL, 0, big, MMT_HKDF_SHA256_MAX_OKM) == 0 && big[MMT_HKDF_SHA256_MAX_OKM] == 0xee,
          "HKDF-Expand produces exactly 255 * 32 bytes");
    CHECK(mmt_hkdf_expand(prk, NULL, 0, big, 0) == 0, "HKDF-Expand of zero bytes");

    /* HKDF-Expand-Label limits (RFC 8446 §7.1) */
    char label[MMT_HKDF_MAX_LABEL + 2];
    memset(label, 'a', sizeof label - 1);
    label[sizeof label - 1] = '\0';
    big[0] = 0xee;
    CHECK(mmt_hkdf_expand_label(prk, label, big, 16) == -1 && big[0] == 0xee,
          "HKDF-Expand-Label refuses a 250-byte label");
    label[MMT_HKDF_MAX_LABEL] = '\0';
    CHECK(mmt_hkdf_expand_label(prk, label, big, 16) == 0, "HKDF-Expand-Label takes a 249-byte label");
    CHECK(mmt_hkdf_expand_label(prk, "x", big, 0x10000) == -1, "HKDF-Expand-Label refuses 65536 bytes");
    CHECK(mmt_hkdf_expand_label(prk, "x", big, MMT_HKDF_SHA256_MAX_OKM + 1) == -1,
          "HKDF-Expand-Label refuses more than 255 blocks");
}

/* The GCM specification's AES-128 test cases 1-4 (96-bit IV). */
static void test_gcm(void) {
    static const struct {
        const char *key, *iv, *pt, *aad, *ct, *tag;
    } tc[] = {
        {"00000000000000000000000000000000", "000000000000000000000000", "", "", "",
         "58e2fccefa7e3061367f1d57a4e7455a"},
        {"00000000000000000000000000000000", "000000000000000000000000", "00000000000000000000000000000000", "",
         "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"},
        {"feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
         "b16aedf5aa0de657ba637b391aafd255",
         "",
         "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa05"
         "1ba30b396a0aac973d58e091473f5985",
         "4d5c2af327cd64a62cf35abd2ba6fab4"},
        {"feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
         "b16aedf5aa0de657ba637b39",
         "feedfacedeadbeeffeedfacedeadbeefabaddad2",
         "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa05"
         "1ba30b396a0aac973d58e091",
         "5bc94fbc3221a5db94fae95ae7121a47"},
    };
    for (size_t i = 0; i < sizeof tc / sizeof tc[0]; i++) {
        uint8_t key[16], iv[12], pt[64], aad[20], in[80], out[64];
        mmt_aes128_ctx_t ctx;
        unhex(tc[i].key, key, sizeof key);
        unhex(tc[i].iv, iv, sizeof iv);
        size_t pt_len = unhex(tc[i].pt, pt, sizeof pt);
        size_t aad_len = unhex(tc[i].aad, aad, sizeof aad);
        size_t ct_len = unhex(tc[i].ct, in, sizeof in);
        unhex(tc[i].tag, in + ct_len, 16);
        mmt_aes128_init(&ctx, key);
        mmt_aead_io_t io = {aad, aad_len, in, ct_len + 16, out};
        CHECK(mmt_aes128_gcm_open(&ctx, iv, &io) == 0 && ct_len == pt_len && memcmp(out, pt, pt_len) == 0,
              "AES-128-GCM open (GCM test cases 1-4)");
        /* every flipped tag, ciphertext and AAD bit position class fails */
        in[ct_len + 15] ^= 0x01;
        memset(out, 0xee, sizeof out);
        CHECK(mmt_aes128_gcm_open(&ctx, iv, &io) == -1 && out[0] == 0xee, "AES-128-GCM: flipped tag refused");
        in[ct_len + 15] ^= 0x01;
        if (ct_len > 0) {
            in[0] ^= 0x80;
            CHECK(mmt_aes128_gcm_open(&ctx, iv, &io) == -1, "AES-128-GCM: flipped ciphertext refused");
            in[0] ^= 0x80;
        }
        if (aad_len > 0) {
            aad[aad_len - 1] ^= 0x01;
            CHECK(mmt_aes128_gcm_open(&ctx, iv, &io) == -1, "AES-128-GCM: flipped AAD refused");
            aad[aad_len - 1] ^= 0x01;
        }
        io.in_len = 15;
        CHECK(mmt_aes128_gcm_open(&ctx, iv, &io) == -1, "AES-128-GCM: input shorter than the tag refused");
    }
}

/* ---- sealing, for packets the RFCs do not publish ------------------------ */

/* AES-128-GCM seal (SP 800-38D §7.1) over the decryptor's own internals:
 * `out` receives `len` ciphertext bytes then the tag. */
static void gcm_seal(const mmt_aes128_ctx_t *ctx, const uint8_t iv[12], const uint8_t *aad, size_t aad_len,
                     const uint8_t *pt, size_t len, uint8_t *out) {
    uint8_t h[16] = {0}, j0[16], cb[16], ks[16], s[16] = {0}, lens[16];
    mmt_aes128_encrypt_block(ctx, h, h);
    memcpy(j0, iv, 12);
    memset(j0 + 12, 0, 3);
    j0[15] = 1;
    memcpy(cb, j0, 16);
    for (size_t off = 0; off < len; off += 16) {
        gcm_inc32(cb);
        mmt_aes128_encrypt_block(ctx, cb, ks);
        for (size_t i = 0; i < 16 && off + i < len; i++) {
            out[off + i] = (uint8_t) (pt[off + i] ^ ks[i]);
        }
    }
    gcm_ghash(s, h, aad, aad_len);
    gcm_ghash(s, h, out, len);
    gcm_store_be64(lens, (uint64_t) aad_len * 8u);
    gcm_store_be64(lens + 8, (uint64_t) len * 8u);
    gcm_ghash(s, h, lens, 16);
    mmt_aes128_encrypt_block(ctx, j0, ks);
    for (unsigned i = 0; i < 16; i++) {
        out[len + i] = (uint8_t) (ks[i] ^ s[i]);
    }
}

/* What a sealed client Initial carries. `flags` is the unprotected first
 * byte: its low two bits give the packet number length. */
typedef struct initial_spec {
    uint32_t version;
    uint8_t flags;
    uint8_t dcid_len;
    uint8_t scid_len;
    size_t token_len;
    uint32_t pn;
    const uint8_t *frames;
    size_t frames_len;
} initial_spec_t;

/* Builds and protects a client Initial (RFC 9001 §5.3-5.4) into `out`;
 * returns its size. The DCID is RFC_DCID padded with 0xd0 bytes. */
static size_t seal_initial(const initial_spec_t *sp, uint8_t *out) {
    uint8_t dcid[QUIC_INITIAL_MAX_CID_LEN + 1];
    memset(dcid, 0xd0, sizeof dcid);
    memcpy(dcid, RFC_DCID, sp->dcid_len < 8 ? sp->dcid_len : 8);
    unsigned pn_len = (sp->flags & 3u) + 1u;
    size_t n = 0;
    out[n++] = sp->flags;
    for (int i = 3; i >= 0; i--) {
        out[n++] = (uint8_t) (sp->version >> (8 * i));
    }
    out[n++] = sp->dcid_len;
    memcpy(out + n, dcid, sp->dcid_len);
    n += sp->dcid_len;
    out[n++] = sp->scid_len;
    memset(out + n, 0xab, sp->scid_len);
    n += sp->scid_len;
    if (sp->token_len < 64) {
        out[n++] = (uint8_t) sp->token_len; /* 1-byte varint */
    } else {
        out[n++] = (uint8_t) (0x40 | (sp->token_len >> 8));
        out[n++] = (uint8_t) sp->token_len;
    }
    memset(out + n, 0x77, sp->token_len);
    n += sp->token_len;
    size_t length = pn_len + sp->frames_len + 16; /* 2-byte varint */
    out[n++] = (uint8_t) (0x40 | (length >> 8));
    out[n++] = (uint8_t) length;
    size_t pn_offset = n;
    for (unsigned i = 0; i < pn_len; i++) {
        out[n++] = (uint8_t) (sp->pn >> (8 * (pn_len - 1 - i)));
    }
    const quic_initial_version_t *ver = sp->version == QUIC_INITIAL_VERSION_2 ? &quic_initial_v2 : &quic_initial_v1;
    uint8_t key[16], iv[12], hp[16], mask[16];
    mmt_aes128_ctx_t aes;
    quic_initial_keys(ver, dcid, sp->dcid_len, key, iv, hp);
    for (unsigned i = 0; i < 4; i++) {
        iv[11 - i] ^= (uint8_t) (sp->pn >> (8 * i));
    }
    mmt_aes128_init(&aes, key);
    gcm_seal(&aes, iv, out, n, sp->frames, sp->frames_len, out + n);
    mmt_aes128_init(&aes, hp);
    mmt_aes128_encrypt_block(&aes, out + pn_offset + 4, mask);
    out[0] ^= mask[0] & 0x0f;
    for (unsigned i = 0; i < pn_len; i++) {
        out[pn_offset + i] ^= mask[1 + i];
    }
    return n + sp->frames_len + 16;
}

/* ---- RFC 9001 / RFC 9369 Appendix A ---------------------------------------- */

static void test_rfc_keys(void) {
    /* every A.1 row: initial secret, client and server secrets, key/iv/hp */
    static const struct {
        const char *name;
        const quic_initial_version_t *ver;
        const char *initial, *secret[2], *key[2], *iv[2], *hp[2];
    } tc[] = {
        {"RFC 9001 A.1", &quic_initial_v1, "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44",
         {"c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
          "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"},
         {"1f369613dd76d5467730efcbe3b1a22d", "cf3a5331653c364c88f0f379b6067e37"},
         {"fa044b2f42a3fd3b46fb255c", "0ac1493ca1905853b0bba03e"},
         {"9f50449e04a0e810283a1e9933adedd2", "c206b8d9b9f0f37644430b490eeaa314"}},
        {"RFC 9369 A.1", &quic_initial_v2, NULL,
         {NULL, NULL},
         {"8b1a0bc121284290a29e0971b5cd045d", "82db637861d55e1d011f19ea71d5d2a7"},
         {"91f73e2351d8fa91660e909f", "dd13c276499c0249d3310652"},
         {"45b95e15235d6f45a6b19cbcb0294ba9", "edf6d05c83121201b436e16877593c3a"}},
    };
    /* RFC 9369 A.1 prints only the first 16 bytes of its secrets */
    static const char *v2_prefix[3] = {"2062e8b3cd8d52092614b8071d0aa1fb", "14ec9d6eb9fd7af83bf5a668bc17a7e2",
                                       "0263db1782731bf4588e7e4d93b74639"};
    static const char *dir_label[2] = {"client in", "server in"};
    for (size_t i = 0; i < sizeof tc / sizeof tc[0]; i++) {
        const quic_initial_version_t *ver = tc[i].ver;
        uint8_t initial[32], secret[32], key[16], iv[12], hp[16];
        mmt_hkdf_extract(ver->salt, sizeof ver->salt, RFC_DCID, sizeof RFC_DCID, initial);
        CHECK(tc[i].initial ? hex_equal(initial, 32, tc[i].initial) : hex_equal(initial, 16, v2_prefix[0]),
              tc[i].name);
        for (int d = 0; d < 2; d++) {
            CHECK(mmt_hkdf_expand_label(initial, dir_label[d], secret, sizeof secret) == 0, tc[i].name);
            CHECK(tc[i].secret[d] ? hex_equal(secret, 32, tc[i].secret[d])
                                  : hex_equal(secret, 16, v2_prefix[1 + d]),
                  tc[i].name);
            CHECK(mmt_hkdf_expand_label(secret, ver->key_label, key, 16) == 0 && hex_equal(key, 16, tc[i].key[d]),
                  tc[i].name);
            CHECK(mmt_hkdf_expand_label(secret, ver->iv_label, iv, 12) == 0 && hex_equal(iv, 12, tc[i].iv[d]),
                  tc[i].name);
            CHECK(mmt_hkdf_expand_label(secret, ver->hp_label, hp, 16) == 0 && hex_equal(hp, 16, tc[i].hp[d]),
                  tc[i].name);
        }
        /* and the decryptor's own derivation agrees on the client side */
        quic_initial_keys(ver, RFC_DCID, sizeof RFC_DCID, key, iv, hp);
        CHECK(hex_equal(key, 16, tc[i].key[0]) && hex_equal(iv, 12, tc[i].iv[0]) && hex_equal(hp, 16, tc[i].hp[0]),
              tc[i].name);
    }
}

/* The A.2 plaintext: the CRYPTO frame, then PADDING to 1162 bytes. */
static void rfc_frames(const char *frame_hex, uint8_t frames[RFC_FRAMES_LEN]) {
    memset(frames, 0, RFC_FRAMES_LEN);
    unhex(frame_hex, frames, RFC_FRAMES_LEN);
}

static void test_rfc_initial(const char *name, uint32_t version, const char *frame_hex, const char *header_hex,
                             const char *protected_hex, const char *sample_hex, const char *mask_hex) {
    uint8_t packet[RFC_PACKET_LEN], frames[RFC_FRAMES_LEN], header[22], out[QUIC_INITIAL_OUT_BUFFER];
    CHECK(unhex(protected_hex, packet, sizeof packet) == RFC_PACKET_LEN, name);
    CHECK(unhex(header_hex, header, sizeof header) == sizeof header, name);
    rfc_frames(frame_hex, frames);

    /* A.2 header protection: mask = AES-ECB(hp, sample)[0..4] */
    uint8_t key[16], iv[12], hp[16], mask[16];
    mmt_aes128_ctx_t aes;
    quic_initial_keys(version == QUIC_INITIAL_VERSION_2 ? &quic_initial_v2 : &quic_initial_v1, RFC_DCID, 8, key,
                      iv, hp);
    mmt_aes128_init(&aes, hp);
    mmt_aes128_encrypt_block(&aes, packet + 22, mask);
    CHECK(hex_equal(packet + 22, 16, sample_hex) && hex_equal(mask, 5, mask_hex), name);

    for (int odd = 0; odd < 2; odd++) {
        uint8_t *block;
        const uint8_t *pkt = exact_copy(packet, sizeof packet, odd, &block);
        quic_initial_info_t info;
        memset(out, 0xee, sizeof out);
        CHECK(quic_ietf_initial_decrypt(pkt, RFC_PACKET_LEN, RFC_PACKET_LEN, out, sizeof out, &info) ==
                  QUIC_INITIAL_OK,
              name);
        CHECK(info.version == version && info.packet_number == 2 && info.pn_length == 4 && info.dcid_len == 8 &&
                  info.scid_len == 0 && info.header_len == 22 && info.payload_len == RFC_FRAMES_LEN &&
                  info.packet_len == RFC_PACKET_LEN,
              name);
        CHECK(memcmp(out, header, sizeof header) == 0, name);
        CHECK(memcmp(out + 22, frames, RFC_FRAMES_LEN) == 0, name);
        CHECK(out[22 + RFC_FRAMES_LEN] == 0xee, name); /* nothing past header + payload */
        free(block);
    }

    /* the sealing helper reproduces the published packet byte for byte */
    initial_spec_t sp = {version, header[0], 8, 0, 0, 2, frames, RFC_FRAMES_LEN};
    uint8_t sealed[RFC_PACKET_LEN];
    CHECK(seal_initial(&sp, sealed) == RFC_PACKET_LEN && memcmp(sealed, packet, RFC_PACKET_LEN) == 0, name);
}

/* ---- malformed and hostile Initials ---------------------------------------- */

static quic_initial_status_t decrypt_exact(const uint8_t *src, size_t len, size_t datagram_len, size_t out_cap) {
    uint8_t *block;
    const uint8_t *pkt = exact_copy(src, len, 1, &block);
    uint8_t *out = malloc(out_cap ? out_cap : 1);
    quic_initial_info_t info;
    if (out == NULL) {
        perror("malloc");
        exit(2);
    }
    quic_initial_status_t st = quic_ietf_initial_decrypt(pkt, len, datagram_len, out, out_cap, &info);
    free(out);
    free(block);
    return st;
}

static void test_prefixes(const char *protected_hex, const char *name) {
    uint8_t packet[RFC_PACKET_LEN];
    unhex(protected_hex, packet, sizeof packet);
    int ok = 1;
    /* each prefix in a heap buffer of exactly its length; the datagram
     * itself is 1200 bytes, so the parser's own bounds are what stop it */
    for (size_t len = 0; len < RFC_PACKET_LEN; len++) {
        if (decrypt_exact(packet, len, RFC_PACKET_LEN, QUIC_INITIAL_OUT_BUFFER) != QUIC_INITIAL_ERR_TRUNCATED) {
            printf("  prefix %zu not refused as truncated\n", len);
            ok = 0;
        }
    }
    CHECK(ok, name);
    CHECK(decrypt_exact(packet, RFC_PACKET_LEN, RFC_PACKET_LEN - 1, QUIC_INITIAL_OUT_BUFFER) ==
              QUIC_INITIAL_ERR_SHORT_DATAGRAM,
          "1199-byte datagram refused");
    CHECK(decrypt_exact(packet, RFC_PACKET_LEN, RFC_PACKET_LEN, RFC_PACKET_LEN - 17) == QUIC_INITIAL_ERR_BUFFER,
          "output one byte short of header + plaintext refused");
    CHECK(decrypt_exact(packet, RFC_PACKET_LEN, RFC_PACKET_LEN, RFC_PACKET_LEN - 16) == QUIC_INITIAL_OK,
          "output of exactly header + plaintext accepted");
}

static void test_malformed(void) {
    uint8_t packet[RFC_PACKET_LEN], frames[RFC_FRAMES_LEN], q[1400], out[QUIC_INITIAL_OUT_BUFFER];
    quic_initial_info_t info;
    unhex(RFC_V1_PROTECTED, packet, sizeof packet);
    rfc_frames(RFC_V1_CRYPTO_FRAME, frames);

    CHECK(quic_ietf_initial_decrypt(NULL, 1200, 1200, out, sizeof out, &info) == QUIC_INITIAL_ERR_ARG &&
              quic_ietf_initial_decrypt(packet, 1200, 1200, NULL, sizeof out, &info) == QUIC_INITIAL_ERR_ARG &&
              quic_ietf_initial_decrypt(packet, 1200, 1200, out, sizeof out, NULL) == QUIC_INITIAL_ERR_ARG,
          "NULL buffers refused");

    /* not a v1/v2 Initial */
    static const struct {
        size_t at;
        uint8_t value;
        const char *msg;
    } edits[] = {
        {0, 0x40, "short header refused"},
        {0, 0x80, "fixed bit clear refused"},
        {0, 0xe0, "v1 Handshake refused"},
        {0, 0xd0, "v1 with the v2 Initial type refused"},
        {4, 0x02, "version 2 with the v1 Initial type refused"},
        {1, 0xff, "version 0xff000001 refused"},
    };
    for (size_t i = 0; i < sizeof edits / sizeof edits[0]; i++) {
        memcpy(q, packet, RFC_PACKET_LEN);
        if (edits[i].at == 4) {
            q[1] = 0x6b, q[2] = 0x33, q[3] = 0x43, q[4] = 0xcf; /* v2; type bits stay 0b00 */
        } else {
            q[edits[i].at] = edits[i].value;
        }
        CHECK(decrypt_exact(q, RFC_PACKET_LEN, RFC_PACKET_LEN, sizeof out) == QUIC_INITIAL_ERR_NOT_INITIAL,
              edits[i].msg);
    }

    /* connection IDs longer than 20 bytes (RFC 9000 §17.2) */
    initial_spec_t sp = {QUIC_INITIAL_VERSION_1, 0xc3, 21, 0, 0, 2, frames, RFC_FRAMES_LEN - 13};
    size_t n = seal_initial(&sp, q);
    CHECK(n == RFC_PACKET_LEN && decrypt_exact(q, n, n, sizeof out) == QUIC_INITIAL_ERR_CID_LENGTH,
          "21-byte DCID refused");
    sp.dcid_len = 8;
    sp.scid_len = 21;
    n = seal_initial(&sp, q);
    CHECK(decrypt_exact(q, n, n, sizeof out) == QUIC_INITIAL_ERR_CID_LENGTH, "21-byte SCID refused");
    q[14] = 5; /* an SCID of 5 bytes the 15-byte buffer does not hold */
    CHECK(decrypt_exact(q, 15, n, sizeof out) == QUIC_INITIAL_ERR_TRUNCATED, "SCID past the buffer refused");

    /* 20-byte IDs, a token, 1- and 2-byte packet numbers all decrypt */
    sp = (initial_spec_t){QUIC_INITIAL_VERSION_1, 0xc0, 20, 20, 37, 0x7a, frames, RFC_FRAMES_LEN - 100};
    n = seal_initial(&sp, q); /* 1166 bytes, padded out to a 1200-byte datagram */
    CHECK(quic_ietf_initial_decrypt(q, n, RFC_PACKET_LEN, out, sizeof out, &info) == QUIC_INITIAL_OK && info.pn_length == 1 &&
              info.packet_number == 0x7a && info.dcid_len == 20 && info.scid_len == 20 &&
              info.header_len == 1 + 4 + 1 + 20 + 1 + 20 + 1 + 37 + 2 + 1 &&
              memcmp(out + info.header_len, frames, info.payload_len) == 0,
          "20-byte IDs with a token and a 1-byte packet number");
    sp = (initial_spec_t){QUIC_INITIAL_VERSION_2, 0xd1, 8, 4, 0, 0x1234, frames, RFC_FRAMES_LEN};
    n = seal_initial(&sp, q);
    CHECK(quic_ietf_initial_decrypt(q, n, n, out, sizeof out, &info) == QUIC_INITIAL_OK && info.pn_length == 2 &&
              info.packet_number == 0x1234 && info.version == QUIC_INITIAL_VERSION_2,
          "v2 with a 2-byte packet number");

    /* reserved bits set under a valid tag (RFC 9000 §17.2) */
    sp = (initial_spec_t){QUIC_INITIAL_VERSION_1, 0xc3 | 0x0c, 8, 0, 0, 2, frames, RFC_FRAMES_LEN};
    n = seal_initial(&sp, q);
    CHECK(decrypt_exact(q, n, n, sizeof out) == QUIC_INITIAL_ERR_RESERVED_BITS, "reserved bits set refused");

    /* coalesced: the packet ends at its Length, not at the buffer */
    memcpy(q, packet, RFC_PACKET_LEN);
    memset(q + RFC_PACKET_LEN, 0x5a, 100);
    CHECK(quic_ietf_initial_decrypt(q, RFC_PACKET_LEN + 100, RFC_PACKET_LEN + 100, out, sizeof out, &info) ==
                  QUIC_INITIAL_OK &&
              info.packet_len == RFC_PACKET_LEN,
          "Initial followed by another packet: packet_len stops at its Length");
    q[16] = 0x40, q[17] = 19; /* Length 19 < packet number + sample */
    CHECK(decrypt_exact(q, RFC_PACKET_LEN, RFC_PACKET_LEN, sizeof out) == QUIC_INITIAL_ERR_TRUNCATED,
          "Length too short for the header-protection sample refused");
    memcpy(q, packet, RFC_PACKET_LEN);
    q[15] = 0x44, q[16] = 0x00; /* token of 1024 bytes */
    CHECK(decrypt_exact(q, RFC_PACKET_LEN, RFC_PACKET_LEN, sizeof out) == QUIC_INITIAL_ERR_TRUNCATED,
          "token past the packet refused");
    memcpy(q, packet, RFC_PACKET_LEN);
    q[16] = 0x80, q[17] = 0x00, q[18] = 0x04, q[19] = 0xb0; /* 4-byte Length 1200 */
    CHECK(decrypt_exact(q, RFC_PACKET_LEN, RFC_PACKET_LEN, sizeof out) == QUIC_INITIAL_ERR_TRUNCATED,
          "Length past the packet refused");

    /* authentication */
    memcpy(q, packet, RFC_PACKET_LEN);
    q[RFC_PACKET_LEN - 1] ^= 0x01;
    CHECK(decrypt_exact(q, RFC_PACKET_LEN, RFC_PACKET_LEN, sizeof out) == QUIC_INITIAL_ERR_AUTH,
          "flipped tag byte refused");
    q[RFC_PACKET_LEN - 1] ^= 0x01;
    q[600] ^= 0x10;
    CHECK(decrypt_exact(q, RFC_PACKET_LEN, RFC_PACKET_LEN, sizeof out) == QUIC_INITIAL_ERR_AUTH,
          "flipped ciphertext byte refused");
    q[600] ^= 0x10;
    q[7] ^= 0x01; /* another DCID derives other keys */
    CHECK(decrypt_exact(q, RFC_PACKET_LEN, RFC_PACKET_LEN, sizeof out) == QUIC_INITIAL_ERR_AUTH,
          "altered DCID refused");

    /* a 1200-byte Initial of filler, like the accuracy corpus' client
     * Initials (tools/phase0/gen_tcpip_pcap.py, pad_to=1200) */
    size_t k = 0;
    q[k++] = 0xc3;
    q[k++] = 0, q[k++] = 0, q[k++] = 0, q[k++] = 1;
    q[k++] = 8;
    memcpy(q + k, RFC_DCID, 8), k += 8;
    q[k++] = 8;
    memset(q + k, 0xb0, 8), k += 8;
    q[k++] = 0;
    size_t length = RFC_PACKET_LEN - k - 2;
    q[k++] = (uint8_t) (0x40 | (length >> 8));
    q[k++] = (uint8_t) length;
    memset(q + k, 0x5a, RFC_PACKET_LEN - k);
    CHECK(decrypt_exact(q, RFC_PACKET_LEN, RFC_PACKET_LEN, sizeof out) == QUIC_INITIAL_ERR_AUTH,
          "1200-byte filler Initial: not decryptable");
}

int main(void) {
    printf("issue #570: QUIC v1/v2 client Initial decryption\n");
    test_aes();
    test_hmac();
    test_hkdf();
    test_gcm();
    test_rfc_keys();
    test_rfc_initial("RFC 9001 A.2 client Initial", QUIC_INITIAL_VERSION_1, RFC_V1_CRYPTO_FRAME, RFC_V1_HEADER,
                     RFC_V1_PROTECTED, "d1b1c98dd7689fb8ec11d242b123dc9b", "437b9aec36");
    test_rfc_initial("RFC 9369 A.2 client Initial", QUIC_INITIAL_VERSION_2, RFC_V2_CRYPTO_FRAME, RFC_V2_HEADER,
                     RFC_V2_PROTECTED, "ffe67b6abcdb4298b485dd04de806071", "94a0c95e80");
    test_prefixes(RFC_V1_PROTECTED, "every prefix of the RFC 9001 A.2 packet refused as truncated");
    test_prefixes(RFC_V2_PROTECTED, "every prefix of the RFC 9369 A.2 packet refused as truncated");
    test_malformed();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    if (g_failures != 0) {
        printf("RESULT: FAIL\n");
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
