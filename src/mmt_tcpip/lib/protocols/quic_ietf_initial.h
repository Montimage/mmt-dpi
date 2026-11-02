/*
 * quic_ietf_initial.h — removes the protection of a QUIC v1/v2 client
 * Initial packet (issue #570, F-BUG-307 part 1).
 *
 * Initial packets are protected with keys every observer can derive: they
 * are a function of the Destination Connection ID the client chose and of a
 * public per-version salt (RFC 9001 §5.2, RFC 9369 §3.3.1). This module
 * derives them (HKDF-SHA256), removes header protection (RFC 9001 §5.4,
 * AES-128 based) and authenticates and decrypts the payload (AES-128-GCM,
 * RFC 9001 §5.3), so that a later step can read the CRYPTO frames — the TLS
 * ClientHello carrying SNI and ALPN (issue #571). No classification verdict
 * reads the result yet.
 *
 * The caller owns every buffer: the packet is read only inside
 * [pkt, pkt + pkt_len), and the unprotected packet is written to the
 * caller's `out` buffer, never past `out_cap` bytes. Nothing is allocated,
 * so no per-flow or per-packet memory is held. Internal to the TCP/IP plugin
 * (hidden visibility), not a public API.
 */
#ifndef MMT_QUIC_IETF_INITIAL_H
#define MMT_QUIC_IETF_INITIAL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** QUIC version 1 (RFC 9000) and version 2 (RFC 9369). */
#define QUIC_INITIAL_VERSION_1 0x00000001u
#define QUIC_INITIAL_VERSION_2 0x6b3343cfu
/** Longest connection ID of a v1/v2 long header (RFC 9000 §17.2). */
#define QUIC_INITIAL_MAX_CID_LEN 20u
/** Smallest UDP payload carrying a client Initial (RFC 9000 §14.1). */
#define QUIC_INITIAL_MIN_DATAGRAM 1200u
/** An output buffer of this size holds the unprotected packet of any
 *  datagram a 1500-byte Ethernet MTU carries. */
#define QUIC_INITIAL_OUT_BUFFER 1500u

/** Outcome of quic_ietf_initial_decrypt(). Only QUIC_INITIAL_OK writes
 *  `info`; on any other outcome `out` holds unspecified bytes (on
 *  QUIC_INITIAL_ERR_RESERVED_BITS, the authenticated packet) that must not
 *  be read. */
typedef enum quic_initial_status {
    QUIC_INITIAL_OK = 0,
    QUIC_INITIAL_ERR_ARG,            /**< a NULL buffer */
    QUIC_INITIAL_ERR_SHORT_DATAGRAM, /**< datagram below 1,200 bytes */
    QUIC_INITIAL_ERR_NOT_INITIAL,    /**< short header, fixed bit clear,
                                          version not 1/2, not an Initial */
    QUIC_INITIAL_ERR_CID_LENGTH,     /**< DCID or SCID longer than 20 */
    QUIC_INITIAL_ERR_TRUNCATED,      /**< a declared span or the
                                          header-protection sample does not
                                          fit in the packet */
    QUIC_INITIAL_ERR_BUFFER,         /**< the unprotected packet does not
                                          fit in `out_cap` bytes */
    QUIC_INITIAL_ERR_AUTH,           /**< the AEAD tag does not verify */
    QUIC_INITIAL_ERR_RESERVED_BITS   /**< authenticated, but the reserved
                                          header bits are not zero
                                          (RFC 9000 §17.2) */
} quic_initial_status_t;

/** Where the unprotected packet lies in `out` once decrypted. */
typedef struct quic_initial_info {
    uint32_t version;       /**< QUIC_INITIAL_VERSION_1 or _2 */
    uint32_t packet_number; /**< truncated packet number as sent */
    uint8_t pn_length;      /**< 1..4 bytes */
    uint8_t dcid_len;
    uint8_t scid_len;
    size_t header_len;      /**< unprotected header, packet number
                                 included: out[0 .. header_len) */
    size_t payload_len;     /**< frames: out[header_len ..
                                 header_len + payload_len) */
    size_t packet_len;      /**< bytes of `pkt` this packet occupies; the
                                 next coalesced packet starts there */
} quic_initial_info_t;

/**
 * Decrypts the client Initial packet at `pkt`.
 *
 * @param pkt          first byte of the QUIC packet
 * @param pkt_len      bytes readable from `pkt` (to the end of the
 *                     captured datagram)
 * @param datagram_len size of the UDP payload holding the packet, for the
 *                     1,200-byte minimum of a client Initial
 * @param out          receives the unprotected header then the plaintext
 * @param out_cap      bytes writable at `out` (QUIC_INITIAL_OUT_BUFFER
 *                     covers a 1500-byte MTU)
 * @param info         set on QUIC_INITIAL_OK only
 */
quic_initial_status_t quic_ietf_initial_decrypt(const uint8_t *pkt, size_t pkt_len, size_t datagram_len,
                                                uint8_t *out, size_t out_cap, quic_initial_info_t *info);

#ifdef __cplusplus
}
#endif

#endif /* MMT_QUIC_IETF_INITIAL_H */
