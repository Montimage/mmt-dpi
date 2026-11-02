/*
 * quic_ietf_crypto.h — the TLS ClientHello a QUIC client sends in the CRYPTO
 * frames of its Initial packets (issue #571, F-BUG-307 part 2).
 *
 * A QUIC client carries its TLS ClientHello in CRYPTO frames (RFC 9001 §4)
 * inside Initial packets, whose protection every observer can remove
 * (quic_ietf_initial.h, issue #570). This module decrypts the client
 * Initials of one flow, walks their frames (RFC 9000 §19), collects the
 * CRYPTO stream with the shared reassembly buffer of tls_client_hello.h and,
 * once the ClientHello is whole, reads its SNI, ALPN and JA4 ('q').
 *
 * Bounds, all per flow:
 *   - at most QUIC_CRYPTO_MAX_ATTEMPTS decryptions, counted before each call
 *     whatever its outcome, then the flow is done (forged Initials cost a
 *     bounded number of AES/GHASH passes);
 *   - a frame length is checked against the plaintext left in its packet
 *     before anything else; a CRYPTO frame whose 62-bit offset + length
 *     passes TLS_HELLO_MAX_MESSAGE is skipped before it is narrowed to the
 *     32-bit positions of the reassembly buffer;
 *   - the buffer is allocated once, at the ClientHello's declared length
 *     (at most TLS_HELLO_MAX_MESSAGE), and only once its 4-byte handshake
 *     header is known; the facts are allocated once the ClientHello parses.
 * Frames at offset 4 or more that arrive in an earlier packet than the last
 * header byte are not kept (the buffer does not exist yet).
 *
 * Internal to the TCP/IP plugin (hidden visibility), not a public API.
 */
#ifndef MMT_QUIC_IETF_CRYPTO_H
#define MMT_QUIC_IETF_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "tls_client_hello.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Initial decryptions per flow, counted before each call. */
#define QUIC_CRYPTO_MAX_ATTEMPTS 8u
/** CRYPTO frames one Initial may carry; more and the flow is done. */
#define QUIC_CRYPTO_MAX_FRAMES 16u
/** Longest SNI kept (RFC 6066 §3: a host_name is at most 255 bytes). */
#define QUIC_HELLO_SNI_CAP 256u
/** Longest ALPN text kept, NUL included. */
#define QUIC_HELLO_ALPN_CAP 128u

/** What a flow's ClientHello names; NUL-terminated texts. */
typedef struct quic_hello_facts {
    char sni[QUIC_HELLO_SNI_CAP];   /**< host_name; empty when absent */
    char alpn[QUIC_HELLO_ALPN_CAP]; /**< protocol names, comma separated */
    char ja4[TLS_JA4_LEN + 1];      /**< JA4 with transport 'q' */
    uint16_t sni_len;
    uint16_t alpn_len;
    uint8_t has_ja4;
    uint8_t sni_hidden;             /**< an outer encrypted_client_hello */
} quic_hello_facts_t;

/** State of a flow: QUIC_CRYPTO_ACTIVE until the hello is read or given up. */
enum quic_crypto_state {
    QUIC_CRYPTO_ACTIVE = 0,
    QUIC_CRYPTO_DONE = 1
};

/** One flow's CRYPTO collection; all zero is a fresh flow. */
typedef struct quic_crypto {
    tls_hello_reasm_t *reasm;   /**< the ClientHello being collected */
    quic_hello_facts_t *hello;  /**< set once it parsed */
    const void *client;         /**< endpoint of the first client Initial
                                     that decrypted; only its Initials are
                                     read afterwards */
    uint8_t hdr[TLS_HANDSHAKE_HEADER_LEN]; /**< CRYPTO offsets [0, 4) */
    uint8_t hdr_have;           /**< bit i: hdr[i] is known */
    uint8_t state;              /**< enum quic_crypto_state */
    uint8_t attempts;           /**< decryptions so far */
} quic_crypto_t;

/** Outcome of quic_crypto_consume(). */
typedef enum quic_crypto_result {
    QUIC_CRYPTO_NONE = 0,  /**< nothing new */
    QUIC_CRYPTO_HELLO = 1  /**< this datagram completed the ClientHello:
                                `hello` is set */
} quic_crypto_result_t;

/**
 * Reads the client Initials of one UDP datagram.
 *
 * @param st           the flow's state
 * @param src          the sending endpoint (compared by address only)
 * @param pkt          first byte of the first QUIC packet
 * @param pkt_len      bytes readable from `pkt` within the datagram
 * @param datagram_len UDP payload size from the UDP header (the 1,200-byte
 *                     minimum of a client Initial)
 */
quic_crypto_result_t quic_crypto_consume(quic_crypto_t *st, const void *src,
        const uint8_t *pkt, size_t pkt_len, size_t datagram_len);

/**
 * Walks the frames of one decrypted Initial (`frames`, `len` bytes of
 * plaintext) and collects its CRYPTO frames; the step quic_crypto_consume()
 * runs per packet, exposed for the tests.
 * @return QUIC_CRYPTO_HELLO when the frames completed the ClientHello.
 */
quic_crypto_result_t quic_crypto_walk_frames(quic_crypto_t *st, const uint8_t *frames,
        size_t len);

/** Frees the reassembly buffer and the facts (the session cleanup of a QUIC
 *  flow); the flow is done afterwards. */
void quic_crypto_release(quic_crypto_t *st);

#ifdef __cplusplus
}
#endif

#endif /* MMT_QUIC_IETF_CRYPTO_H */
