/*
 * tls_client_hello.h — transport-independent TLS ClientHello parser and the
 * bounded buffer that collects a ClientHello spread over several segments
 * (issue #568, F-BUG-302).
 *
 * The parser reads a ClientHello from a byte buffer the caller owns: a
 * handshake message (TLS over TCP: the body of the first handshake record;
 * QUIC: the CRYPTO stream) or, for the legacy single-segment path, the
 * ClientHello body that follows the 4-byte handshake header. It never reads
 * outside [buf, buf + len), never allocates and keeps pointers into the
 * caller's buffer, so a result is valid as long as that buffer is.
 *
 * The reassembly buffer holds one handshake message of a declared length, at
 * most TLS_HELLO_MAX_MESSAGE bytes (2^14, the TLS record plaintext limit of
 * RFC 8446 §5.1), allocated once with mmt_malloc() at its declared size. Bytes
 * are placed by their stream position (a TCP sequence number, a QUIC CRYPTO
 * offset), so duplicates add nothing and a reordered segment lands where it
 * belongs; anything past the declared length is ignored. It is dropped — and
 * freed — when it would need more than TLS_HELLO_MAX_RANGES disjoint ranges,
 * or after TLS_HELLO_MAX_STALLS segments that added no byte.
 */
#ifndef MMT_TLS_CLIENT_HELLO_H
#define MMT_TLS_CLIENT_HELLO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Handshake type of a ClientHello (RFC 8446 §4). */
#define TLS_HANDSHAKE_CLIENT_HELLO 1
/** Extension type of server_name (RFC 6066 §3). */
#define TLS_EXT_SERVER_NAME 0
/** Largest handshake message the reassembly buffer holds: 2^14 bytes. */
#define TLS_HELLO_MAX_MESSAGE 16384u
/** Disjoint byte ranges a reassembly may track before it is dropped. */
#define TLS_HELLO_MAX_RANGES 4
/** Segments adding no byte (duplicates, out of window) before a drop. */
#define TLS_HELLO_MAX_STALLS 8

/** Outcome of a parse. */
typedef enum tls_client_hello_status {
    TLS_CH_OK = 0,        /**< every fixed field and the extension block fit */
    TLS_CH_TRUNCATED = 1, /**< the extension block declares more bytes than
                               the buffer holds: the extensions that fit were
                               walked */
    TLS_CH_MALFORMED = 2  /**< not a ClientHello, or a fixed field overruns
                               the buffer: no field of `out` is set */
} tls_client_hello_status_t;

/** Outcome of reading the server_name extension. */
typedef enum tls_sni_status {
    TLS_SNI_ABSENT = 0,   /**< no server_name extension was walked */
    TLS_SNI_OK = 1,       /**< host_name found: `sni` / `sni_len` set */
    TLS_SNI_MALFORMED = 2 /**< the first server_name entry is not a well-formed
                               host_name (RFC 6066 §3) */
} tls_sni_status_t;

/** A parsed ClientHello. Every pointer points into the parsed buffer. */
typedef struct tls_client_hello {
    uint16_t legacy_version;       /**< client_version / legacy_version */
    const uint8_t *random;         /**< 32 bytes */
    const uint8_t *session_id;
    uint8_t session_id_len;
    uint8_t compression_len;
    uint16_t cipher_suites_len;    /**< bytes (2 per suite on the wire) */
    const uint8_t *cipher_suites;
    const uint8_t *compression;
    const uint8_t *extensions;     /**< first extension header; NULL if none */
    uint16_t extensions_len;       /**< bytes of `extensions` walked (clamped
                                        to the buffer on TLS_CH_TRUNCATED) */
    uint16_t sni_len;
    const uint8_t *sni;            /**< host_name bytes, not NUL terminated */
    tls_sni_status_t sni_status;
    uint16_t extension_count;      /**< extensions that fit and were walked */
} tls_client_hello_t;

/**
 * Parses a ClientHello body: the bytes after the 4-byte handshake header,
 * starting at legacy_version, `len` of them readable.
 * @return TLS_CH_OK, TLS_CH_TRUNCATED or TLS_CH_MALFORMED.
 */
tls_client_hello_status_t tls_client_hello_parse_body(const uint8_t *body, size_t len,
        tls_client_hello_t *out);

/**
 * Parses a ClientHello handshake message: msg_type 1, a 24-bit length, then
 * the body. The body is bounded by the declared length and by `len`; a
 * declared length past `len` parses what is there (TLS_CH_TRUNCATED at most).
 */
tls_client_hello_status_t tls_client_hello_parse(const uint8_t *msg, size_t len,
        tls_client_hello_t *out);

/** Called once per extension that fits; a non-zero return stops the walk. */
typedef int (*tls_client_hello_ext_fn)(uint16_t type, const uint8_t *data,
        uint16_t len, void *ctx);

/**
 * Walks the extensions of a parsed ClientHello in wire order (for the
 * ALPN, supported_versions, ECH and fingerprint readers).
 * @return the number of extensions visited.
 */
unsigned tls_client_hello_foreach_extension(const tls_client_hello_t *ch,
        tls_client_hello_ext_fn fn, void *ctx);

/** Outcome of feeding a segment to a reassembly. */
typedef enum tls_hello_reasm_status {
    TLS_REASM_PENDING = 0,  /**< more bytes are needed */
    TLS_REASM_COMPLETE = 1, /**< every byte of the message is present */
    TLS_REASM_DROPPED = 2   /**< refused or given up: the slot is freed (NULL) */
} tls_hello_reasm_status_t;

/** One handshake message being collected. Opaque outside tls_client_hello.c. */
typedef struct tls_hello_reasm tls_hello_reasm_t;

/**
 * Starts collecting a `need`-byte message whose first byte has stream
 * position `base`, into the empty slot `*slot`; `tag` is caller data (the
 * TLS classifier keeps the client direction there). Refused (DROPPED, no
 * allocation) when `need` is 0 or above TLS_HELLO_MAX_MESSAGE, when `*slot`
 * is already in use, or when the allocation fails.
 */
tls_hello_reasm_status_t tls_hello_reasm_begin(tls_hello_reasm_t **slot, uint32_t need,
        uint32_t base, uint8_t tag);

/**
 * Places `len` bytes whose first byte has stream position `pos`. Positions
 * compare modulo 2^32 (TCP sequence space); bytes before the message start
 * or past its end are ignored. DROPPED frees the slot. A caller with wider
 * positions (QUIC CRYPTO offsets are 62-bit) must refuse data whose offset
 * + length exceeds base + TLS_HELLO_MAX_MESSAGE before narrowing to 32 bits,
 * or a far offset would wrap into the buffer.
 */
tls_hello_reasm_status_t tls_hello_reasm_feed(tls_hello_reasm_t **slot, uint32_t pos,
        const uint8_t *data, size_t len);

/** The collected message (valid once COMPLETE) and its length. */
const uint8_t *tls_hello_reasm_data(const tls_hello_reasm_t *r, uint32_t *len);

/** The caller data given to tls_hello_reasm_begin(). */
uint8_t tls_hello_reasm_tag(const tls_hello_reasm_t *r);

/** Bytes the reassembly holds allocated (header included); 0 for NULL. */
size_t tls_hello_reasm_footprint(const tls_hello_reasm_t *r);

/** Frees the reassembly in `*slot` (if any) and clears the slot. */
void tls_hello_reasm_release(tls_hello_reasm_t **slot);

#ifdef __cplusplus
}
#endif

#endif /* MMT_TLS_CLIENT_HELLO_H */
