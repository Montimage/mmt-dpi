/*
 * tls_client_hello.h — transport-independent TLS ClientHello parser and the
 * bounded buffer that collects a ClientHello spread over several segments
 * (issue #568, F-BUG-302), plus the readers of the ALPN, supported_versions
 * and encrypted_client_hello extensions, the JA4 fingerprint and a ServerHello
 * parser (issue #569).
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

/* ---- wire constants (issue #569, F-CLEAN-005) -------------------------- */

/** Record header (RFC 8446 §5.1): content type, legacy version, length. */
#define TLS_RECORD_HEADER_LEN 5u
#define TLS_RECORD_TYPE_OFFSET 0
#define TLS_RECORD_VERSION_OFFSET 1
#define TLS_RECORD_VERSION_MINOR_OFFSET 2
#define TLS_RECORD_LENGTH_OFFSET 3
/** Content types (RFC 8446 §5.1, RFC 6520). */
#define TLS_CONTENT_CHANGE_CIPHER_SPEC 20
#define TLS_CONTENT_ALERT 21
#define TLS_CONTENT_HANDSHAKE 22
#define TLS_CONTENT_APPLICATION_DATA 23
#define TLS_CONTENT_HEARTBEAT 24
/** Major version byte of SSL 3.0 through TLS 1.3 (0x0300-0x0304). */
#define TLS_VERSION_MAJOR 0x03
/** Highest minor version a legacy_version field carries: 3 (TLS 1.2). */
#define TLS_LEGACY_MINOR_MAX 0x03
/** Handshake header: msg_type (1) and a 24-bit length (RFC 8446 §4). */
#define TLS_HANDSHAKE_HEADER_LEN 4u
/** Offsets in a record that starts with a handshake message. */
#define TLS_HANDSHAKE_TYPE_OFFSET 5
#define TLS_HANDSHAKE_LENGTH_OFFSET 6
/** Low 16 bits of the 24-bit handshake length. */
#define TLS_HANDSHAKE_LENGTH_LOW_OFFSET 7
/** legacy_version of a ClientHello / ServerHello: major, minor. */
#define TLS_HELLO_VERSION_OFFSET 9
#define TLS_HELLO_VERSION_MINOR_OFFSET 10
/** Handshake message types (RFC 8446 §4). */
#define TLS_HANDSHAKE_CLIENT_HELLO 1
#define TLS_HANDSHAKE_SERVER_HELLO 2
#define TLS_HANDSHAKE_CERTIFICATE 11
/** Protocol versions (RFC 8446 §4.2.1). */
#define TLS_VERSION_1_3 0x0304
/** Extension types (IANA TLS ExtensionType Values). */
#define TLS_EXT_SERVER_NAME 0               /**< RFC 6066 §3 */
#define TLS_EXT_SIGNATURE_ALGORITHMS 13     /**< RFC 8446 §4.2.3 */
#define TLS_EXT_ALPN 16                     /**< RFC 7301 §3.1 */
#define TLS_EXT_SUPPORTED_VERSIONS 43       /**< RFC 8446 §4.2.1 */
#define TLS_EXT_ENCRYPTED_CLIENT_HELLO 0xfe0d /**< RFC 9849 §5 */
/** ECHClientHelloType of an outer ClientHello (RFC 9849 §5). */
#define TLS_ECH_OUTER 0
/** RFC 8701 GREASE value: 0x?a?a with both bytes equal. */
#define TLS_IS_GREASE(v) ((((v) & 0x0f0fu) == 0x0a0au) && (((v) >> 8) == ((v) & 0xffu)))
/** Characters of a JA4 fingerprint: "t13d1516h2_8daaf6152771_e5627efa2ab1". */
#define TLS_JA4_LEN 36u
/** Cipher suites or extensions a JA4 sorts; a hello with more has none. */
#define TLS_JA4_MAX_ITEMS 256u
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
    /* Issue #569: the first extension of each type, as it is on the wire
     * (NULL when absent); every one fits the buffer. */
    const uint8_t *alpn;           /**< ALPN body: ProtocolNameList */
    uint16_t alpn_len;
    const uint8_t *supported_versions; /**< supported_versions body */
    uint16_t supported_versions_len;
    const uint8_t *signature_algorithms; /**< signature_algorithms body */
    uint16_t signature_algorithms_len;
    uint8_t has_sni_extension;     /**< a server_name extension was walked */
    uint8_t ech_outer;             /**< an outer encrypted_client_hello was walked */
} tls_client_hello_t;

/** A parsed ServerHello (or HelloRetryRequest). Pointers into the buffer. */
typedef struct tls_server_hello {
    uint16_t legacy_version;       /**< legacy_version (0x0303 for TLS 1.3) */
    uint16_t cipher_suite;
    uint16_t selected_version;     /**< supported_versions; 0 when absent */
    const uint8_t *alpn;           /**< ALPN body (one ProtocolName); NULL if none */
    uint16_t alpn_len;
} tls_server_hello_t;

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

/**
 * The version a ClientHello advertises: the highest non-GREASE entry of its
 * supported_versions extension (RFC 8446 §4.2.1), else legacy_version.
 */
uint16_t tls_client_hello_version(const tls_client_hello_t *ch);

/**
 * Parses a ServerHello handshake message (msg_type 2, 24-bit length, body),
 * bounded like tls_client_hello_parse(). The extensions read are
 * supported_versions (selected_version) and ALPN.
 * @return TLS_CH_OK, TLS_CH_TRUNCATED or TLS_CH_MALFORMED (`out` zeroed).
 */
tls_client_hello_status_t tls_server_hello_parse(const uint8_t *msg, size_t len,
        tls_server_hello_t *out);

/**
 * Writes the protocol names of an ALPN ProtocolNameList (RFC 7301 §3.1),
 * comma separated and NUL terminated, to `out` (`cap` bytes, cap > 0): the
 * well-formed names that fit whole, in wire order, up to the first that
 * does not; bytes are copied as they are.
 * @return the characters written (0: no list, or no well-formed name).
 */
size_t tls_alpn_text(const uint8_t *list, uint16_t len, char *out, size_t cap);

/**
 * Computes the JA4 fingerprint of a parsed ClientHello (FoxIO JA4
 * specification, technical_details/JA4.md): `transport` is 't' (TCP),
 * 'q' (QUIC) or 'd' (DTLS). Writes TLS_JA4_LEN characters and a NUL to
 * `out`. GREASE values are skipped everywhere.
 * @return 1, or 0 when the hello has more than TLS_JA4_MAX_ITEMS cipher
 *         suites or extensions (`out` is then the empty string).
 */
int tls_client_hello_ja4(const tls_client_hello_t *ch, char transport,
        char out[TLS_JA4_LEN + 1]);

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
