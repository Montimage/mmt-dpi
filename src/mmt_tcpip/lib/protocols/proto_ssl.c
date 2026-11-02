#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "plugin_defs.h"
#include "mmt_core.h"
#include "tls_client_hello.h"

#include <ctype.h>

/*
Content types
Hex Dec Type
0x14    20  ChangeCipherSpec
0x15    21  Alert
0x16    22  Handshake
0x17    23  Application
0x18    24  Heartbeat


Versions
Major
version Minor
version Version type
3   0   SSL 3.0
3   1   TLS 1.0
3   2   TLS 1.1
3   3   TLS 1.2
 */

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////
#define MMT_MAX_SSL_REQUEST_SIZE 10000

/*
 * Size of the thread-local buffer the ClientHello / ServerHello detectors hand
 * to the server-name extractors. RFC 6066 caps a host_name at 255 bytes, so 256
 * holds the longest legal SNI hostname (255 bytes + NUL) without truncation
 * (issue #103); the previous 64-byte buffers silently clipped anything past 63.
 */
#define MMT_SSL_CERTIFICATE_BUF_LEN 256

static MMT_PROTOCOL_BITMASK detection_bitmask;
static MMT_PROTOCOL_BITMASK excluded_protocol_bitmask;
static MMT_SELECTION_BITMASK_PROTOCOL_SIZE selection_bitmask;

/*
 * The ClientHello SNI the detectors hand to the hostname table and point
 * packet->https_server_name at (packet-scoped: reset on every packet by
 * mmt_classify_ssl()). One per thread; both the single-segment and the
 * reassembled ClientHello paths write it (issue #568).
 */
static __thread char ssl_client_hello_sni[MMT_SSL_CERTIFICATE_BUF_LEN];

/*
 * Read a big-endian (network-order) 16-bit value at byte offset `off`.
 * Equivalent to ntohs(get_u16(payload, off)) but byte-assembled, so it is
 * safe on payload pointers that are not 2-byte aligned. The get_u16 macro
 * casts to uint16_t* and dereferences, which is undefined behaviour on a
 * misaligned address (UBSan -fsanitize=alignment); TLS record fields sit at
 * odd offsets (1 and 3) so that fires on real captures (issue #5, H2).
 */
static inline uint16_t ssl_read_u16_be(const uint8_t * payload, int off){
    return (uint16_t)(((uint16_t)payload[off] << 8) | (uint16_t)payload[off + 1]);
}

/* ---- record and handshake shapes (issue #569, F-CLEAN-005) --------------
 * Named reads for the classifier gates; offsets and constants are in
 * tls_client_hello.h. Each reader states how many bytes it needs. */

/* In a Certificate handshake message (RFC 5246 §7.4.2): the type, the low
 * 16 bits of the handshake length and of the certificate_list length. */
#define SSL_HS_TYPE_IN_MESSAGE 0
#define SSL_HS_LENGTH_LOW_IN_MESSAGE 2
#define SSL_CERT_LIST_LENGTH_LOW_IN_MESSAGE 5
/* First certificate: handshake header (4) + list length (3) + its length (3) */
#define SSL_CERT_MESSAGE_FIRST_CERT 10
/* The same from the start of a record holding the message. */
#define SSL_CERT_RECORD_FIRST_CERT (TLS_RECORD_HEADER_LEN + SSL_CERT_MESSAGE_FIRST_CERT)
/* Kept as it was: 0x11 (17) is no handshake type — a Certificate is 11 —
 * so this path only fires on a message of type 17. Correcting it moves
 * classification verdicts, which issue #569 leaves unchanged. */
#define SSL_CERT_MESSAGE_LEGACY_TYPE 0x11

/* SSLv2 record (draft-hickman-netscape-ssl-00 §B): a 2-byte header whose
 * second byte is the low length byte, then the message type and version. */
#define SSL2_LENGTH_LOW_OFFSET 1
#define SSL2_MSG_TYPE_OFFSET 2
#define SSL2_VERSION_MAJOR_OFFSET 3
#define SSL2_VERSION_MINOR_OFFSET 4
#define SSL2_CLIENT_HELLO 1
/* Header bytes before the length an SSLv2 record header counts. */
#define SSL2_HEADER_LEN 2
/* Highest version minor an SSLv2-framed hello carries: 3.2 (TLS 1.1). */
#define SSL2_MINOR_MAX 0x02

/* Version 3.0-3.3 in a major/minor pair. */
static inline int ssl_is_legacy_version(uint8_t major, uint8_t minor) {
    return major == TLS_VERSION_MAJOR && minor <= TLS_LEGACY_MINOR_MAX;
}

/* A record header of content type `type`, version 3.0-3.3 (3 bytes). */
static inline int ssl_is_record_of(const uint8_t *rec, uint8_t type) {
    return rec[TLS_RECORD_TYPE_OFFSET] == type
            && ssl_is_legacy_version(rec[TLS_RECORD_VERSION_OFFSET], rec[TLS_RECORD_VERSION_MINOR_OFFSET]);
}

/* One handshake message fills the record: its length is 4 below the
 * record's (9 bytes). */
static inline int ssl_handshake_fills_record(const uint8_t *rec) {
    return ssl_read_u16_be(rec, TLS_RECORD_LENGTH_OFFSET)
            - ssl_read_u16_be(rec, TLS_HANDSHAKE_LENGTH_LOW_OFFSET) == (int) TLS_HANDSHAKE_HEADER_LEN;
}

/* The hello in the record has legacy_version 3.0-3.3 (11 bytes). */
static inline int ssl_hello_version_ok(const uint8_t *rec) {
    return ssl_is_legacy_version(rec[TLS_HELLO_VERSION_OFFSET], rec[TLS_HELLO_VERSION_MINOR_OFFSET]);
}

/* The certificate_list fills the Certificate message `hs`: its length is 3
 * below the message's (7 bytes). */
static inline int ssl_certificate_fills_message(const uint8_t *hs) {
    return ssl_read_u16_be(hs, SSL_HS_LENGTH_LOW_IN_MESSAGE)
            - ssl_read_u16_be(hs, SSL_CERT_LIST_LENGTH_LOW_IN_MESSAGE) == 3;
}

/* A record whose handshake message has type `hs_type` (6 bytes). */
static inline int ssl_handshake_type_is(const uint8_t *rec, uint8_t hs_type) {
    return rec[TLS_HANDSHAKE_TYPE_OFFSET] == hs_type;
}

/* SSL 3.0 (0x0300) through TLS 1.2 (0x0303): the legacy record versions. */
#define SSL_RECORD_VERSION_MIN 0x0300
#define SSL_RECORD_VERSION_MAX 0x0303

int ssl_is_tls_record_header(const uint8_t * payload, int payload_len){
    /* A TLS/SSL record header is 5 bytes: 1 content-type + 2 version +
     * 2 length. Reject anything shorter before reading any of those fields,
     * otherwise the content-type/version/length reads below run off the end
     * of the captured payload (issue #5, H2). */
    if(payload_len < (int) TLS_RECORD_HEADER_LEN) return 0;
    uint8_t content_type = payload[TLS_RECORD_TYPE_OFFSET];
    if(content_type < TLS_CONTENT_CHANGE_CIPHER_SPEC || content_type > TLS_CONTENT_HEARTBEAT){
        // Incorrect content type
        return 0;
    }
    uint16_t version = ssl_read_u16_be(payload, TLS_RECORD_VERSION_OFFSET);
    if(version < SSL_RECORD_VERSION_MIN || version > SSL_RECORD_VERSION_MAX){
        // Incorrect version: 3.0 (768), 1.0 (769), 1.1 (770), 1.2 (771)
        return 0;
    }

    uint16_t length = ssl_read_u16_be(payload, TLS_RECORD_LENGTH_OFFSET);
    if(payload_len < length){
        // Invalid payload length
        return 0;
    }
    return 1;
}

int tls_get_number_records(const ipacket_t * ipacket){
    int nb_record = 0;
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    int payload_len = packet->payload_packet_len;
    if(payload_len <= 0) return 0;
    int offset = packet->payload_packet_len - payload_len;
    if(ssl_is_tls_record_header(packet->payload + offset,payload_len)){
        // SSL packet
        /* Require a full 5-byte record header to remain before reading the
         * record length, so the walk can never advance past the payload end
         * (issue #5, H2). The header re-check at the bottom enforces the same
         * bound for each subsequent record; this guard makes the top-of-loop
         * read self-evidently safe regardless of that invariant. */
        while(payload_len >= (int) TLS_RECORD_HEADER_LEN){
            nb_record++;
            int tls_total_length = ssl_read_u16_be(packet->payload + offset, TLS_RECORD_LENGTH_OFFSET)
                    + (int) TLS_RECORD_HEADER_LEN;
            offset += tls_total_length;
            payload_len -= tls_total_length;
            if(ssl_is_tls_record_header(packet->payload + offset,payload_len)!=1){
                break;
            }
        }
    }
    return nb_record;
}

//////////////// SSL attributes extraction routines.

int ssl_server_name_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    if ((ipacket->internal_packet)) {
        if (ipacket->internal_packet->packet_id == ipacket->packet_id) {
            if (ipacket->internal_packet->https_server_name.ptr != NULL && ((mmt_tcpip_internal_packet_t *) ipacket->internal_packet)->https_server_name.len > 0) {
                extracted_data->data = (void *) &ipacket->internal_packet->https_server_name;
                return 1;
            }
        }
    }
    return 0;
}

/*
 * The TLS record the SSL layer of this packet starts with: `*rec` points at
 * its header. The span is bounded by the TCP payload and by the captured
 * bytes. Returns the readable length, or 0 when no valid record header is
 * there.
 */
static int ssl_record_span(const ipacket_t * ipacket, unsigned proto_index, const uint8_t **rec) {
    int tcp_index = get_protocol_index_by_id(ipacket,PROTO_TCP);
    /* get_packet_offset_at_index() returns -1 for an invalid index and may
     * return an offset beyond the capture — reject both before touching data
     * (F-BUG-073). */
    if( tcp_index < 0 )
        return 0;
    int tcp_offset = get_packet_offset_at_index(ipacket,tcp_index + 1);
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    int ssl_offset = get_packet_offset_at_index(ipacket, proto_index);
    if( tcp_offset < 0 || ssl_offset < 0
            || (size_t)ssl_offset + TLS_RECORD_HEADER_LEN > ipacket->p_hdr->caplen )
        return 0;
    int ssl_payload_len = tcp_offset + packet->payload_packet_len - ssl_offset;
    /* never claim more than the captured bytes past ssl_offset */
    if( ssl_payload_len > (int)(ipacket->p_hdr->caplen - (size_t)ssl_offset) )
        ssl_payload_len = (int)(ipacket->p_hdr->caplen - (size_t)ssl_offset);
    if(ssl_is_tls_record_header(&ipacket->data[ssl_offset],ssl_payload_len)!=1){
        return 0;
    }
    *rec = &ipacket->data[ssl_offset];
    return ssl_payload_len;
}

/* ---- hello facts (issue #569) -------------------------------------------
 * The ALPN, version, ECH and JA4 a ClientHello or ServerHello carries are
 * reported on the packet that carries the hello, like ssl.server_name: they
 * live in the handler's packet (packet->tls_hello), keyed by packet id, never
 * in the flow. A hello one record holds is read on first use by an
 * extractor; one collected over several segments (issue #568) is read by the
 * classifier when it completes, before the collection is freed.
 */

static void ssl_facts_alpn(struct mmt_tls_hello_facts *f, const uint8_t *list, uint16_t len) {
    f->alpn.len = (uint16_t) tls_alpn_text(list, len, f->alpn_text, sizeof f->alpn_text);
    f->alpn.ptr = (const uint8_t *) f->alpn_text;
}

static void ssl_facts_from_client_hello(struct mmt_tls_hello_facts *f, const uint8_t *msg, uint32_t len) {
    tls_client_hello_t ch;
    if (tls_client_hello_parse(msg, len, &ch) != TLS_CH_OK) {
        return;
    }
    f->handshake_type = TLS_HANDSHAKE_CLIENT_HELLO;
    f->version = tls_client_hello_version(&ch);
    f->sni_hidden = ch.ech_outer;
    ssl_facts_alpn(f, ch.alpn, ch.alpn_len);
    if (tls_client_hello_ja4(&ch, 't', f->ja4_text)) {
        f->has_ja4 = 1;
        f->ja4.ptr = (const uint8_t *) f->ja4_text;
        f->ja4.len = TLS_JA4_LEN;
    }
}

static void ssl_facts_from_server_hello(struct mmt_tls_hello_facts *f, const uint8_t *msg, uint32_t len) {
    tls_server_hello_t sh;
    if (tls_server_hello_parse(msg, len, &sh) != TLS_CH_OK) {
        return;
    }
    f->handshake_type = TLS_HANDSHAKE_SERVER_HELLO;
    /* RFC 8446 §4.2.1: a TLS 1.3 server names its version in
     * supported_versions; legacy_version stays 0x0303 */
    f->version = sh.selected_version != 0 ? sh.selected_version : sh.legacy_version;
    ssl_facts_alpn(f, sh.alpn, sh.alpn_len);
}

/* Records the facts of the handshake message `msg` (header first) for the
 * current packet, replacing whatever an earlier packet left. */
static struct mmt_tls_hello_facts *ssl_note_hello(const ipacket_t * ipacket,
                                                  const uint8_t *msg, uint32_t len) {
    struct mmt_tls_hello_facts *f = &ipacket->internal_packet->tls_hello;
    memset(f, 0, sizeof *f);
    f->packet_id = ipacket->packet_id;
    f->filled = 1;
    if (msg != NULL && len >= TLS_HANDSHAKE_HEADER_LEN) {
        if (msg[0] == TLS_HANDSHAKE_CLIENT_HELLO) {
            ssl_facts_from_client_hello(f, msg, len);
        } else if (msg[0] == TLS_HANDSHAKE_SERVER_HELLO) {
            ssl_facts_from_server_hello(f, msg, len);
        }
    }
    return f;
}

/* The hello facts of this packet, or NULL when it carries no whole hello:
 * a handshake record that the packet holds entirely. */
static const struct mmt_tls_hello_facts *ssl_packet_facts(const ipacket_t * ipacket, unsigned proto_index) {
    if (ipacket->internal_packet == NULL) {
        return NULL;
    }
    struct mmt_tls_hello_facts *f = &ipacket->internal_packet->tls_hello;
    if (!f->filled || f->packet_id != ipacket->packet_id) {
        const uint8_t *rec = NULL;
        int avail = ssl_record_span(ipacket, proto_index, &rec);
        uint32_t rec_len = avail > 0 ? ssl_read_u16_be(rec, TLS_RECORD_LENGTH_OFFSET) : 0;
        if (avail > 0 && rec[TLS_RECORD_TYPE_OFFSET] == TLS_CONTENT_HANDSHAKE
                && rec_len + TLS_RECORD_HEADER_LEN <= (uint32_t) avail) {
            f = ssl_note_hello(ipacket, rec + TLS_RECORD_HEADER_LEN, rec_len);
        } else {
            f = ssl_note_hello(ipacket, NULL, 0);
        }
    }
    return f->handshake_type != 0 ? f : NULL;
}

int tls_content_type_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    const uint8_t *rec = NULL;
    if (ssl_record_span(ipacket, proto_index, &rec) == 0) {
        return 0;
    }
    return general_char_extraction(ipacket,proto_index,extracted_data);
}

/* The record-layer version; on a packet carrying a whole ClientHello the
 * highest version it advertises, on a ServerHello the negotiated one
 * (supported_versions, RFC 8446 §4.2.1 — issue #569, F-BUG-309). */
int tls_version_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    const struct mmt_tls_hello_facts *f = ssl_packet_facts(ipacket, proto_index);
    if (f != NULL) {
        if (extracted_data->data == NULL)
            return 0;
        memcpy(extracted_data->data, &f->version, sizeof f->version);
        return 1;
    }
    const uint8_t *rec = NULL;
    if (ssl_record_span(ipacket, proto_index, &rec) == 0) {
        return 0;
    }
    return general_short_extraction_with_ordering_change(ipacket,proto_index,extracted_data);
}


int tls_length_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    const uint8_t *rec = NULL;
    if (ssl_record_span(ipacket, proto_index, &rec) == 0) {
        return 0;
    }
    return general_short_extraction_with_ordering_change(ipacket,proto_index,extracted_data);
}

/* ALPN protocol names of a ClientHello (comma separated, wire order) or the
 * one a ServerHello selected (issue #569). */
int tls_alpn_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    const struct mmt_tls_hello_facts *f = ssl_packet_facts(ipacket, proto_index);
    if (f == NULL || f->alpn.len == 0) {
        return 0;
    }
    extracted_data->data = (void *) &f->alpn;
    return 1;
}

/* 1 when a ClientHello carries an outer encrypted_client_hello (RFC 9849):
 * its server_name is the ECH public name, the real one is encrypted. A
 * GREASE ECH extension (RFC 9849 §6.2) looks the same on the wire. */
int tls_sni_hidden_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    const struct mmt_tls_hello_facts *f = ssl_packet_facts(ipacket, proto_index);
    if (f == NULL || f->handshake_type != TLS_HANDSHAKE_CLIENT_HELLO || extracted_data->data == NULL) {
        return 0;
    }
    memcpy(extracted_data->data, &f->sni_hidden, sizeof f->sni_hidden);
    return 1;
}

/* JA4 fingerprint of a ClientHello (FoxIO JA4 specification). */
int tls_ja4_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    const struct mmt_tls_hello_facts *f = ssl_packet_facts(ipacket, proto_index);
    if (f == NULL || !f->has_ja4) {
        return 0;
    }
    extracted_data->data = (void *) &f->ja4;
    return 1;
}

int tls_number_record_extraction(const ipacket_t * ipacket, unsigned proto_index, attribute_t * extracted_data) {
    int nb_record = tls_get_number_records(ipacket);
    if(nb_record){
        /* extracted_data->data may be NULL (not-extracted branch taken on an
         * earlier packet) and need not be 2-byte aligned — store via memcpy
         * (issue #216). */
        if (extracted_data->data == NULL)
            return 0;
        memcpy(extracted_data->data, &nb_record, sizeof(uint16_t));
        return 1;
    }
    return 0;
}


///////// Extract Handshake protocol
// Message types
// Code    Description
// 0   HelloRequest
// 1   ClientHello
// 2   ServerHello
// 4   NewSessionTicket
// 11  Certificate
// 12  ServerKeyExchange
// 13  CertificateRequest
// 14  ServerHelloDone
// 15  CertificateVerify
// 16  ClientKeyExchange
// 20  Finished

//////////////// End of SSL attributes extraction routines

static void mmt_int_ssl_add_connection(ipacket_t * ipacket, uint32_t protocol) {
    if (protocol != PROTO_SSL) {
        mmt_internal_add_connection(ipacket, protocol, MMT_CORRELATED_PROTOCOL);
    } else {
        mmt_internal_add_connection(ipacket, protocol, MMT_REAL_PROTOCOL);
        set_session_timeout_delay(ipacket->session, ipacket->mmt_handler->long_session_timed_out);
    }
}

/* Issue #567: a service attributed from the SNI/certificate name (hostname
 * table) or from the IP-range table records that method, not "correlated". */
static void mmt_int_ssl_add_connection_by(ipacket_t * ipacket, uint32_t protocol, uint8_t method) {
    if (protocol != PROTO_SSL) {
        mmt_internal_add_connection_by(ipacket, protocol, MMT_CORRELATED_PROTOCOL, method);
    } else {
        mmt_int_ssl_add_connection(ipacket, protocol);
    }
}

static inline int mmt_ssl_min(uint32_t a, uint32_t b) {
    return (a < b ? a : b);
}

static void stripCertificateTrailer(char *buffer, int buffer_len) {
    int i;

    for (i = 0; i < buffer_len; i++) {
        if ((buffer[i] != '.')
                && (buffer[i] != '-')
                && (!isalpha(buffer[i]))
                && (!isdigit(buffer[i]))) {
            buffer[i] = '\0';
            break;
        }
    }
}

int getServerNameFromServerHello(ipacket_t * ipacket, char *buffer, int buffer_len) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    if (10 > packet->payload_packet_len) {
        return PROTO_UNKNOWN;
    }

    /* payload is byte-aligned: ssl_read_u16_be, not ntohs(get_u16()) — the
     * macro dereferences a uint16_t* on a possibly-odd offset, which is UB
     * and trips UBSan (issue #216). */
    /* the end of the ServerHello message: its record and handshake headers
     * plus the (low 16 bits of the) handshake length */
    uint16_t offset = 0, total_len = ssl_read_u16_be(packet->payload, TLS_HANDSHAKE_LENGTH_LOW_OFFSET)
            + TLS_RECORD_HEADER_LEN + TLS_HANDSHAKE_HEADER_LEN;
    /* what follows it, when enough of the payload is left to hold the start
     * of a certificate */
    const uint8_t *next = (total_len + SSL_CERT_RECORD_FIRST_CERT) < packet->payload_packet_len
            ? packet->payload + total_len : NULL;

    if (next != NULL
            && ssl_is_record_of(next, TLS_CONTENT_HANDSHAKE)
            && ssl_handshake_fills_record(next)
            && ssl_certificate_fills_message(next + TLS_RECORD_HEADER_LEN)
            && (next[TLS_HANDSHAKE_TYPE_OFFSET] == TLS_HANDSHAKE_CERTIFICATE)
            ) {
        offset = total_len + SSL_CERT_RECORD_FIRST_CERT; //This is the offset of the beginning of the certificate.
	}else if(next != NULL
            && (next[SSL_HS_TYPE_IN_MESSAGE] == SSL_CERT_MESSAGE_LEGACY_TYPE)
            && ssl_certificate_fills_message(next)
            ) {
        offset = total_len + SSL_CERT_MESSAGE_FIRST_CERT; //This is the offset of the beginning of the certificate.
	}

	if(offset) {
        if (offset + 2 > packet->payload_packet_len) {
            return PROTO_UNKNOWN;
        }
        //printf("Offset = %u --- val at offset = %u\n", offset, (uint32_t) packet->payload[offset]);
        //The objective is not to parse the certificate, rather to get the subject CN text from the first one
        uint8_t nb_offset = 1; //This is the '30' value
        if (offset + nb_offset >= packet->payload_packet_len) {
            return PROTO_UNKNOWN;
        }
        if (packet->payload[offset + nb_offset] & 0x80) {
            nb_offset += (packet->payload[offset + nb_offset] & 0xF) + 1;
            if (offset + nb_offset > packet->payload_packet_len) return PROTO_UNKNOWN;
        } else {
            nb_offset += 1;
        }
        if (offset + nb_offset > packet->payload_packet_len) return PROTO_UNKNOWN;
        offset += nb_offset; // start of the signed certificate
        //printf("Offset = %u --- val at offset = %u\n", offset, (uint32_t) packet->payload[offset]);
        if (offset + 4 > packet->payload_packet_len) {
            return PROTO_UNKNOWN;
        }

        nb_offset = 1;
        if (offset + nb_offset >= packet->payload_packet_len) {
            return PROTO_UNKNOWN;
        }
        if (packet->payload[offset + nb_offset] & 0x80) {
            nb_offset += (packet->payload[offset + nb_offset] & 0xF) + 1;
            if (offset + nb_offset > packet->payload_packet_len) return PROTO_UNKNOWN;
        } else {
            nb_offset += 1;
        }
        if (offset + nb_offset > packet->payload_packet_len) return PROTO_UNKNOWN;
        offset += nb_offset; //len of the serial number
        //printf("Offset = %u --- val at offset = %u\n", offset, (uint32_t) packet->payload[offset]);
        if (offset + 4 > packet->payload_packet_len) {
            return PROTO_UNKNOWN;
        }
        offset += 6 /* 4 octets + version field + next octet */; //len of the serial number
        if (offset > packet->payload_packet_len) {
            return PROTO_UNKNOWN;
        }

        if (offset >= packet->payload_packet_len) return PROTO_UNKNOWN;
        uint8_t sn_len = packet->payload[offset], items_nb = 0;

        if (offset + sn_len + 1 > packet->payload_packet_len) return PROTO_UNKNOWN;
        offset += sn_len + 1; //+1 for the len field on 1 byte
        while ((offset + 4 < packet->payload_packet_len) && items_nb < 4) {
            uint32_t item_offset;
            nb_offset = 1;
            //printf("Test 1\n");
            if (offset + nb_offset >= packet->payload_packet_len) return PROTO_UNKNOWN;
            if (packet->payload[offset + nb_offset] & 0x80) {
                nb_offset += (packet->payload[offset + nb_offset] & 0xF) + 1;
                if (offset + nb_offset > packet->payload_packet_len) return PROTO_UNKNOWN;
                if (nb_offset == 3) {
                    if (offset + nb_offset - 1 >= packet->payload_packet_len) return PROTO_UNKNOWN;
                    item_offset = packet->payload[offset + nb_offset - 1];
                } else {
                    if (offset + nb_offset < 2 || offset + nb_offset - 2 + 1 >= packet->payload_packet_len) return PROTO_UNKNOWN;
                    item_offset = ssl_read_u16_be(packet->payload, offset + nb_offset - 2);
                }
            } else {
                if (offset + nb_offset >= packet->payload_packet_len) return PROTO_UNKNOWN;
                item_offset = packet->payload[offset + nb_offset];
                nb_offset += 1;
            }
            if (offset + nb_offset > packet->payload_packet_len) return PROTO_UNKNOWN;
            if (item_offset > packet->payload_packet_len) return PROTO_UNKNOWN;
            offset += nb_offset;
            items_nb += 1;
            if (items_nb == 4 /* Subject part of the certificate */ && (offset + item_offset < packet->payload_packet_len)) {
                //printf("item 4\n");
                uint16_t sub_offset = 0;
                uint16_t current_offset = offset;
                while (sub_offset < item_offset) {
                    uint16_t sub_item_offset;
                    nb_offset = 1;
                    if (current_offset + nb_offset + 4 > packet->payload_packet_len) {
                        return PROTO_UNKNOWN;
                    }
                    if (current_offset + nb_offset >= packet->payload_packet_len) return PROTO_UNKNOWN;

                    if (packet->payload[current_offset + nb_offset] & 0x80) {
                        if (current_offset + nb_offset >= packet->payload_packet_len) return PROTO_UNKNOWN;
                        nb_offset += (packet->payload[current_offset + nb_offset] & 0xF) + 1;
                        if (current_offset + nb_offset > packet->payload_packet_len) return PROTO_UNKNOWN;
                        if (nb_offset == 3) {
                            if (current_offset + nb_offset - 1 >= packet->payload_packet_len) return PROTO_UNKNOWN;
                            sub_item_offset = packet->payload[current_offset + nb_offset - 1];
                        } else {
                            if (current_offset + nb_offset < 2 || current_offset + nb_offset - 2 + 1 >= packet->payload_packet_len) return PROTO_UNKNOWN;
                            sub_item_offset = ssl_read_u16_be(packet->payload, current_offset + nb_offset - 2);
                        }
                    } else {
                        if (current_offset + nb_offset >= packet->payload_packet_len) return PROTO_UNKNOWN;
                        sub_item_offset = packet->payload[current_offset + nb_offset];
                        nb_offset += 1;
                    }
                    if (current_offset + nb_offset * 2 + 2 + 3 + 2 >= packet->payload_packet_len) {
                        // not enough bytes for CN pattern check - advance safely
                        if (sub_item_offset + nb_offset > item_offset - sub_offset) return PROTO_UNKNOWN;
                        if (current_offset + sub_item_offset + nb_offset > packet->payload_packet_len) return PROTO_UNKNOWN;
                        sub_offset += sub_item_offset + nb_offset;
                        current_offset += sub_item_offset + nb_offset;
                        continue;
                    }
                    char subject_CN_pattern[] = {0x55, 0x04, 0x03};
                    if ((current_offset + nb_offset * 2 + 2 + 3 + 2 < packet->payload_packet_len) && mmt_memcmp(&packet->payload[current_offset + nb_offset * 2 + 2], subject_CN_pattern, 3) == 0) {
                        if (current_offset + nb_offset * 2 + 2 + 3 + 1 >= packet->payload_packet_len) return PROTO_UNKNOWN;
                        uint8_t CN_len = packet->payload[current_offset + nb_offset * 2 + 2 + 3 + 1];
                        /* unused
                        uint8_t CN_ecoding_type = packet->payload[current_offset + nb_offset * 2 + 2 + 3];
                        uint8_t min_len = mmt_ssl_min(CN_len, buffer_len - 1);
                        */
                        if((uint32_t)CN_len + current_offset + nb_offset * 2 + 2 + 3 + 2 >= packet->payload_packet_len) {
                            return 0;
                        }

                        u_int begin = 0, len;
                        char *server_name = (char*) &packet->payload[current_offset + nb_offset * 2 + 2 + 3 + 2];

                        while (begin < CN_len) {
                            if ((!isprint(server_name[begin]))
                                    || ispunct(server_name[begin])
                                    || isspace(server_name[begin]))
                                begin++;
                            else
                                break;
                        }

                        len = mmt_ssl_min(CN_len - begin, buffer_len - 1);
                        strncpy(buffer, &server_name[begin], len);
                        buffer[len] = '\0';
                        stripCertificateTrailer(buffer, buffer_len);
                        packet->https_server_name.ptr = (const uint8_t*)buffer;
                        //packet->https_server_name.ptr = &server_name[begin];
                        packet->https_server_name.len = len;
                        packet->packet_id = ipacket->packet_id;
                        return 1;
                    }
                    if (sub_item_offset + nb_offset > item_offset - sub_offset) return PROTO_UNKNOWN;
                    if (current_offset + sub_item_offset + nb_offset > packet->payload_packet_len) return PROTO_UNKNOWN;
                    sub_offset += sub_item_offset + nb_offset;
                    current_offset += sub_item_offset + nb_offset;
                    if (current_offset > packet->payload_packet_len) return PROTO_UNKNOWN;
                }
            }
            if (offset + item_offset > packet->payload_packet_len) return PROTO_UNKNOWN;
            offset += item_offset;
        }
    }
    return (0); /* Not found */
}

/*
 * Copy the host_name of a parsed ClientHello (tls_client_hello.c reads the RFC
 * 6066 server_name entry per its wire structure: name_type host_name, a
 * name_length that fits the extension — issue #103) into `buffer`: up to
 * buffer_len-1 bytes, NUL terminated, cut at the first byte that cannot be in
 * a host name, and point the packet's https_server_name at it. Returns 2
 * (hostname found) or 0 (no SNI, or a malformed / non-host_name first entry).
 */
static int ssl_sni_from_client_hello(ipacket_t * ipacket, const tls_client_hello_t * ch,
                                     char *buffer, int buffer_len) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (ch->sni_status != TLS_SNI_OK) {
        return 0;
    }
    int len = mmt_ssl_min(ch->sni_len, buffer_len - 1);
    memcpy(buffer, ch->sni, len);
    buffer[len] = '\0';
    stripCertificateTrailer(buffer, buffer_len);
    packet->https_server_name.ptr = (const uint8_t*)buffer;
    packet->https_server_name.len = len;
    packet->packet_id = ipacket->packet_id;
    return (2 /* Client Certificate */);
}

/*
 * SNI of a ClientHello whose record starts this packet's payload. The body is
 * bounded by the record length and by the captured payload (F-BUG-064): the
 * extension walk stops at the first extension that does not fit, and a
 * declared extension block longer than the bytes present is walked as far
 * as they go (tls_client_hello_parse_body()).
 */
int getServerNameFromClientHello(ipacket_t * ipacket, char *buffer, int buffer_len) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    /* record header (5) + handshake header (4) precede the ClientHello body */
    const uint32_t body_offset = TLS_RECORD_HEADER_LEN + TLS_HANDSHAKE_HEADER_LEN;

    memset(buffer, 0, buffer_len);
    if (packet->payload_packet_len <= body_offset) {
        return 0;
    }
    /* payload is byte-aligned: ssl_read_u16_be, not an ntohs(*(uint16_t*))
     * dereference — the latter is a misaligned load and trips UBSan
     * (issue #216). */
    uint32_t end = (uint32_t) ssl_read_u16_be(packet->payload, TLS_RECORD_LENGTH_OFFSET) + TLS_RECORD_HEADER_LEN;
    if (end > packet->payload_packet_len) {
        end = packet->payload_packet_len;
    }
    if (end <= body_offset) {
        return 0;
    }
    tls_client_hello_t ch;
    tls_client_hello_parse_body(packet->payload + body_offset, end - body_offset, &ch);
    return ssl_sni_from_client_hello(ipacket, &ch, buffer, buffer_len);
}

/* The service a ClientHello SNI names: the hostname table, else the mail
 * prefixes of the SSL-wrapped mail protocols. */
static uint32_t ssl_detect_protocol_from_sni(ipacket_t * ipacket, char *certificate) {
    /* Check the protocol by hostname */
    uint32_t proto = PROTO_UNKNOWN;
    if (ipacket->mmt_handler->hostname_classify == 1)
    {
        proto = get_proto_id_by_hostname(ipacket, certificate, strlen(certificate));
    }
    if (proto != PROTO_UNKNOWN) {
        mmt_int_ssl_add_connection_by(ipacket, proto, MMT_CLASSIFICATION_METHOD_HOSTNAME);
        return proto;
    }
    if(mmt_memcmp((void *) certificate, (void *) "pop.", 4) == 0) {
        mmt_int_ssl_add_connection(ipacket, PROTO_POPS);
        return PROTO_POPS;
    } else if(mmt_memcmp((void *) certificate, (void *) "imap.", 5) == 0) {
        mmt_int_ssl_add_connection(ipacket, PROTO_IMAPS);
        return PROTO_IMAPS;
    } else if(mmt_memcmp((void *) certificate, (void *) "pop3.", 5) == 0) {
        mmt_int_ssl_add_connection(ipacket, PROTO_POPS);
        return PROTO_POPS;
    } else if(mmt_memcmp((void *) certificate, (void *) "smtp.", 5) == 0) {
        mmt_int_ssl_add_connection(ipacket, PROTO_SMTPS);
        return PROTO_SMTPS;
    }
    return PROTO_UNKNOWN;
}

uint32_t sslDetectProtocolFromClientHello(ipacket_t * ipacket) {
    ssl_client_hello_sni[0] = '\0';
    if (getServerNameFromClientHello(ipacket, ssl_client_hello_sni, sizeof (ssl_client_hello_sni)) > 0) {
        return ssl_detect_protocol_from_sni(ipacket, ssl_client_hello_sni);
    }
    return PROTO_UNKNOWN;
}

/* Same, for a ClientHello handshake message collected over several segments
 * (issue #568): `msg` is the record body, the 4-byte handshake header first. */
static uint32_t ssl_detect_protocol_from_client_hello_message(ipacket_t * ipacket,
                                                              const uint8_t *msg, uint32_t len) {
    tls_client_hello_t ch;
    memset(ssl_client_hello_sni, 0, sizeof (ssl_client_hello_sni));
    tls_client_hello_parse(msg, len, &ch);
    if (ssl_sni_from_client_hello(ipacket, &ch, ssl_client_hello_sni, sizeof (ssl_client_hello_sni)) > 0) {
        return ssl_detect_protocol_from_sni(ipacket, ssl_client_hello_sni);
    }
    return PROTO_UNKNOWN;
}

uint32_t sslDetectProtocolFromServerHello(ipacket_t * ipacket) {
    //printf("Test from Detect From Server Hello\n");
    /* unused
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    */

    static __thread char certificate[MMT_SSL_CERTIFICATE_BUF_LEN];
    certificate[0] = '\0';
    int rc = getServerNameFromServerHello(ipacket, certificate, sizeof (certificate));
    //int rc = 0;

    if (rc > 0) {
        /* Check the protocol by hostname */
        uint32_t proto = PROTO_UNKNOWN;
        if (ipacket->mmt_handler->hostname_classify == 1)
        {
            proto = get_proto_id_by_hostname(ipacket, certificate, strlen(certificate));
        }
        //printf("Protocol detected has id = %u --- Server: %s --- %u \n", proto, certificate, strlen(certificate));
        if (proto != PROTO_UNKNOWN) {
            mmt_int_ssl_add_connection_by(ipacket, proto, MMT_CLASSIFICATION_METHOD_HOSTNAME);
            return proto;
        }
    }

    return PROTO_UNKNOWN;
}

uint32_t sslDetectProtocolFromServerCertificate(ipacket_t * ipacket) {
    //printf("Test from Detect From Server Certificate\n");
    return PROTO_UNKNOWN;
}

/* Offset of the type byte that starts a WhatsApp frame. */
#define WHATSAPP_LEAD_OFFSET 0

int check_whatsapp(ipacket_t * ipacket) {
    //Whatsapp signatures are all orthogonal with SSL signature! If we detect any valid Whatsapp signature return a positive value
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    /* whatsapp runs over port 443 */
    if (packet->tcp->source == htons(443) || packet->tcp->dest == htons(443)) {

        if (packet->iph /* IPv4 only */) {
            /*
             * Whatsapp IM IPs 50.22.231.32/27. This is not the only range but it seems this is for the IM.
             * Anyway, if this is not the case, check the signatures.
             */
            if (((ntohl(packet->iph->saddr) & 0xFFFFFFE0 /* 255.255.255.224 */) == 0x3216E720 /* 50.22.231.32 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFFFFE0 /* 255.255.255.224 */) == 0x3216E720 /* 50.22.231.32 */)) {
                mmt_internal_add_connection_by(ipacket, PROTO_WHATSAPP, MMT_REAL_PROTOCOL, MMT_CLASSIFICATION_METHOD_IP); /* #567: address-range match */
                return 1;
            }
        }

        char whatsapp_pattern[] = {0x57, 0x41, 0x01, 0x02, 0x00};
        /* the first byte of a WhatsApp frame: its type (0x57 'W' opens the
         * connection header) */
        const uint8_t lead = packet->payload_packet_len >= 1 ? packet->payload[WHATSAPP_LEAD_OFFSET] : 0;

        if ((flow->l4.tcp.whatsapp_conn_stage == 2 && flow->l4.tcp.whatsapp_stage >= 2) || (flow->l4.tcp.whatsapp_stage >= 6)) {
            mmt_internal_add_connection(ipacket, PROTO_WHATSAPP, MMT_REAL_PROTOCOL);
            return 1;
        }
        if (flow->l4.tcp.whatsapp_conn_stage == 0 && packet->payload_packet_len >= 1 && lead == 0x57) {
            if (packet->payload_packet_len > 5 && (mmt_memcmp(packet->payload, whatsapp_pattern, sizeof (whatsapp_pattern)) == 0)) {
                flow->l4.tcp.whatsapp_conn_stage = 2;
                return 1;
            }
            flow->l4.tcp.whatsapp_conn_stage = 1;
            return 1;
        }
        if ((flow->l4.tcp.whatsapp_conn_stage == 1) && (packet->payload_packet_len > 5) &&
                (mmt_memcmp(packet->payload, &whatsapp_pattern[1], sizeof (whatsapp_pattern) - 1) == 0)) {
            flow->l4.tcp.whatsapp_conn_stage = 2;
            return 1;
        }
        if ((lead == 0x10) && (packet->payload_packet_len == 1)) {
            flow->l4.tcp.whatsapp_stage += 1;
            return 1;
        }
        if (((lead == 0x10 || lead == 0x80) && (packet->payload_packet_len > 3) &&
                (ssl_read_u16_be(packet->payload, WHATSAPP_LEAD_OFFSET + 1) == packet->payload_packet_len)) ||
                (lead == 0x00 && (packet->payload_packet_len > 3) && (ssl_read_u16_be(packet->payload, WHATSAPP_LEAD_OFFSET) == packet->payload_packet_len))) {
            flow->l4.tcp.whatsapp_stage += 1;
            return 1;
        }
    }
    return 0;
}

int check_viber_tcp(ipacket_t * ipacket) {
    //Viber signatures are all orthogonal with SSL signature! If we detect any valid vider signature return a positive value
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    /* viber runs over tcp port 4244 or 5242 */
    if (packet->tcp->source == htons(5242) || packet->tcp->dest == htons(5242) || packet->tcp->source == htons(4244) || packet->tcp->dest == htons(4244)) {
        if (packet->iph /* IPv4 only */) {
            /*
                Viber Media AWS-VIBER-MEDIA (NET-54-169-63-160-1) 54.169.63.160 - 54.169.63.191
                Viber Media S a r l AWS-VIBER-MEDIA-S-A-R-L (NET-54-93-255-64-1) 54.93.255.64 - 54.93.255.127
                Crittercism AWS-VIBER-MEDIA (NET-52-0-252-0-1) 52.0.252.0 - 52.0.255.255
                54.169.63.160/27
                54.93.255.64/26
                52.0.252.0/22
              */
            /*
             * Viber is hosted over Amazon cloud
             * Check if this is the case
             * 50.16.0.0/14
             * 107.20.0.0/14
             * 23.20.0.0/14
             * 54.224.0.0/11
             * 46.51.0.0/16
             * 46.137.0.0/16
             * 176.34.0.0/16
             * These are not the only ranges but the most consequent ones
             */
            if (((ntohl(packet->iph->saddr) & 0xFFFFFFE0 /* 255.255.255.224 */) == 0x36A93FA0 /* 54.169.63.160 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFFFFE0 /* 255.255.255.224 */) == 0x36A93FA0 /* 54.169.63.160 */)) {
                mmt_internal_add_connection_by(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL, MMT_CLASSIFICATION_METHOD_IP); /* #567: address-range match */
                return 1;
            }

            if (((ntohl(packet->iph->saddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0x3400FC00 /* 52.0.252.0 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0x3400FC00 /* 52.0.252.0 */)) {
                mmt_internal_add_connection_by(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL, MMT_CLASSIFICATION_METHOD_IP); /* #567: address-range match */
                return 1;
            }

            if (((ntohl(packet->iph->saddr) & 0xFFFFFFC0 /* 255.255.255.192 */) == 0x365DFF40 /* 54.93.255.64 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFFFFC0 /* 255.255.255.192 */) == 0x365DFF40 /* 54.93.255.64 */)) {
                mmt_internal_add_connection_by(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL, MMT_CLASSIFICATION_METHOD_IP); /* #567: address-range match */
                return 1;
            }

            if (((ntohl(packet->iph->saddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x32100000 /* 50.16.0.0/14 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x32100000 /* 50.16.0.0/14 */)) {
                mmt_internal_add_connection_by(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL, MMT_CLASSIFICATION_METHOD_IP); /* #567: address-range match */
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x6B140000 /* 107.20.0.0/14 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x6B140000 /* 107.20.0.0/14 */)) {
                mmt_internal_add_connection_by(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL, MMT_CLASSIFICATION_METHOD_IP); /* #567: address-range match */
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x17140000 /* 23.20.0.0/14 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFC0000 /* 255.252.0.0 */) == 0x17140000 /* 23.20.0.0/14 */)) {
                mmt_internal_add_connection_by(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL, MMT_CLASSIFICATION_METHOD_IP); /* #567: address-range match */
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFE00000 /* 255.224.0.0 */) == 0x36E00000 /* 54.224.0.0/14 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFE00000 /* 255.224.0.0 */) == 0x36E00000 /* 54.224.0.0/14 */)) {
                mmt_internal_add_connection_by(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL, MMT_CLASSIFICATION_METHOD_IP); /* #567: address-range match */
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x2E330000 /* 46.51.0.0/16 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x2E330000 /* 46.51.0.0/16 */)) {
                mmt_internal_add_connection_by(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL, MMT_CLASSIFICATION_METHOD_IP); /* #567: address-range match */
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x2E890000 /* 46.137.0.0/16 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0x2E890000 /* 46.137.0.0/16 */)) {
                mmt_internal_add_connection_by(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL, MMT_CLASSIFICATION_METHOD_IP); /* #567: address-range match */
                return 1;
            }
            if (((ntohl(packet->iph->saddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0xB0220000 /* 176.34.0.0/16 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0xB0220000 /* 176.34.0.0/16 */)) {
                mmt_internal_add_connection_by(ipacket, PROTO_VIBER, MMT_REAL_PROTOCOL, MMT_CLASSIFICATION_METHOD_IP); /* #567: address-range match */
                return 1;
            }
        }
    }
    return 0;
}

int check_gameforge_tcp(ipacket_t * ipacket) {
    //Gameforge may use SSL port 443, skip it when this is the case
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    /* Skip TCP port 443 */
    if (packet->tcp->source != htons(443) && packet->tcp->dest != htons(443) && packet->tcp->source != htons(80) && packet->tcp->dest != htons(80)) {
        if (packet->iph /* IPv4 only */) {
            /*
             * Gameforge has 79.110.80.0 - 79.110.95.255 (79.110.80.0/22) IP range
             */
            if (((ntohl(packet->iph->saddr) & 0xFFFFF000 /* 255.255.240.0 */) == 0x4F6E5000 /* 79.110.80.0 */)
                    || ((ntohl(packet->iph->daddr) & 0xFFFFF000 /* 255.255.240.0 */) == 0x4F6E5000 /* 79.110.80.0 */)) {
                mmt_internal_add_connection_by(ipacket, PROTO_GAMEFORGE, MMT_REAL_PROTOCOL, MMT_CLASSIFICATION_METHOD_IP); /* #567: address-range match */
                return 1;
            }
        }
    }
    return 0;
}

/*
 * Issue #568 (F-BUG-302): a ClientHello split over several TCP segments — the
 * norm since post-quantum key shares pushed browser hellos past one MSS.
 *
 * The record header and handshake header of a ClientHello: handshake type 1,
 * client version 3.0-3.3, and a handshake length 4 bytes below the record
 * length (one handshake message filling its record). The caller has checked
 * the record type and version and that more than 12 bytes are present.
 */
static int ssl_is_client_hello_start(const struct mmt_tcpip_internal_packet_struct *packet) {
    const uint8_t *p = packet->payload;
    return ssl_handshake_type_is(p, TLS_HANDSHAKE_CLIENT_HELLO) && ssl_hello_version_ok(p)
            && ssl_handshake_fills_record(p);
}

/*
 * Start collecting a ClientHello record this segment holds only the start of:
 * once per flow, only for a record within the 2^14-byte TLS plaintext limit
 * (RFC 8446 §5.1) — a larger one is no valid record and is never buffered.
 * The record body (the handshake message) is collected by TCP sequence
 * number from the client direction. Returns 1 when collection started.
 */
static int ssl_begin_client_hello(ipacket_t * ipacket, struct mmt_internal_tcpip_session_struct *flow) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    uint16_t record_len = ssl_read_u16_be(packet->payload, TLS_RECORD_LENGTH_OFFSET);

    if (flow->l4.tcp.ssl_hello_started || ipacket->session == NULL || packet->tcp == NULL
            || record_len > TLS_HELLO_MAX_MESSAGE) {
        return 0;
    }
    flow->l4.tcp.ssl_hello_started = 1;
    uint32_t body_seq = ntohl(packet->tcp->seq) + TLS_RECORD_HEADER_LEN;
    if (tls_hello_reasm_begin(&flow->tls_hello, record_len, body_seq,
                              ipacket->session->last_packet_direction) != TLS_REASM_PENDING) {
        return 0;
    }
    tls_hello_reasm_feed(&flow->tls_hello, body_seq, packet->payload + TLS_RECORD_HEADER_LEN,
                         (size_t) packet->payload_packet_len - TLS_RECORD_HEADER_LEN);
    return 1;
}

/*
 * A client segment of a ClientHello being collected: once the record is
 * complete, its SNI is read like a single-segment one and the buffer is
 * freed. Returns the classifier verdict, or -1 when the packet is not part of
 * the collection (server direction) or the collection was dropped — gap past
 * TLS_HELLO_MAX_RANGES, TLS_HELLO_MAX_STALLS segments without a new byte —
 * and the packet takes the usual path.
 */
static int ssl_continue_client_hello(ipacket_t * ipacket, struct mmt_internal_tcpip_session_struct *flow) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;

    if (ipacket->session == NULL || packet->tcp == NULL
            || ipacket->session->last_packet_direction != tls_hello_reasm_tag(flow->tls_hello)) {
        return -1;
    }
    tls_hello_reasm_status_t status = tls_hello_reasm_feed(&flow->tls_hello,
            ntohl(packet->tcp->seq), packet->payload, packet->payload_packet_len);
    if (status == TLS_REASM_DROPPED) {
        return -1;
    }
    if (status == TLS_REASM_COMPLETE) {
        uint32_t len = 0;
        const uint8_t *msg = tls_hello_reasm_data(flow->tls_hello, &len);
        mmt_int_ssl_add_connection(ipacket, PROTO_SSL);
        ssl_detect_protocol_from_client_hello_message(ipacket, msg, len);
        /* issue #569: its ALPN, version, ECH and JA4, before it is freed */
        ssl_note_hello(ipacket, msg, len);
        tls_hello_reasm_release(&flow->tls_hello);
    }
    return 1;
}

/*
 * A handshake record (content type 22, version 3.0-3.3) starting the payload
 * of a packet of more than 12 bytes: a ClientHello (whole, or the start of
 * one collected over later segments — issue #568), a ServerHello or a
 * Certificate. Returns the verdict, or -1 when it is none of them.
 */
static int ssl_classify_handshake_record(ipacket_t * ipacket, struct mmt_internal_tcpip_session_struct *flow) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    const uint8_t *p = packet->payload;

    if (ssl_is_client_hello_start(packet)
            && packet->payload_packet_len >= ssl_read_u16_be(p, TLS_RECORD_LENGTH_OFFSET) + TLS_RECORD_HEADER_LEN) { /* the whole record is here (issue #568: what follows it is not parsed) */
        //This is a client hello! process it as so
        mmt_int_ssl_add_connection(ipacket, PROTO_SSL);
        //Now try to get the server from this packet
        sslDetectProtocolFromClientHello(ipacket);
        return 1;
    }
    if (ssl_is_client_hello_start(packet) && ssl_begin_client_hello(ipacket, flow)) {
        /* Issue #568: the record continues in later segments; its SNI is
         * read once they complete it (ssl_continue_client_hello()). */
        mmt_int_ssl_add_connection(ipacket, PROTO_SSL);
        return 1;
    }
    /* A Server Hello may share its record with other handshake messages:
     * either its length fills the record, or the flow is already TLS (we
     * have seen the Client Hello, the server sends several messages). */
    if ((ssl_handshake_fills_record(p) || packet->detected_protocol_stack[0] == PROTO_SSL)
            && ssl_handshake_type_is(p, TLS_HANDSHAKE_SERVER_HELLO) && ssl_hello_version_ok(p)) {
        //This is a server hello! process it as so
        mmt_int_ssl_add_connection(ipacket, PROTO_SSL);
        //Now try to parse this message to check if it contains a certificate record
        sslDetectProtocolFromServerHello(ipacket);
        return 1;
    }
    if (ssl_handshake_fills_record(p)
            && ssl_certificate_fills_message(p + TLS_RECORD_HEADER_LEN)
            && ssl_handshake_type_is(p, TLS_HANDSHAKE_CERTIFICATE)) {
        //This is a server certificate! process it as so
        mmt_int_ssl_add_connection(ipacket, PROTO_SSL);
        //Now try to parse this certificate to get the subject and try to get the corresonding protocol
        sslDetectProtocolFromServerCertificate(ipacket);
        return 1;
    }
    return -1;
}

/*
 * The records other than a handshake one the classifier recognises in a
 * payload of more than 12 bytes: an SSLv2 ClientHello, TLS application data
 * and an encrypted alert (versions 3.0-3.3). Each raises the flow's SSL
 * stage and asks for more packets (4). Returns -1 when none matches.
 */
static int ssl_classify_other_record(const struct mmt_tcpip_internal_packet_struct *packet,
                                     struct mmt_internal_tcpip_session_struct *flow) {
    const uint8_t *p = packet->payload;
    int sslv2_hello = p[SSL2_MSG_TYPE_OFFSET] == SSL2_CLIENT_HELLO
            && p[SSL2_VERSION_MAJOR_OFFSET] == TLS_VERSION_MAJOR
            && p[SSL2_VERSION_MINOR_OFFSET] <= SSL2_MINOR_MAX;

	// SSLv2 Record
	/* BW: Who the hell is still using SSL2.0 !!!!! */
	if (sslv2_hello && (packet->payload_packet_len - p[SSL2_LENGTH_LOW_OFFSET] == SSL2_HEADER_LEN)) {
	  flow->l4.tcp.ssl_stage += 1;
	  return 4;
	}

	/* BW: Who the hell is still using SSL2.0 !!!!! */
	if (sslv2_hello && (packet->payload_packet_len - SSL2_HEADER_LEN) >= p[SSL2_LENGTH_LOW_OFFSET]
		&& (flow->l4.tcp.ssl_stage > 0)) {
   	    flow->l4.tcp.ssl_stage += 1;
	  return 4;
	}

	/* BW: I saw TLS packets less than 40 bytes!
	 * TLS application: 0x17 followed by version (3.0 or 3.1 or 3.2) followed by len */
	if (ssl_is_record_of(p, TLS_CONTENT_APPLICATION_DATA)
			&& (packet->payload_packet_len <= (ssl_read_u16_be(p, TLS_RECORD_LENGTH_OFFSET) + TLS_RECORD_HEADER_LEN))) {
		// SSLv3 Record
		flow->l4.tcp.ssl_stage += 1;
		return 4;
	}

	/* BW:
	 * TLS application: 0x15 (encrypted alert) followed by version (3.0 or 3.1 or 3.2) followed by len
	 * TLS encrypted alert! This is SSL. The encrypted alert cannot be
	 * detected in stage 0 — the record only becomes readable here.
	 */
	if (ssl_is_record_of(p, TLS_CONTENT_ALERT)
			&& (packet->payload_packet_len - ssl_read_u16_be(p, TLS_RECORD_LENGTH_OFFSET) == (int) TLS_RECORD_HEADER_LEN)) {
		// SSLv3 Record
		flow->l4.tcp.ssl_stage += 1;
		return 4;
	}
    return -1;
}

int mmt_classify_ssl(ipacket_t * ipacket, unsigned index) {
    struct mmt_tcpip_internal_packet_struct *packet = ipacket->internal_packet;
    struct mmt_internal_tcpip_session_struct *flow = packet->flow;

    packet->https_server_name.ptr = NULL;
    packet->https_server_name.len = 0;

    /* Issue #568: the rest of a ClientHello whose record started earlier —
     * before the heuristics below read its middle bytes as record headers. */
    if (flow->tls_hello != NULL) {
        int verdict = ssl_continue_client_hello(ipacket, flow);
        if (verdict >= 0) {
            return verdict;
        }
    }

	if (check_whatsapp(ipacket) || check_viber_tcp(ipacket) || check_gameforge_tcp(ipacket)) {
		return 0;
	}

    if (packet->payload_packet_len <= 12) {
        return 0;
    }

	/*
	 * BW: stage 3 = detected SSL like messages process this as SSL
	 */
	if (flow->l4.tcp.ssl_stage >= 3) {
		mmt_int_ssl_add_connection(ipacket, PROTO_SSL);
		//try to guess from IP address! this is the only way now!
        uint32_t proto = PROTO_UNKNOWN;
        if (ipacket->mmt_handler->ip_address_classify == 1)
        {
            proto = get_proto_id_from_address(ipacket);
        }
        if (proto != PROTO_UNKNOWN) {
			mmt_int_ssl_add_connection_by(ipacket, proto, MMT_CLASSIFICATION_METHOD_IP);
		}
		return 1;
	}

    if (ssl_is_record_of(packet->payload, TLS_CONTENT_HANDSHAKE)) {
        int verdict = ssl_classify_handshake_record(ipacket, flow);
        if (verdict >= 0) {
            return verdict;
        }
        // SSLv3 Record
        flow->l4.tcp.ssl_stage += 1;
    }

    int verdict = ssl_classify_other_record(packet, flow);
    if (verdict >= 0) {
        return verdict;
    }

    if (ipacket->session->data_packet_count_direction[ipacket->session->last_packet_direction] < 8) {
		//Wait for more packets before deciding this is not SSL
        return 4;
    }

    MMT_EXCLUDE_PROTOCOL(flow, PROTO_SSL);
    return 0;
}

int mmt_check_ssl(ipacket_t * ipacket, unsigned index) {
    { /* guard evaluated by the classifier walk (issue #561) */
        return mmt_classify_ssl(ipacket, index);
    }
    return 4;
}

//////////////// SSL attributes
static attribute_metadata_t ssl_attributes_metadata[SSL_ATTRIBUTES_NB] = {
    {SSL_SERVER_NAME, SSL_SERVER_NAME_ALIAS, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_SESSION_CHANGING, ssl_server_name_extraction},
    {TLS_NUMBER_RECORD, TLS_NUMBER_RECORD_ALIAS, MMT_U16_DATA, sizeof (short), POSITION_NOT_KNOWN, SCOPE_PACKET, tls_number_record_extraction},
    {TLS_CONTENT_TYPE, TLS_CONTENT_TYPE_ALIAS, MMT_U8_DATA, sizeof (char), 0, SCOPE_PACKET, tls_content_type_extraction},
    {TLS_VERSION, TLS_VERSION_ALIAS, MMT_U16_DATA, sizeof (short), 1, SCOPE_PACKET, tls_version_extraction},
    {TLS_LENGTH, TLS_LENGTH_ALIAS, MMT_U16_DATA, sizeof (short), 3, SCOPE_PACKET, tls_length_extraction},
    {TLS_ALPN, TLS_ALPN_ALIAS, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_PACKET, tls_alpn_extraction},
    {TLS_SNI_HIDDEN, TLS_SNI_HIDDEN_ALIAS, MMT_U8_DATA, sizeof (char), POSITION_NOT_KNOWN, SCOPE_PACKET, tls_sni_hidden_extraction},
    {TLS_JA4, TLS_JA4_ALIAS, MMT_HEADER_LINE, sizeof (void *), POSITION_NOT_KNOWN, SCOPE_PACKET, tls_ja4_extraction},
};

/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

int init_proto_ssl_struct() {
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_SSL, PROTO_SSL_ALIAS);
    if (protocol_struct != NULL) {
        int i = 0;

        for (; i < SSL_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &ssl_attributes_metadata[i]);
        }

        mmt_init_classify_bitmasks(&selection_bitmask, &detection_bitmask,
                &excluded_protocol_bitmask,
                MMT_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD,
                PROTO_SSL, PROTO_SSL);

        return register_protocol(protocol_struct, PROTO_SSL);
    } else {
        return 0;
    }
}

